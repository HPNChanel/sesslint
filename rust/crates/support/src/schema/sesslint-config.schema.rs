//! RX-SCH-sesslint-config.schema: advisory draft-07 input validation.
//!
//! Source: `02694d537104659df66cdd084354739f3cccc440`. This is not the
//! TOML loader: it neither discovers files nor applies CLI defaults. The pin
//! has no config JSON producer, so no producer-byte parity is claimed.
//! Numbers retain their JSON spelling and are classified exactly, without
//! binary-float rounding. Duplicate keys, lone surrogates, more than 64 nested
//! containers and documents larger than 1 MiB are refused at the parser boundary.

use std::error::Error;
use std::fmt;

/// Exact bytes of the schema on the card pin, including its final LF.
pub const CONFIG_SCHEMA_JSON: &str = r##"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://raw.githubusercontent.com/HPNChanel/sesslint/main/schemas/sesslint-config.schema.json",
  "title": "sesslint-config/v1",
  "description": "SessLint configuration: sesslint.toml, .sesslint.toml, or [tool.sesslint] in pyproject.toml. Mirrors the fail-closed key validation in sesslint.config — unknown keys are rejected, and select and ignore cannot both be set.",
  "type": "object",
  "additionalProperties": false,
  "allOf": [
    {
      "not": {
        "required": ["select", "ignore"]
      }
    }
  ],
  "properties": {
    "profile": {
      "type": "string",
      "description": "Severity/triad preset to apply.",
      "enum": [
        "claude-strict",
        "neutral",
        "openai-strict"
      ]
    },
    "adapter": {
      "type": "string",
      "description": "Input ledger adapter; 'auto' sniffs the first lines.",
      "enum": [
        "auto",
        "canonical",
        "claude",
        "claude-code-jsonl",
        "codex",
        "codex-rollout",
        "openai",
        "openai-agents"
      ]
    },
    "policy": {
      "type": "string",
      "description": "Repair policy: conservative refuses uncertain fixes; salvage additionally extracts a partial ledger when repair is refused.",
      "enum": [
        "conservative",
        "salvage"
      ]
    },
    "fail_on": {
      "type": "string",
      "description": "Lowest severity that produces a nonzero exit code.",
      "enum": [
        "error",
        "warning"
      ]
    },
    "select": {
      "type": "array",
      "description": "Rule codes to include (allow-list); when set, only these run. Mutually exclusive with ignore.",
      "items": {"type": "string", "pattern": "\\S"}
    },
    "ignore": {
      "type": "array",
      "description": "Rule codes to suppress from the report. Mutually exclusive with select.",
      "items": {"type": "string", "pattern": "\\S"}
    },
    "skip_undetected": {
      "type": "boolean",
      "description": "Exit 0 instead of 2 when format detection fails on every input."
    },
    "confidence_min": {
      "type": "number",
      "description": "Minimum detection confidence required to accept a format verdict."
    },
    "margin_min": {
      "type": "number",
      "description": "Minimum confidence margin between the top two format candidates."
    },
    "max_files": {
      "type": "integer",
      "minimum": 1,
      "description": "Upper bound on files visited during a recursive scan."
    },
    "max_bytes": {
      "type": "integer",
      "minimum": 1,
      "description": "Maximum cumulative bytes in a directory scan."
    },
    "exclude": {
      "type": "array",
      "description": "Glob patterns for paths excluded from scanning.",
      "items": {
        "type": "string",
        "pattern": "\\S"
      }
    },
    "ext": {
      "type": "array",
      "description": "File extensions scanned in directory mode (e.g. ['.jsonl']).",
      "items": {
        "type": "string",
        "pattern": "\\S"
      }
    },
    "max_file_bytes": {
      "type": "integer",
      "minimum": 1
    },
    "max_findings_per_code": {
      "type": "integer",
      "minimum": 1
    },
    "timestamp_skew_ms": {
      "type": "integer",
      "minimum": 0
    },
    "fail_on_unsupported": {
      "type": "boolean"
    }
  }
}
"##;

const PARSE_MAX_DEPTH: usize = 64;
const MAX_INPUT_BYTES: usize = 1_048_576;

/// Content-free rejection. Field names always come from the fixed schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSchemaError {
    Syntax {
        byte: usize,
    },
    Limit,
    Reject {
        keyword: &'static str,
        field: &'static str,
    },
}

impl fmt::Display for ConfigSchemaError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { byte } => write!(out, "config schema syntax at byte {byte}"),
            Self::Limit => out.write_str("config schema input limit"),
            Self::Reject { keyword, field } => write!(out, "config schema {keyword} at {field}"),
        }
    }
}
impl Error for ConfigSchemaError {}

fn reject(keyword: &'static str, field: &'static str) -> ConfigSchemaError {
    ConfigSchemaError::Reject { keyword, field }
}

/// A syntactically valid JSON number, retaining arbitrary precision and spelling.
#[derive(Clone, PartialEq, Eq)]
pub struct JsonNumber(String);

impl fmt::Debug for JsonNumber {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("JsonNumber(..)")
    }
}

impl JsonNumber {
    pub fn as_json(&self) -> &str {
        &self.0
    }

    /// Mathematical integer membership, including integral fractions/exponents.
    pub fn is_integer(&self) -> bool {
        let body = self.0.strip_prefix('-').unwrap_or(&self.0);
        let (mantissa, exponent) = body.split_once(['e', 'E']).unwrap_or((body, "0"));
        let digits: Vec<u8> = mantissa.bytes().filter(|b| *b != b'.').collect();
        if digits.iter().all(|b| *b == b'0') {
            return true;
        }
        let fractional = mantissa.split_once('.').map_or(0, |(_, s)| s.len());
        // Any magnitude beyond the input length has the same classification.
        // Saturating the exponent avoids allocating a huge power of ten.
        let negative = exponent.starts_with('-');
        let mut magnitude = 0i64;
        for b in exponent.bytes().filter(u8::is_ascii_digit) {
            magnitude = (magnitude * 10 + i64::from(b - b'0')).min(2_097_152);
        }
        let signed = if negative { -magnitude } else { magnitude };
        let scale = signed - fractional as i64;
        scale >= 0 || digits.iter().rev().take_while(|b| **b == b'0').count() as i64 >= -scale
    }

    fn is_zero(&self) -> bool {
        self.0
            .split(['e', 'E'])
            .next()
            .unwrap_or("")
            .bytes()
            .filter(u8::is_ascii_digit)
            .all(|b| b == b'0')
    }

    fn meets_minimum(&self, zero_allowed: bool) -> bool {
        self.is_integer()
            && if self.is_zero() {
                zero_allowed
            } else {
                !self.0.starts_with('-')
            }
    }
}

macro_rules! text_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $text),+ } }
            fn read(value: &Json, field: &'static str) -> Result<Self, ConfigSchemaError> {
                let Json::String(text) = value else { return Err(reject("type", field)); };
                match text.as_str() { $($text => Ok(Self::$variant)),+, _ => Err(reject("enum", field)) }
            }
        }
    };
}
text_enum!(Profile { ClaudeStrict => "claude-strict", Neutral => "neutral", OpenaiStrict => "openai-strict" });
text_enum!(Adapter { Auto => "auto", Canonical => "canonical", Claude => "claude", ClaudeCodeJsonl => "claude-code-jsonl", Codex => "codex", CodexRollout => "codex-rollout", Openai => "openai", OpenaiAgents => "openai-agents" });
text_enum!(Policy { Conservative => "conservative", Salvage => "salvage" });
text_enum!(FailOn { Error => "error", Warning => "warning" });

/// Typed schema fields. All fields are optional; parsing preserves presence.
/// Constructing/mutating this struct directly does not perform validation.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct Config {
    pub profile: Option<Profile>,
    pub adapter: Option<Adapter>,
    pub policy: Option<Policy>,
    pub fail_on: Option<FailOn>,
    pub select: Option<Vec<String>>,
    pub ignore: Option<Vec<String>>,
    pub skip_undetected: Option<bool>,
    pub confidence_min: Option<JsonNumber>,
    pub margin_min: Option<JsonNumber>,
    pub max_files: Option<JsonNumber>,
    pub max_bytes: Option<JsonNumber>,
    pub exclude: Option<Vec<String>>,
    pub ext: Option<Vec<String>>,
    pub max_file_bytes: Option<JsonNumber>,
    pub max_findings_per_code: Option<JsonNumber>,
    pub timestamp_skew_ms: Option<JsonNumber>,
    pub fail_on_unsupported: Option<bool>,
}

impl Config {
    pub fn parse(input: &str) -> Result<Self, ConfigSchemaError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(ConfigSchemaError::Limit);
        }
        let Json::Object(entries) = parse_json(input)? else {
            return Err(reject("type", "<root>"));
        };
        if entries.iter().any(|(k, _)| k == "select") && entries.iter().any(|(k, _)| k == "ignore")
        {
            return Err(reject("not", "<root>"));
        }
        let mut result = Self::default();
        for (key, value) in entries {
            match key.as_str() {
                "profile" => result.profile = Some(Profile::read(&value, "profile")?),
                "adapter" => result.adapter = Some(Adapter::read(&value, "adapter")?),
                "policy" => result.policy = Some(Policy::read(&value, "policy")?),
                "fail_on" => result.fail_on = Some(FailOn::read(&value, "fail_on")?),
                "select" => result.select = Some(read_list(value, "select")?),
                "ignore" => result.ignore = Some(read_list(value, "ignore")?),
                "exclude" => result.exclude = Some(read_list(value, "exclude")?),
                "ext" => result.ext = Some(read_list(value, "ext")?),
                "skip_undetected" => {
                    result.skip_undetected = Some(read_bool(value, "skip_undetected")?)
                }
                "fail_on_unsupported" => {
                    result.fail_on_unsupported = Some(read_bool(value, "fail_on_unsupported")?)
                }
                "confidence_min" => {
                    result.confidence_min = Some(read_number(value, "confidence_min", None)?)
                }
                "margin_min" => result.margin_min = Some(read_number(value, "margin_min", None)?),
                "max_files" => {
                    result.max_files = Some(read_number(value, "max_files", Some(false))?)
                }
                "max_bytes" => {
                    result.max_bytes = Some(read_number(value, "max_bytes", Some(false))?)
                }
                "max_file_bytes" => {
                    result.max_file_bytes = Some(read_number(value, "max_file_bytes", Some(false))?)
                }
                "max_findings_per_code" => {
                    result.max_findings_per_code =
                        Some(read_number(value, "max_findings_per_code", Some(false))?)
                }
                "timestamp_skew_ms" => {
                    result.timestamp_skew_ms =
                        Some(read_number(value, "timestamp_skew_ms", Some(true))?)
                }
                _ => return Err(reject("additionalProperties", "<root>")),
            }
        }
        Ok(result)
    }
}

pub fn validate(input: &str) -> Result<(), ConfigSchemaError> {
    Config::parse(input).map(|_| ())
}

fn read_bool(value: Json, field: &'static str) -> Result<bool, ConfigSchemaError> {
    match value {
        Json::Bool(b) => Ok(b),
        _ => Err(reject("type", field)),
    }
}
fn read_number(
    value: Json,
    field: &'static str,
    minimum: Option<bool>,
) -> Result<JsonNumber, ConfigSchemaError> {
    let Json::Number(n) = value else {
        return Err(reject("type", field));
    };
    if let Some(zero_allowed) = minimum {
        if !n.is_integer() {
            return Err(reject("type", field));
        }
        if !n.meets_minimum(zero_allowed) {
            return Err(reject("minimum", field));
        }
    }
    Ok(n)
}
fn read_list(value: Json, field: &'static str) -> Result<Vec<String>, ConfigSchemaError> {
    let Json::Array(items) = value else {
        return Err(reject("type", field));
    };
    items
        .into_iter()
        .map(|item| {
            let Json::String(text) = item else {
                return Err(reject("type", field));
            };
            // Python's Unicode regex \s also includes the four information separators.
            if !text
                .chars()
                .any(|c| !(c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)))
            {
                return Err(reject("pattern", field));
            }
            Ok(text)
        })
        .collect()
}

#[derive(Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(JsonNumber),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

fn parse_json(input: &str) -> Result<Json, ConfigSchemaError> {
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

    fn syntax(&self) -> ConfigSchemaError {
        ConfigSchemaError::Syntax { byte: self.index }
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

    fn enter(&mut self) -> Result<(), ConfigSchemaError> {
        if self.depth >= PARSE_MAX_DEPTH {
            return Err(self.syntax());
        }
        self.depth += 1;
        Ok(())
    }

    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_value(&mut self) -> Result<Json, ConfigSchemaError> {
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

    fn parse_literal(&mut self, literal: &str, value: Json) -> Result<Json, ConfigSchemaError> {
        if self.rest().starts_with(literal) {
            self.index += literal.len();
            Ok(value)
        } else {
            Err(self.syntax())
        }
    }

    fn parse_number(&mut self) -> Result<Json, ConfigSchemaError> {
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

    fn parse_array(&mut self) -> Result<Json, ConfigSchemaError> {
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

    fn parse_object(&mut self) -> Result<Json, ConfigSchemaError> {
        self.bump_byte();
        self.enter()?;
        self.skip_ws();
        let mut entries = Vec::new();
        let mut keys = std::collections::BTreeSet::new();
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
            if !keys.insert(key.clone()) {
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

    fn parse_string(&mut self) -> Result<String, ConfigSchemaError> {
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
    ) -> Result<(), ConfigSchemaError> {
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

    fn read_hex4(&mut self) -> Result<u32, ConfigSchemaError> {
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
    ) -> Result<(), ConfigSchemaError> {
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
    Json::Number(JsonNumber(token.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(value: &'a Json, name: &str) -> &'a Json {
        let Json::Object(entries) = value else {
            panic!("expected object");
        };
        &entries
            .iter()
            .find(|(key, _)| key == name)
            .expect("field")
            .1
    }
    fn string(value: &Json) -> &str {
        let Json::String(s) = value else {
            panic!("expected string");
        };
        s
    }

    #[test]
    fn pinned_schema_bytes() {
        assert_eq!(
            CONFIG_SCHEMA_JSON.as_bytes(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../parity/schemas/sesslint-config.schema/schema.json"
            ))
        );
    }

    #[test]
    fn python_oracle_corpus() {
        let raw = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../parity/schemas/sesslint-config.schema/vectors.json"
        ));
        let corpus = parse_json(raw).unwrap();
        let Json::Array(rows) = field(&corpus, "vectors") else {
            panic!("vectors");
        };
        assert_eq!(rows.len(), 495);
        for row in rows {
            let Json::Bool(expected) = field(row, "valid") else {
                panic!("valid");
            };
            assert_eq!(
                validate(string(field(row, "input"))).is_ok(),
                *expected,
                "{}",
                string(field(row, "id"))
            );
        }
    }

    #[test]
    fn typed_fields_preserve_presence_and_number_spelling() {
        let c = Config::parse(
            r#"{"profile":"neutral","max_files":4.0,"select":[],"skip_undetected":false}"#,
        )
        .unwrap();
        assert_eq!(c.profile, Some(Profile::Neutral));
        assert_eq!(c.max_files.as_ref().unwrap().as_json(), "4.0");
        assert_eq!(c.select, Some(vec![]));
        assert_eq!(c.ignore, None);
        assert_eq!(c.skip_undetected, Some(false));
    }

    #[test]
    fn every_typed_field_is_assigned_without_coercion() {
        let c = Config::parse(
            r#"{
            "profile":"openai-strict","adapter":"codex-rollout",
            "policy":"salvage","fail_on":"warning","select":["SL101"],
            "skip_undetected":true,"confidence_min":-0.125,"margin_min":0.25,
            "max_files":2,"max_bytes":3,"exclude":[" synthetic "],"ext":[".jsonl"],
            "max_file_bytes":4,"max_findings_per_code":5,"timestamp_skew_ms":0,
            "fail_on_unsupported":false
        }"#,
        )
        .unwrap();
        assert_eq!(c.profile, Some(Profile::OpenaiStrict));
        assert_eq!(c.adapter, Some(Adapter::CodexRollout));
        assert_eq!(c.policy, Some(Policy::Salvage));
        assert_eq!(c.fail_on, Some(FailOn::Warning));
        assert_eq!(c.select, Some(vec!["SL101".to_owned()]));
        assert_eq!(c.ignore, None);
        assert_eq!(c.skip_undetected, Some(true));
        assert_eq!(c.confidence_min.unwrap().as_json(), "-0.125");
        assert_eq!(c.margin_min.unwrap().as_json(), "0.25");
        assert_eq!(c.max_files.unwrap().as_json(), "2");
        assert_eq!(c.max_bytes.unwrap().as_json(), "3");
        assert_eq!(c.exclude, Some(vec![" synthetic ".to_owned()]));
        assert_eq!(c.ext, Some(vec![".jsonl".to_owned()]));
        assert_eq!(c.max_file_bytes.unwrap().as_json(), "4");
        assert_eq!(c.max_findings_per_code.unwrap().as_json(), "5");
        assert_eq!(c.timestamp_skew_ms.unwrap().as_json(), "0");
        assert_eq!(c.fail_on_unsupported, Some(false));
        let ignored = Config::parse(r#"{"ignore":["SL102"]}"#).unwrap();
        assert_eq!(ignored.ignore, Some(vec!["SL102".to_owned()]));
        assert_eq!(ignored.select, None);
    }

    #[test]
    fn exact_numbers_do_not_round_fractional_values_into_integers() {
        assert!(validate(r#"{"max_files":1.0000000000000001}"#).is_err());
        assert!(validate(r#"{"max_files":1000000000000000000000000000000000000000000000000000000000000000000000000000000000}"#).is_ok());
        assert!(validate(r#"{"max_files":1e400}"#).is_ok());
        assert!(validate(r#"{"max_files":1e-400}"#).is_err());
        assert!(validate(r#"{"timestamp_skew_ms":-0.0}"#).is_ok());
    }

    #[test]
    fn parser_refusals_are_separate_from_schema_acceptance() {
        for input in [
            "",
            "{}{}",
            "{\"max_files\":01}",
            "{\"max_files\":NaN}",
            "{\"profile\":\"neutral\",\"profile\":\"neutral\"}",
            "{\"ext\":[\"\\ud800\"]}",
        ] {
            assert!(matches!(
                validate(input),
                Err(ConfigSchemaError::Syntax { .. })
            ));
        }
        let depth = format!("{}0{}", "[".repeat(65), "]".repeat(65));
        assert!(matches!(
            validate(&depth),
            Err(ConfigSchemaError::Syntax { .. })
        ));
        assert_eq!(
            validate(&" ".repeat(MAX_INPUT_BYTES + 1)),
            Err(ConfigSchemaError::Limit)
        );
    }

    #[test]
    fn errors_never_echo_unknown_keys_or_values() {
        for input in [
            r#"{"PRIVATE-MARKER":true}"#,
            r#"{"profile":"PRIVATE-MARKER"}"#,
        ] {
            let error = validate(input).unwrap_err();
            assert!(!format!("{error:?} {error}").contains("PRIVATE-MARKER"));
        }
    }

    #[test]
    fn list_pattern_uses_python_whitespace_set() {
        assert!(validate(r#"{"ext":["\u001c"]}"#).is_err());
        assert!(validate(r#"{"ext":["\u200b"]}"#).is_ok());
        assert!(validate(r#"{"ext":["\ud83d\ude00"]}"#).is_ok());
    }
}
