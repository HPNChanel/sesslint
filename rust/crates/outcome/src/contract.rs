//! OutcomeGuard contract model, strict JSON and validation helpers (CON-01/02/05/07).
//!
//! Port of outcome/contract.py at 02694d537104659df66cdd084354739f3cccc440,
//! lines 1..317. No contract is executed. Errors retain source declaration order.
//! Strings use Unicode scalar values; unpaired JSON surrogate escapes fail closed.
//! Parsing is bounded to depth 128 (not Python's configurable recursion limit).
//! Diagnostic repr follows Python 3.11's Unicode 14.0.0 printability table.
//! Syntax errors are typed, not Python JSONDecodeError message/position replicas.
//! JSON-unhashable predicate operators produce a validation problem, not TypeError.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const CONTRACT_SCHEMA_VERSION: &str = "sesslint.outcome-contract/v1";
pub const MAX_CONTRACT_BYTES: usize = 1024 * 1024;
pub const MAX_CONDITIONS: usize = 64;
pub const MAX_PREDICATES: usize = 32;
pub const MAX_VALUES: usize = 1000;
pub const MAX_KEY_FIELDS: usize = 8;
pub const MAX_WITHIN_SECONDS: u64 = 10 * 366 * 24 * 3600;
pub const CONDITION_TYPES: &[&str] = &[
    "any_of", "count", "equals", "exists", "on_time", "one_of", "range", "required", "route",
    "type",
];
pub const PREDICATE_OPS: &[&str] = &[
    "absent", "eq", "gt", "gte", "in", "lt", "lte", "ne", "not_in", "present",
];
pub const VALUE_KINDS: &[&str] = &["boolean", "date-time", "integer", "number", "string"];
pub const NORMALIZATIONS: &[&str] = &["trim", "casefold"];
pub const DEADLINE_BASES: &[&str] = &["observation", "target_time"];
pub const COMMON_KEYS: &[&str] = &["id", "type", "advisory", "disabled", "description"];
pub const TOP_KEYS: &[&str] = &[
    "schema_version",
    "name",
    "version",
    "description",
    "key",
    "eligibility",
    "due",
    "conditions",
];
pub const MAX_FIELD_CHARS: usize = 256;
pub const MAX_TEXT_CHARS: usize = 2000;

pub fn type_keys(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "exists" => &[],
        "count" => &["min", "max"],
        "required" => &["field", "allow_null", "allow_empty"],
        "type" => &["field", "kind"],
        "one_of" => &["field", "values", "normalize"],
        "equals" => &["field", "source_field", "normalize"],
        "range" => &["field", "min", "max"],
        "route" => &["field", "values", "when", "normalize"],
        "on_time" => &["basis", "field"],
        "any_of" => &["conditions"],
        _ => return None,
    })
}

/// Python's `$` allows one final newline, unlike an absolute end anchor.
pub fn valid_id(value: &str) -> bool {
    let value = value.strip_suffix('\n').unwrap_or(value);
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
}

/// Arbitrary-size integral decimal, with validated canonical spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integer(String);

impl Integer {
    pub fn parse(value: &str) -> Result<Self, ParseError> {
        let digits = value.strip_prefix('-').unwrap_or(value);
        if digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
            || (digits.len() > 1 && digits.starts_with('0'))
        {
            return Err(ParseError::Syntax);
        }
        Ok(Self(if value == "-0" {
            "0".into()
        } else {
            value.into()
        }))
    }
    pub fn decimal(&self) -> &str {
        &self.0
    }
}

impl From<i64> for Integer {
    fn from(value: i64) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug, Clone)]
pub enum Scalar {
    Null,
    Bool(bool),
    Int(Integer),
    Float(f64),
    String(String),
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::String(a), Self::String(b)) => a == b,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Int(a), Self::Int(b)) => a == b,
            (Self::Float(a), Self::Float(b)) => a == b,
            (Self::Bool(a), Self::Int(b)) | (Self::Int(b), Self::Bool(a)) => {
                b.decimal() == if *a { "1" } else { "0" }
            }
            (Self::Bool(a), Self::Float(b)) | (Self::Float(b), Self::Bool(a)) => {
                *b == if *a { 1.0 } else { 0.0 }
            }
            (Self::Int(a), Self::Float(b)) | (Self::Float(b), Self::Int(a)) => {
                // Converting the int to f64 would round and compare unequal integers equal.
                b.is_finite()
                    && b.fract() == 0.0
                    && a.decimal()
                        == if *b == 0.0 {
                            "0".to_string()
                        } else {
                            format!("{b:.0}")
                        }
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Scalar(Scalar),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

pub type Mapping = BTreeMap<String, Json>;
const NULL: Json = Json::Scalar(Scalar::Null);

impl Json {
    pub fn as_str(&self) -> Option<&str> {
        if let Self::Scalar(Scalar::String(s)) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Scalar(Scalar::Null))
    }
    pub fn as_scalar(&self) -> Option<&Scalar> {
        if let Self::Scalar(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractError {
    pub problems: Vec<String>,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.problems.join("; "))
    }
}
impl std::error::Error for ContractError {}

#[derive(Debug, Clone, PartialEq)]
pub struct Predicate {
    pub field: String,
    pub op: String,
    pub value: Scalar,
    pub values: Vec<Scalar>,
}

impl Predicate {
    pub fn new(field: impl Into<String>, op: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            op: op.into(),
            value: Scalar::Null,
            values: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Due {
    pub source_time_field: String,
    pub within_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Condition {
    pub id: String,
    pub kind: String,
    pub advisory: bool,
    pub disabled: Option<String>,
    pub description: Option<String>,
    pub field: Option<String>,
    pub source_field: Option<String>,
    pub values: Vec<Scalar>,
    pub normalize: Vec<String>,
    pub value_kind: Option<String>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub allow_null: bool,
    pub allow_empty: bool,
    pub when: Vec<Predicate>,
    pub basis: Option<String>,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Contract {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub source_key: Vec<String>,
    pub target_key: Vec<String>,
    pub eligibility: Vec<Predicate>,
    pub due: Option<Due>,
    pub conditions: Vec<Condition>,
    pub sha256: String,
}

impl Contract {
    pub fn warnings(&self) -> Vec<String> {
        let active: Vec<_> = self
            .conditions
            .iter()
            .filter(|c| c.disabled.is_none() && !c.advisory)
            .collect();
        let mut out = Vec::new();
        if !active
            .iter()
            .any(|c| matches!(c.kind.as_str(), "exists" | "count"))
        {
            out.push("no active exists/count condition: a missing target record cannot be reported as a violation".into());
        }
        if self.due.is_none() {
            out.push("no due window declared: absence is judged at the evaluation instant".into());
        }
        if !active.is_empty() && active.iter().all(|c| c.kind == "any_of") {
            out.push("every decisive condition is an any_of branch".into());
        }
        out
    }

    pub fn relevant_source_fields(&self) -> BTreeSet<String> {
        let mut fields: BTreeSet<_> = self.source_key.iter().cloned().collect();
        fields.extend(self.eligibility.iter().map(|p| p.field.clone()));
        if let Some(due) = &self.due {
            fields.insert(due.source_time_field.clone());
        }
        let mut stack: Vec<_> = self.conditions.iter().collect();
        while let Some(condition) = stack.pop() {
            if let Some(field) = &condition.source_field {
                fields.insert(field.clone());
            }
            fields.extend(condition.when.iter().map(|p| p.field.clone()));
            stack.extend(&condition.conditions);
        }
        fields
    }

    /// Preserve the source's one-level expansion, not a recursive traversal.
    pub fn iter_conditions(&self) -> Vec<&Condition> {
        self.conditions
            .iter()
            .flat_map(|c| std::iter::once(c).chain(c.conditions.iter()))
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Problems {
    pub items: Vec<String>,
}
impl Problems {
    pub fn add(&mut self, location: &str, message: impl AsRef<str>) {
        self.items.push(format!("{location}: {}", message.as_ref()));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Syntax,
    NonFinite(String),
    DuplicateKey(String),
    DepthLimit,
    IntegerDigitLimit,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonFinite(token) => write!(f, "non-finite number {token} is not allowed"),
            Self::DuplicateKey(key) => write!(f, "duplicate key {}", py_repr(key)),
            Self::Syntax => f.write_str("invalid strict JSON"),
            Self::DepthLimit => f.write_str("JSON depth exceeds supported limit"),
            Self::IntegerDigitLimit => f.write_str("JSON integer exceeds 4300 digits"),
        }
    }
}
impl std::error::Error for ParseError {}

pub fn reject_constant(token: &str) -> ParseError {
    ParseError::NonFinite(token.into())
}

pub fn no_duplicate_keys(pairs: Vec<(String, Json)>) -> Result<Mapping, ParseError> {
    let mut result = Mapping::new();
    for (key, value) in pairs {
        if result.contains_key(&key) {
            return Err(ParseError::DuplicateKey(key));
        }
        result.insert(key, value);
    }
    Ok(result)
}

struct Parser<'a> {
    text: &'a str,
    pos: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.peek().is_some_and(|b| b" \t\r\n".contains(&b)) {
            self.pos += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }
    fn take(&mut self, expected: u8) -> Result<(), ParseError> {
        self.ws();
        if self.peek() != Some(expected) {
            return Err(ParseError::Syntax);
        }
        self.pos += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String, ParseError> {
        self.ws();
        let start = self.pos;
        self.take(b'"')?;
        let mut escaped = false;
        while let Some(byte) = self.peek() {
            self.pos += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return serde_json::from_str(&self.text[start..self.pos])
                    .map_err(|_| ParseError::Syntax);
            }
        }
        Err(ParseError::Syntax)
    }
    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > 128 {
            return Err(ParseError::DepthLimit);
        }
        self.ws();
        match self.peek() {
            Some(b'"') => return Ok(Json::Scalar(Scalar::String(self.string()?))),
            Some(b'[') => {
                self.pos += 1;
                self.ws();
                let mut values = Vec::new();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Json::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    self.ws();
                    if self.peek() == Some(b']') {
                        self.pos += 1;
                        return Ok(Json::Array(values));
                    }
                    self.take(b',')?;
                }
            }
            Some(b'{') => {
                self.pos += 1;
                self.ws();
                let mut pairs = Vec::new();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Json::Object(Mapping::new()));
                }
                loop {
                    let key = self.string()?;
                    self.take(b':')?;
                    pairs.push((key, self.value(depth + 1)?));
                    self.ws();
                    if self.peek() == Some(b'}') {
                        self.pos += 1;
                        return no_duplicate_keys(pairs).map(Json::Object);
                    }
                    self.take(b',')?;
                }
            }
            _ => {}
        }
        for (token, value) in [
            ("null", Scalar::Null),
            ("true", Scalar::Bool(true)),
            ("false", Scalar::Bool(false)),
        ] {
            if self.text[self.pos..].starts_with(token) {
                self.pos += token.len();
                return Ok(Json::Scalar(value));
            }
        }
        for token in ["NaN", "Infinity", "-Infinity"] {
            if self.text[self.pos..].starts_with(token) {
                return Err(reject_constant(token));
            }
        }
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err(ParseError::Syntax),
        }
        let mut float = false;
        if self.peek() == Some(b'.') {
            float = true;
            self.pos += 1;
            let digits = self.pos;
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == digits {
                return Err(ParseError::Syntax);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let digits = self.pos;
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
            if self.pos == digits {
                return Err(ParseError::Syntax);
            }
        }
        let spelling = &self.text[start..self.pos];
        let scalar = if float {
            // Python accepts exponent overflow as +/-inf; parse_constant rejects only literals.
            Scalar::Float(spelling.parse::<f64>().map_err(|_| ParseError::Syntax)?)
        } else {
            if spelling.trim_start_matches('-').len() > 4300 {
                return Err(ParseError::IntegerDigitLimit);
            }
            Scalar::Int(Integer::parse(spelling)?)
        };
        Ok(Json::Scalar(scalar))
    }
}

pub fn parse_strict_json(text: &str) -> Result<Json, ParseError> {
    let mut parser = Parser { text, pos: 0 };
    let result = parser.value(0)?;
    parser.ws();
    if parser.pos != text.len() {
        return Err(ParseError::Syntax);
    }
    Ok(result)
}

pub fn is_scalar(value: &Json) -> bool {
    matches!(value, Json::Scalar(_))
}
pub fn is_number(value: &Json) -> bool {
    matches!(value, Json::Scalar(Scalar::Int(_) | Scalar::Float(_)))
}

pub fn field(raw: &Mapping, key: &str, location: &str, problems: &mut Problems) -> Option<String> {
    match raw.get(key).and_then(Json::as_str) {
        Some(value) if !value.is_empty() && value.chars().count() <= MAX_FIELD_CHARS => {
            Some(value.into())
        }
        _ => {
            problems.add(
                location,
                format!("'{key}' must be a non-empty field name (at most 256 characters)"),
            );
            None
        }
    }
}

fn python_space(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{1c}'..='\u{1f}')
}

pub fn text(raw: &Mapping, key: &str, location: &str, problems: &mut Problems) -> Option<String> {
    let value = raw.get(key).unwrap_or(&NULL);
    if value.is_null() {
        return None;
    }
    match value.as_str() {
        Some(value)
            if value.chars().any(|c| !python_space(c))
                && value.chars().count() <= MAX_TEXT_CHARS =>
        {
            Some(value.into())
        }
        _ => {
            problems.add(
                location,
                format!("'{key}' must be a non-empty string (at most 2000 characters)"),
            );
            None
        }
    }
}

/// Python-style repr for scalar Unicode text; control and whitespace escapes retained.
fn py_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::from(quote);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if !python_printable(c) => {
                let n = c as u32;
                if n <= 0xff {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n <= 0xffff {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn repr_list<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    format!(
        "[{}]",
        values
            .into_iter()
            .map(py_repr)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub fn unknown_keys(raw: &Mapping, allowed: &[&str], location: &str, problems: &mut Problems) {
    for key in raw.keys().filter(|key| !allowed.contains(&key.as_str())) {
        problems.add(location, format!("unknown key {}", py_repr(key)));
    }
}

pub fn values(raw: &Mapping, location: &str, problems: &mut Problems, key: &str) -> Vec<Scalar> {
    let Some(Json::Array(items)) = raw.get(key) else {
        problems.add(
            location,
            format!("'{key}' must be a non-empty list of at most {MAX_VALUES} values"),
        );
        return Vec::new();
    };
    if items.is_empty() || items.len() > MAX_VALUES {
        problems.add(
            location,
            format!("'{key}' must be a non-empty list of at most {MAX_VALUES} values"),
        );
        return Vec::new();
    }
    let Some(values) = items
        .iter()
        .map(Json::as_scalar)
        .map(|s| s.cloned())
        .collect::<Option<Vec<_>>>()
    else {
        problems.add(
            location,
            format!("'{key}' may only hold strings, numbers, booleans or null"),
        );
        return Vec::new();
    };
    values
}

pub fn normalize(raw: &Mapping, location: &str, problems: &mut Problems) -> Vec<String> {
    let empty = Json::Array(Vec::new());
    let value = raw.get("normalize").unwrap_or(&empty);
    let items = match value {
        Json::Array(items) => items.iter().map(Json::as_str).collect::<Option<Vec<_>>>(),
        _ => None,
    };
    let Some(items) = items else {
        problems.add(location, "'normalize' must be a list of step names");
        return Vec::new();
    };
    let steps: BTreeSet<_> = items.iter().copied().collect();
    let unknown: Vec<_> = steps
        .iter()
        .copied()
        .filter(|step| !NORMALIZATIONS.contains(step))
        .collect();
    if !unknown.is_empty() {
        problems.add(
            location,
            format!(
                "unsupported normalize step(s) {}; use trim, casefold",
                repr_list(unknown)
            ),
        );
    }
    if steps.len() != items.len() {
        problems.add(location, "'normalize' lists a step twice");
    }
    NORMALIZATIONS
        .iter()
        .filter(|step| steps.contains(**step))
        .map(|step| (*step).into())
        .collect()
}

pub fn predicate(raw: &Json, location: &str, problems: &mut Problems) -> Option<Predicate> {
    let Json::Object(raw) = raw else {
        problems.add(location, "predicate must be an object");
        return None;
    };
    let op = raw.get("op").and_then(Json::as_str);
    let Some(op) = op.filter(|op| PREDICATE_OPS.contains(op)) else {
        problems.add(
            location,
            format!(
                "'op' must be one of {}",
                repr_list(PREDICATE_OPS.iter().copied())
            ),
        );
        return None;
    };
    let mut allowed = vec!["field", "op"];
    let field = field(raw, "field", location, problems);
    let mut value = Scalar::Null;
    let mut choices = Vec::new();
    if matches!(op, "in" | "not_in") {
        allowed.push("values");
        choices = values(raw, location, problems, "values");
    } else if matches!(op, "gt" | "gte" | "lt" | "lte") {
        allowed.push("value");
        let raw_value = raw.get("value").unwrap_or(&NULL);
        if !is_number(raw_value) {
            problems.add(location, format!("'{op}' needs a numeric 'value'"));
        } else if let Some(scalar) = raw_value.as_scalar() {
            value = scalar.clone();
        }
    } else if matches!(op, "eq" | "ne") {
        allowed.push("value");
        if let Some(scalar) = raw.get("value").and_then(Json::as_scalar) {
            value = scalar.clone();
        } else {
            problems.add(location, format!("'{op}' needs a scalar 'value'"));
        }
    }
    unknown_keys(raw, &allowed, location, problems);
    field.map(|field| Predicate {
        field,
        op: op.into(),
        value,
        values: choices,
    })
}

pub fn predicates(raw: &Json, location: &str, problems: &mut Problems) -> Vec<Predicate> {
    if raw.is_null() {
        return Vec::new();
    }
    let Json::Array(items) = raw else {
        problems.add(
            location,
            format!("must be a list of at most {MAX_PREDICATES} predicates"),
        );
        return Vec::new();
    };
    if items.len() > MAX_PREDICATES {
        problems.add(
            location,
            format!("must be a list of at most {MAX_PREDICATES} predicates"),
        );
        return Vec::new();
    }
    items
        .iter()
        .enumerate()
        .filter_map(|(i, raw)| predicate(raw, &format!("{location}[{i}]"), problems))
        .collect()
}

pub fn bound(raw: &Mapping, key: &str, location: &str, problems: &mut Problems) -> Option<f64> {
    match raw.get(key).unwrap_or(&NULL) {
        Json::Scalar(Scalar::Null) => None,
        Json::Scalar(Scalar::Float(value)) => Some(*value),
        Json::Scalar(Scalar::Int(value)) => match value.decimal().parse::<f64>() {
            Ok(value) if value.is_finite() => Some(value),
            _ => {
                problems.add(location, format!("'{key}' is too large"));
                None
            }
        },
        _ => {
            problems.add(location, format!("'{key}' must be a number"));
            None
        }
    }
}

// Python 3.11 Unicode 14.0.0 str.isprintable(), generated over all codepoints.
const NONPRINTABLE: &[(u32, u32)] = &[
    (0x0, 0x1f),
    (0x7f, 0xa0),
    (0xad, 0xad),
    (0x378, 0x379),
    (0x380, 0x383),
    (0x38b, 0x38b),
    (0x38d, 0x38d),
    (0x3a2, 0x3a2),
    (0x530, 0x530),
    (0x557, 0x558),
    (0x58b, 0x58c),
    (0x590, 0x590),
    (0x5c8, 0x5cf),
    (0x5eb, 0x5ee),
    (0x5f5, 0x605),
    (0x61c, 0x61c),
    (0x6dd, 0x6dd),
    (0x70e, 0x70f),
    (0x74b, 0x74c),
    (0x7b2, 0x7bf),
    (0x7fb, 0x7fc),
    (0x82e, 0x82f),
    (0x83f, 0x83f),
    (0x85c, 0x85d),
    (0x85f, 0x85f),
    (0x86b, 0x86f),
    (0x88f, 0x897),
    (0x8e2, 0x8e2),
    (0x984, 0x984),
    (0x98d, 0x98e),
    (0x991, 0x992),
    (0x9a9, 0x9a9),
    (0x9b1, 0x9b1),
    (0x9b3, 0x9b5),
    (0x9ba, 0x9bb),
    (0x9c5, 0x9c6),
    (0x9c9, 0x9ca),
    (0x9cf, 0x9d6),
    (0x9d8, 0x9db),
    (0x9de, 0x9de),
    (0x9e4, 0x9e5),
    (0x9ff, 0xa00),
    (0xa04, 0xa04),
    (0xa0b, 0xa0e),
    (0xa11, 0xa12),
    (0xa29, 0xa29),
    (0xa31, 0xa31),
    (0xa34, 0xa34),
    (0xa37, 0xa37),
    (0xa3a, 0xa3b),
    (0xa3d, 0xa3d),
    (0xa43, 0xa46),
    (0xa49, 0xa4a),
    (0xa4e, 0xa50),
    (0xa52, 0xa58),
    (0xa5d, 0xa5d),
    (0xa5f, 0xa65),
    (0xa77, 0xa80),
    (0xa84, 0xa84),
    (0xa8e, 0xa8e),
    (0xa92, 0xa92),
    (0xaa9, 0xaa9),
    (0xab1, 0xab1),
    (0xab4, 0xab4),
    (0xaba, 0xabb),
    (0xac6, 0xac6),
    (0xaca, 0xaca),
    (0xace, 0xacf),
    (0xad1, 0xadf),
    (0xae4, 0xae5),
    (0xaf2, 0xaf8),
    (0xb00, 0xb00),
    (0xb04, 0xb04),
    (0xb0d, 0xb0e),
    (0xb11, 0xb12),
    (0xb29, 0xb29),
    (0xb31, 0xb31),
    (0xb34, 0xb34),
    (0xb3a, 0xb3b),
    (0xb45, 0xb46),
    (0xb49, 0xb4a),
    (0xb4e, 0xb54),
    (0xb58, 0xb5b),
    (0xb5e, 0xb5e),
    (0xb64, 0xb65),
    (0xb78, 0xb81),
    (0xb84, 0xb84),
    (0xb8b, 0xb8d),
    (0xb91, 0xb91),
    (0xb96, 0xb98),
    (0xb9b, 0xb9b),
    (0xb9d, 0xb9d),
    (0xba0, 0xba2),
    (0xba5, 0xba7),
    (0xbab, 0xbad),
    (0xbba, 0xbbd),
    (0xbc3, 0xbc5),
    (0xbc9, 0xbc9),
    (0xbce, 0xbcf),
    (0xbd1, 0xbd6),
    (0xbd8, 0xbe5),
    (0xbfb, 0xbff),
    (0xc0d, 0xc0d),
    (0xc11, 0xc11),
    (0xc29, 0xc29),
    (0xc3a, 0xc3b),
    (0xc45, 0xc45),
    (0xc49, 0xc49),
    (0xc4e, 0xc54),
    (0xc57, 0xc57),
    (0xc5b, 0xc5c),
    (0xc5e, 0xc5f),
    (0xc64, 0xc65),
    (0xc70, 0xc76),
    (0xc8d, 0xc8d),
    (0xc91, 0xc91),
    (0xca9, 0xca9),
    (0xcb4, 0xcb4),
    (0xcba, 0xcbb),
    (0xcc5, 0xcc5),
    (0xcc9, 0xcc9),
    (0xcce, 0xcd4),
    (0xcd7, 0xcdc),
    (0xcdf, 0xcdf),
    (0xce4, 0xce5),
    (0xcf0, 0xcf0),
    (0xcf3, 0xcff),
    (0xd0d, 0xd0d),
    (0xd11, 0xd11),
    (0xd45, 0xd45),
    (0xd49, 0xd49),
    (0xd50, 0xd53),
    (0xd64, 0xd65),
    (0xd80, 0xd80),
    (0xd84, 0xd84),
    (0xd97, 0xd99),
    (0xdb2, 0xdb2),
    (0xdbc, 0xdbc),
    (0xdbe, 0xdbf),
    (0xdc7, 0xdc9),
    (0xdcb, 0xdce),
    (0xdd5, 0xdd5),
    (0xdd7, 0xdd7),
    (0xde0, 0xde5),
    (0xdf0, 0xdf1),
    (0xdf5, 0xe00),
    (0xe3b, 0xe3e),
    (0xe5c, 0xe80),
    (0xe83, 0xe83),
    (0xe85, 0xe85),
    (0xe8b, 0xe8b),
    (0xea4, 0xea4),
    (0xea6, 0xea6),
    (0xebe, 0xebf),
    (0xec5, 0xec5),
    (0xec7, 0xec7),
    (0xece, 0xecf),
    (0xeda, 0xedb),
    (0xee0, 0xeff),
    (0xf48, 0xf48),
    (0xf6d, 0xf70),
    (0xf98, 0xf98),
    (0xfbd, 0xfbd),
    (0xfcd, 0xfcd),
    (0xfdb, 0xfff),
    (0x10c6, 0x10c6),
    (0x10c8, 0x10cc),
    (0x10ce, 0x10cf),
    (0x1249, 0x1249),
    (0x124e, 0x124f),
    (0x1257, 0x1257),
    (0x1259, 0x1259),
    (0x125e, 0x125f),
    (0x1289, 0x1289),
    (0x128e, 0x128f),
    (0x12b1, 0x12b1),
    (0x12b6, 0x12b7),
    (0x12bf, 0x12bf),
    (0x12c1, 0x12c1),
    (0x12c6, 0x12c7),
    (0x12d7, 0x12d7),
    (0x1311, 0x1311),
    (0x1316, 0x1317),
    (0x135b, 0x135c),
    (0x137d, 0x137f),
    (0x139a, 0x139f),
    (0x13f6, 0x13f7),
    (0x13fe, 0x13ff),
    (0x1680, 0x1680),
    (0x169d, 0x169f),
    (0x16f9, 0x16ff),
    (0x1716, 0x171e),
    (0x1737, 0x173f),
    (0x1754, 0x175f),
    (0x176d, 0x176d),
    (0x1771, 0x1771),
    (0x1774, 0x177f),
    (0x17de, 0x17df),
    (0x17ea, 0x17ef),
    (0x17fa, 0x17ff),
    (0x180e, 0x180e),
    (0x181a, 0x181f),
    (0x1879, 0x187f),
    (0x18ab, 0x18af),
    (0x18f6, 0x18ff),
    (0x191f, 0x191f),
    (0x192c, 0x192f),
    (0x193c, 0x193f),
    (0x1941, 0x1943),
    (0x196e, 0x196f),
    (0x1975, 0x197f),
    (0x19ac, 0x19af),
    (0x19ca, 0x19cf),
    (0x19db, 0x19dd),
    (0x1a1c, 0x1a1d),
    (0x1a5f, 0x1a5f),
    (0x1a7d, 0x1a7e),
    (0x1a8a, 0x1a8f),
    (0x1a9a, 0x1a9f),
    (0x1aae, 0x1aaf),
    (0x1acf, 0x1aff),
    (0x1b4d, 0x1b4f),
    (0x1b7f, 0x1b7f),
    (0x1bf4, 0x1bfb),
    (0x1c38, 0x1c3a),
    (0x1c4a, 0x1c4c),
    (0x1c89, 0x1c8f),
    (0x1cbb, 0x1cbc),
    (0x1cc8, 0x1ccf),
    (0x1cfb, 0x1cff),
    (0x1f16, 0x1f17),
    (0x1f1e, 0x1f1f),
    (0x1f46, 0x1f47),
    (0x1f4e, 0x1f4f),
    (0x1f58, 0x1f58),
    (0x1f5a, 0x1f5a),
    (0x1f5c, 0x1f5c),
    (0x1f5e, 0x1f5e),
    (0x1f7e, 0x1f7f),
    (0x1fb5, 0x1fb5),
    (0x1fc5, 0x1fc5),
    (0x1fd4, 0x1fd5),
    (0x1fdc, 0x1fdc),
    (0x1ff0, 0x1ff1),
    (0x1ff5, 0x1ff5),
    (0x1fff, 0x200f),
    (0x2028, 0x202f),
    (0x205f, 0x206f),
    (0x2072, 0x2073),
    (0x208f, 0x208f),
    (0x209d, 0x209f),
    (0x20c1, 0x20cf),
    (0x20f1, 0x20ff),
    (0x218c, 0x218f),
    (0x2427, 0x243f),
    (0x244b, 0x245f),
    (0x2b74, 0x2b75),
    (0x2b96, 0x2b96),
    (0x2cf4, 0x2cf8),
    (0x2d26, 0x2d26),
    (0x2d28, 0x2d2c),
    (0x2d2e, 0x2d2f),
    (0x2d68, 0x2d6e),
    (0x2d71, 0x2d7e),
    (0x2d97, 0x2d9f),
    (0x2da7, 0x2da7),
    (0x2daf, 0x2daf),
    (0x2db7, 0x2db7),
    (0x2dbf, 0x2dbf),
    (0x2dc7, 0x2dc7),
    (0x2dcf, 0x2dcf),
    (0x2dd7, 0x2dd7),
    (0x2ddf, 0x2ddf),
    (0x2e5e, 0x2e7f),
    (0x2e9a, 0x2e9a),
    (0x2ef4, 0x2eff),
    (0x2fd6, 0x2fef),
    (0x2ffc, 0x3000),
    (0x3040, 0x3040),
    (0x3097, 0x3098),
    (0x3100, 0x3104),
    (0x3130, 0x3130),
    (0x318f, 0x318f),
    (0x31e4, 0x31ef),
    (0x321f, 0x321f),
    (0xa48d, 0xa48f),
    (0xa4c7, 0xa4cf),
    (0xa62c, 0xa63f),
    (0xa6f8, 0xa6ff),
    (0xa7cb, 0xa7cf),
    (0xa7d2, 0xa7d2),
    (0xa7d4, 0xa7d4),
    (0xa7da, 0xa7f1),
    (0xa82d, 0xa82f),
    (0xa83a, 0xa83f),
    (0xa878, 0xa87f),
    (0xa8c6, 0xa8cd),
    (0xa8da, 0xa8df),
    (0xa954, 0xa95e),
    (0xa97d, 0xa97f),
    (0xa9ce, 0xa9ce),
    (0xa9da, 0xa9dd),
    (0xa9ff, 0xa9ff),
    (0xaa37, 0xaa3f),
    (0xaa4e, 0xaa4f),
    (0xaa5a, 0xaa5b),
    (0xaac3, 0xaada),
    (0xaaf7, 0xab00),
    (0xab07, 0xab08),
    (0xab0f, 0xab10),
    (0xab17, 0xab1f),
    (0xab27, 0xab27),
    (0xab2f, 0xab2f),
    (0xab6c, 0xab6f),
    (0xabee, 0xabef),
    (0xabfa, 0xabff),
    (0xd7a4, 0xd7af),
    (0xd7c7, 0xd7ca),
    (0xd7fc, 0xf8ff),
    (0xfa6e, 0xfa6f),
    (0xfada, 0xfaff),
    (0xfb07, 0xfb12),
    (0xfb18, 0xfb1c),
    (0xfb37, 0xfb37),
    (0xfb3d, 0xfb3d),
    (0xfb3f, 0xfb3f),
    (0xfb42, 0xfb42),
    (0xfb45, 0xfb45),
    (0xfbc3, 0xfbd2),
    (0xfd90, 0xfd91),
    (0xfdc8, 0xfdce),
    (0xfdd0, 0xfdef),
    (0xfe1a, 0xfe1f),
    (0xfe53, 0xfe53),
    (0xfe67, 0xfe67),
    (0xfe6c, 0xfe6f),
    (0xfe75, 0xfe75),
    (0xfefd, 0xff00),
    (0xffbf, 0xffc1),
    (0xffc8, 0xffc9),
    (0xffd0, 0xffd1),
    (0xffd8, 0xffd9),
    (0xffdd, 0xffdf),
    (0xffe7, 0xffe7),
    (0xffef, 0xfffb),
    (0xfffe, 0xffff),
    (0x1000c, 0x1000c),
    (0x10027, 0x10027),
    (0x1003b, 0x1003b),
    (0x1003e, 0x1003e),
    (0x1004e, 0x1004f),
    (0x1005e, 0x1007f),
    (0x100fb, 0x100ff),
    (0x10103, 0x10106),
    (0x10134, 0x10136),
    (0x1018f, 0x1018f),
    (0x1019d, 0x1019f),
    (0x101a1, 0x101cf),
    (0x101fe, 0x1027f),
    (0x1029d, 0x1029f),
    (0x102d1, 0x102df),
    (0x102fc, 0x102ff),
    (0x10324, 0x1032c),
    (0x1034b, 0x1034f),
    (0x1037b, 0x1037f),
    (0x1039e, 0x1039e),
    (0x103c4, 0x103c7),
    (0x103d6, 0x103ff),
    (0x1049e, 0x1049f),
    (0x104aa, 0x104af),
    (0x104d4, 0x104d7),
    (0x104fc, 0x104ff),
    (0x10528, 0x1052f),
    (0x10564, 0x1056e),
    (0x1057b, 0x1057b),
    (0x1058b, 0x1058b),
    (0x10593, 0x10593),
    (0x10596, 0x10596),
    (0x105a2, 0x105a2),
    (0x105b2, 0x105b2),
    (0x105ba, 0x105ba),
    (0x105bd, 0x105ff),
    (0x10737, 0x1073f),
    (0x10756, 0x1075f),
    (0x10768, 0x1077f),
    (0x10786, 0x10786),
    (0x107b1, 0x107b1),
    (0x107bb, 0x107ff),
    (0x10806, 0x10807),
    (0x10809, 0x10809),
    (0x10836, 0x10836),
    (0x10839, 0x1083b),
    (0x1083d, 0x1083e),
    (0x10856, 0x10856),
    (0x1089f, 0x108a6),
    (0x108b0, 0x108df),
    (0x108f3, 0x108f3),
    (0x108f6, 0x108fa),
    (0x1091c, 0x1091e),
    (0x1093a, 0x1093e),
    (0x10940, 0x1097f),
    (0x109b8, 0x109bb),
    (0x109d0, 0x109d1),
    (0x10a04, 0x10a04),
    (0x10a07, 0x10a0b),
    (0x10a14, 0x10a14),
    (0x10a18, 0x10a18),
    (0x10a36, 0x10a37),
    (0x10a3b, 0x10a3e),
    (0x10a49, 0x10a4f),
    (0x10a59, 0x10a5f),
    (0x10aa0, 0x10abf),
    (0x10ae7, 0x10aea),
    (0x10af7, 0x10aff),
    (0x10b36, 0x10b38),
    (0x10b56, 0x10b57),
    (0x10b73, 0x10b77),
    (0x10b92, 0x10b98),
    (0x10b9d, 0x10ba8),
    (0x10bb0, 0x10bff),
    (0x10c49, 0x10c7f),
    (0x10cb3, 0x10cbf),
    (0x10cf3, 0x10cf9),
    (0x10d28, 0x10d2f),
    (0x10d3a, 0x10e5f),
    (0x10e7f, 0x10e7f),
    (0x10eaa, 0x10eaa),
    (0x10eae, 0x10eaf),
    (0x10eb2, 0x10eff),
    (0x10f28, 0x10f2f),
    (0x10f5a, 0x10f6f),
    (0x10f8a, 0x10faf),
    (0x10fcc, 0x10fdf),
    (0x10ff7, 0x10fff),
    (0x1104e, 0x11051),
    (0x11076, 0x1107e),
    (0x110bd, 0x110bd),
    (0x110c3, 0x110cf),
    (0x110e9, 0x110ef),
    (0x110fa, 0x110ff),
    (0x11135, 0x11135),
    (0x11148, 0x1114f),
    (0x11177, 0x1117f),
    (0x111e0, 0x111e0),
    (0x111f5, 0x111ff),
    (0x11212, 0x11212),
    (0x1123f, 0x1127f),
    (0x11287, 0x11287),
    (0x11289, 0x11289),
    (0x1128e, 0x1128e),
    (0x1129e, 0x1129e),
    (0x112aa, 0x112af),
    (0x112eb, 0x112ef),
    (0x112fa, 0x112ff),
    (0x11304, 0x11304),
    (0x1130d, 0x1130e),
    (0x11311, 0x11312),
    (0x11329, 0x11329),
    (0x11331, 0x11331),
    (0x11334, 0x11334),
    (0x1133a, 0x1133a),
    (0x11345, 0x11346),
    (0x11349, 0x1134a),
    (0x1134e, 0x1134f),
    (0x11351, 0x11356),
    (0x11358, 0x1135c),
    (0x11364, 0x11365),
    (0x1136d, 0x1136f),
    (0x11375, 0x113ff),
    (0x1145c, 0x1145c),
    (0x11462, 0x1147f),
    (0x114c8, 0x114cf),
    (0x114da, 0x1157f),
    (0x115b6, 0x115b7),
    (0x115de, 0x115ff),
    (0x11645, 0x1164f),
    (0x1165a, 0x1165f),
    (0x1166d, 0x1167f),
    (0x116ba, 0x116bf),
    (0x116ca, 0x116ff),
    (0x1171b, 0x1171c),
    (0x1172c, 0x1172f),
    (0x11747, 0x117ff),
    (0x1183c, 0x1189f),
    (0x118f3, 0x118fe),
    (0x11907, 0x11908),
    (0x1190a, 0x1190b),
    (0x11914, 0x11914),
    (0x11917, 0x11917),
    (0x11936, 0x11936),
    (0x11939, 0x1193a),
    (0x11947, 0x1194f),
    (0x1195a, 0x1199f),
    (0x119a8, 0x119a9),
    (0x119d8, 0x119d9),
    (0x119e5, 0x119ff),
    (0x11a48, 0x11a4f),
    (0x11aa3, 0x11aaf),
    (0x11af9, 0x11bff),
    (0x11c09, 0x11c09),
    (0x11c37, 0x11c37),
    (0x11c46, 0x11c4f),
    (0x11c6d, 0x11c6f),
    (0x11c90, 0x11c91),
    (0x11ca8, 0x11ca8),
    (0x11cb7, 0x11cff),
    (0x11d07, 0x11d07),
    (0x11d0a, 0x11d0a),
    (0x11d37, 0x11d39),
    (0x11d3b, 0x11d3b),
    (0x11d3e, 0x11d3e),
    (0x11d48, 0x11d4f),
    (0x11d5a, 0x11d5f),
    (0x11d66, 0x11d66),
    (0x11d69, 0x11d69),
    (0x11d8f, 0x11d8f),
    (0x11d92, 0x11d92),
    (0x11d99, 0x11d9f),
    (0x11daa, 0x11edf),
    (0x11ef9, 0x11faf),
    (0x11fb1, 0x11fbf),
    (0x11ff2, 0x11ffe),
    (0x1239a, 0x123ff),
    (0x1246f, 0x1246f),
    (0x12475, 0x1247f),
    (0x12544, 0x12f8f),
    (0x12ff3, 0x12fff),
    (0x1342f, 0x143ff),
    (0x14647, 0x167ff),
    (0x16a39, 0x16a3f),
    (0x16a5f, 0x16a5f),
    (0x16a6a, 0x16a6d),
    (0x16abf, 0x16abf),
    (0x16aca, 0x16acf),
    (0x16aee, 0x16aef),
    (0x16af6, 0x16aff),
    (0x16b46, 0x16b4f),
    (0x16b5a, 0x16b5a),
    (0x16b62, 0x16b62),
    (0x16b78, 0x16b7c),
    (0x16b90, 0x16e3f),
    (0x16e9b, 0x16eff),
    (0x16f4b, 0x16f4e),
    (0x16f88, 0x16f8e),
    (0x16fa0, 0x16fdf),
    (0x16fe5, 0x16fef),
    (0x16ff2, 0x16fff),
    (0x187f8, 0x187ff),
    (0x18cd6, 0x18cff),
    (0x18d09, 0x1afef),
    (0x1aff4, 0x1aff4),
    (0x1affc, 0x1affc),
    (0x1afff, 0x1afff),
    (0x1b123, 0x1b14f),
    (0x1b153, 0x1b163),
    (0x1b168, 0x1b16f),
    (0x1b2fc, 0x1bbff),
    (0x1bc6b, 0x1bc6f),
    (0x1bc7d, 0x1bc7f),
    (0x1bc89, 0x1bc8f),
    (0x1bc9a, 0x1bc9b),
    (0x1bca0, 0x1ceff),
    (0x1cf2e, 0x1cf2f),
    (0x1cf47, 0x1cf4f),
    (0x1cfc4, 0x1cfff),
    (0x1d0f6, 0x1d0ff),
    (0x1d127, 0x1d128),
    (0x1d173, 0x1d17a),
    (0x1d1eb, 0x1d1ff),
    (0x1d246, 0x1d2df),
    (0x1d2f4, 0x1d2ff),
    (0x1d357, 0x1d35f),
    (0x1d379, 0x1d3ff),
    (0x1d455, 0x1d455),
    (0x1d49d, 0x1d49d),
    (0x1d4a0, 0x1d4a1),
    (0x1d4a3, 0x1d4a4),
    (0x1d4a7, 0x1d4a8),
    (0x1d4ad, 0x1d4ad),
    (0x1d4ba, 0x1d4ba),
    (0x1d4bc, 0x1d4bc),
    (0x1d4c4, 0x1d4c4),
    (0x1d506, 0x1d506),
    (0x1d50b, 0x1d50c),
    (0x1d515, 0x1d515),
    (0x1d51d, 0x1d51d),
    (0x1d53a, 0x1d53a),
    (0x1d53f, 0x1d53f),
    (0x1d545, 0x1d545),
    (0x1d547, 0x1d549),
    (0x1d551, 0x1d551),
    (0x1d6a6, 0x1d6a7),
    (0x1d7cc, 0x1d7cd),
    (0x1da8c, 0x1da9a),
    (0x1daa0, 0x1daa0),
    (0x1dab0, 0x1deff),
    (0x1df1f, 0x1dfff),
    (0x1e007, 0x1e007),
    (0x1e019, 0x1e01a),
    (0x1e022, 0x1e022),
    (0x1e025, 0x1e025),
    (0x1e02b, 0x1e0ff),
    (0x1e12d, 0x1e12f),
    (0x1e13e, 0x1e13f),
    (0x1e14a, 0x1e14d),
    (0x1e150, 0x1e28f),
    (0x1e2af, 0x1e2bf),
    (0x1e2fa, 0x1e2fe),
    (0x1e300, 0x1e7df),
    (0x1e7e7, 0x1e7e7),
    (0x1e7ec, 0x1e7ec),
    (0x1e7ef, 0x1e7ef),
    (0x1e7ff, 0x1e7ff),
    (0x1e8c5, 0x1e8c6),
    (0x1e8d7, 0x1e8ff),
    (0x1e94c, 0x1e94f),
    (0x1e95a, 0x1e95d),
    (0x1e960, 0x1ec70),
    (0x1ecb5, 0x1ed00),
    (0x1ed3e, 0x1edff),
    (0x1ee04, 0x1ee04),
    (0x1ee20, 0x1ee20),
    (0x1ee23, 0x1ee23),
    (0x1ee25, 0x1ee26),
    (0x1ee28, 0x1ee28),
    (0x1ee33, 0x1ee33),
    (0x1ee38, 0x1ee38),
    (0x1ee3a, 0x1ee3a),
    (0x1ee3c, 0x1ee41),
    (0x1ee43, 0x1ee46),
    (0x1ee48, 0x1ee48),
    (0x1ee4a, 0x1ee4a),
    (0x1ee4c, 0x1ee4c),
    (0x1ee50, 0x1ee50),
    (0x1ee53, 0x1ee53),
    (0x1ee55, 0x1ee56),
    (0x1ee58, 0x1ee58),
    (0x1ee5a, 0x1ee5a),
    (0x1ee5c, 0x1ee5c),
    (0x1ee5e, 0x1ee5e),
    (0x1ee60, 0x1ee60),
    (0x1ee63, 0x1ee63),
    (0x1ee65, 0x1ee66),
    (0x1ee6b, 0x1ee6b),
    (0x1ee73, 0x1ee73),
    (0x1ee78, 0x1ee78),
    (0x1ee7d, 0x1ee7d),
    (0x1ee7f, 0x1ee7f),
    (0x1ee8a, 0x1ee8a),
    (0x1ee9c, 0x1eea0),
    (0x1eea4, 0x1eea4),
    (0x1eeaa, 0x1eeaa),
    (0x1eebc, 0x1eeef),
    (0x1eef2, 0x1efff),
    (0x1f02c, 0x1f02f),
    (0x1f094, 0x1f09f),
    (0x1f0af, 0x1f0b0),
    (0x1f0c0, 0x1f0c0),
    (0x1f0d0, 0x1f0d0),
    (0x1f0f6, 0x1f0ff),
    (0x1f1ae, 0x1f1e5),
    (0x1f203, 0x1f20f),
    (0x1f23c, 0x1f23f),
    (0x1f249, 0x1f24f),
    (0x1f252, 0x1f25f),
    (0x1f266, 0x1f2ff),
    (0x1f6d8, 0x1f6dc),
    (0x1f6ed, 0x1f6ef),
    (0x1f6fd, 0x1f6ff),
    (0x1f774, 0x1f77f),
    (0x1f7d9, 0x1f7df),
    (0x1f7ec, 0x1f7ef),
    (0x1f7f1, 0x1f7ff),
    (0x1f80c, 0x1f80f),
    (0x1f848, 0x1f84f),
    (0x1f85a, 0x1f85f),
    (0x1f888, 0x1f88f),
    (0x1f8ae, 0x1f8af),
    (0x1f8b2, 0x1f8ff),
    (0x1fa54, 0x1fa5f),
    (0x1fa6e, 0x1fa6f),
    (0x1fa75, 0x1fa77),
    (0x1fa7d, 0x1fa7f),
    (0x1fa87, 0x1fa8f),
    (0x1faad, 0x1faaf),
    (0x1fabb, 0x1fabf),
    (0x1fac6, 0x1facf),
    (0x1fada, 0x1fadf),
    (0x1fae8, 0x1faef),
    (0x1faf7, 0x1faff),
    (0x1fb93, 0x1fb93),
    (0x1fbcb, 0x1fbef),
    (0x1fbfa, 0x1ffff),
    (0x2a6e0, 0x2a6ff),
    (0x2b739, 0x2b73f),
    (0x2b81e, 0x2b81f),
    (0x2cea2, 0x2ceaf),
    (0x2ebe1, 0x2f7ff),
    (0x2fa1e, 0x2ffff),
    (0x3134b, 0xe00ff),
    (0xe01f0, 0x10ffff),
];
fn python_printable(ch: char) -> bool {
    let cp = ch as u32;
    let i = NONPRINTABLE.partition_point(|(_, end)| *end < cp);
    NONPRINTABLE.get(i).is_none_or(|(start, _)| cp < *start)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(text: &str) -> Mapping {
        match parse_strict_json(text).unwrap() {
            Json::Object(raw) => raw,
            _ => panic!("test object required"),
        }
    }

    #[test]
    fn scalar_dataclass_equality_uses_python_numeric_equality_without_rounding() {
        assert_eq!(Scalar::Bool(true), Scalar::Int(1.into()));
        assert_eq!(Scalar::Bool(false), Scalar::Float(-0.0));
        assert_eq!(
            Scalar::Int(Integer::parse("1267650600228229401496703205376").unwrap()),
            Scalar::Float(2.0_f64.powi(100))
        );
        assert_ne!(
            Scalar::Int(Integer::parse("1267650600228229401496703205377").unwrap()),
            Scalar::Float(2.0_f64.powi(100))
        );
        assert_ne!(Scalar::Float(f64::NAN), Scalar::Float(f64::NAN));
        assert_ne!(Scalar::String("1".into()), Scalar::Int(1.into()));
        assert_eq!(Predicate::new("x", "eq").value, Scalar::Null);
    }

    #[test]
    fn strict_json_retains_integer_float_and_boolean_types() {
        let value = object(
            r#"{"int":1234567890123456789012345678901234567890,"float":1.0,"bool":true,"negative_zero":-0}"#,
        );
        assert_eq!(
            value["int"],
            Json::Scalar(Scalar::Int(
                Integer::parse("1234567890123456789012345678901234567890").unwrap()
            ))
        );
        assert!(matches!(value["int"], Json::Scalar(Scalar::Int(_))));
        assert!(matches!(value["float"], Json::Scalar(Scalar::Float(x)) if x == 1.0));
        assert!(matches!(value["bool"], Json::Scalar(Scalar::Bool(true))));
        assert!(!is_number(&value["bool"]));
        assert_eq!(value["negative_zero"], Json::Scalar(Scalar::Int(0.into())));
    }

    #[test]
    fn strict_rejections_and_nested_error_precedence_match_python() {
        for token in ["NaN", "Infinity", "-Infinity"] {
            assert_eq!(
                parse_strict_json(token),
                Err(ParseError::NonFinite(token.into()))
            );
        }
        let nested = r#"{"a":1,"a":2,"b":{"x":0,"x":1}}"#;
        assert_eq!(
            parse_strict_json(nested),
            Err(ParseError::DuplicateKey("x".into()))
        );
        assert_eq!(
            parse_strict_json(r#"{"a":1,"a":NaN}"#),
            Err(ParseError::NonFinite("NaN".into()))
        );
        assert_eq!(
            parse_strict_json(r#"{"a":1,"a":2}"#),
            Err(ParseError::DuplicateKey("a".into()))
        );
        assert!(
            matches!(parse_strict_json("1e999"), Ok(Json::Scalar(Scalar::Float(x))) if x == f64::INFINITY)
        );
    }

    #[test]
    fn malformed_json_never_panics_or_accepts_prefixes() {
        for input in [
            "",
            " ",
            "01",
            "-",
            "-.1",
            "1.",
            "1e",
            "1e+",
            "[1,]",
            r#"{"a":1,}"#,
            "truefalse",
            "[",
            "{",
            "\u{feff}null",
            "中",
            r#""\q""#,
            "\"unterminated",
        ] {
            assert!(parse_strict_json(input).is_err(), "{input:?}");
        }
        let deep = format!("{}0{}", "[".repeat(130), "]".repeat(130));
        assert_eq!(parse_strict_json(&deep), Err(ParseError::DepthLimit));
        assert_eq!(
            parse_strict_json(&"1".repeat(4301)),
            Err(ParseError::IntegerDigitLimit)
        );
        assert!(parse_strict_json(r#""\ud800""#).is_err());
        assert_eq!(
            parse_strict_json(r#""\ud83d\ude00""#),
            Ok(Json::Scalar(Scalar::String("😀".into())))
        );
    }

    #[test]
    fn field_text_limits_count_characters_and_use_python_whitespace() {
        let mut raw = Mapping::new();
        let mut problems = Problems::default();
        raw.insert(
            "field".into(),
            Json::Scalar(Scalar::String("😀".repeat(256))),
        );
        assert!(field(&raw, "field", "w", &mut problems).is_some());
        raw.insert(
            "field".into(),
            Json::Scalar(Scalar::String("😀".repeat(257))),
        );
        assert!(field(&raw, "field", "w", &mut problems).is_none());
        raw.insert("text".into(), Json::Scalar(Scalar::String("\u{1c}".into())));
        assert!(text(&raw, "text", "w", &mut problems).is_none());
        assert!(text(&raw, "missing", "w", &mut problems).is_none());
        assert_eq!(problems.items.len(), 2);
    }

    #[test]
    fn normalize_reports_sorted_unknown_then_duplicate_and_fixes_published_order() {
        let raw = object(r#"{"normalize":["zzz","casefold","trim","aaa","zzz"]}"#);
        let mut problems = Problems::default();
        assert_eq!(normalize(&raw, "w", &mut problems), ["trim", "casefold"]);
        assert_eq!(
            problems.items,
            [
                "w: unsupported normalize step(s) ['aaa', 'zzz']; use trim, casefold",
                "w: 'normalize' lists a step twice"
            ]
        );
        assert!(normalize(&object("{}"), "w", &mut Problems::default()).is_empty());
        for raw in [r#"{"normalize":null}"#, r#"{"normalize":[1]}"#] {
            let mut p = Problems::default();
            assert!(normalize(&object(raw), "w", &mut p).is_empty());
            assert_eq!(p.items, ["w: 'normalize' must be a list of step names"]);
        }
    }

    #[test]
    fn predicate_collects_errors_in_source_order_and_preserves_partial_value() {
        let raw = parse_strict_json(r#"{"op":"gt","value":true,"zzz":1,"aaa":2}"#).unwrap();
        let mut p = Problems::default();
        assert!(predicate(&raw, "w", &mut p).is_none());
        assert_eq!(
            p.items,
            [
                "w: 'field' must be a non-empty field name (at most 256 characters)",
                "w: 'gt' needs a numeric 'value'",
                "w: unknown key 'aaa'",
                "w: unknown key 'zzz'"
            ]
        );
        let mut p = Problems::default();
        let partial = predicate(
            &parse_strict_json(r#"{"op":"in","field":"x","values":[]}"#).unwrap(),
            "w",
            &mut p,
        )
        .unwrap();
        assert!(partial.values.is_empty());
        assert_eq!(p.items.len(), 1);
        let mut p = Problems::default();
        assert!(predicate(
            &parse_strict_json(r#"{"op":"unknown","bad":1}"#).unwrap(),
            "w",
            &mut p
        )
        .is_none());
        assert_eq!(p.items.len(), 1);
    }

    #[test]
    fn predicate_operator_branches_and_list_limit() {
        for op in PREDICATE_OPS {
            let raw = if matches!(*op, "in" | "not_in") {
                format!(r#"{{"op":"{op}","field":"x","values":[1,null,true]}}"#)
            } else if matches!(*op, "present" | "absent") {
                format!(r#"{{"op":"{op}","field":"x"}}"#)
            } else {
                format!(r#"{{"op":"{op}","field":"x","value":1}}"#)
            };
            let mut p = Problems::default();
            assert!(predicate(&parse_strict_json(&raw).unwrap(), "w", &mut p).is_some());
            assert!(p.items.is_empty(), "{op}: {:?}", p.items);
        }
        let mut p = Problems::default();
        assert!(predicates(&Json::Array(vec![NULL; 33]), "w", &mut p).is_empty());
        assert_eq!(p.items, ["w: must be a list of at most 32 predicates"]);
        let mut p = Problems::default();
        assert!(predicates(&NULL, "w", &mut p).is_empty());
        assert!(p.items.is_empty());
    }

    #[test]
    fn scalar_lists_reject_compounds_without_losing_null_and_boolean() {
        let mut p = Problems::default();
        assert_eq!(
            values(
                &object(r#"{"values":[null,true,1,"x"]}"#),
                "w",
                &mut p,
                "values"
            )
            .len(),
            4
        );
        assert!(p.items.is_empty());
        assert!(values(&object(r#"{"values":[{}]}"#), "w", &mut p, "values").is_empty());
        assert_eq!(
            p.items,
            ["w: 'values' may only hold strings, numbers, booleans or null"]
        );
    }

    #[test]
    fn bound_overflow_is_an_integer_error_but_infinite_float_is_preserved() {
        let mut raw = object(r#"{"min":true,"max":1e999}"#);
        let mut p = Problems::default();
        assert_eq!(bound(&raw, "min", "w", &mut p), None);
        assert_eq!(bound(&raw, "max", "w", &mut p), Some(f64::INFINITY));
        raw.insert(
            "min".into(),
            Json::Scalar(Scalar::Int(Integer::parse(&"9".repeat(400)).unwrap())),
        );
        assert_eq!(bound(&raw, "min", "w", &mut p), None);
        assert_eq!(
            p.items,
            ["w: 'min' must be a number", "w: 'min' is too large"]
        );
    }

    #[test]
    fn contract_helpers_preserve_one_level_iteration_and_recursive_field_collection() {
        let leaf = Condition {
            id: "leaf".into(),
            kind: "equals".into(),
            source_field: Some("deep".into()),
            ..Condition::default()
        };
        let child = Condition {
            id: "child".into(),
            kind: "any_of".into(),
            conditions: vec![leaf],
            ..Condition::default()
        };
        let parent = Condition {
            id: "parent".into(),
            kind: "any_of".into(),
            conditions: vec![child],
            ..Condition::default()
        };
        let mut contract = Contract {
            name: "synthetic".into(),
            version: "1".into(),
            description: None,
            source_key: vec!["key".into()],
            target_key: vec![],
            eligibility: vec![],
            due: None,
            conditions: vec![parent],
            sha256: String::new(),
        };
        assert_eq!(contract.warnings().len(), 3);
        assert_eq!(
            contract
                .iter_conditions()
                .iter()
                .map(|c| c.id.as_str())
                .collect::<Vec<_>>(),
            ["parent", "child"]
        );
        assert_eq!(
            contract.relevant_source_fields(),
            BTreeSet::from(["key".into(), "deep".into()])
        );
        contract.conditions.push(Condition {
            kind: "exists".into(),
            ..Condition::default()
        });
        assert_eq!(
            contract.warnings(),
            ["no due window declared: absence is judged at the evaluation instant"]
        );
        contract.conditions[1].advisory = true;
        contract.due = Some(Due {
            source_time_field: "time".into(),
            within_seconds: 0,
        });
        assert_eq!(contract.warnings().len(), 2);
        assert!(contract.relevant_source_fields().contains("time"));
    }

    #[test]
    fn id_anchor_and_error_join_match_source() {
        assert!(valid_id("valid\n"));
        assert!(!valid_id("valid\n\n"));
        assert!(!valid_id("_bad"));
        assert!(!valid_id(&"x".repeat(65)));
        assert_eq!(
            ContractError {
                problems: vec!["a".into(), "b".into()]
            }
            .to_string(),
            "a; b"
        );
        assert_eq!(
            ParseError::DuplicateKey("a'b".into()).to_string(),
            "duplicate key \"a'b\""
        );
        assert_eq!(py_repr("\u{a0}\u{1c}\t"), "'\\xa0\\x1c\\t'");
        assert_eq!(
            py_repr("\u{200b}\u{378}\u{e000}\u{10ffff}"),
            "'\\u200b\\u0378\\ue000\\U0010ffff'"
        );
    }
}
