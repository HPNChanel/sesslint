//! RX-SCH-sesslint.outcome-report.v1: validated report projection and exact JSON.
//! Pinned schema 02694d537104659df66cdd084354739f3cccc440, Draft 2020-12.
//! This closed validator implements only keywords/patterns used by that schema.
//! It does not consult runtime registries or infer stronger timestamp/key rules.
//! Strict JSON inherits scalar Unicode, binary64 and depth128/integer4300 limits.
use crate::contract::{parse_strict_json, Json, Mapping, Scalar};
use crate::report::{json_text, OutcomeReport};
use std::fmt;
use std::sync::OnceLock;

pub const SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../parity/schemas/sesslint.outcome-report.v1/schema.json"
));

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    StrictJson,
    Definition,
    Reject(&'static str),
    Serialization,
}
impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StrictJson => f.write_str("report schema strict JSON rejected"),
            Self::Definition => f.write_str("report schema definition unsupported"),
            Self::Reject(keyword) => write!(f, "report schema rejected {keyword}"),
            Self::Serialization => f.write_str("report schema serialization failed"),
        }
    }
}
impl std::error::Error for SchemaError {}
fn reject(keyword: &'static str) -> SchemaError {
    SchemaError::Reject(keyword)
}
fn object(value: &Json) -> Result<&Mapping, SchemaError> {
    match value {
        Json::Object(m) => Ok(m),
        _ => Err(reject("type")),
    }
}
fn array(value: &Json) -> Result<&[Json], SchemaError> {
    match value {
        Json::Array(a) => Ok(a),
        _ => Err(reject("type")),
    }
}
fn text(value: &Json) -> Result<&str, SchemaError> {
    value.as_str().ok_or_else(|| reject("type"))
}
fn flag(value: &Json) -> Result<bool, SchemaError> {
    match value {
        Json::Scalar(Scalar::Bool(b)) => Ok(*b),
        _ => Err(reject("type")),
    }
}
fn get<'a>(map: &'a Mapping, key: &str) -> Result<&'a Json, SchemaError> {
    map.get(key).ok_or_else(|| reject("required"))
}
fn integer(value: &Json) -> bool {
    matches!(value, Json::Scalar(Scalar::Int(_)))
        || matches!(value, Json::Scalar(Scalar::Float(f)) if f.is_finite() && f.fract() == 0.0)
}
fn kind(value: &Json, name: &str) -> Result<bool, SchemaError> {
    Ok(match name {
        "object" => matches!(value, Json::Object(_)),
        "array" => matches!(value, Json::Array(_)),
        "string" => value.as_str().is_some(),
        "integer" => integer(value),
        "boolean" => matches!(value, Json::Scalar(Scalar::Bool(_))),
        "null" => matches!(value, Json::Scalar(Scalar::Null)),
        _ => return Err(SchemaError::Definition),
    })
}
fn bound(value: &Json) -> Result<usize, SchemaError> {
    if let Json::Scalar(Scalar::Int(n)) = value {
        n.decimal().parse().map_err(|_| SchemaError::Definition)
    } else {
        Err(SchemaError::Definition)
    }
}
fn minimum(value: &Json, limit: usize) -> Result<bool, SchemaError> {
    // The pinned schema contains only zero and one; preserve arbitrary integers.
    if limit > 1 {
        return Err(SchemaError::Definition);
    }
    Ok(match value {
        Json::Scalar(Scalar::Int(n)) => {
            !n.decimal().starts_with('-') && (limit == 0 || n.decimal() != "0")
        }
        Json::Scalar(Scalar::Float(n)) => *n >= limit as f64,
        _ => true, // JSON Schema numeric keywords ignore other types.
    })
}
fn pattern(value: &str, regex: &str) -> Result<bool, SchemaError> {
    // Python `$` also matches before exactly one trailing LF.
    let value = value.strip_suffix('\n').unwrap_or(value);
    let b = value.as_bytes();
    let hex = |s: &[u8]| {
        s.iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    };
    Ok(match regex {
        "^[0-9a-f]{64}$" => b.len() == 64 && hex(b),
        "^sha256:[0-9a-f]{16}$" => b.len() == 23 && b.starts_with(b"sha256:") && hex(&b[7..]),
        "^[a-z][a-z_]*$" => {
            !b.is_empty()
                && b[0].is_ascii_lowercase()
                && b.iter().all(|c| c.is_ascii_lowercase() || *c == b'_')
        }
        "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$" => {
            b.len() >= 13
                && b[..4].iter().all(u8::is_ascii_digit)
                && b[4] == b'-'
                && b[5..7].iter().all(u8::is_ascii_digit)
                && b[7] == b'-'
                && b[8..10].iter().all(u8::is_ascii_digit)
                && b[10] == b'T'
                && b[b.len() - 1] == b'Z'
                && b[11..b.len() - 1]
                    .iter()
                    .all(|c| c.is_ascii_digit() || *c == b':' || *c == b'.')
        }
        _ => return Err(SchemaError::Definition),
    })
}
fn check(value: &Json, rule: &Json, root: &Json, depth: usize) -> Result<(), SchemaError> {
    if depth > 512 {
        return Err(reject("depth"));
    }
    let rule = object(rule).map_err(|_| SchemaError::Definition)?;
    const KEYWORDS: &[&str] = &[
        "$schema",
        "$id",
        "$defs",
        "$ref",
        "title",
        "description",
        "type",
        "const",
        "enum",
        "anyOf",
        "oneOf",
        "minimum",
        "pattern",
        "minItems",
        "maxItems",
        "items",
        "required",
        "properties",
        "additionalProperties",
    ];
    if rule.keys().any(|key| !KEYWORDS.contains(&key.as_str())) {
        return Err(SchemaError::Definition);
    }
    if let Some(reference) = rule.get("$ref") {
        let name = text(reference)?
            .strip_prefix("#/$defs/")
            .ok_or(SchemaError::Definition)?;
        let defs = object(get(object(root)?, "$defs")?)?;
        check(
            value,
            defs.get(name).ok_or(SchemaError::Definition)?,
            root,
            depth + 1,
        )?;
    }
    if let Some(types) = rule.get("type") {
        let allowed = match types {
            Json::Array(types) => types
                .iter()
                .map(|t| kind(value, text(t)?))
                .collect::<Result<Vec<_>, SchemaError>>()?
                .into_iter()
                .any(|yes| yes),
            _ => kind(value, text(types)?)?,
        };
        if !allowed {
            return Err(reject("type"));
        }
    }
    if let Some(expected) = rule.get("const") {
        if value != expected {
            return Err(reject("const"));
        }
    }
    if let Some(choices) = rule.get("enum") {
        if !array(choices)?.contains(value) {
            return Err(reject("enum"));
        }
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(choices) = rule.get(keyword) {
            let mut matches = 0;
            for choice in array(choices)? {
                match check(value, choice, root, depth + 1) {
                    Ok(()) => matches += 1,
                    Err(SchemaError::Definition) => return Err(SchemaError::Definition),
                    Err(_) => (),
                }
            }
            if matches == 0 || (keyword == "oneOf" && matches != 1) {
                return Err(reject(keyword));
            }
        }
    }
    if let Some(limit) = rule.get("minimum") {
        if !minimum(value, bound(limit)?)? {
            return Err(reject("minimum"));
        }
    }
    if let (Some(regex), Some(value)) = (rule.get("pattern"), value.as_str()) {
        if !pattern(value, text(regex)?)? {
            return Err(reject("pattern"));
        }
    }
    if let Json::Array(values) = value {
        for (keyword, too_many) in [("minItems", false), ("maxItems", true)] {
            if let Some(limit) = rule.get(keyword) {
                let limit = bound(limit)?;
                if if too_many {
                    values.len() > limit
                } else {
                    values.len() < limit
                } {
                    return Err(reject(keyword));
                }
            }
        }
        if let Some(item_rule) = rule.get("items") {
            for item in values {
                check(item, item_rule, root, depth + 1)?;
            }
        }
    }
    if let Json::Object(values) = value {
        if let Some(required) = rule.get("required") {
            for name in array(required)? {
                if !values.contains_key(text(name)?) {
                    return Err(reject("required"));
                }
            }
        }
        let properties = rule.get("properties").map(object).transpose()?;
        for (key, value) in values {
            if let Some(property) = properties.and_then(|p| p.get(key)) {
                check(value, property, root, depth + 1)?;
            } else if let Some(extra) = rule.get("additionalProperties") {
                match extra {
                    Json::Scalar(Scalar::Bool(false)) => {
                        return Err(reject("additionalProperties"))
                    }
                    Json::Scalar(Scalar::Bool(true)) => (),
                    _ => check(value, extra, root, depth + 1)?,
                }
            }
        }
    }
    Ok(())
}
pub fn validate_value(value: &Json) -> Result<(), SchemaError> {
    static SCHEMA: OnceLock<Result<Json, SchemaError>> = OnceLock::new();
    let schema =
        SCHEMA.get_or_init(|| parse_strict_json(SCHEMA_JSON).map_err(|_| SchemaError::Definition));
    let schema = schema.as_ref().map_err(Clone::clone)?;
    check(value, schema, schema, 0)
}
pub fn validate(text: &str) -> Result<(), SchemaError> {
    validate_value(&parse_strict_json(text).map_err(|_| SchemaError::StrictJson)?)
}

/// Typed top-level projection. Nested maps/arrays are validated against the exact
/// closed schema. Emission revalidates all fields, including caller modifications.
#[derive(Clone)]
pub struct Report<'a> {
    pub schema_version: &'a str,
    pub tool_version: &'a str,
    pub run_status: &'a str,
    pub evaluated_at: &'a str,
    pub outcome: &'a str,
    pub outcome_reasons: &'a [Json],
    pub demo: bool,
    pub dimensions: &'a Mapping,
    pub contract: &'a Mapping,
    pub observations: &'a Mapping,
    pub coverage: &'a Mapping,
    pub condition_summary: &'a Mapping,
    pub condition_detail: &'a str,
    pub key_display: &'a str,
    pub items: &'a [Json],
    pub unmatched_target_keys: &'a [Json],
    pub unmatched_target_keys_truncated: bool,
    pub limitations: &'a [Json],
}
impl fmt::Debug for Report<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Report(..)")
    }
}
impl<'a> Report<'a> {
    pub fn from_json(value: &'a Json) -> Result<Self, SchemaError> {
        validate_value(value)?;
        let m = object(value)?;
        Ok(Self {
            schema_version: text(get(m, "schema_version")?)?,
            tool_version: text(get(m, "tool_version")?)?,
            run_status: text(get(m, "run_status")?)?,
            evaluated_at: text(get(m, "evaluated_at")?)?,
            outcome: text(get(m, "outcome")?)?,
            outcome_reasons: array(get(m, "outcome_reasons")?)?,
            demo: flag(get(m, "demo")?)?,
            dimensions: object(get(m, "dimensions")?)?,
            contract: object(get(m, "contract")?)?,
            observations: object(get(m, "observations")?)?,
            coverage: object(get(m, "coverage")?)?,
            condition_summary: object(get(m, "condition_summary")?)?,
            condition_detail: text(get(m, "condition_detail")?)?,
            key_display: text(get(m, "key_display")?)?,
            items: array(get(m, "items")?)?,
            unmatched_target_keys: array(get(m, "unmatched_target_keys")?)?,
            unmatched_target_keys_truncated: flag(get(m, "unmatched_target_keys_truncated")?)?,
            limitations: array(get(m, "limitations")?)?,
        })
    }
    pub fn to_json(&self) -> Result<String, SchemaError> {
        let mut m = Mapping::new();
        for (key, value) in [
            ("schema_version", self.schema_version),
            ("tool_version", self.tool_version),
            ("run_status", self.run_status),
            ("evaluated_at", self.evaluated_at),
            ("outcome", self.outcome),
            ("condition_detail", self.condition_detail),
            ("key_display", self.key_display),
        ] {
            m.insert(key.into(), Json::Scalar(Scalar::String(value.into())));
        }
        for (key, value) in [
            ("demo", self.demo),
            (
                "unmatched_target_keys_truncated",
                self.unmatched_target_keys_truncated,
            ),
        ] {
            m.insert(key.into(), Json::Scalar(Scalar::Bool(value)));
        }
        for (key, value) in [
            ("outcome_reasons", self.outcome_reasons),
            ("items", self.items),
            ("unmatched_target_keys", self.unmatched_target_keys),
            ("limitations", self.limitations),
        ] {
            m.insert(key.into(), Json::Array(value.to_vec()));
        }
        for (key, value) in [
            ("dimensions", self.dimensions),
            ("contract", self.contract),
            ("observations", self.observations),
            ("coverage", self.coverage),
            ("condition_summary", self.condition_summary),
        ] {
            m.insert(key.into(), Json::Object(value.clone()));
        }
        let value = Json::Object(m);
        validate_value(&value)?;
        json_text(&value, true).map_err(|_| SchemaError::Serialization)
    }
}
pub fn emit(report: &OutcomeReport<'_>) -> Result<String, SchemaError> {
    let value = Json::Object(report.to_dict().map_err(|_| SchemaError::Serialization)?);
    Report::from_json(&value)?.to_json()
}
