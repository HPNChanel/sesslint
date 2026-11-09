//! Outcome report presentation and user-asserted session dimension (EVD-04, EXE-03).
//! Pinned report.py lines 1..355; no snapshot payload values are added to reports.
//! The unported check_file integration fails with typed Unsupported by default.
use crate::contract::{repr_list, Condition, Contract, Integer, Json, Mapping, Predicate, Scalar};
use crate::engine::{
    Evaluation, ItemResult, HASHED_KEY_LIMITATION, LIMITATIONS, MAX_UNMATCHED_KEYS, NOT_APPLICABLE,
    REASONS, STATUSES, VERIFIED,
};
use crate::snapshot::{format_instant, Snapshot};
use codec::canonical_codec::{self, CanonicalCodec, PurePythonCanonicalCodec, Value};
use model::version::CLI_VERSION;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::{self, Write};
use std::path::Path;

pub const OUTCOME_REPORT_SCHEMA_VERSION: &str = "sesslint.outcome-report/v1";
pub const MAX_HUMAN_ITEMS: usize = 50;
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;
pub const SESSION_LABELS: &[(&str, &str)] = &[
    ("not_linked", "not linked (no session supplied)"),
    ("no_findings", "no findings in the checks run"),
    ("findings", "findings present"),
    ("unreadable", "unreadable or unsupported format"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    Unsupported(&'static str),
    Key(String),
    Serialization,
    InvalidValue(&'static str),
}
impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(s) => f.write_str(s),
            Self::Key(k) => {
                let r = repr_list([k.as_str()]);
                f.write_str(&r[1..r.len() - 1])
            }
            Self::Serialization => f.write_str("report serialization failed"),
            Self::InvalidValue(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for ReportError {}

fn string(s: impl Into<String>) -> Json {
    Json::Scalar(Scalar::String(s.into()))
}
fn boolean(v: bool) -> Json {
    Json::Scalar(Scalar::Bool(v))
}
fn count(v: usize) -> Result<Json, ReportError> {
    Ok(Json::Scalar(Scalar::Int(
        Integer::parse(&v.to_string()).map_err(|_| ReportError::Serialization)?,
    )))
}
fn strings<'a>(s: impl IntoIterator<Item = &'a str>) -> Json {
    Json::Array(s.into_iter().map(string).collect())
}
fn object<const N: usize>(rows: [(&str, Json); N]) -> Mapping {
    rows.into_iter().map(|(k, v)| (k.into(), v)).collect()
}
fn time(v: Option<crate::snapshot::Instant>) -> Json {
    format_instant(v)
        .map(string)
        .unwrap_or(Json::Scalar(Scalar::Null))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCheck {
    pub assurance: String,
    pub total: usize,
    pub by_code: BTreeMap<String, usize>,
    pub source_fingerprint: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCheckError {
    Os,
    Value,
    Unsupported,
}
pub trait SessionBackend {
    fn check_file(
        &self,
        path: &Path,
        max_file_bytes: i64,
    ) -> Result<SessionCheck, SessionCheckError>;
}
struct Unavailable;
impl SessionBackend for Unavailable {
    fn check_file(
        &self,
        _path: &Path,
        _max_file_bytes: i64,
    ) -> Result<SessionCheck, SessionCheckError> {
        Err(SessionCheckError::Unsupported)
    }
}
pub fn session_dimension(
    path: Option<&Path>,
    max_file_bytes: Option<i64>,
) -> Result<Mapping, ReportError> {
    session_dimension_with(path, max_file_bytes, &Unavailable)
}
pub fn session_dimension_with(
    path: Option<&Path>,
    max_file_bytes: Option<i64>,
    backend: &impl SessionBackend,
) -> Result<Mapping, ReportError> {
    let Some(path) = path else {
        return Ok(object([("status", string("not_linked"))]));
    };
    let limit = max_file_bytes
        .filter(|n| *n != 0)
        .unwrap_or(DEFAULT_MAX_FILE_BYTES);
    let result = match backend.check_file(path, limit) {
        Ok(result) => result,
        Err(SessionCheckError::Os | SessionCheckError::Value) => {
            return Ok(object([
                ("status", string("unreadable")),
                ("link", string("user_asserted")),
                ("assurance", string("A0")),
            ]))
        }
        Err(SessionCheckError::Unsupported) => {
            return Err(ReportError::Unsupported(
                "sesslint.api.check_file is not available",
            ))
        }
    };
    let status = if result.assurance == "A0" {
        "unreadable"
    } else if result.total > 0 {
        "findings"
    } else {
        "no_findings"
    };
    Ok(object([
        ("status", string(status)),
        ("link", string("user_asserted")),
        ("assurance", string(result.assurance)),
        ("finding_count", count(result.total)?),
        (
            "by_code",
            Json::Object(
                result
                    .by_code
                    .into_iter()
                    .map(|(k, v)| Ok((k, count(v)?)))
                    .collect::<Result<_, ReportError>>()?,
            ),
        ),
        (
            "source_fingerprint",
            result
                .source_fingerprint
                .map(string)
                .unwrap_or(Json::Scalar(Scalar::Null)),
        ),
    ]))
}

pub fn hashed(key: &[String]) -> Result<String, ReportError> {
    let values = Value::array(key.iter().map(|s| Value::string(s.clone())).collect());
    let bytes = canonical_codec::canonical_json_bytes(&values, false)
        .map_err(|_| ReportError::Serialization)?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    Ok(format!("sha256:{}", &digest[..16]))
}

/// Python ensure_ascii string quoting, including UTF-16 surrogate pairs.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}
fn float_text(v: f64) -> Result<String, ReportError> {
    if v.is_nan() {
        return Ok("NaN".into());
    }
    if v == f64::INFINITY {
        return Ok("Infinity".into());
    }
    if v == f64::NEG_INFINITY {
        return Ok("-Infinity".into());
    }
    String::from_utf8(
        PurePythonCanonicalCodec
            .canonical_json_bytes(&Value::float(v), false)
            .map_err(|_| ReportError::Serialization)?,
    )
    .map_err(|_| ReportError::Serialization)
}
/// Serialize a typed tree using Python json.dumps defaults or indent=2.
pub fn json_text(value: &Json, pretty: bool) -> Result<String, ReportError> {
    fn render(value: &Json, pretty: bool, depth: usize) -> Result<String, ReportError> {
        if depth > 128 {
            return Err(ReportError::InvalidValue("report JSON nesting exceeds 128"));
        }
        Ok(match value {
            Json::Scalar(Scalar::Null) => "null".into(),
            Json::Scalar(Scalar::Bool(v)) => v.to_string(),
            Json::Scalar(Scalar::Int(v)) => v.decimal().into(),
            Json::Scalar(Scalar::Float(v)) => float_text(*v)?,
            Json::Scalar(Scalar::String(s)) => quote(s),
            Json::Array(values) => {
                let parts = values
                    .iter()
                    .map(|v| render(v, pretty, depth + 1))
                    .collect::<Result<Vec<_>, _>>()?;
                container("[", "]", &parts, pretty, depth)
            }
            Json::Object(values) => {
                let parts = values
                    .iter()
                    .map(|(k, v)| Ok(format!("{}: {}", quote(k), render(v, pretty, depth + 1)?)))
                    .collect::<Result<Vec<_>, ReportError>>()?;
                container("{", "}", &parts, pretty, depth)
            }
        })
    }
    fn container(left: &str, right: &str, parts: &[String], pretty: bool, depth: usize) -> String {
        if parts.is_empty() {
            return format!("{left}{right}");
        }
        if pretty {
            let pad = "  ".repeat(depth + 1);
            format!(
                "{left}\n{pad}{}\n{}{right}",
                parts.join(&format!(",\n{pad}")),
                "  ".repeat(depth)
            )
        } else {
            format!("{left}{}{right}", parts.join(", "))
        }
    }
    render(value, pretty, 0)
}
fn python_str(value: &Json) -> Result<String, ReportError> {
    Ok(match value {
        Json::Scalar(Scalar::String(s)) => s.clone(),
        Json::Scalar(Scalar::Null) => "None".into(),
        Json::Scalar(Scalar::Bool(v)) => if *v { "True" } else { "False" }.into(),
        Json::Scalar(Scalar::Int(v)) => v.decimal().into(),
        Json::Scalar(Scalar::Float(v)) => {
            if v.is_nan() {
                "nan".into()
            } else if v.is_infinite() {
                if v.is_sign_positive() { "inf" } else { "-inf" }.into()
            } else {
                float_text(*v)?
            }
        }
        _ => return Err(ReportError::InvalidValue("session status must be a scalar")),
    })
}

fn snapshot_metadata(s: &Snapshot) -> Result<Json, ReportError> {
    Ok(Json::Object(object([
        ("role", string(&s.role)),
        ("name", string(&s.name)),
        ("sha256", string(&s.sha256)),
        ("input_format", string(&s.input_format)),
        ("record_count", count(s.records.len())?),
        ("observed_at", time(s.observed_at)),
        ("completeness", string(&s.completeness)),
        ("origin", string(&s.origin)),
        ("demo", boolean(s.demo)),
    ])))
}
fn passing(status: &str) -> bool {
    matches!(status, VERIFIED | NOT_APPLICABLE)
}
fn reason(code: &str) -> Result<&'static str, ReportError> {
    REASONS
        .iter()
        .find(|(k, _)| *k == code)
        .map(|(_, v)| *v)
        .ok_or_else(|| ReportError::Key(code.into()))
}

pub struct OutcomeReport<'a> {
    pub evaluation: Evaluation<'a>,
    pub session: Mapping,
    pub hash_keys: bool,
    pub all_conditions: bool,
}
impl<'a> OutcomeReport<'a> {
    pub fn new(evaluation: Evaluation<'a>) -> Self {
        Self {
            evaluation,
            session: object([("status", string("not_linked"))]),
            hash_keys: false,
            all_conditions: false,
        }
    }
    pub fn outcome(&self) -> &str {
        &self.evaluation.outcome
    }
    pub fn exit_code(&self) -> i32 {
        i32::from(self.outcome() != VERIFIED)
    }
    pub fn demo(&self) -> bool {
        self.evaluation.source.demo || self.evaluation.target.demo
    }
    pub fn key(&self, key: Option<&[String]>) -> Result<Json, ReportError> {
        Ok(match key {
            None => Json::Scalar(Scalar::Null),
            Some(key) if self.hash_keys => string(hashed(key)?),
            Some(key) => strings(key.iter().map(String::as_str)),
        })
    }
    pub fn limitations(&self) -> Vec<&'static str> {
        let mut out = LIMITATIONS.to_vec();
        if self.hash_keys {
            out.push(HASHED_KEY_LIMITATION);
        }
        out
    }
    pub fn ordered_items(&self) -> Result<Vec<&ItemResult>, ReportError> {
        let mut out: Vec<_> = self.evaluation.items.iter().collect();
        if self.hash_keys {
            let mut keyed = out
                .into_iter()
                .map(|i| {
                    let h = match i.key.as_deref() {
                        Some(k) if !k.is_empty() => hashed(k)?,
                        _ => String::new(),
                    };
                    Ok(((i.key.is_none(), h, i.source_row), i))
                })
                .collect::<Result<Vec<_>, ReportError>>()?;
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            out = keyed.into_iter().map(|(_, i)| i).collect();
        }
        Ok(out)
    }
    pub fn conditions(&self, item: &ItemResult) -> Vec<Json> {
        item.conditions
            .iter()
            .filter(|c| self.all_conditions || !passing(&item.status) || !passing(&c.status))
            .map(|c| Json::Object(c.to_dict()))
            .collect()
    }
    pub fn condition_summary(&self) -> Result<Mapping, ReportError> {
        let mut summary: BTreeMap<String, BTreeMap<&str, usize>> = self
            .evaluation
            .contract
            .conditions
            .iter()
            .map(|c| (c.id.clone(), STATUSES.iter().map(|s| (*s, 0)).collect()))
            .collect();
        for item in &self.evaluation.items {
            for result in &item.conditions {
                let row = summary
                    .get_mut(&result.id)
                    .ok_or_else(|| ReportError::Key(result.id.clone()))?;
                let n = row
                    .get_mut(result.status.as_str())
                    .ok_or_else(|| ReportError::Key(result.status.clone()))?;
                *n += 1;
            }
        }
        summary
            .into_iter()
            .map(|(k, row)| {
                Ok((
                    k,
                    Json::Object(
                        row.into_iter()
                            .map(|(s, n)| Ok((s.into(), count(n)?)))
                            .collect::<Result<_, ReportError>>()?,
                    ),
                ))
            })
            .collect()
    }
    pub fn item(&self, item: &ItemResult) -> Result<Json, ReportError> {
        let mut out = object([
            ("key", self.key(item.key.as_deref())?),
            ("source_row", count(item.source_row)?),
            ("source_rows", count(item.source_rows)?),
            ("status", string(&item.status)),
            ("reason", string(&item.reason)),
            ("deadline", time(item.deadline)),
            ("matched_records", count(item.matched_records)?),
            ("conditions", Json::Array(self.conditions(item))),
        ]);
        if !item.detail.is_empty() {
            out.insert("detail".into(), Json::Object(item.detail.clone()));
        }
        Ok(Json::Object(out))
    }
    pub fn to_dict(&self) -> Result<Mapping, ReportError> {
        let ev = &self.evaluation;
        let mut unmatched = ev
            .unmatched_target_keys
            .iter()
            .map(|k| self.key(Some(k)))
            .collect::<Result<Vec<_>, _>>()?;
        if self.hash_keys {
            unmatched.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        }
        let truncated = unmatched.len() > MAX_UNMATCHED_KEYS;
        unmatched.truncate(MAX_UNMATCHED_KEYS);
        Ok(object([
            ("schema_version", string(OUTCOME_REPORT_SCHEMA_VERSION)),
            ("tool_version", string(CLI_VERSION)),
            ("run_status", string("completed")),
            ("evaluated_at", time(Some(ev.as_of))),
            ("outcome", string(&ev.outcome)),
            (
                "outcome_reasons",
                strings(ev.outcome_reasons.iter().map(String::as_str)),
            ),
            ("demo", boolean(self.demo())),
            (
                "dimensions",
                Json::Object(object([
                    ("session_integrity", Json::Object(self.session.clone())),
                    (
                        "outcome_verification",
                        Json::Object(object([("status", string(&ev.outcome))])),
                    ),
                    (
                        "monitoring_health",
                        Json::Object(object([
                            ("status", string("not_configured")),
                            ("detail", string("snapshot evaluation; no live monitoring")),
                        ])),
                    ),
                    (
                        "incident_handling",
                        Json::Object(object([("status", string("not_tracked"))])),
                    ),
                ])),
            ),
            (
                "contract",
                Json::Object(object([
                    ("name", string(&ev.contract.name)),
                    ("version", string(&ev.contract.version)),
                    ("sha256", string(&ev.contract.sha256)),
                    ("condition_count", count(ev.contract.conditions.len())?),
                    (
                        "warnings",
                        strings(ev.contract.warnings().iter().map(String::as_str)),
                    ),
                ])),
            ),
            (
                "observations",
                Json::Object(object([
                    ("source", snapshot_metadata(&ev.source)?),
                    ("target", snapshot_metadata(&ev.target)?),
                ])),
            ),
            ("coverage", Json::Object(ev.coverage.clone())),
            ("condition_summary", Json::Object(self.condition_summary()?)),
            (
                "condition_detail",
                string(if self.all_conditions {
                    "all"
                } else {
                    "non_passing"
                }),
            ),
            (
                "key_display",
                string(if self.hash_keys { "sha256" } else { "plain" }),
            ),
            (
                "items",
                Json::Array(
                    self.ordered_items()?
                        .into_iter()
                        .map(|i| self.item(i))
                        .collect::<Result<_, _>>()?,
                ),
            ),
            ("unmatched_target_keys", Json::Array(unmatched)),
            ("unmatched_target_keys_truncated", boolean(truncated)),
            ("limitations", strings(self.limitations())),
        ]))
    }
    pub fn to_json(&self) -> Result<String, ReportError> {
        json_text(&Json::Object(self.to_dict()?), true)
    }
    pub fn display_key(&self, item: &ItemResult) -> Result<String, ReportError> {
        match &item.key {
            None => Ok(format!("(source record {}, no key)", item.source_row)),
            Some(k) if self.hash_keys => hashed(k),
            Some(k) => Ok(k.iter().map(|s| quote(s)).collect::<Vec<_>>().join(" | ")),
        }
    }
    pub fn render_human(&self) -> Result<String, ReportError> {
        let ev = &self.evaluation;
        let counts = match ev.coverage.get("counts") {
            Some(Json::Object(m)) => m,
            _ => {
                return Err(ReportError::InvalidValue(
                    "coverage counts must be an object",
                ))
            }
        };
        let cov = |name: &str| {
            ev.coverage
                .get(name)
                .ok_or_else(|| ReportError::Key(name.into()))
                .and_then(python_str)
        };
        let mut lines = vec![format!(
            "SessLint outcome: {}  (contract {} v{}, evaluated at {})",
            ev.outcome,
            ev.contract.name,
            ev.contract.version,
            format_instant(Some(ev.as_of)).ok_or(ReportError::Serialization)?
        )];
        if self.demo() {
            lines.push("  DEMO DATA - not a verification of real work".into());
        }
        let status = self
            .session
            .get("status")
            .map(python_str)
            .transpose()?
            .unwrap_or_else(|| "not_linked".into());
        let label = SESSION_LABELS
            .iter()
            .find(|(k, _)| *k == status)
            .map(|(_, v)| *v)
            .unwrap_or(&status);
        lines.extend([
            "Dimensions:".into(),
            format!("  session integrity:    {label}"),
            format!("  outcome verification: {}", ev.outcome),
            "  monitoring health:    not configured (snapshot evaluation)".into(),
            "  incident handling:    not tracked".into(),
            "Observations:".into(),
        ]);
        for snap in [&ev.source, &ev.target] {
            lines.push(format!(
                "  {}: {} records, {}, observed {} ({}, {})",
                snap.role,
                snap.records.len(),
                snap.completeness,
                format_instant(snap.observed_at).unwrap_or_else(|| "time unknown".into()),
                snap.origin,
                snap.input_format
            ));
        }
        let mut parts = Vec::new();
        for status in STATUSES {
            let n = counts
                .get(*status)
                .ok_or_else(|| ReportError::Key((*status).into()))?;
            let text = python_str(n)?;
            if text != "0" {
                parts.push(format!("{status} {text}"));
            }
        }
        lines.push(format!(
            "Items: {} work items from {} source rows; {}",
            cov("work_items")?,
            cov("source_rows")?,
            parts.join(", ")
        ));
        let unmatched = cov("unmatched_target_records")?;
        if unmatched != "0" {
            lines.push(format!(
                "  {unmatched} target record(s) match no source item"
            ));
        }
        let problems: Vec<_> = self
            .ordered_items()?
            .into_iter()
            .filter(|i| !passing(&i.status))
            .collect();
        if !problems.is_empty() {
            lines.push(format!(
                "Items needing attention (first {MAX_HUMAN_ITEMS}):"
            ));
        }
        for item in problems.iter().take(MAX_HUMAN_ITEMS) {
            lines.push(format!("  {:<13} {}", item.status, self.display_key(item)?));
            let decisive: Vec<_> = item
                .conditions
                .iter()
                .filter(|c| c.status == item.status && !c.advisory)
                .collect();
            if decisive.is_empty() {
                lines.push(format!("      {}", reason(&item.reason)?));
            }
            let mut by_reason: Vec<(&str, Vec<&str>)> = Vec::new();
            for c in decisive {
                if let Some((_, ids)) = by_reason.iter_mut().find(|(r, _)| *r == c.reason) {
                    ids.push(&c.id);
                } else {
                    by_reason.push((&c.reason, vec![&c.id]));
                }
            }
            for (code, ids) in by_reason {
                lines.push(format!(
                    "      {}: {code} - {}",
                    ids.join(", "),
                    reason(code)?
                ));
            }
        }
        if problems.len() > MAX_HUMAN_ITEMS {
            lines.push(format!(
                "  ... {} more (use --json)",
                problems.len() - MAX_HUMAN_ITEMS
            ));
        }
        lines.push("Outcome reasons:".into());
        for code in &ev.outcome_reasons {
            lines.push(format!("  - {code}: {}", reason(code)?));
        }
        let warnings = ev.contract.warnings();
        if !warnings.is_empty() {
            lines.push("Contract warnings:".into());
            lines.extend(warnings.into_iter().map(|w| format!("  - {w}")));
        }
        lines.push("Limitations:".into());
        lines.extend(self.limitations().into_iter().map(|s| format!("  - {s}")));
        Ok(lines.join("\n"))
    }
}

pub fn describe_predicate(pred: &Predicate) -> Result<String, ReportError> {
    let lit = |v: &Scalar| json_text(&Json::Scalar(v.clone()), false);
    Ok(match pred.op.as_str() {
        "present" => format!("{} is present and non-empty", pred.field),
        "absent" => format!("{} is absent, null or empty", pred.field),
        "in" | "not_in" => format!(
            "{} {} one of {}",
            pred.field,
            if pred.op == "in" { "is" } else { "is not" },
            pred.values
                .iter()
                .map(lit)
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        ),
        op => {
            let symbol = match op {
                "eq" => "=",
                "ne" => "!=",
                "gt" => ">",
                "gte" => ">=",
                "lt" => "<",
                "lte" => "<=",
                _ => return Err(ReportError::Key(op.into())),
            };
            format!("{} {symbol} {}", pred.field, lit(&pred.value)?)
        }
    })
}

/// Python's default :g is six significant decimal digits, round to nearest/even.
/// Choose fixed/scientific notation using the rounded exponent, not log10(x).
fn general_float(value: f64) -> Result<String, ReportError> {
    if value.is_nan() {
        return Ok("nan".into());
    }
    if value.is_infinite() {
        return Ok(if value.is_sign_positive() {
            "inf"
        } else {
            "-inf"
        }
        .into());
    }
    let scientific = format!("{value:.5e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .ok_or(ReportError::Serialization)?;
    let exponent: i32 = exponent.parse().map_err(|_| ReportError::Serialization)?;
    if !(-4..6).contains(&exponent) {
        let mantissa = mantissa.trim_end_matches('0').trim_end_matches('.');
        Ok(format!(
            "{mantissa}e{}{:02}",
            if exponent >= 0 { "+" } else { "-" },
            exponent.unsigned_abs()
        ))
    } else {
        let places = (5 - exponent) as usize;
        let fixed = format!("{value:.places$}");
        Ok(if places > 0 {
            fixed.trim_end_matches('0').trim_end_matches('.').into()
        } else {
            fixed
        })
    }
}
fn count_bound(value: f64) -> Result<String, ReportError> {
    if value.is_nan() {
        return Err(ReportError::InvalidValue(
            "cannot convert float NaN to integer",
        ));
    }
    if value.is_infinite() {
        return Err(ReportError::InvalidValue(
            "cannot convert float infinity to integer",
        ));
    }
    if value.trunc() == 0.0 {
        return Ok("0".into());
    }
    Ok(format!("{:.0}", value.trunc()))
}
pub fn describe_condition(cond: &Condition) -> Result<String, ReportError> {
    describe_condition_at(cond, 0)
}
fn describe_condition_at(cond: &Condition, depth: usize) -> Result<String, ReportError> {
    if depth > 128 {
        return Err(ReportError::InvalidValue("condition nesting exceeds 128"));
    }
    let norm = if cond.normalize.is_empty() {
        String::new()
    } else {
        format!(" (after {})", cond.normalize.join(", "))
    };
    let values = cond
        .values
        .iter()
        .map(|v| json_text(&Json::Scalar(v.clone()), false))
        .collect::<Result<Vec<_>, _>>()?
        .join(", ");
    let field = cond.field.as_deref().unwrap_or("None");
    let mut text = match cond.kind.as_str() {
        "exists" => "at least one matching target record exists".into(),
        "count" => {
            let low = count_bound(cond.minimum.unwrap_or(0.0))?;
            let high = cond.maximum.map(count_bound).transpose()?;
            match high {
                None => format!("at least {low} matching target record(s) exist"),
                Some(high) if high == low => {
                    format!("exactly {low} matching target record(s) exist")
                }
                Some(high) => format!("between {low} and {high} matching target records exist"),
            }
        }
        "required" => {
            let allowed: Vec<_> = [("null", cond.allow_null), ("empty", cond.allow_empty)]
                .into_iter()
                .filter(|(_, v)| *v)
                .map(|(n, _)| n)
                .collect();
            let extra = if allowed.is_empty() {
                String::new()
            } else {
                format!(" ({} allowed)", allowed.join(" and "))
            };
            format!("target field {field} is present, non-null and non-empty{extra}")
        }
        "type" => format!(
            "target field {field}, when present, is a {}",
            cond.value_kind.as_deref().unwrap_or("None")
        ),
        "one_of" => format!("target field {field}, when present, is one of {values}{norm}"),
        "equals" => format!(
            "target field {field} equals source field {}{norm}",
            cond.source_field.as_deref().unwrap_or("None")
        ),
        "range" => {
            let mut bounds = Vec::new();
            if let Some(low) = cond.minimum {
                bounds.push(format!(">= {}", general_float(low)?));
            }
            if let Some(high) = cond.maximum {
                bounds.push(format!("<= {}", general_float(high)?));
            }
            format!(
                "target field {field}, when present, is a number {}",
                bounds.join(" and ")
            )
        }
        "route" => format!(
            "when {}: target field {field} is one of {values}{norm}",
            cond.when
                .iter()
                .map(describe_predicate)
                .collect::<Result<Vec<_>, _>>()?
                .join(" and ")
        ),
        "on_time" if cond.basis.as_deref() == Some("target_time") => {
            format!("target completion time {field} is at or before the deadline")
        }
        "on_time" => {
            "the record is visible in a target snapshot taken at or before the deadline".into()
        }
        _ => format!(
            "any one of: {}",
            cond.conditions
                .iter()
                .map(|c| describe_condition_at(c, depth + 1))
                .collect::<Result<Vec<_>, _>>()?
                .join("; ")
        ),
    };
    if let Some(disabled) = &cond.disabled {
        text.push_str(&format!(" [disabled: {disabled}]"));
    } else if cond.advisory {
        text.push_str(" [advisory: reported, does not decide the outcome]");
    }
    Ok(text)
}
pub fn explain_contract(contract: &Contract) -> Result<String, ReportError> {
    let short_hash: String = contract.sha256.chars().take(16).collect();
    let mut lines = vec![format!(
        "Contract {} v{} (sha256 {short_hash})",
        contract.name, contract.version
    )];
    if let Some(description) = &contract.description {
        if !description.is_empty() {
            lines.push(format!("  {description}"));
        }
    }
    lines.push(format!(
        "Work items: one per distinct source key ({}), matched exactly to target key ({}).",
        contract.source_key.join(", "),
        contract.target_key.join(", ")
    ));
    if contract.eligibility.is_empty() {
        lines.push("Applies to every keyed source record.".into());
    } else {
        lines.push("Applies only when all of:".into());
        for predicate in &contract.eligibility {
            lines.push(format!("  - {}", describe_predicate(predicate)?));
        }
    }
    if let Some(due) = &contract.due {
        lines.push(format!(
            "Deadline: {} + {}s; before it, missing results are PENDING.",
            due.source_time_field, due.within_seconds
        ));
    }
    lines.push("Conditions:".into());
    for c in &contract.conditions {
        lines.push(format!("  - {}: {}", c.id, describe_condition(c)?));
    }
    lines.extend(
        contract
            .warnings()
            .into_iter()
            .map(|w| format!("Warning: {w}")),
    );
    lines.push("Absence is proven only from a target snapshot declared complete and observed at or after the deadline; otherwise the verdict is INCONCLUSIVE.".into());
    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{contract_from_dict, parse_strict_json, Condition};
    use crate::engine::{evaluate, INCONCLUSIVE};
    use crate::snapshot::{parse_instant_str, scalarize};
    use std::cell::Cell;

    fn fixture() -> (crate::contract::Contract, Snapshot, Snapshot) {
        let c = contract_from_dict(&parse_strict_json(r#"{"schema_version":"sesslint.outcome-contract/v1","name":"synthetic","version":"1","key":{"source":["id"],"target":["id"]},"conditions":[{"id":"exists","type":"exists"}]}"#).unwrap()).unwrap();
        let rows = [r#"{"id":"private-key","note":"SOURCE-PAYLOAD"}"#]
            .into_iter()
            .map(|s| {
                let Json::Object(m) = parse_strict_json(s).unwrap() else {
                    panic!()
                };
                scalarize(&m)
            })
            .collect();
        let s = Snapshot {
            role: "source".into(),
            name: "synthetic.json".into(),
            sha256: "0".repeat(64),
            input_format: "json".into(),
            records: rows,
            fields: ["id".into(), "note".into()].into_iter().collect(),
            observed_at: parse_instant_str("2026-11-09T00:00:00Z"),
            completeness: "complete".into(),
            origin: "user_file".into(),
            demo: false,
        };
        let mut t = s.clone();
        t.role = "target".into();
        (c, s, t)
    }

    #[test]
    fn general_format_uses_rounded_exponent_and_keeps_negative_zero() {
        for (value, expected) in [
            (0.0, "0"),
            (-0.0, "-0"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (999999.4, "999999"),
            (999999.6, "1e+06"),
            (f64::MAX, "1.79769e+308"),
            (f64::from_bits(1), "4.94066e-324"),
        ] {
            assert_eq!(general_float(value).unwrap(), expected);
        }
        assert_eq!(general_float(f64::NEG_INFINITY).unwrap(), "-inf");
        assert_eq!(general_float(f64::NAN).unwrap(), "nan");
        assert_eq!(count_bound(-0.9).unwrap(), "0");
        assert_eq!(count_bound(1.9).unwrap(), "1");
        assert_eq!(count_bound(-1.9).unwrap(), "-1");
        assert!(count_bound(f64::NAN).is_err());
        assert!(count_bound(f64::INFINITY).is_err());
    }

    #[test]
    fn condition_descriptions_preserve_flags_null_fields_and_bound_shapes() {
        let mut c = Condition {
            kind: "count".into(),
            minimum: Some(-0.9),
            maximum: Some(0.9),
            ..Condition::default()
        };
        assert_eq!(
            describe_condition(&c).unwrap(),
            "exactly 0 matching target record(s) exist"
        );
        c.kind = "required".into();
        c.allow_null = true;
        c.allow_empty = true;
        c.advisory = true;
        c.disabled = Some(String::new());
        assert_eq!(describe_condition(&c).unwrap(),"target field None is present, non-null and non-empty (null and empty allowed) [disabled: ]");
        c.kind = "range".into();
        c.disabled = None;
        c.advisory = false;
        c.minimum = None;
        c.maximum = None;
        assert_eq!(
            describe_condition(&c).unwrap(),
            "target field None, when present, is a number "
        );
        let outer = Condition {
            kind: "unknown".into(),
            conditions: vec![c],
            ..Condition::default()
        };
        assert_eq!(
            describe_condition(&outer).unwrap(),
            "any one of: target field None, when present, is a number "
        );
    }

    #[test]
    fn explain_preserves_contract_order_and_unicode_hash_prefix() {
        let (mut c, _, _) = fixture();
        c.description = Some("description".into());
        c.sha256 = "🚀".repeat(20);
        c.eligibility = vec![Predicate::new("paid", "present")];
        c.due = Some(crate::contract::Due {
            source_time_field: "start".into(),
            within_seconds: 0,
        });
        let text = explain_contract(&c).unwrap();
        assert!(text.starts_with(&format!(
            "Contract synthetic v1 (sha256 {})\n  description\n",
            "🚀".repeat(16)
        )));
        assert!(text.contains("Applies only when all of:\n  - paid is present and non-empty\nDeadline: start + 0s; before it, missing results are PENDING.\nConditions:\n  - exists: at least one matching target record exists"));
        c.eligibility[0].op = "bad".into();
        assert_eq!(explain_contract(&c), Err(ReportError::Key("bad".into())));
        let mut child = Condition::default();
        for _ in 0..130 {
            child = Condition {
                conditions: vec![child],
                ..Condition::default()
            };
        }
        assert_eq!(
            describe_condition(&child),
            Err(ReportError::InvalidValue("condition nesting exceeds 128"))
        );
    }

    #[test]
    fn json_serializer_preserves_python_ascii_numbers_and_container_layout() {
        let value = Json::Array(vec![
            string("é🚀\u{7f}"),
            Json::Scalar(Scalar::Float(-0.0)),
            Json::Object(Mapping::new()),
        ]);
        assert_eq!(
            json_text(&value, false).unwrap(),
            r#"["\u00e9\ud83d\ude80\u007f", -0.0, {}]"#
        );
        assert_eq!(
            json_text(&value, true).unwrap(),
            "[\n  \"\\u00e9\\ud83d\\ude80\\u007f\",\n  -0.0,\n  {}\n]"
        );
        assert_eq!(
            json_text(&Json::Scalar(Scalar::Float(f64::NAN)), false).unwrap(),
            "NaN"
        );
        assert_eq!(hashed(&[]).unwrap(), "sha256:4f53cda18c2baa0c");
        assert_eq!(hashed(&["a".into()]).unwrap().len(), 23);
    }

    #[test]
    fn linked_session_never_claims_live_check_support() {
        assert_eq!(
            session_dimension(None, None).unwrap(),
            object([("status", string("not_linked"))])
        );
        assert!(matches!(
            session_dimension(Some(Path::new("synthetic")), None),
            Err(ReportError::Unsupported(_))
        ));
        struct Backend {
            limit: Cell<i64>,
            result: Result<SessionCheck, SessionCheckError>,
        }
        impl SessionBackend for Backend {
            fn check_file(
                &self,
                _path: &Path,
                limit: i64,
            ) -> Result<SessionCheck, SessionCheckError> {
                self.limit.set(limit);
                self.result.clone()
            }
        }
        let b = Backend {
            limit: Cell::new(0),
            result: Err(SessionCheckError::Value),
        };
        let r = session_dimension_with(Some(Path::new("synthetic")), Some(0), &b).unwrap();
        assert_eq!(b.limit.get(), DEFAULT_MAX_FILE_BYTES);
        assert_eq!(
            r,
            object([
                ("status", string("unreadable")),
                ("link", string("user_asserted")),
                ("assurance", string("A0"))
            ])
        );
        let _ = session_dimension_with(Some(Path::new("synthetic")), Some(-1), &b).unwrap();
        assert_eq!(b.limit.get(), -1);
        for (assurance, total, status) in [
            ("A0", 0, "unreadable"),
            ("A1", 0, "no_findings"),
            ("A2", 2, "findings"),
        ] {
            let b = Backend {
                limit: Cell::new(0),
                result: Ok(SessionCheck {
                    assurance: assurance.into(),
                    total,
                    by_code: BTreeMap::from([("SL002".into(), 1), ("SL001".into(), 1)]),
                    source_fingerprint: None,
                }),
            };
            let r = session_dimension_with(Some(Path::new("synthetic")), None, &b).unwrap();
            assert_eq!(r["status"], string(status));
            assert_eq!(r["finding_count"], count(total).unwrap());
        }
    }

    #[test]
    fn reports_keep_dimensions_separate_and_omit_snapshot_payloads() {
        let (mut c, s, mut t) = fixture();
        t.demo = true;
        c.conditions.push(Condition {
            id: "advisory".into(),
            kind: "required".into(),
            field: Some("missing".into()),
            advisory: true,
            ..Condition::default()
        });
        let ev = evaluate(&c, &s, &t, s.observed_at).unwrap();
        let mut report = OutcomeReport::new(ev);
        assert_eq!(report.exit_code(), 0);
        assert!(report.demo());
        let json = report.to_json().unwrap();
        let human = report.render_human().unwrap();
        assert!(!json.contains("SOURCE-PAYLOAD"));
        assert!(!human.contains("SOURCE-PAYLOAD"));
        assert!(json.contains("private-key"));
        assert!(human.contains("DEMO DATA"));
        assert_eq!(report.conditions(&report.evaluation.items[0]).len(), 1);
        assert_eq!(
            match &report.conditions(&report.evaluation.items[0])[0] {
                Json::Object(m) => m["id"].clone(),
                _ => panic!("condition must be an object"),
            },
            string("advisory")
        );
        report.all_conditions = true;
        assert_eq!(report.conditions(&report.evaluation.items[0]).len(), 2);
        report.hash_keys = true;
        assert!(!report.to_json().unwrap().contains("private-key"));
        assert!(report.to_json().unwrap().contains("pseudonymous"));
        report.session = object([("status", string("findings"))]);
        assert_eq!(report.exit_code(), 0);
        assert!(report
            .render_human()
            .unwrap()
            .contains("session integrity:    findings present"));
    }

    #[test]
    fn hashed_order_and_both_display_limits_are_explicit() {
        let (c, s, mut t) = fixture();
        t.records.clear();
        let mut ev = evaluate(&c, &s, &t, s.observed_at).unwrap();
        let item = ev.items[0].clone();
        ev.items = (0..55)
            .map(|n| {
                let mut i = item.clone();
                i.key = Some(vec![format!("key-{n:03}")]);
                i.source_row = n + 1;
                i
            })
            .collect();
        ev.unmatched_target_keys = (0..MAX_UNMATCHED_KEYS + 1)
            .map(|n| vec![format!("other-{n:04}")])
            .collect();
        let mut report = OutcomeReport::new(ev);
        report.hash_keys = true;
        let ordered = report.ordered_items().unwrap();
        let keys: Vec<_> = ordered
            .iter()
            .map(|i| report.display_key(i).unwrap())
            .collect();
        assert!(keys.windows(2).all(|w| w[0] <= w[1]));
        let out = report.to_dict().unwrap();
        assert_eq!(
            match &out["unmatched_target_keys"] {
                Json::Array(a) => a.len(),
                _ => panic!("unmatched keys must be an array"),
            },
            MAX_UNMATCHED_KEYS
        );
        assert_eq!(out["unmatched_target_keys_truncated"], boolean(true));
        let human = report.render_human().unwrap();
        assert!(human.contains("... 5 more (use --json)"));
        assert_eq!(human.matches("  VIOLATED      sha256:").count(), 50);
    }

    #[test]
    fn invalid_report_models_return_errors_instead_of_panicking() {
        let (c, s, t) = fixture();
        let ev = evaluate(&c, &s, &t, s.observed_at).unwrap();
        let mut report = OutcomeReport::new(ev);
        report.evaluation.items[0].conditions[0].id = "unknown".into();
        assert_eq!(
            report.condition_summary(),
            Err(ReportError::Key("unknown".into()))
        );
        report.evaluation.items[0].conditions.clear();
        report.evaluation.items[0].status = INCONCLUSIVE.into();
        report.evaluation.items[0].reason = "unknown".into();
        assert_eq!(
            report.render_human(),
            Err(ReportError::Key("unknown".into()))
        );
        let p = Predicate::new("field", "unknown");
        assert_eq!(
            describe_predicate(&p),
            Err(ReportError::Key("unknown".into()))
        );
        let p = Predicate::new("field", "present");
        assert_eq!(
            describe_predicate(&p).unwrap(),
            "field is present and non-empty"
        );
        assert_eq!(report.exit_code(), 0); // evaluation outcome stays independent of manually altered items
    }
}
