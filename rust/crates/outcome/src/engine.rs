//! Outcome reconciliation values and comparisons (REC-01..08, RULE-01..08).
//!
//! Port of pinned engine.py lines 1..834. Evaluation time is always supplied.
//! Reconciliation uses supplied typed observations. Unicode behavior is frozen
//! to CPython 3.11.9 / Unicode 14.0.0.
use crate::contract::{repr_list, Condition, Contract, Integer, Json, Mapping, Predicate, Scalar};
use crate::snapshot::{format_instant, parse_instant_str, Instant, Record, Snapshot, Value};
use codec::canonical_codec::{CanonicalCodec, PurePythonCanonicalCodec, Value as CodecValue};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const VERIFIED: &str = "VERIFIED";
pub const VIOLATED: &str = "VIOLATED";
pub const PENDING: &str = "PENDING";
pub const INCONCLUSIVE: &str = "INCONCLUSIVE";
pub const NOT_APPLICABLE: &str = "NOT_APPLICABLE";
pub const NOT_EVALUATED: &str = "NOT_EVALUATED";
pub const STATUSES: &[&str] = &[
    VERIFIED,
    VIOLATED,
    PENDING,
    INCONCLUSIVE,
    NOT_APPLICABLE,
    NOT_EVALUATED,
];
const PRIORITY: &[&str] = &[
    VIOLATED,
    INCONCLUSIVE,
    PENDING,
    VERIFIED,
    NOT_EVALUATED,
    NOT_APPLICABLE,
];
pub const MAX_UNMATCHED_KEYS: usize = 1000;
pub const REASONS: &[(&str, &str)] = &[
    ("present", "a matching target record was observed"),
    ("count_within", "the matched record count is within bounds in a complete snapshot"),
    ("missing", "no matching target record in a complete snapshot observed at or after the deadline"),
    ("too_few", "fewer matching records than required in a complete snapshot observed at or after the deadline"),
    ("too_many", "more matching records than allowed in a complete snapshot"),
    ("duplicates_unconfirmed", "more matching records than allowed were seen, but the snapshot is not declared complete, so paging artifacts cannot be excluded"),
    ("upper_bound_unproven", "enough records were seen, but only a complete snapshot can show there are no extra ones"),
    ("awaiting_due", "the deadline has not passed at the evaluation instant"),
    ("due_unknown", "the source event time is absent or has no UTC offset, so the deadline is unknown"),
    ("target_unavailable", "the target observation is marked unavailable"),
    ("target_incomplete", "the target snapshot is not declared complete, so absence cannot be proven"),
    ("target_stale", "the target snapshot was observed before the deadline"),
    ("target_observed_at_unknown", "the target snapshot has no observation time"),
    ("target_unkeyed_rows", "some target rows have no usable key, so a missing record may be hidden behind a broken mapping"),
    ("no_target_record", "no matched target record to inspect"),
    ("field_not_in_snapshot", "the field does not occur anywhere in the snapshot (mapping changed?)"),
    ("field_present", "the field holds an accepted value"),
    ("field_absent", "the field is absent from the matched record"),
    ("field_null", "the field is null"),
    ("field_empty", "the field is an empty string"),
    ("value_absent", "the optional value is absent or null; pair with a required condition to demand it"),
    ("value_nested", "the value is nested and cannot be compared"),
    ("type_ok", "the value has the declared kind"),
    ("type_mismatch", "the value does not have the declared kind"),
    ("value_allowed", "the value is in the allowed set"),
    ("value_not_allowed", "the value is not in the allowed set"),
    ("in_range", "the value is within the declared bounds"),
    ("out_of_range", "the value is outside the declared bounds"),
    ("not_a_number", "the value is not a number"),
    ("values_match", "source and target values match after the declared normalization"),
    ("values_differ", "source and target values differ after the declared normalization"),
    ("source_value_absent", "the source value is absent, null or nested"),
    ("target_value_absent", "the target value is absent or null"),
    ("route_not_applicable", "the route predicate is false for this item"),
    ("route_undecidable", "a route predicate field is absent or not comparable"),
    ("route_ok", "the record is on the declared route"),
    ("wrong_route", "the record exists but is not on the declared route"),
    ("completed_on_time", "the target completion time is at or before the deadline"),
    ("late", "the target completion time is after the deadline"),
    ("late_unconfirmed", "the visible completion is late, but an earlier record may be missing from an incomplete snapshot"),
    ("not_completed_by_deadline", "no matching record in a complete snapshot observed at or after the deadline"),
    ("completion_time_unusable", "the target completion time is absent or has no UTC offset"),
    ("observed_on_time", "the record was visible in a snapshot taken at or before the deadline"),
    ("first_seen_after_deadline", "the record was first supplied in a snapshot taken after the deadline; earlier visibility is unknown"),
    ("disabled", "the condition is disabled in the contract"),
    ("any_branch_verified", "at least one branch is verified"),
    ("all_branches_violated", "every applicable branch is violated"),
    ("branches_undecided", "no branch is verified and at least one could not be decided"),
    ("branches_pending", "no branch is verified and at least one is still within its deadline"),
    ("branches_not_applicable", "no branch applies to this item"),
    ("conditions_verified", "every decisive condition is verified"),
    ("condition_violated", "at least one decisive condition is violated"),
    ("condition_inconclusive", "at least one decisive condition could not be decided"),
    ("condition_pending", "at least one decisive condition is still within its deadline"),
    ("conditions_not_applicable", "no decisive condition applies to this item"),
    ("conditions_not_evaluated", "no decisive condition could be evaluated"),
    ("conditions_partly_evaluated", "the evaluated conditions are verified, but at least one decisive condition could not be evaluated"),
    ("key_missing", "the source record has no value for a key field"),
    ("key_invalid", "a key value is not a non-empty string or integer"),
    ("source_conflict", "source rows sharing this key disagree on contract-relevant fields"),
    ("not_eligible", "an eligibility predicate is false; excluded by the contract"),
    ("eligibility_undecidable", "an eligibility field is absent or not comparable"),
    ("source_unavailable", "the source observation is marked unavailable"),
    ("source_coverage_unproven", "the source snapshot is not declared complete, so items it does not list were not evaluated"),
    ("source_key_field_absent", "a source key field occurs nowhere in the source snapshot"),
    ("target_key_field_absent", "a target key field occurs nowhere in the target snapshot"),
    ("no_source_items", "the source snapshot lists no work items"),
    ("some_items_violated", "at least one item is violated"),
    ("some_items_inconclusive", "at least one item could not be decided"),
    ("some_items_pending", "at least one item is still within its deadline"),
    ("all_items_verified", "every applicable item is verified"),
    ("all_items_not_applicable", "every item is excluded by eligibility"),
    ("items_not_evaluated", "no item could be evaluated"),
    ("some_items_not_evaluated", "the other items are verified, but at least one item could not be evaluated"),
];
pub const LIMITATIONS: &[&str] = &[
    "Verdicts cover only the supplied snapshots at their observation times; they do not prove who or what produced a record, exactly-once effects, or semantic correctness.",
    "Absence is proven only from a target snapshot declared complete and observed at or after the deadline; a session that looks clean is not evidence of a correct outcome.",
    "Keys are compared exactly, without trimming, case folding or numeric conversion.",
];
pub const HASHED_KEY_LIMITATION: &str =
    "Hashed keys are pseudonymous, not anonymous: small key spaces can be enumerated.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationError(pub String);
impl fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for EvaluationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperError {
    Key(String),
    Formatting,
    InvalidCondition(&'static str),
    NumericBound,
    InvalidGroup,
}
impl fmt::Display for HelperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(key) => {
                // The existing helper owns Python Unicode repr. Strip only its
                // literal list brackets to obtain the single KeyError argument.
                let repr = repr_list([key.as_str()]);
                f.write_str(&repr[1..repr.len() - 1])
            }
            Self::InvalidCondition(field) => write!(f, "condition requires {field}"),
            Self::NumericBound => f.write_str("condition bound cannot be converted to an integer"),
            Self::InvalidGroup => f.write_str("source group has no records"),
            Self::Formatting => f.write_str("numeric comparison text could not be formatted"),
        }
    }
}
impl std::error::Error for HelperError {}

#[derive(Debug, Clone, PartialEq)]
pub struct ConditionResult {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub reason: String,
    pub advisory: bool,
    pub detail: Mapping,
    pub branches: Vec<ConditionResult>,
}
impl ConditionResult {
    pub fn new(
        id: impl Into<String>,
        kind: impl Into<String>,
        status: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            status: status.into(),
            reason: reason.into(),
            advisory: false,
            detail: Mapping::new(),
            branches: Vec::new(),
        }
    }
    pub fn to_dict(&self) -> Mapping {
        let mut out: Mapping = [
            ("id", &self.id),
            ("type", &self.kind),
            ("status", &self.status),
            ("reason", &self.reason),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), Json::Scalar(Scalar::String(v.clone()))))
        .collect();
        out.insert("advisory".into(), Json::Scalar(Scalar::Bool(self.advisory)));
        if !self.detail.is_empty() {
            out.insert("detail".into(), Json::Object(self.detail.clone()));
        }
        if !self.branches.is_empty() {
            out.insert(
                "branches".into(),
                Json::Array(
                    self.branches
                        .iter()
                        .map(|b| Json::Object(b.to_dict()))
                        .collect(),
                ),
            );
        }
        out
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct ItemResult {
    pub key: Option<Vec<String>>,
    pub source_row: usize,
    pub source_rows: usize,
    pub status: String,
    pub reason: String,
    pub deadline: Option<Instant>,
    pub matched_records: usize,
    pub conditions: Vec<ConditionResult>,
    pub detail: Mapping,
}
/// Borrow observations without duplicating potentially large record collections.
#[derive(Debug, Clone, PartialEq)]
pub struct Evaluation<'a> {
    pub contract: &'a Contract,
    pub source: &'a Snapshot,
    pub target: &'a Snapshot,
    pub as_of: Instant,
    pub outcome: String,
    pub outcome_reasons: Vec<String>,
    pub items: Vec<ItemResult>,
    pub coverage: Mapping,
    pub unmatched_target_keys: Vec<Vec<String>>,
}
pub fn worst<'a>(
    statuses: impl IntoIterator<Item = &'a str>,
) -> Result<Option<&'a str>, HelperError> {
    let mut result = None;
    let mut rank = usize::MAX;
    for status in statuses {
        let current = PRIORITY
            .iter()
            .position(|s| *s == status)
            .ok_or_else(|| HelperError::Key(status.into()))?;
        if current < rank {
            rank = current;
            result = Some(status);
        }
    }
    Ok(result)
}

pub fn text(value: &Value) -> Result<Option<String>, HelperError> {
    Ok(Some(match value {
        Value::NonScalar(_) | Value::Scalar(Scalar::Null) => return Ok(None),
        Value::Scalar(Scalar::Bool(v)) => if *v { "true" } else { "false" }.into(),
        Value::Scalar(Scalar::String(v)) => v.clone(),
        Value::Scalar(Scalar::Int(v)) => v.decimal().into(),
        Value::Scalar(Scalar::Float(v)) => {
            if v.fract() == 0.0 && v.abs() < 9_223_372_036_854_775_808.0 {
                (*v as i64).to_string()
            } else if v.is_nan() {
                "nan".into()
            } else if *v == f64::INFINITY {
                "inf".into()
            } else if *v == f64::NEG_INFINITY {
                "-inf".into()
            } else {
                let bytes = PurePythonCanonicalCodec
                    .canonical_json_bytes(&CodecValue::float(*v), false)
                    .map_err(|_| HelperError::Formatting)?;
                String::from_utf8(bytes).map_err(|_| HelperError::Formatting)?
            }
        }
    }))
}
fn python_space(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}
pub fn normalized(value: &Value, steps: &[String]) -> Result<Option<String>, HelperError> {
    let Some(mut text) = text(value)? else {
        return Ok(None);
    };
    if steps.iter().any(|s| s == "trim") {
        text = text.trim_matches(python_space).into();
    }
    if steps.iter().any(|s| s == "casefold") {
        text = casefold(&text);
    }
    Ok(Some(text))
}

/// Preserve Python integers exactly, even beyond binary64's range/precision.
#[derive(Debug, Clone)]
pub enum Number {
    Int(Integer),
    Float(f64),
}
fn decimal_cmp(a: &str, b: &str) -> Ordering {
    let an = a.starts_with('-');
    let bn = b.starts_with('-');
    if an != bn {
        return if an {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let a = a.strip_prefix('-').unwrap_or(a);
    let b = b.strip_prefix('-').unwrap_or(b);
    let cmp = a.len().cmp(&b.len()).then_with(|| a.cmp(b));
    if an {
        cmp.reverse()
    } else {
        cmp
    }
}
fn int_float_cmp(a: &Integer, b: f64) -> Option<Ordering> {
    if b.is_nan() {
        return None;
    }
    if b == f64::INFINITY {
        return Some(Ordering::Less);
    }
    if b == f64::NEG_INFINITY {
        return Some(Ordering::Greater);
    }
    let integral = if b.trunc() == 0.0 {
        "0".into()
    } else {
        format!("{:.0}", b.trunc())
    };
    let cmp = decimal_cmp(a.decimal(), &integral);
    Some(if cmp == Ordering::Equal && b.fract() != 0.0 {
        if b > 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    } else {
        cmp
    })
}
impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}
impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Int(a), Self::Int(b)) => Some(decimal_cmp(a.decimal(), b.decimal())),
            (Self::Float(a), Self::Float(b)) => a.partial_cmp(b),
            (Self::Int(a), Self::Float(b)) => int_float_cmp(a, *b),
            (Self::Float(a), Self::Int(b)) => int_float_cmp(b, *a).map(Ordering::reverse),
        }
    }
}
fn decimal_digit(c: char) -> Option<u8> {
    let n = c as u32;
    let i = DECIMAL_STARTS
        .partition_point(|start| *start <= n)
        .checked_sub(1)?;
    let offset = n - DECIMAL_STARTS[i];
    (offset < 10).then_some(offset as u8)
}
/// Match Python's Unicode-decimal regex and its single-final-newline `$` anchor.
fn numeric_text(value: &str, integer_only: bool) -> Option<String> {
    let value = value.strip_suffix('\n').unwrap_or(value);
    let mut ascii = String::with_capacity(value.len());
    for c in value.chars() {
        if let Some(n) = decimal_digit(c) {
            ascii.push(char::from(b'0' + n));
        } else if matches!(c, '+' | '-' | '.' | 'e' | 'E') {
            ascii.push(c);
        } else {
            return None;
        }
    }
    let b = ascii.as_bytes();
    let mut p = usize::from(matches!(b.first(), Some(b'+' | b'-')));
    let start = p;
    while b.get(p).is_some_and(u8::is_ascii_digit) {
        p += 1;
    }
    let before = p - start;
    if integer_only {
        return (before > 0 && p == b.len()).then_some(ascii);
    }
    let mut after = 0;
    if b.get(p) == Some(&b'.') {
        p += 1;
        let start = p;
        while b.get(p).is_some_and(u8::is_ascii_digit) {
            p += 1;
        }
        after = p - start;
    }
    if before + after == 0 {
        return None;
    }
    if matches!(b.get(p), Some(b'e' | b'E')) {
        p += 1;
        if matches!(b.get(p), Some(b'+' | b'-')) {
            p += 1;
        }
        let start = p;
        while b.get(p).is_some_and(u8::is_ascii_digit) {
            p += 1;
        }
        if p == start {
            return None;
        }
    }
    (p == b.len()).then_some(ascii)
}
pub fn number(value: &Value, typed: bool) -> Option<Number> {
    let n = match value {
        Value::Scalar(Scalar::Int(v)) => return Some(Number::Int(v.clone())),
        Value::Scalar(Scalar::Float(v)) => *v,
        Value::Scalar(Scalar::String(v)) if !typed => {
            numeric_text(v, false)?.parse::<f64>().ok()?
        }
        _ => return None,
    };
    n.is_finite().then_some(Number::Float(n))
}
#[derive(Debug, Clone, Copy)]
pub struct ComparisonContext {
    pub source_typed: bool,
    pub target_typed: bool,
}
pub fn equal(
    source: &Value,
    target: &Value,
    steps: &[String],
    ctx: ComparisonContext,
) -> Result<bool, HelperError> {
    if [source, target]
        .iter()
        .any(|v| matches!(v, Value::Scalar(Scalar::Int(_) | Scalar::Float(_))))
    {
        if let (Some(a), Some(b)) = (
            number(source, ctx.source_typed),
            number(target, ctx.target_typed),
        ) {
            return Ok(a == b);
        }
    }
    Ok(normalized(source, steps)? == normalized(target, steps)?)
}
pub fn kind_ok(value: &Value, kind: &str, typed: bool) -> bool {
    match kind {
        "string" => matches!(value, Value::Scalar(Scalar::String(_))),
        "integer" => match value {
            Value::Scalar(Scalar::Int(_)) => true,
            Value::Scalar(Scalar::String(v)) if !typed => numeric_text(v, true).is_some(),
            _ => false,
        },
        "number" => number(value, typed).is_some(),
        "boolean" => {
            matches!(value, Value::Scalar(Scalar::Bool(_)))
                || (!typed
                    && matches!(value,Value::Scalar(Scalar::String(v)) if v=="true" || v=="false"))
        }
        "date-time" => {
            matches!(value,Value::Scalar(Scalar::String(v)) if parse_instant_str(v).is_some())
        }
        _ => false,
    }
}
pub fn predicate(
    pred: &Predicate,
    record: &Record,
    typed: bool,
) -> Result<Option<bool>, HelperError> {
    if pred.op == "present" || pred.op == "absent" {
        let present = record.get(&pred.field).is_some_and(|v| {
            !matches!(v, Value::Scalar(Scalar::Null))
                && !matches!(v,Value::Scalar(Scalar::String(v)) if v.is_empty())
        });
        return Ok(Some(if pred.op == "present" {
            present
        } else {
            !present
        }));
    }
    let Some(value) = record.get(&pred.field) else {
        return Ok(None);
    };
    if matches!(value, Value::NonScalar(_)) {
        return Ok(None);
    }
    if ["eq", "ne", "in", "not_in"].contains(&pred.op.as_str()) {
        let wanted = if pred.op == "in" || pred.op == "not_in" {
            pred.values.as_slice()
        } else {
            std::slice::from_ref(&pred.value)
        };
        let actual = text(value)?;
        let mut matched = false;
        // Evaluate every wanted text, as Python constructs the complete set.
        for w in wanted {
            if text(&Value::Scalar(w.clone()))? == actual {
                matched = true;
            }
        }
        return Ok(Some(if pred.op == "eq" || pred.op == "in" {
            matched
        } else {
            !matched
        }));
    }
    let Some(number) = number(value, typed) else {
        return Ok(None);
    };
    let bound = match &pred.value {
        Scalar::Int(i) => Number::Int(i.clone()),
        Scalar::Float(v) => Number::Float(*v),
        Scalar::Bool(v) => Number::Int(Integer::from(i64::from(*v))),
        _ => return Ok(None),
    };
    Ok(Some(match pred.op.as_str() {
        "gt" => number > bound,
        "gte" => number >= bound,
        "lt" => number < bound,
        "lte" => number <= bound,
        _ => return Err(HelperError::Key(pred.op.clone())),
    }))
}

/// Conjunction keeps the first unknown unless a later false decides the result.
pub fn all_predicates(
    preds: &[Predicate],
    record: &Record,
    typed: bool,
) -> Result<(Option<bool>, Option<usize>), HelperError> {
    let mut unknown = None;
    for (index, pred) in preds.iter().enumerate() {
        match predicate(pred, record, typed)? {
            Some(false) => return Ok((Some(false), Some(index))),
            None if unknown.is_none() => unknown = Some(index),
            _ => (),
        }
    }
    Ok(if unknown.is_some() {
        (None, unknown)
    } else {
        (Some(true), None)
    })
}

/// Key text is exact: integers and strings only, with no trimming/coercion.
pub fn key(record: &Record, fields: &[String]) -> (Option<Vec<String>>, Option<&'static str>) {
    let mut parts = Vec::with_capacity(fields.len());
    for field in fields {
        let part = match record.get(field) {
            None | Some(Value::Scalar(Scalar::Null)) => return (None, Some("key_missing")),
            Some(Value::Scalar(Scalar::String(s))) if s.is_empty() => {
                return (None, Some("key_missing"))
            }
            Some(Value::Scalar(Scalar::String(s))) => s.clone(),
            Some(Value::Scalar(Scalar::Int(i))) => i.decimal().into(),
            _ => return (None, Some("key_invalid")),
        };
        parts.push(part);
    }
    (Some(parts), None)
}

/// Per-evaluation cache; keys intentionally follow Python condition ids.
pub struct Context<'a> {
    pub contract: &'a Contract,
    pub target: &'a Snapshot,
    pub as_of: Instant,
    pub unkeyed_target_rows: usize,
    pub source_typed: bool,
    pub target_typed: bool,
    allowed_values: BTreeMap<String, BTreeSet<Option<String>>>,
}
impl<'a> Context<'a> {
    pub fn new(
        contract: &'a Contract,
        target: &'a Snapshot,
        as_of: Instant,
        unkeyed_target_rows: usize,
        source_typed: bool,
        target_typed: bool,
    ) -> Self {
        Self {
            contract,
            target,
            as_of,
            unkeyed_target_rows,
            source_typed,
            target_typed,
            allowed_values: BTreeMap::new(),
        }
    }
    pub fn allowed(&mut self, cond: &Condition) -> Result<&BTreeSet<Option<String>>, HelperError> {
        use std::collections::btree_map::Entry;
        Ok(match self.allowed_values.entry(cond.id.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let values = cond
                    .values
                    .iter()
                    .map(|v| normalized(&Value::Scalar(v.clone()), &cond.normalize))
                    .collect::<Result<_, _>>()?;
                entry.insert(values)
            }
        })
    }
    fn comparison(&self) -> ComparisonContext {
        ComparisonContext {
            source_typed: self.source_typed,
            target_typed: self.target_typed,
        }
    }
}
pub fn absence_blocker(ctx: &Context<'_>, deadline: Option<Instant>) -> Option<&'static str> {
    if ctx.target.completeness != "complete" {
        return Some("target_incomplete");
    }
    let Some(observed) = ctx.target.observed_at else {
        return Some("target_observed_at_unknown");
    };
    if deadline.is_some_and(|d| observed < d) {
        return Some("target_stale");
    }
    if ctx.unkeyed_target_rows != 0 {
        return Some("target_unkeyed_rows");
    }
    None
}
pub fn waiting(
    ctx: &Context<'_>,
    deadline: Option<Instant>,
    due_known: bool,
) -> Option<(&'static str, &'static str)> {
    if ctx.target.completeness == "unavailable" {
        return Some((INCONCLUSIVE, "target_unavailable"));
    }
    if !due_known {
        return Some((INCONCLUSIVE, "due_unknown"));
    }
    if deadline.is_some_and(|d| ctx.as_of < d) {
        return Some((PENDING, "awaiting_due"));
    }
    None
}
pub type CheckResult = (String, String, Mapping);
fn check(status: &str, reason: &str, detail: Mapping) -> CheckResult {
    (status.into(), reason.into(), detail)
}
fn string_detail(key: &str, value: &str) -> Mapping {
    Mapping::from([(key.into(), Json::Scalar(Scalar::String(value.into())))])
}
pub fn per_record(results: &[CheckResult]) -> Result<CheckResult, HelperError> {
    let status = worst(results.iter().map(|r| r.0.as_str()))?.unwrap_or(NOT_EVALUATED);
    Ok(results
        .iter()
        .find(|r| r.0 == status)
        .cloned()
        .unwrap_or_else(|| check(status, "no_target_record", Mapping::new())))
}
pub fn field_check(
    cond: &Condition,
    records: &[Record],
    ctx: &mut Context<'_>,
    source: &Record,
) -> Result<CheckResult, HelperError> {
    let name = cond
        .field
        .as_deref()
        .ok_or(HelperError::InvalidCondition("field"))?;
    let field_detail = || string_detail("field", name);
    if !ctx.target.fields.contains(name) {
        return Ok(check(INCONCLUSIVE, "field_not_in_snapshot", field_detail()));
    }
    let null = Value::Scalar(Scalar::Null);
    let mut results = Vec::with_capacity(records.len());
    for record in records {
        let present = record.contains_key(name);
        let value = record.get(name).unwrap_or(&null);
        let is_null = matches!(value, Value::Scalar(Scalar::Null));
        let (status, reason, detail) = if cond.kind == "required" {
            let (status, reason) = if !present {
                (VIOLATED, "field_absent")
            } else if is_null && !cond.allow_null {
                (VIOLATED, "field_null")
            } else if matches!(value, Value::Scalar(Scalar::String(v)) if v.is_empty())
                && !cond.allow_empty
            {
                (VIOLATED, "field_empty")
            } else {
                (VERIFIED, "field_present")
            };
            (status, reason, field_detail())
        } else if cond.kind == "equals" {
            let source_name = cond
                .source_field
                .as_deref()
                .ok_or(HelperError::InvalidCondition("source_field"))?;
            let source_value = source.get(source_name);
            if source_value.is_none() || text(source_value.unwrap_or(&null))?.is_none() {
                (
                    INCONCLUSIVE,
                    "source_value_absent",
                    string_detail("field", source_name),
                )
            } else if !present || is_null {
                (VIOLATED, "target_value_absent", field_detail())
            } else if matches!(value, Value::NonScalar(_)) {
                (INCONCLUSIVE, "value_nested", field_detail())
            } else if equal(
                source_value.unwrap_or(&null),
                value,
                &cond.normalize,
                ctx.comparison(),
            )? {
                (VERIFIED, "values_match", field_detail())
            } else {
                (VIOLATED, "values_differ", field_detail())
            }
        } else if !present || is_null {
            if cond.kind == "route" {
                (VIOLATED, "wrong_route", field_detail())
            } else {
                (NOT_APPLICABLE, "value_absent", field_detail())
            }
        } else if matches!(value, Value::NonScalar(_)) {
            (INCONCLUSIVE, "value_nested", field_detail())
        } else {
            match cond.kind.as_str() {
                "type" => {
                    let kind = cond
                        .value_kind
                        .as_deref()
                        .ok_or(HelperError::InvalidCondition("kind"))?;
                    let ok = kind_ok(value, kind, ctx.target_typed);
                    (
                        if ok { VERIFIED } else { VIOLATED },
                        if ok { "type_ok" } else { "type_mismatch" },
                        Mapping::new(),
                    )
                }
                "one_of" | "route" => {
                    let actual = normalized(value, &cond.normalize)?;
                    let ok = ctx.allowed(cond)?.contains(&actual);
                    let reason = match (cond.kind.as_str(), ok) {
                        ("one_of", true) => "value_allowed",
                        ("one_of", false) => "value_not_allowed",
                        (_, true) => "route_ok",
                        (_, false) => "wrong_route",
                    };
                    (if ok { VERIFIED } else { VIOLATED }, reason, field_detail())
                }
                "range" => {
                    if let Some(n) = number(value, ctx.target_typed) {
                        let ok = cond.minimum.is_none_or(|v| n >= Number::Float(v))
                            && cond.maximum.is_none_or(|v| n <= Number::Float(v));
                        (
                            if ok { VERIFIED } else { VIOLATED },
                            if ok { "in_range" } else { "out_of_range" },
                            field_detail(),
                        )
                    } else {
                        (VIOLATED, "not_a_number", field_detail())
                    }
                }
                _ => continue,
            }
        };
        results.push(check(status, reason, detail));
    }
    per_record(&results)
}
fn integral_bound(value: f64) -> Result<Integer, HelperError> {
    if !value.is_finite() {
        return Err(HelperError::NumericBound);
    }
    Integer::parse(&format!("{:.0}", value.trunc())).map_err(|_| HelperError::NumericBound)
}
pub fn count_check(
    cond: &Condition,
    matched: usize,
    ctx: &Context<'_>,
    deadline: Option<Instant>,
    due_known: bool,
) -> Result<CheckResult, HelperError> {
    let low = if cond.kind == "exists" {
        Integer::from(1)
    } else {
        integral_bound(cond.minimum.unwrap_or(0.0))?
    };
    let high = if cond.kind == "exists" {
        None
    } else {
        cond.maximum.map(integral_bound).transpose()?
    };
    let actual = Integer::parse(&matched.to_string()).map_err(|_| HelperError::NumericBound)?;
    let mut detail = Mapping::from([(
        "matched_records".into(),
        Json::Scalar(Scalar::Int(actual.clone())),
    )]);
    if let Some(high) = &high {
        detail.insert("max".into(), Json::Scalar(Scalar::Int(high.clone())));
    }
    if cond.kind == "count" {
        detail.insert("min".into(), Json::Scalar(Scalar::Int(low.clone())));
    }
    let complete = ctx.target.completeness == "complete";
    if high
        .as_ref()
        .is_some_and(|h| decimal_cmp(actual.decimal(), h.decimal()) == Ordering::Greater)
    {
        return Ok(if complete {
            check(VIOLATED, "too_many", detail)
        } else {
            check(INCONCLUSIVE, "duplicates_unconfirmed", detail)
        });
    }
    let minimum = if decimal_cmp(low.decimal(), "1") == Ordering::Less {
        "1"
    } else {
        low.decimal()
    };
    if decimal_cmp(actual.decimal(), minimum) != Ordering::Less
        || (low.decimal() == "0" && matched == 0 && high.is_some())
    {
        return Ok(if high.is_none() {
            check(VERIFIED, "present", detail)
        } else if complete {
            check(VERIFIED, "count_within", detail)
        } else {
            check(INCONCLUSIVE, "upper_bound_unproven", detail)
        });
    }
    if let Some((s, r)) = waiting(ctx, deadline, due_known) {
        return Ok(check(s, r, detail));
    }
    if let Some(r) = absence_blocker(ctx, deadline) {
        return Ok(check(INCONCLUSIVE, r, detail));
    }
    Ok(check(
        VIOLATED,
        if matched == 0 { "missing" } else { "too_few" },
        detail,
    ))
}
/// int(timedelta.total_seconds()) for a positive difference of valid Instants.
/// Python divides the exact integer microseconds, rounding only the quotient.
/// Integer seconds fit exactly in binary64 throughout years 1..9999. Rounding
/// can change their truncation only at the midpoint below the next integer.
/// That integer has an even significand; ties round upward. Its predecessor
/// gap times 500000 is an exact dyadic value, so the comparison loses no bits.
fn positive_total_seconds_integer(microseconds: i64) -> i64 {
    let whole = microseconds / 1_000_000;
    let remainder = microseconds % 1_000_000;
    if remainder == 0 {
        return whole;
    }
    let next = (whole + 1) as f64;
    let predecessor = f64::from_bits(next.to_bits() - 1);
    let half_gap_microseconds = (next - predecessor) * 500_000.0;
    if (1_000_000 - remainder) as f64 <= half_gap_microseconds {
        whole + 1
    } else {
        whole
    }
}

pub fn on_time_check(
    cond: &Condition,
    records: &[Record],
    ctx: &Context<'_>,
    deadline: Option<Instant>,
    due_known: bool,
) -> Result<CheckResult, HelperError> {
    if ctx.target.completeness == "unavailable" {
        return Ok(check(INCONCLUSIVE, "target_unavailable", Mapping::new()));
    }
    let deadline = match deadline {
        Some(d) if due_known => d,
        _ => return Ok(check(INCONCLUSIVE, "due_unknown", Mapping::new())),
    };
    let formatted = format_instant(Some(deadline)).ok_or(HelperError::Formatting)?;
    let mut detail = string_detail("deadline", &formatted);
    detail.insert(
        "basis".into(),
        cond.basis.as_ref().map_or(Json::Scalar(Scalar::Null), |b| {
            Json::Scalar(Scalar::String(b.clone()))
        }),
    );
    if !records.is_empty() {
        if cond.basis.as_deref() == Some("observation") {
            return Ok(match ctx.target.observed_at {
                None => check(INCONCLUSIVE, "target_observed_at_unknown", detail),
                Some(t) if t <= deadline => check(VERIFIED, "observed_on_time", detail),
                _ => check(INCONCLUSIVE, "first_seen_after_deadline", detail),
            });
        }
        let field = cond
            .field
            .as_deref()
            .ok_or(HelperError::InvalidCondition("field"))?;
        if !ctx.target.fields.contains(field) {
            detail.extend(string_detail("field", field));
            return Ok(check(INCONCLUSIVE, "field_not_in_snapshot", detail));
        }
        let valid: Vec<_> = records
            .iter()
            .filter_map(|r| match r.get(field) {
                Some(Value::Scalar(Scalar::String(t))) => parse_instant_str(t),
                _ => None,
            })
            .collect();
        let earliest = valid.iter().min().copied();
        if earliest.is_some_and(|t| t <= deadline) {
            return Ok(check(VERIFIED, "completed_on_time", detail));
        }
        let earliest = match earliest {
            Some(t) if valid.len() == records.len() => t,
            _ => return Ok(check(INCONCLUSIVE, "completion_time_unusable", detail)),
        };
        let late =
            positive_total_seconds_integer(earliest.microseconds() - deadline.microseconds());
        detail.insert(
            "late_by_seconds".into(),
            Json::Scalar(Scalar::Int(Integer::from(late))),
        );
        return Ok(if ctx.target.completeness == "complete" {
            check(VIOLATED, "late", detail)
        } else {
            check(INCONCLUSIVE, "late_unconfirmed", detail)
        });
    }
    if let Some((s, r)) = waiting(ctx, Some(deadline), due_known) {
        return Ok(check(s, r, detail));
    }
    if let Some(r) = absence_blocker(ctx, Some(deadline)) {
        return Ok(check(INCONCLUSIVE, r, detail));
    }
    Ok(check(VIOLATED, "not_completed_by_deadline", detail))
}
pub fn evaluate_condition(
    cond: &Condition,
    source: &Record,
    records: &[Record],
    ctx: &mut Context<'_>,
    deadline: Option<Instant>,
    due_known: bool,
) -> Result<ConditionResult, HelperError> {
    let done = |(s, r, detail): CheckResult| {
        let mut result = ConditionResult::new(&cond.id, &cond.kind, s, r);
        result.advisory = cond.advisory;
        result.detail = detail;
        result
    };
    if cond.disabled.is_some() {
        return Ok(done(check(NOT_EVALUATED, "disabled", Mapping::new())));
    }
    if cond.kind == "exists" || cond.kind == "count" {
        return count_check(cond, records.len(), ctx, deadline, due_known).map(done);
    }
    if cond.kind == "on_time" {
        return on_time_check(cond, records, ctx, deadline, due_known).map(done);
    }
    if cond.kind == "any_of" {
        let branches = cond
            .conditions
            .iter()
            .map(|c| evaluate_condition(c, source, records, ctx, deadline, due_known))
            .collect::<Result<Vec<_>, _>>()?;
        let (status, reason) = [
            (VERIFIED, "any_branch_verified"),
            (INCONCLUSIVE, "branches_undecided"),
            (PENDING, "branches_pending"),
            (VIOLATED, "all_branches_violated"),
            (NOT_EVALUATED, "no_target_record"),
        ]
        .into_iter()
        .find(|(s, _)| branches.iter().any(|b| b.status == *s))
        .unwrap_or((NOT_APPLICABLE, "branches_not_applicable"));
        let mut result = done(check(status, reason, Mapping::new()));
        result.branches = branches;
        return Ok(result);
    }
    if cond.kind == "route" {
        match all_predicates(&cond.when, source, ctx.source_typed)? {
            (Some(false), _) => {
                return Ok(done(check(
                    NOT_APPLICABLE,
                    "route_not_applicable",
                    Mapping::new(),
                )))
            }
            (None, Some(i)) => {
                let pred = cond
                    .when
                    .get(i)
                    .ok_or(HelperError::InvalidCondition("when"))?;
                return Ok(done(check(
                    INCONCLUSIVE,
                    "route_undecidable",
                    string_detail("field", &pred.field),
                )));
            }
            _ => (),
        }
    }
    if records.is_empty() {
        let (status, reason) =
            waiting(ctx, deadline, due_known).unwrap_or((NOT_EVALUATED, "no_target_record"));
        return Ok(done(check(status, reason, Mapping::new())));
    }
    if ctx.target.completeness == "unavailable" {
        return Ok(done(check(
            INCONCLUSIVE,
            "target_unavailable",
            Mapping::new(),
        )));
    }
    field_check(cond, records, ctx, source).map(done)
}
pub fn item_verdict(results: &[ConditionResult]) -> Result<(String, String), HelperError> {
    let decisive: Vec<_> = results
        .iter()
        .filter(|r| !r.advisory && r.reason != "disabled")
        .map(|r| r.status.as_str())
        .collect();
    let status = worst(decisive.iter().copied())?.unwrap_or(NOT_EVALUATED);
    if status == VERIFIED && decisive.contains(&NOT_EVALUATED) {
        return Ok((INCONCLUSIVE.into(), "conditions_partly_evaluated".into()));
    }
    let reason = match status {
        VIOLATED => "condition_violated",
        INCONCLUSIVE => "condition_inconclusive",
        PENDING => "condition_pending",
        VERIFIED => "conditions_verified",
        NOT_EVALUATED => "conditions_not_evaluated",
        NOT_APPLICABLE => "conditions_not_applicable",
        _ => return Err(HelperError::Key(status.into())),
    };
    Ok((status.into(), reason.into()))
}
/// Rows borrow the supplied source snapshot, retaining first occurrence order.
pub struct Group<'a> {
    pub key: Vec<String>,
    pub first_row: usize,
    pub rows: Vec<&'a Record>,
}

/// Compare only relevant fields, retaining missing/null/nested distinctions.
pub fn conflicting(rows: &[&Record], fields: &BTreeSet<String>) -> Result<bool, HelperError> {
    let (first, rest) = rows.split_first().ok_or(HelperError::InvalidGroup)?;
    let null = Value::Scalar(Scalar::Null);
    for row in rest {
        for name in fields {
            let a = first.get(name);
            let b = row.get(name);
            if a.is_some() != b.is_some()
                || text(a.unwrap_or(&null))? != text(b.unwrap_or(&null))?
                || matches!(a, Some(Value::NonScalar(_))) != matches!(b, Some(Value::NonScalar(_)))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn count_json(count: usize) -> Result<Json, HelperError> {
    Ok(Json::Scalar(Scalar::Int(
        Integer::parse(&count.to_string()).map_err(|_| HelperError::NumericBound)?,
    )))
}

pub fn evaluate_item(
    contract: &Contract,
    ctx: &mut Context<'_>,
    key: &[String],
    group: &Group<'_>,
    matched: &[Record],
    relevant: &BTreeSet<String>,
) -> Result<ItemResult, HelperError> {
    let mut item = ItemResult {
        key: Some(key.to_vec()),
        source_row: group.first_row,
        source_rows: group.rows.len(),
        status: INCONCLUSIVE.into(),
        reason: "source_conflict".into(),
        deadline: None,
        matched_records: matched.len(),
        conditions: Vec::new(),
        detail: Mapping::new(),
    };
    if group.rows.len() > 1 && conflicting(&group.rows, relevant)? {
        return Ok(item);
    }
    let record = group.rows.first().ok_or(HelperError::InvalidGroup)?;
    let (eligible, pred_index) = all_predicates(&contract.eligibility, record, ctx.source_typed)?;
    if eligible != Some(true) {
        let index = pred_index.ok_or(HelperError::InvalidCondition("eligibility predicate"))?;
        let pred = contract
            .eligibility
            .get(index)
            .ok_or(HelperError::InvalidCondition("eligibility predicate"))?;
        item.detail = string_detail("field", &pred.field);
        item.detail.insert("predicate".into(), count_json(index)?);
        (item.status, item.reason) = if eligible == Some(false) {
            (NOT_APPLICABLE.into(), "not_eligible".into())
        } else {
            (INCONCLUSIVE.into(), "eligibility_undecidable".into())
        };
        return Ok(item);
    }
    let mut due_known = true;
    if let Some(due) = &contract.due {
        let started = match record.get(&due.source_time_field) {
            Some(Value::Scalar(Scalar::String(s))) => parse_instant_str(s),
            _ => None,
        };
        item.deadline = started.and_then(|started| {
            let delta = i64::try_from(due.within_seconds)
                .ok()?
                .checked_mul(1_000_000)?;
            Instant::from_microseconds(started.microseconds().checked_add(delta)?)
        });
        due_known = item.deadline.is_some();
    }
    item.conditions = contract
        .conditions
        .iter()
        .map(|cond| evaluate_condition(cond, record, matched, ctx, item.deadline, due_known))
        .collect::<Result<_, _>>()?;
    (item.status, item.reason) = item_verdict(&item.conditions)?;
    Ok(item)
}

/// Reconcile one pair of observations. None represents a missing/naive instant;
/// a valid Instant is already aware and normalized to UTC by the snapshot layer.
pub fn evaluate<'a>(
    contract: &'a Contract,
    source: &'a Snapshot,
    target: &'a Snapshot,
    as_of: Option<Instant>,
) -> Result<Evaluation<'a>, EvaluationError> {
    let as_of =
        as_of.ok_or_else(|| EvaluationError("the evaluation instant needs a UTC offset".into()))?;
    for snap in [source, target] {
        if snap.observed_at.is_some_and(|time| time > as_of) {
            return Err(EvaluationError(format!(
                "the evaluation instant precedes the {} observation time",
                snap.role
            )));
        }
    }
    reconcile(contract, source, target, as_of).map_err(|e| EvaluationError(e.to_string()))
}

fn reconcile<'a>(
    contract: &'a Contract,
    source: &'a Snapshot,
    target: &'a Snapshot,
    as_of: Instant,
) -> Result<Evaluation<'a>, HelperError> {
    let mut issues = BTreeSet::new();
    for (snap, fields, issue) in [
        (source, &contract.source_key, "source_key_field_absent"),
        (target, &contract.target_key, "target_key_field_absent"),
    ] {
        if !snap.records.is_empty() && fields.iter().any(|name| !snap.fields.contains(name)) {
            issues.insert(issue.to_owned());
        }
    }
    let mut index: BTreeMap<Vec<String>, Vec<&Record>> = BTreeMap::new();
    let mut unkeyed_target = 0;
    for record in &target.records {
        if let (Some(key), _) = key(record, &contract.target_key) {
            index.entry(key).or_default().push(record);
        } else {
            unkeyed_target += 1;
        }
    }
    // Preserve Python dict insertion order for evaluation/cache side effects;
    // only the final public item list is lexically sorted.
    let mut groups: Vec<Group<'_>> = Vec::new();
    let mut group_index: BTreeMap<Vec<String>, usize> = BTreeMap::new();
    let mut items = Vec::new();
    for (i, record) in source.records.iter().enumerate() {
        let (key, problem) = key(record, &contract.source_key);
        let Some(key) = key else {
            items.push(ItemResult {
                key: None,
                source_row: i + 1,
                source_rows: 1,
                status: INCONCLUSIVE.into(),
                reason: problem.unwrap_or("key_missing").into(),
                deadline: None,
                matched_records: 0,
                conditions: Vec::new(),
                detail: Mapping::new(),
            });
            continue;
        };
        if let Some(&position) = group_index.get(&key) {
            groups[position].rows.push(record);
        } else {
            group_index.insert(key.clone(), groups.len());
            groups.push(Group {
                key,
                first_row: i + 1,
                rows: vec![record],
            });
        }
    }
    let mut ctx = Context::new(
        contract,
        target,
        as_of,
        unkeyed_target,
        source.input_format != "csv",
        target.input_format != "csv",
    );
    let relevant = contract.relevant_source_fields();
    for group in &groups {
        // Existing condition APIs consume &[Record]. Clone only this group's
        // matching rows, not the entire target observation per source group.
        let matched: Vec<_> = index
            .get(&group.key)
            .into_iter()
            .flatten()
            .map(|row| (*row).clone())
            .collect();
        items.push(evaluate_item(
            contract, &mut ctx, &group.key, group, &matched, &relevant,
        )?);
    }
    let unmatched: Vec<_> = index
        .keys()
        .filter(|key| !group_index.contains_key(*key))
        .cloned()
        .collect();
    items.sort_by(|a, b| {
        (a.key.is_none(), &a.key, a.source_row).cmp(&(b.key.is_none(), &b.key, b.source_row))
    });
    let statuses: Vec<_> = items.iter().map(|i| i.status.as_str()).collect();
    let mut outcome_reasons: Vec<_> = issues.iter().cloned().collect();
    let mut outcome;
    if source.completeness == "unavailable" {
        outcome = INCONCLUSIVE;
        outcome_reasons.insert(0, "source_unavailable".into());
    } else if items.is_empty() {
        outcome = NOT_EVALUATED;
        outcome_reasons.insert(0, "no_source_items".into());
    } else {
        outcome = worst(statuses.iter().copied())?.unwrap_or(NOT_EVALUATED);
        let reason = match outcome {
            VIOLATED => "some_items_violated",
            INCONCLUSIVE => "some_items_inconclusive",
            PENDING => "some_items_pending",
            VERIFIED => "all_items_verified",
            NOT_EVALUATED => "items_not_evaluated",
            NOT_APPLICABLE => "all_items_not_applicable",
            _ => return Err(HelperError::Key(outcome.into())),
        };
        outcome_reasons.insert(0, reason.into());
        if outcome == VERIFIED && statuses.contains(&NOT_EVALUATED) {
            outcome = INCONCLUSIVE;
            outcome_reasons[0] = "some_items_not_evaluated".into();
        }
        if source.completeness != "complete" {
            outcome_reasons.push("source_coverage_unproven".into());
            if outcome == VERIFIED {
                outcome = INCONCLUSIVE;
            }
        }
        if !issues.is_empty() && outcome == VERIFIED {
            outcome = INCONCLUSIVE;
        }
    }
    let counts: Mapping = STATUSES
        .iter()
        .map(|status| {
            Ok((
                (*status).into(),
                count_json(statuses.iter().filter(|s| *s == status).count())?,
            ))
        })
        .collect::<Result<_, HelperError>>()?;
    let mut coverage: Mapping = [
        ("source_rows", source.records.len()),
        ("work_items", items.len()),
        (
            "unkeyed_source_rows",
            items.iter().filter(|i| i.key.is_none()).count(),
        ),
        (
            "excluded_items",
            items.iter().filter(|i| i.reason == "not_eligible").count(),
        ),
        (
            "retried_items",
            items.iter().filter(|i| i.source_rows > 1).count(),
        ),
        ("target_rows", target.records.len()),
        (
            "matched_target_records",
            index
                .iter()
                .filter(|(k, _)| group_index.contains_key(*k))
                .map(|(_, rows)| rows.len())
                .sum(),
        ),
        (
            "unmatched_target_records",
            index
                .iter()
                .filter(|(k, _)| !group_index.contains_key(*k))
                .map(|(_, rows)| rows.len())
                .sum(),
        ),
        ("unkeyed_target_rows", unkeyed_target),
    ]
    .into_iter()
    .map(|(name, count)| Ok((name.into(), count_json(count)?)))
    .collect::<Result<_, HelperError>>()?;
    coverage.insert("counts".into(), Json::Object(counts));
    Ok(Evaluation {
        contract,
        source,
        target,
        as_of,
        outcome: outcome.into(),
        outcome_reasons,
        items,
        coverage,
        unmatched_target_keys: unmatched,
    })
}

fn casefold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let n = c as u32;
        if let Ok(i) = CASEFOLD_EXPANSIONS.binary_search_by_key(&n, |(code, _)| *code) {
            out.push_str(CASEFOLD_EXPANSIONS[i].1);
            continue;
        }
        let i = CASEFOLD_RANGES.partition_point(|(start, _, _, _)| *start <= n);
        if let Some((start, end, step, offset)) = i.checked_sub(1).map(|i| CASEFOLD_RANGES[i]) {
            if n <= end && (n - start).is_multiple_of(step) {
                if let Some(c) = char::from_u32((i64::from(n) + i64::from(offset)) as u32) {
                    out.push(c);
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}
// Frozen from CPython 3.11.9 Unicode 14.0.0; all scalar mappings checked.
const DECIMAL_STARTS: &[u32] = &[
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
    0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
    0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10,
    0x104a0, 0x10d30, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650,
    0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x16a60, 0x16ac0, 0x16b50,
    0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e950, 0x1fbf0,
];
const CASEFOLD_RANGES: &[(u32, u32, u32, i32)] = &[
    (0x41, 0x5a, 1, 32),
    (0xb5, 0xb5, 1, 775),
    (0xc0, 0xd6, 1, 32),
    (0xd8, 0xde, 1, 32),
    (0x100, 0x12e, 2, 1),
    (0x132, 0x136, 2, 1),
    (0x139, 0x147, 2, 1),
    (0x14a, 0x176, 2, 1),
    (0x178, 0x178, 1, -121),
    (0x179, 0x17d, 2, 1),
    (0x17f, 0x17f, 1, -268),
    (0x181, 0x181, 1, 210),
    (0x182, 0x184, 2, 1),
    (0x186, 0x186, 1, 206),
    (0x187, 0x187, 1, 1),
    (0x189, 0x18a, 1, 205),
    (0x18b, 0x18b, 1, 1),
    (0x18e, 0x18e, 1, 79),
    (0x18f, 0x18f, 1, 202),
    (0x190, 0x190, 1, 203),
    (0x191, 0x191, 1, 1),
    (0x193, 0x193, 1, 205),
    (0x194, 0x194, 1, 207),
    (0x196, 0x196, 1, 211),
    (0x197, 0x197, 1, 209),
    (0x198, 0x198, 1, 1),
    (0x19c, 0x19c, 1, 211),
    (0x19d, 0x19d, 1, 213),
    (0x19f, 0x19f, 1, 214),
    (0x1a0, 0x1a4, 2, 1),
    (0x1a6, 0x1a6, 1, 218),
    (0x1a7, 0x1a7, 1, 1),
    (0x1a9, 0x1a9, 1, 218),
    (0x1ac, 0x1ac, 1, 1),
    (0x1ae, 0x1ae, 1, 218),
    (0x1af, 0x1af, 1, 1),
    (0x1b1, 0x1b2, 1, 217),
    (0x1b3, 0x1b5, 2, 1),
    (0x1b7, 0x1b7, 1, 219),
    (0x1b8, 0x1b8, 1, 1),
    (0x1bc, 0x1bc, 1, 1),
    (0x1c4, 0x1c4, 1, 2),
    (0x1c5, 0x1c5, 1, 1),
    (0x1c7, 0x1c7, 1, 2),
    (0x1c8, 0x1c8, 1, 1),
    (0x1ca, 0x1ca, 1, 2),
    (0x1cb, 0x1db, 2, 1),
    (0x1de, 0x1ee, 2, 1),
    (0x1f1, 0x1f1, 1, 2),
    (0x1f2, 0x1f4, 2, 1),
    (0x1f6, 0x1f6, 1, -97),
    (0x1f7, 0x1f7, 1, -56),
    (0x1f8, 0x21e, 2, 1),
    (0x220, 0x220, 1, -130),
    (0x222, 0x232, 2, 1),
    (0x23a, 0x23a, 1, 10795),
    (0x23b, 0x23b, 1, 1),
    (0x23d, 0x23d, 1, -163),
    (0x23e, 0x23e, 1, 10792),
    (0x241, 0x241, 1, 1),
    (0x243, 0x243, 1, -195),
    (0x244, 0x244, 1, 69),
    (0x245, 0x245, 1, 71),
    (0x246, 0x24e, 2, 1),
    (0x345, 0x345, 1, 116),
    (0x370, 0x372, 2, 1),
    (0x376, 0x376, 1, 1),
    (0x37f, 0x37f, 1, 116),
    (0x386, 0x386, 1, 38),
    (0x388, 0x38a, 1, 37),
    (0x38c, 0x38c, 1, 64),
    (0x38e, 0x38f, 1, 63),
    (0x391, 0x3a1, 1, 32),
    (0x3a3, 0x3ab, 1, 32),
    (0x3c2, 0x3c2, 1, 1),
    (0x3cf, 0x3cf, 1, 8),
    (0x3d0, 0x3d0, 1, -30),
    (0x3d1, 0x3d1, 1, -25),
    (0x3d5, 0x3d5, 1, -15),
    (0x3d6, 0x3d6, 1, -22),
    (0x3d8, 0x3ee, 2, 1),
    (0x3f0, 0x3f0, 1, -54),
    (0x3f1, 0x3f1, 1, -48),
    (0x3f4, 0x3f4, 1, -60),
    (0x3f5, 0x3f5, 1, -64),
    (0x3f7, 0x3f7, 1, 1),
    (0x3f9, 0x3f9, 1, -7),
    (0x3fa, 0x3fa, 1, 1),
    (0x3fd, 0x3ff, 1, -130),
    (0x400, 0x40f, 1, 80),
    (0x410, 0x42f, 1, 32),
    (0x460, 0x480, 2, 1),
    (0x48a, 0x4be, 2, 1),
    (0x4c0, 0x4c0, 1, 15),
    (0x4c1, 0x4cd, 2, 1),
    (0x4d0, 0x52e, 2, 1),
    (0x531, 0x556, 1, 48),
    (0x10a0, 0x10c5, 1, 7264),
    (0x10c7, 0x10c7, 1, 7264),
    (0x10cd, 0x10cd, 1, 7264),
    (0x13f8, 0x13fd, 1, -8),
    (0x1c80, 0x1c80, 1, -6222),
    (0x1c81, 0x1c81, 1, -6221),
    (0x1c82, 0x1c82, 1, -6212),
    (0x1c83, 0x1c84, 1, -6210),
    (0x1c85, 0x1c85, 1, -6211),
    (0x1c86, 0x1c86, 1, -6204),
    (0x1c87, 0x1c87, 1, -6180),
    (0x1c88, 0x1c88, 1, 35267),
    (0x1c90, 0x1cba, 1, -3008),
    (0x1cbd, 0x1cbf, 1, -3008),
    (0x1e00, 0x1e94, 2, 1),
    (0x1e9b, 0x1e9b, 1, -58),
    (0x1ea0, 0x1efe, 2, 1),
    (0x1f08, 0x1f0f, 1, -8),
    (0x1f18, 0x1f1d, 1, -8),
    (0x1f28, 0x1f2f, 1, -8),
    (0x1f38, 0x1f3f, 1, -8),
    (0x1f48, 0x1f4d, 1, -8),
    (0x1f59, 0x1f5f, 2, -8),
    (0x1f68, 0x1f6f, 1, -8),
    (0x1fb8, 0x1fb9, 1, -8),
    (0x1fba, 0x1fbb, 1, -74),
    (0x1fbe, 0x1fbe, 1, -7173),
    (0x1fc8, 0x1fcb, 1, -86),
    (0x1fd8, 0x1fd9, 1, -8),
    (0x1fda, 0x1fdb, 1, -100),
    (0x1fe8, 0x1fe9, 1, -8),
    (0x1fea, 0x1feb, 1, -112),
    (0x1fec, 0x1fec, 1, -7),
    (0x1ff8, 0x1ff9, 1, -128),
    (0x1ffa, 0x1ffb, 1, -126),
    (0x2126, 0x2126, 1, -7517),
    (0x212a, 0x212a, 1, -8383),
    (0x212b, 0x212b, 1, -8262),
    (0x2132, 0x2132, 1, 28),
    (0x2160, 0x216f, 1, 16),
    (0x2183, 0x2183, 1, 1),
    (0x24b6, 0x24cf, 1, 26),
    (0x2c00, 0x2c2f, 1, 48),
    (0x2c60, 0x2c60, 1, 1),
    (0x2c62, 0x2c62, 1, -10743),
    (0x2c63, 0x2c63, 1, -3814),
    (0x2c64, 0x2c64, 1, -10727),
    (0x2c67, 0x2c6b, 2, 1),
    (0x2c6d, 0x2c6d, 1, -10780),
    (0x2c6e, 0x2c6e, 1, -10749),
    (0x2c6f, 0x2c6f, 1, -10783),
    (0x2c70, 0x2c70, 1, -10782),
    (0x2c72, 0x2c72, 1, 1),
    (0x2c75, 0x2c75, 1, 1),
    (0x2c7e, 0x2c7f, 1, -10815),
    (0x2c80, 0x2ce2, 2, 1),
    (0x2ceb, 0x2ced, 2, 1),
    (0x2cf2, 0x2cf2, 1, 1),
    (0xa640, 0xa66c, 2, 1),
    (0xa680, 0xa69a, 2, 1),
    (0xa722, 0xa72e, 2, 1),
    (0xa732, 0xa76e, 2, 1),
    (0xa779, 0xa77b, 2, 1),
    (0xa77d, 0xa77d, 1, -35332),
    (0xa77e, 0xa786, 2, 1),
    (0xa78b, 0xa78b, 1, 1),
    (0xa78d, 0xa78d, 1, -42280),
    (0xa790, 0xa792, 2, 1),
    (0xa796, 0xa7a8, 2, 1),
    (0xa7aa, 0xa7aa, 1, -42308),
    (0xa7ab, 0xa7ab, 1, -42319),
    (0xa7ac, 0xa7ac, 1, -42315),
    (0xa7ad, 0xa7ad, 1, -42305),
    (0xa7ae, 0xa7ae, 1, -42308),
    (0xa7b0, 0xa7b0, 1, -42258),
    (0xa7b1, 0xa7b1, 1, -42282),
    (0xa7b2, 0xa7b2, 1, -42261),
    (0xa7b3, 0xa7b3, 1, 928),
    (0xa7b4, 0xa7c2, 2, 1),
    (0xa7c4, 0xa7c4, 1, -48),
    (0xa7c5, 0xa7c5, 1, -42307),
    (0xa7c6, 0xa7c6, 1, -35384),
    (0xa7c7, 0xa7c9, 2, 1),
    (0xa7d0, 0xa7d0, 1, 1),
    (0xa7d6, 0xa7d8, 2, 1),
    (0xa7f5, 0xa7f5, 1, 1),
    (0xab70, 0xabbf, 1, -38864),
    (0xff21, 0xff3a, 1, 32),
    (0x10400, 0x10427, 1, 40),
    (0x104b0, 0x104d3, 1, 40),
    (0x10570, 0x1057a, 1, 39),
    (0x1057c, 0x1058a, 1, 39),
    (0x1058c, 0x10592, 1, 39),
    (0x10594, 0x10595, 1, 39),
    (0x10c80, 0x10cb2, 1, 64),
    (0x118a0, 0x118bf, 1, 32),
    (0x16e40, 0x16e5f, 1, 32),
    (0x1e900, 0x1e921, 1, 34),
];
const CASEFOLD_EXPANSIONS: &[(u32, &str)] = &[
    (0xdf, "ss"),
    (0x130, "i\u{307}"),
    (0x149, "\u{2bc}n"),
    (0x1f0, "j\u{30c}"),
    (0x390, "\u{3b9}\u{308}\u{301}"),
    (0x3b0, "\u{3c5}\u{308}\u{301}"),
    (0x587, "\u{565}\u{582}"),
    (0x1e96, "h\u{331}"),
    (0x1e97, "t\u{308}"),
    (0x1e98, "w\u{30a}"),
    (0x1e99, "y\u{30a}"),
    (0x1e9a, "a\u{2be}"),
    (0x1e9e, "ss"),
    (0x1f50, "\u{3c5}\u{313}"),
    (0x1f52, "\u{3c5}\u{313}\u{300}"),
    (0x1f54, "\u{3c5}\u{313}\u{301}"),
    (0x1f56, "\u{3c5}\u{313}\u{342}"),
    (0x1f80, "\u{1f00}\u{3b9}"),
    (0x1f81, "\u{1f01}\u{3b9}"),
    (0x1f82, "\u{1f02}\u{3b9}"),
    (0x1f83, "\u{1f03}\u{3b9}"),
    (0x1f84, "\u{1f04}\u{3b9}"),
    (0x1f85, "\u{1f05}\u{3b9}"),
    (0x1f86, "\u{1f06}\u{3b9}"),
    (0x1f87, "\u{1f07}\u{3b9}"),
    (0x1f88, "\u{1f00}\u{3b9}"),
    (0x1f89, "\u{1f01}\u{3b9}"),
    (0x1f8a, "\u{1f02}\u{3b9}"),
    (0x1f8b, "\u{1f03}\u{3b9}"),
    (0x1f8c, "\u{1f04}\u{3b9}"),
    (0x1f8d, "\u{1f05}\u{3b9}"),
    (0x1f8e, "\u{1f06}\u{3b9}"),
    (0x1f8f, "\u{1f07}\u{3b9}"),
    (0x1f90, "\u{1f20}\u{3b9}"),
    (0x1f91, "\u{1f21}\u{3b9}"),
    (0x1f92, "\u{1f22}\u{3b9}"),
    (0x1f93, "\u{1f23}\u{3b9}"),
    (0x1f94, "\u{1f24}\u{3b9}"),
    (0x1f95, "\u{1f25}\u{3b9}"),
    (0x1f96, "\u{1f26}\u{3b9}"),
    (0x1f97, "\u{1f27}\u{3b9}"),
    (0x1f98, "\u{1f20}\u{3b9}"),
    (0x1f99, "\u{1f21}\u{3b9}"),
    (0x1f9a, "\u{1f22}\u{3b9}"),
    (0x1f9b, "\u{1f23}\u{3b9}"),
    (0x1f9c, "\u{1f24}\u{3b9}"),
    (0x1f9d, "\u{1f25}\u{3b9}"),
    (0x1f9e, "\u{1f26}\u{3b9}"),
    (0x1f9f, "\u{1f27}\u{3b9}"),
    (0x1fa0, "\u{1f60}\u{3b9}"),
    (0x1fa1, "\u{1f61}\u{3b9}"),
    (0x1fa2, "\u{1f62}\u{3b9}"),
    (0x1fa3, "\u{1f63}\u{3b9}"),
    (0x1fa4, "\u{1f64}\u{3b9}"),
    (0x1fa5, "\u{1f65}\u{3b9}"),
    (0x1fa6, "\u{1f66}\u{3b9}"),
    (0x1fa7, "\u{1f67}\u{3b9}"),
    (0x1fa8, "\u{1f60}\u{3b9}"),
    (0x1fa9, "\u{1f61}\u{3b9}"),
    (0x1faa, "\u{1f62}\u{3b9}"),
    (0x1fab, "\u{1f63}\u{3b9}"),
    (0x1fac, "\u{1f64}\u{3b9}"),
    (0x1fad, "\u{1f65}\u{3b9}"),
    (0x1fae, "\u{1f66}\u{3b9}"),
    (0x1faf, "\u{1f67}\u{3b9}"),
    (0x1fb2, "\u{1f70}\u{3b9}"),
    (0x1fb3, "\u{3b1}\u{3b9}"),
    (0x1fb4, "\u{3ac}\u{3b9}"),
    (0x1fb6, "\u{3b1}\u{342}"),
    (0x1fb7, "\u{3b1}\u{342}\u{3b9}"),
    (0x1fbc, "\u{3b1}\u{3b9}"),
    (0x1fc2, "\u{1f74}\u{3b9}"),
    (0x1fc3, "\u{3b7}\u{3b9}"),
    (0x1fc4, "\u{3ae}\u{3b9}"),
    (0x1fc6, "\u{3b7}\u{342}"),
    (0x1fc7, "\u{3b7}\u{342}\u{3b9}"),
    (0x1fcc, "\u{3b7}\u{3b9}"),
    (0x1fd2, "\u{3b9}\u{308}\u{300}"),
    (0x1fd3, "\u{3b9}\u{308}\u{301}"),
    (0x1fd6, "\u{3b9}\u{342}"),
    (0x1fd7, "\u{3b9}\u{308}\u{342}"),
    (0x1fe2, "\u{3c5}\u{308}\u{300}"),
    (0x1fe3, "\u{3c5}\u{308}\u{301}"),
    (0x1fe4, "\u{3c1}\u{313}"),
    (0x1fe6, "\u{3c5}\u{342}"),
    (0x1fe7, "\u{3c5}\u{308}\u{342}"),
    (0x1ff2, "\u{1f7c}\u{3b9}"),
    (0x1ff3, "\u{3c9}\u{3b9}"),
    (0x1ff4, "\u{3ce}\u{3b9}"),
    (0x1ff6, "\u{3c9}\u{342}"),
    (0x1ff7, "\u{3c9}\u{342}\u{3b9}"),
    (0x1ffc, "\u{3c9}\u{3b9}"),
    (0xfb00, "ff"),
    (0xfb01, "fi"),
    (0xfb02, "fl"),
    (0xfb03, "ffi"),
    (0xfb04, "ffl"),
    (0xfb05, "st"),
    (0xfb06, "st"),
    (0xfb13, "\u{574}\u{576}"),
    (0xfb14, "\u{574}\u{565}"),
    (0xfb15, "\u{574}\u{56b}"),
    (0xfb16, "\u{57e}\u{576}"),
    (0xfb17, "\u{574}\u{56d}"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::NON_SCALAR;
    fn string(v: &str) -> Value {
        Value::Scalar(Scalar::String(v.into()))
    }
    fn int(v: &str) -> Value {
        Value::Scalar(Scalar::Int(Integer::parse(v).unwrap()))
    }
    fn float(v: f64) -> Value {
        Value::Scalar(Scalar::Float(v))
    }
    fn steps(v: &[&str]) -> Vec<String> {
        v.iter().map(|v| (*v).into()).collect()
    }
    #[test]
    fn worst_is_order_independent_but_still_checks_later_unknowns() {
        assert_eq!(worst([]).unwrap(), None);
        assert_eq!(worst(STATUSES.iter().copied()).unwrap(), Some(VIOLATED));
        assert_eq!(
            worst([NOT_APPLICABLE, NOT_EVALUATED]).unwrap(),
            Some(NOT_EVALUATED)
        );
        assert_eq!(
            worst([VERIFIED, PENDING, INCONCLUSIVE]).unwrap(),
            Some(INCONCLUSIVE)
        );
        assert_eq!(
            worst([VIOLATED, "bad"]),
            Err(HelperError::Key("bad".into()))
        );
        assert_eq!(worst(["bad"]).unwrap_err().to_string(), "'bad'");
    }
    #[test]
    fn comparison_text_keeps_python_float_threshold_and_nonfinite_repr() {
        for (v, want) in [
            (int("9223372036854775808"), "9223372036854775808"),
            (float(9223372036854775808.0), "9.223372036854776e+18"),
            (float(-0.0), "0"),
            (float(12.0), "12"),
            (float(1e-5), "1e-05"),
            (float(f64::NAN), "nan"),
            (float(f64::INFINITY), "inf"),
            (float(f64::NEG_INFINITY), "-inf"),
            (Value::Scalar(Scalar::Bool(true)), "true"),
        ] {
            assert_eq!(text(&v).unwrap().as_deref(), Some(want));
        }
        assert_eq!(text(&Value::Scalar(Scalar::Null)).unwrap(), None);
        assert_eq!(text(&Value::NonScalar(NON_SCALAR)).unwrap(), None);
    }
    #[test]
    fn normalization_is_trim_then_unicode14_casefold_without_nfc() {
        assert_eq!(
            normalized(
                &string("\x1c Straße İ Ꭰ ẞ Σς \u{85}"),
                &steps(&["casefold", "trim"])
            )
            .unwrap()
            .as_deref(),
            Some("strasse i\u{307} Ꭰ ss σσ")
        );
        assert_eq!(
            normalized(&string(" É "), &steps(&["unknown"]))
                .unwrap()
                .as_deref(),
            Some(" É ")
        );
        assert_ne!(
            normalized(&string("É"), &steps(&["casefold"])).unwrap(),
            normalized(&string("E\u{301}"), &steps(&["casefold"])).unwrap()
        );
        assert_eq!(casefold("\u{1c89}"), "\u{1c89}"); // unassigned in Unicode14
    }
    #[test]
    fn numeric_coercion_preserves_ints_and_only_parses_csv_strings() {
        assert!(matches!(
            number(&int(&"9".repeat(400)), true),
            Some(Number::Int(_))
        ));
        for raw in ["0012", "+١٢.٥", ".5", "12.", "-1e+2", "12\n", "１２.５"] {
            assert!(number(&string(raw), false).is_some(), "{raw}");
            assert_eq!(number(&string(raw), true), None);
        }
        for raw in [
            " 12", "12 ", "12\r\n", "12\n\n", "1_000", "NaN", "Infinity", "1e400", "²", "1.2.3",
            "", "+", ".e2",
        ] {
            assert_eq!(number(&string(raw), false), None, "{raw}");
        }
        for v in [
            float(f64::NAN),
            float(f64::INFINITY),
            Value::Scalar(Scalar::Bool(true)),
            Value::Scalar(Scalar::Null),
            Value::NonScalar(NON_SCALAR),
        ] {
            assert_eq!(number(&v, false), None);
        }
    }
    #[test]
    fn integer_float_order_never_rounds_the_integer() {
        let n = |s: &str| Number::Int(Integer::parse(s).unwrap());
        assert!(n("9007199254740993") > Number::Float(9007199254740992.0));
        assert!(n("-9007199254740993") < Number::Float(-9007199254740992.0));
        assert!(n("0") < Number::Float(f64::from_bits(1)));
        assert!(n("0") > Number::Float(-f64::from_bits(1)));
        assert!(n("-1") > Number::Float(-1.5));
        assert!(n("1") < Number::Float(1.5));
        assert!(n(&"9".repeat(400)) > Number::Float(f64::MAX));
        assert_eq!(n("0"), Number::Float(-0.0));
        assert_eq!(n("1").partial_cmp(&Number::Float(f64::NAN)), None);
        assert!(n(&"9".repeat(400)) < Number::Float(f64::INFINITY));
    }
    #[test]
    fn equality_respects_each_snapshot_type_and_source_null_semantics() {
        let csv_json = ComparisonContext {
            source_typed: false,
            target_typed: true,
        };
        let json_json = ComparisonContext {
            source_typed: true,
            target_typed: true,
        };
        assert!(equal(&string("12.50"), &float(12.5), &[], csv_json).unwrap());
        assert!(!equal(&string("12.50"), &float(12.5), &[], json_json).unwrap());
        assert!(!equal(&string("0012"), &string("12"), &[], csv_json).unwrap());
        assert!(!equal(
            &int("9007199254740993"),
            &float(9007199254740992.0),
            &[],
            csv_json
        )
        .unwrap());
        assert!(equal(
            &Value::Scalar(Scalar::Bool(true)),
            &string("true"),
            &[],
            json_json
        )
        .unwrap());
        // This helper compares None==None; later field checks reject nested data.
        assert!(equal(
            &Value::Scalar(Scalar::Null),
            &Value::NonScalar(NON_SCALAR),
            &[],
            json_json
        )
        .unwrap());
    }
    #[test]
    fn kind_validation_distinguishes_bool_integer_float_and_csv() {
        assert!(!kind_ok(
            &Value::Scalar(Scalar::Bool(true)),
            "integer",
            false
        ));
        assert!(!kind_ok(&float(1.0), "integer", false));
        assert!(kind_ok(&int("1"), "integer", true));
        assert!(kind_ok(&string("١٢\n"), "integer", false));
        assert!(!kind_ok(&string("1.0"), "integer", false));
        assert!(kind_ok(&string("true"), "boolean", false));
        assert!(!kind_ok(&string("True"), "boolean", false));
        assert!(!kind_ok(&string("true"), "boolean", true));
        assert!(kind_ok(&string("2026-10-20T12Z"), "date-time", true));
        assert!(!kind_ok(&string("2026-10-20T12"), "date-time", false));
        assert!(!kind_ok(&string("x"), "unknown", false));
    }
    #[test]
    fn predicates_keep_unknown_missing_present_and_null_distinct() {
        let mut r = Record::new();
        let mut p = Predicate::new("x", "eq");
        assert_eq!(predicate(&p, &r, false).unwrap(), None);
        p.op = "present".into();
        assert_eq!(predicate(&p, &r, false).unwrap(), Some(false));
        r.insert("x".into(), Value::NonScalar(NON_SCALAR));
        assert_eq!(predicate(&p, &r, false).unwrap(), Some(true));
        p.op = "eq".into();
        assert_eq!(predicate(&p, &r, false).unwrap(), None);
        r.insert("x".into(), Value::Scalar(Scalar::Null));
        assert_eq!(predicate(&p, &r, false).unwrap(), Some(true));
        p.op = "ne".into();
        assert_eq!(predicate(&p, &r, false).unwrap(), Some(false));
        p.op = "present".into();
        assert_eq!(predicate(&p, &r, false).unwrap(), Some(false));
        r.insert("x".into(), Value::Scalar(Scalar::Bool(false)));
        assert_eq!(predicate(&p, &r, false).unwrap(), Some(true));
        p.op = "absent".into();
        assert_eq!(predicate(&p, &r, false).unwrap(), Some(false));
    }
    #[test]
    fn predicates_use_text_membership_and_exact_numeric_comparison() {
        let mut r = Record::new();
        r.insert("x".into(), float(12.0));
        let mut p = Predicate::new("x", "in");
        p.values = vec![Scalar::String("12".into())];
        assert_eq!(predicate(&p, &r, true).unwrap(), Some(true));
        p.op = "not_in".into();
        assert_eq!(predicate(&p, &r, true).unwrap(), Some(false));
        p.op = "gt".into();
        p.value = Scalar::Bool(true);
        assert_eq!(predicate(&p, &r, true).unwrap(), Some(true));
        p.value = Scalar::Float(f64::NAN);
        assert_eq!(predicate(&p, &r, true).unwrap(), Some(false));
        p.op = "invalid".into();
        assert!(matches!(predicate(&p, &r, true), Err(HelperError::Key(_))));
        r.insert("x".into(), string("bad"));
        assert_eq!(predicate(&p, &r, false).unwrap(), None);
        r.insert("x".into(), int("9007199254740993"));
        p.op = "gt".into();
        p.value = Scalar::Float(9007199254740992.0);
        assert_eq!(predicate(&p, &r, true).unwrap(), Some(true));
    }
    #[test]
    fn condition_result_omits_empty_collections_and_preserves_branches() {
        let mut r = ConditionResult::new("c", "exists", VERIFIED, "present");
        assert_eq!(r.to_dict().len(), 5);
        r.advisory = true;
        r.detail
            .insert("count".into(), Json::Scalar(Scalar::Int(3.into())));
        r.branches
            .push(ConditionResult::new("b", "exists", VIOLATED, "missing"));
        let d = r.to_dict();
        assert_eq!(d.len(), 7);
        assert_eq!(d["advisory"], Json::Scalar(Scalar::Bool(true)));
        assert!(matches!(&d["branches"],Json::Array(a) if a.len()==1));
        assert!(REASONS
            .iter()
            .any(|(k, v)| *k == "missing" && v.contains("complete snapshot")));
    }
}

#[cfg(test)]
mod decision_tests {
    use super::*;
    use crate::contract::{contract_from_dict, parse_strict_json};
    use crate::snapshot::{scalarize, NON_SCALAR};
    fn at(s: &str) -> Instant {
        parse_instant_str(s).unwrap()
    }
    fn due() -> Instant {
        at("2026-11-09T00:00:01Z")
    }
    fn record(s: &str) -> Record {
        let Json::Object(m) = parse_strict_json(s).unwrap() else {
            panic!()
        };
        scalarize(&m)
    }
    fn contract() -> Contract {
        contract_from_dict(&parse_strict_json(r#"{"schema_version":"sesslint.outcome-contract/v1","name":"synthetic","version":"1","key":{"source":["x"],"target":["x"]},"conditions":[{"id":"exists","type":"exists"}]}"#).unwrap()).unwrap()
    }
    fn target() -> Snapshot {
        Snapshot {
            role: "target".into(),
            name: "synthetic.json".into(),
            sha256: "0".repeat(64),
            input_format: "json".into(),
            records: vec![],
            fields: ["x".into(), "done".into()].into_iter().collect(),
            observed_at: Some(due()),
            completeness: "complete".into(),
            origin: "user_file".into(),
            demo: false,
        }
    }
    fn condition(kind: &str) -> Condition {
        Condition {
            id: "c".into(),
            kind: kind.into(),
            field: Some("x".into()),
            ..Condition::default()
        }
    }

    fn observation(role: &str, rows: &[&str]) -> Snapshot {
        let mut s = target();
        s.role = role.into();
        s.records = rows.iter().map(|r| record(r)).collect();
        s.fields = s.records.iter().flat_map(|r| r.keys().cloned()).collect();
        s
    }

    #[test]
    fn conflict_preserves_presence_text_and_nested_identity() {
        let fields = BTreeSet::from(["x".into()]);
        for (a, b, expected) in [
            (r#"{}"#, r#"{"x":null}"#, true),
            (r#"{"x":null}"#, r#"{"x":[]}"#, true),
            (r#"{"x":{}}"#, r#"{"x":[]}"#, false),
            (r#"{"x":1}"#, r#"{"x":"1"}"#, false),
            (r#"{"x":true}"#, r#"{"x":"true"}"#, false),
            (r#"{"x":" a "}"#, r#"{"x":"a"}"#, true),
            (r#"{"x":1,"other":2}"#, r#"{"x":1,"other":3}"#, false),
        ] {
            assert_eq!(
                conflicting(&[&record(a), &record(b)], &fields).unwrap(),
                expected
            );
        }
        assert_eq!(conflicting(&[], &fields), Err(HelperError::InvalidGroup));
    }

    #[test]
    fn evaluation_validates_time_before_observations_in_source_order() {
        let c = contract();
        let s = observation("source", &[]);
        let t = observation("target", &[]);
        assert_eq!(
            evaluate(&c, &s, &t, None).unwrap_err().0,
            "the evaluation instant needs a UTC offset"
        );
        let earlier = Some(at("2026-11-09T00:00:00Z"));
        assert_eq!(
            evaluate(&c, &s, &t, earlier).unwrap_err().0,
            "the evaluation instant precedes the source observation time"
        );
        let mut s = s;
        s.observed_at = None;
        assert_eq!(
            evaluate(&c, &s, &t, earlier).unwrap_err().0,
            "the evaluation instant precedes the target observation time"
        );
    }

    #[test]
    fn evaluation_groups_retries_sorts_keys_and_accounts_for_every_row() {
        let c = contract();
        let s = observation(
            "source",
            &[
                r#"{"x":"z"}"#,
                "{}",
                r#"{"x":"a"}"#,
                r#"{"x":"z"}"#,
                r#"{"x":false}"#,
            ],
        );
        let t = observation(
            "target",
            &[
                r#"{"x":"z"}"#,
                r#"{"x":"z"}"#,
                r#"{"x":"a"}"#,
                r#"{"x":"y"}"#,
                r#"{"x":"b"}"#,
                "{}",
            ],
        );
        let e = evaluate(&c, &s, &t, Some(due())).unwrap();
        assert_eq!(e.outcome, INCONCLUSIVE);
        assert_eq!(
            e.items.iter().map(|i| i.source_row).collect::<Vec<_>>(),
            [3, 1, 2, 5]
        );
        assert_eq!(e.items[1].source_rows, 2);
        assert_eq!(e.items[1].matched_records, 2);
        assert_eq!(
            e.unmatched_target_keys,
            [vec!["b".to_owned()], vec!["y".to_owned()]]
        );
        for (name, count) in [
            ("source_rows", 5),
            ("work_items", 4),
            ("unkeyed_source_rows", 2),
            ("retried_items", 1),
            ("matched_target_records", 3),
            ("unmatched_target_records", 2),
            ("unkeyed_target_rows", 1),
        ] {
            assert_eq!(e.coverage[name], count_json(count).unwrap());
        }
        assert!(std::ptr::eq(e.source, &s));
    }

    #[test]
    fn conflict_precedes_eligibility_and_eligibility_precedes_conditions() {
        let mut c = contract();
        c.eligibility = vec![Predicate::new("eligible", "present")];
        let s = observation(
            "source",
            &[
                r#"{"x":"a","eligible":null}"#,
                r#"{"x":"a","eligible":true}"#,
                r#"{"x":"b"}"#,
            ],
        );
        let t = observation("target", &[]);
        let e = evaluate(&c, &s, &t, Some(due())).unwrap();
        assert_eq!(e.items[0].reason, "source_conflict");
        assert_eq!(e.items[1].reason, "not_eligible");
        assert!(e.items.iter().all(|i| i.conditions.is_empty()));
        assert_eq!(e.coverage["excluded_items"], count_json(1).unwrap());
        c.eligibility = vec![Predicate::new("eligible", "eq")];
        let e = evaluate(&c, &s, &t, Some(due())).unwrap();
        assert_eq!(e.items[1].reason, "eligibility_undecidable");
        assert_eq!(e.items[1].detail["predicate"], count_json(0).unwrap());
    }

    #[test]
    fn due_overflow_and_missing_times_stay_unknown() {
        let mut c = contract();
        c.due = Some(crate::contract::Due {
            source_time_field: "start".into(),
            within_seconds: 1,
        });
        let s = observation(
            "source",
            &[
                r#"{"x":"a","start":"9999-12-31T23:59:59.999999Z"}"#,
                r#"{"x":"b"}"#,
                r#"{"x":"c","start":"2026-11-09T00:00:00Z"}"#,
            ],
        );
        let t = observation("target", &[]);
        let e = evaluate(&c, &s, &t, Some(due())).unwrap();
        assert_eq!(e.items[0].conditions[0].reason, "due_unknown");
        assert_eq!(e.items[1].conditions[0].reason, "due_unknown");
        assert_eq!(e.items[2].deadline, Some(due()));
        assert_eq!(e.items[2].status, VIOLATED);
        c.due.as_mut().unwrap().within_seconds = u64::MAX;
        assert!(evaluate(&c, &s, &t, Some(due()))
            .unwrap()
            .items
            .iter()
            .all(|i| i.deadline.is_none()));
    }

    #[test]
    fn source_coverage_and_missing_mapping_never_establish_verified() {
        let c = contract();
        let mut s = observation("source", &[r#"{"x":"a"}"#]);
        let mut t = observation("target", &[r#"{"x":"a"}"#]);
        assert_eq!(evaluate(&c, &s, &t, Some(due())).unwrap().outcome, VERIFIED);
        s.completeness = "partial".into();
        let e = evaluate(&c, &s, &t, Some(due())).unwrap();
        assert_eq!(e.outcome, INCONCLUSIVE);
        assert_eq!(
            e.outcome_reasons,
            ["all_items_verified", "source_coverage_unproven"]
        );
        s.completeness = "complete".into();
        t.fields.clear();
        let e = evaluate(&c, &s, &t, Some(due())).unwrap();
        assert_eq!(e.outcome, INCONCLUSIVE);
        assert_eq!(
            e.outcome_reasons,
            ["all_items_verified", "target_key_field_absent"]
        );
        s.records.clear();
        assert_eq!(
            evaluate(&c, &s, &t, Some(due())).unwrap().outcome,
            NOT_EVALUATED
        );
        s.completeness = "unavailable".into();
        assert_eq!(
            evaluate(&c, &s, &t, Some(due())).unwrap().outcome_reasons,
            ["source_unavailable", "target_key_field_absent"]
        );
    }

    #[test]
    fn excluded_and_unevaluated_items_remain_distinct() {
        let mut c = contract();
        let s = observation("source", &[r#"{"x":"a"}"#]);
        let t = observation("target", &[]);
        c.conditions[0].disabled = Some(String::new());
        assert_eq!(
            evaluate(&c, &s, &t, Some(due())).unwrap().outcome,
            NOT_EVALUATED
        );
        c.eligibility = vec![Predicate::new("missing", "present")];
        assert_eq!(
            evaluate(&c, &s, &t, Some(due())).unwrap().outcome,
            NOT_APPLICABLE
        );
        let mut context = Context::new(&c, &t, due(), 0, true, true);
        let group = Group {
            key: vec![],
            first_row: 1,
            rows: vec![],
        };
        assert_eq!(
            evaluate_item(&c, &mut context, &[], &group, &[], &BTreeSet::new()),
            Err(HelperError::InvalidGroup)
        );
    }

    #[test]
    fn timedelta_rounds_exact_quotient_without_double_rounding() {
        for (micros, expected) in [
            (999_999, 0),
            (1_000_000, 1),
            (9_999_999_999_999_999, 9_999_999_999),
            (99_999_999_999_999_992, 99_999_999_999),
            (99_999_999_999_999_993, 100_000_000_000),
            (199_999_999_999_999_984, 199_999_999_999),
            (299_999_999_999_999_969, 299_999_999_999),
            (299_999_999_999_999_970, 300_000_000_000),
        ] {
            assert_eq!(positive_total_seconds_integer(micros), expected);
        }
        let c = contract();
        let t = target();
        let ctx = Context::new(&c, &t, due(), 0, true, true);
        let mut cond = condition("on_time");
        cond.field = Some("done".into());
        cond.basis = Some("target_time".into());
        let out = on_time_check(
            &cond,
            &[record(r#"{"done":"0317-11-21T17:46:39.999999Z"}"#)],
            &ctx,
            Some(at("0001-01-01T00:00:00Z")),
            true,
        )
        .unwrap();
        assert_eq!(
            out.2["late_by_seconds"],
            Json::Scalar(Scalar::Int(Integer::from(9_999_999_999)))
        );
    }

    #[test]
    fn conjunction_false_overrides_unknown_and_keys_are_exact() {
        let mut p = Predicate::new("x", "eq");
        p.value = Scalar::String("yes".into());
        let r = record(r#"{"x":"no","n":123,"b":true,"blank":" "}"#);
        assert_eq!(
            all_predicates(&[Predicate::new("missing", "eq"), p], &r, true).unwrap(),
            (Some(false), Some(1))
        );
        assert_eq!(
            all_predicates(&[Predicate::new("missing", "eq")], &r, true).unwrap(),
            (None, Some(0))
        );
        assert_eq!(all_predicates(&[], &r, true).unwrap(), (Some(true), None));
        assert_eq!(
            key(&r, &["n".into(), "blank".into()]),
            (Some(vec!["123".into(), " ".into()]), None)
        );
        assert_eq!(
            key(&r, &["missing".into(), "b".into()]),
            (None, Some("key_missing"))
        );
        assert_eq!(
            key(&r, &["b".into(), "missing".into()]),
            (None, Some("key_invalid"))
        );
    }
    #[test]
    fn absence_and_waiting_preserve_gate_precedence() {
        let c = contract();
        let mut t = target();
        t.completeness = "partial".into();
        t.observed_at = None;
        assert_eq!(
            absence_blocker(&Context::new(&c, &t, due(), 1, true, true), Some(due())),
            Some("target_incomplete")
        );
        t.completeness = "complete".into();
        assert_eq!(
            absence_blocker(&Context::new(&c, &t, due(), 1, true, true), Some(due())),
            Some("target_observed_at_unknown")
        );
        t.observed_at = Some(at("2026-11-09T00:00:00Z"));
        assert_eq!(
            absence_blocker(&Context::new(&c, &t, due(), 1, true, true), Some(due())),
            Some("target_stale")
        );
        t.observed_at = Some(due());
        assert_eq!(
            absence_blocker(&Context::new(&c, &t, due(), 1, true, true), Some(due())),
            Some("target_unkeyed_rows")
        );
        assert_eq!(
            absence_blocker(&Context::new(&c, &t, due(), 0, true, true), Some(due())),
            None
        );
        let early = at("2026-11-09T00:00:00Z");
        assert_eq!(
            waiting(
                &Context::new(&c, &t, early, 0, true, true),
                Some(due()),
                false
            ),
            Some((INCONCLUSIVE, "due_unknown"))
        );
        assert_eq!(
            waiting(
                &Context::new(&c, &t, early, 0, true, true),
                Some(due()),
                true
            ),
            Some((PENDING, "awaiting_due"))
        );
        t.completeness = "unavailable".into();
        assert_eq!(
            waiting(
                &Context::new(&c, &t, early, 0, true, true),
                Some(due()),
                false
            ),
            Some((INCONCLUSIVE, "target_unavailable"))
        );
    }
    #[test]
    fn count_positive_evidence_and_upper_bound_proofs_differ() {
        let c = contract();
        let mut t = target();
        t.completeness = "unavailable".into();
        let ctx = Context::new(&c, &t, due(), 0, true, true);
        assert_eq!(
            count_check(&condition("exists"), 1, &ctx, None, false)
                .unwrap()
                .0,
            VERIFIED
        );
        let mut cond = condition("count");
        cond.minimum = Some(0.0);
        cond.maximum = Some(1.0);
        assert_eq!(
            count_check(&cond, 0, &ctx, None, false).unwrap().1,
            "upper_bound_unproven"
        );
        assert_eq!(
            count_check(&cond, 2, &ctx, None, false).unwrap().1,
            "duplicates_unconfirmed"
        );
        t.completeness = "complete".into();
        let ctx = Context::new(&c, &t, due(), 0, true, true);
        assert_eq!(
            count_check(&cond, 0, &ctx, None, false).unwrap().1,
            "count_within"
        );
        assert_eq!(
            count_check(&cond, 2, &ctx, None, false).unwrap().1,
            "too_many"
        );
        cond.maximum = None;
        cond.minimum = Some(1e100);
        let out = count_check(&cond, 1, &ctx, None, true).unwrap();
        assert_eq!(out.1, "too_few");
        let Json::Scalar(Scalar::Int(i)) = &out.2["min"] else {
            panic!()
        };
        assert!(i.decimal().len() > 90);
    }
    #[test]
    fn nested_fields_and_source_absence_do_not_become_verified() {
        let c = contract();
        let t = target();
        let mut ctx = Context::new(&c, &t, due(), 0, true, true);
        let nested = Record::from([("x".into(), Value::NonScalar(NON_SCALAR))]);
        assert_eq!(
            field_check(
                &condition("required"),
                std::slice::from_ref(&nested),
                &mut ctx,
                &Record::new()
            )
            .unwrap()
            .1,
            "field_present"
        );
        let mut cond = condition("equals");
        cond.source_field = Some("x".into());
        assert_eq!(
            field_check(
                &cond,
                std::slice::from_ref(&nested),
                &mut ctx,
                &Record::new()
            )
            .unwrap()
            .1,
            "source_value_absent"
        );
        assert_eq!(
            field_check(&cond, &[nested], &mut ctx, &record(r#"{"x":1}"#))
                .unwrap()
                .1,
            "value_nested"
        );
        cond.kind = "range".into();
        cond.minimum = Some(9007199254740992.0);
        cond.maximum = cond.minimum;
        assert_eq!(
            field_check(
                &cond,
                &[record(r#"{"x":9007199254740993}"#)],
                &mut ctx,
                &Record::new()
            )
            .unwrap()
            .1,
            "out_of_range"
        );
    }
    #[test]
    fn earliest_timely_record_wins_before_other_unusable_times() {
        let c = contract();
        let mut t = target();
        t.completeness = "partial".into();
        let mut cond = condition("on_time");
        cond.field = Some("done".into());
        cond.basis = Some("target_time".into());
        let ctx = Context::new(&c, &t, due(), 0, true, true);
        let timely = record(r#"{"done":"2026-11-09T00:00:01Z"}"#);
        let late = record(r#"{"done":"2026-11-09T00:00:01.999999Z"}"#);
        assert_eq!(
            on_time_check(&cond, &[Record::new(), timely], &ctx, Some(due()), true)
                .unwrap()
                .1,
            "completed_on_time"
        );
        assert_eq!(
            on_time_check(
                &cond,
                &[Record::new(), late.clone()],
                &ctx,
                Some(due()),
                true
            )
            .unwrap()
            .1,
            "completion_time_unusable"
        );
        let out = on_time_check(&cond, &[late], &ctx, Some(due()), true).unwrap();
        assert_eq!(out.1, "late_unconfirmed");
        assert_eq!(
            out.2["late_by_seconds"],
            Json::Scalar(Scalar::Int(Integer::from(0)))
        );
    }
    #[test]
    fn branch_status_priority_and_partial_item_evaluation_are_distinct() {
        let c = contract();
        let t = target();
        let mut ctx = Context::new(&c, &t, due(), 0, true, true);
        let rows = [record(r#"{"x":"yes"}"#)];
        let source = Record::new();
        let mut missing = condition("equals");
        missing.source_field = Some("missing".into());
        let mut any = condition("any_of");
        any.conditions = vec![missing, condition("exists")];
        let out = evaluate_condition(&any, &source, &rows, &mut ctx, Some(due()), true).unwrap();
        assert_eq!(out.reason, "any_branch_verified");
        assert_eq!(out.branches.len(), 2);
        let pass = ConditionResult::new("a", "exists", VERIFIED, "present");
        let mut skip = ConditionResult::new("b", "required", NOT_EVALUATED, "no_target_record");
        assert_eq!(
            item_verdict(&[pass.clone(), skip.clone()]).unwrap(),
            (INCONCLUSIVE.into(), "conditions_partly_evaluated".into())
        );
        skip.reason = "disabled".into();
        assert_eq!(item_verdict(&[pass, skip]).unwrap().0, VERIFIED);
        let mut route = condition("route");
        route.when = vec![Predicate::new("x", "eq")];
        assert_eq!(
            evaluate_condition(&route, &source, &[], &mut ctx, None, false)
                .unwrap()
                .reason,
            "route_undecidable"
        );
        route.disabled = Some(String::new());
        assert_eq!(
            evaluate_condition(&route, &source, &[], &mut ctx, None, false)
                .unwrap()
                .reason,
            "disabled"
        );
    }
    #[test]
    fn cache_uses_condition_id_and_first_worst_record_is_retained() {
        let c = contract();
        let t = target();
        let mut ctx = Context::new(&c, &t, due(), 0, true, true);
        let mut cond = condition("one_of");
        cond.normalize = vec!["casefold".into()];
        cond.values = vec![Scalar::String("Straße".into())];
        assert!(ctx
            .allowed(&cond)
            .unwrap()
            .contains(&Some("strasse".into())));
        cond.values = vec![Scalar::String("other".into())];
        assert!(ctx
            .allowed(&cond)
            .unwrap()
            .contains(&Some("strasse".into())));
        cond.id = "other".into();
        assert!(ctx.allowed(&cond).unwrap().contains(&Some("other".into())));
        let rows = [
            check(VERIFIED, "pass", Mapping::new()),
            check(VIOLATED, "first", Mapping::new()),
            check(VIOLATED, "second", Mapping::new()),
        ];
        assert_eq!(per_record(&rows).unwrap().1, "first");
        assert_eq!(per_record(&[]).unwrap().1, "no_target_record");
    }
    #[test]
    fn invalid_typed_conditions_return_errors_without_panicking() {
        let c = contract();
        let t = target();
        let mut ctx = Context::new(&c, &t, due(), 0, true, true);
        let rows = [record(r#"{"x":1}"#)];
        let source = Record::new();
        let mut cond = condition("required");
        cond.field = None;
        assert_eq!(
            field_check(&cond, &rows, &mut ctx, &source),
            Err(HelperError::InvalidCondition("field"))
        );
        cond = condition("equals");
        assert_eq!(
            field_check(&cond, &rows, &mut ctx, &source),
            Err(HelperError::InvalidCondition("source_field"))
        );
        cond = condition("type");
        assert_eq!(
            field_check(&cond, &rows, &mut ctx, &source),
            Err(HelperError::InvalidCondition("kind"))
        );
        cond = condition("count");
        cond.minimum = Some(f64::NAN);
        assert_eq!(
            count_check(&cond, 0, &ctx, None, true),
            Err(HelperError::NumericBound)
        );
        assert!(
            item_verdict(&[ConditionResult::new("x", "exists", "invalid", "present")]).is_err()
        );
    }
}
