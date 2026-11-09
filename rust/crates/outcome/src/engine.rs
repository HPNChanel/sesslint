//! Outcome reconciliation values and comparisons (REC-01..08, RULE-01..08).
//!
//! Port of pinned engine.py lines 1..329. Evaluation time is always supplied.
//! The complete evaluator/context belong to later parts; no verdict is inferred
//! here. Unicode behavior is frozen to CPython 3.11.9 / Unicode 14.0.0.
use crate::contract::{repr_list, Contract, Integer, Json, Mapping, Predicate, Scalar};
use crate::snapshot::{parse_instant_str, Instant, Record, Snapshot, Value};
use codec::canonical_codec::{CanonicalCodec, PurePythonCanonicalCodec, Value as CodecValue};
use std::cmp::Ordering;
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
