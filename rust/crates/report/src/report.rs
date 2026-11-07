//! Assurance level, finding counts, coverage, the report envelope, repair
//! actions, and revalidation summaries.
//!
//! Port of `src/sesslint/report.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Lines 1–270: [`compute_assurance`], [`Counts`], and [`skip_sort_key`],
//! plus [`ASSURANCE_LIMITATIONS`] and [`REQUIRED_SEVERITIES`].
//!
//! Lines 273–542: [`CoverageSkip`], [`Coverage`], [`default_coverage`],
//! [`Report`], and [`action_sort_key`]. Those symbols also read
//! [`REPORT_SCHEMA_VERSION`], [`VALID_ASSURANCE_LEVELS`], and
//! [`VALID_COVERAGE_SKIP_REASONS`] (defined above line 273). Policy sets,
//! manifest fields, finding-key sets, and the SHA-256 pattern are not read
//! here.
//!
//! [`default_coverage`] stops at the late import
//! `sesslint.profiles.builtin.ALL_RULES`. This crate does not link that
//! module. Display is `sesslint.profiles.builtin.ALL_RULES is not available`.
//! Pure checks that run before a provided coverage value still run.
//!
//! Lines 545–688: [`RepairAction`] and [`RevalidationSummary`].
//! [`RepairAction`] orders with [`action_sort_key`] after stripping.
//! Content checks call [`enforce_content_free_text`]. `FindingError` becomes
//! [`ContentLeakError`] whose message is the pin's `Intrinsic content leak`
//! text. [`RevalidationSummary`] checks [`VALID_ASSURANCE_LEVELS`] and does
//! not call [`enforce_content_free_text`].
//!
//! Lines 691–963: [`RepairManifest`], [`build_report`], and
//! [`compute_manifest_idempotency_key`]. [`RepairManifest`] keeps
//! fingerprints when `strip()` is non-empty and does not call
//! [`enforce_content_free_text`]. Omitted coverage in [`build_report`]
//! calls [`default_coverage`] before `model::finding::sort_findings`.
//! [`compute_manifest_idempotency_key`] calls
//! `model::canonical::to_canonical_json` after the fingerprint and raw
//! policy checks. That returns [`CanonicalUnavailable`]. This crate does
//! not hash a substitute encoding.
//!
//! Lines 966–1128: [`build_manifest`] and [`dump_report`]. Fingerprints,
//! raw policy, declared loss, the revalidate path, and revalidation run
//! before `assurance_ceiling`. `None` there is
//! [`COMPUTE_ASSURANCE_CEILING`] and does not run the later content checks
//! or the idempotency call. A provided ceiling is an exact
//! [`VALID_ASSURANCE_LEVELS`] member. Content checks call
//! [`enforce_content_free_text`]. The idempotency call then returns
//! [`CanonicalUnavailable`]. [`build_manifest`] does not build a
//! [`RepairManifest`]. [`dump_report`] calls
//! `model::canonical::to_canonical_json` on [`Report::to_dict`] and returns
//! the same unavailable error. It does not emit JSON.
//!
//! Lines 1131–1346: [`parse_report`] and [`dump_manifest`]. A string is the
//! `json.loads` branch. This crate has no JSON parser, so that branch
//! returns [`JsonLoadsUnavailable`] and does not invent a mapping. A mapping
//! checks unknown fields, required fields, and schema version before the
//! remaining fields. Findings go through [`parse_finding_dict`] and
//! [`sort_findings`]. Counts, coverage, and the envelope go through the
//! existing constructors. The first failure wins. [`dump_manifest`] calls
//! `model::canonical::to_canonical_json` on [`RepairManifest::to_dict`] and
//! returns [`CanonicalUnavailable`]. It does not emit JSON.
//!
//! Lines 1349–1607: [`parse_manifest`]. A string is the `json.loads` branch
//! and returns [`JsonLoadsUnavailable`]. It is not parsed and it is not
//! reported as malformed JSON. A mapping checks synthetic success fields,
//! unknown keys in insertion order, and missing required fields in source
//! literal order ([`MANIFEST_FIELD_ORDER_DEVIATION`]) before
//! `schema_version`. Actions are a list or tuple, sorted with
//! [`action_sort_key`]. `declared_loss` keeps input order. The function
//! then calls [`RepairAction::try_new`], [`RevalidationSummary::try_new`],
//! and [`RepairManifest::try_new`] and returns their errors unchanged.
//! It does not call `sesslint._resources`, `sesslint.profiles.builtin`, or
//! `sesslint.repair.refusals`. The first failure wins.
//!
//! The late import `sesslint.codes` (`SL001`, `SL002`, `Severity`) is the
//! ported codes registry. `enforce_content_free_text` is the ported finding
//! helper. No wall clock, randomness, or `HashMap` is used.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use model::canonical::CanonicalUnavailable;
use model::codes::{Severity, SL001, SL002};
use model::errors::{
    AssuranceError, ContentLeakError, FindingError, SchemaError, UnknownFieldError, VersionError,
};
use model::finding::{
    enforce_content_free_evidence_recursive, enforce_content_free_text, parse_finding_dict,
    sort_findings, DictValue, Evidence, EvidenceKey, Finding, PyValue,
    SCHEMA_VERSION as FINDING_SCHEMA_VERSION,
};
use model::version::MANIFEST_SCHEMA_VERSION;
use sha2::{Digest, Sha256};

/// Python: `ASSURANCE_LIMITATIONS`, insertion order A0 through A4.
pub const ASSURANCE_LIMITATIONS: [(&str, &str); 5] = [
    ("A0", "No structural conclusion."),
    ("A1", "Relationships may still be invalid."),
    (
        "A2",
        "Provider/runtime replay has not been independently exercised.",
    ),
    (
        "A3",
        "Does not prove semantic equivalence or external side effects.",
    ),
    (
        "A4",
        "Still not proof of model behavior, business correctness, or exactly-once effects.",
    ),
];

/// Python: `REQUIRED_SEVERITIES`.
pub const REQUIRED_SEVERITIES: [&str; 4] = ["fatal", "error", "warning", "info"];

/// Python: `REPORT_SCHEMA_VERSION`.
pub const REPORT_SCHEMA_VERSION: &str = "sesslint.report/v1";

/// Python: `VALID_ASSURANCE_LEVELS`, source order A0 through A4.
pub const VALID_ASSURANCE_LEVELS: [&str; 5] = ["A0", "A1", "A2", "A3", "A4"];

/// Python: `VALID_COVERAGE_SKIP_REASONS`, literal order. Membership is exact.
///
/// The reason error sorts this list before rendering it.
pub const VALID_COVERAGE_SKIP_REASONS: [&str; 7] = [
    "profile-gated",
    "adapter-not-applicable",
    "version-gated",
    "empty-input",
    "cap-exceeded",
    "single-doc-fallback",
    "deselected",
];

/// Qualified name of the late import inside [`default_coverage`].
pub const PROFILES_BUILTIN_ALL_RULES: &str = "sesslint.profiles.builtin.ALL_RULES";

/// `VersionError` stores `Option<String>`. A non-string `schema_version` is
/// rendered in the message, and `version()` stays empty.
pub const VERSION_NON_STR_DEVIATION: &str = "VersionError.version stores a string. A non-string Report.schema_version is rendered in the message and version() is None";

/// Set snapshots keep the caller's order after equality dedupe.
///
/// CPython set order follows the process hash seed. This crate does not
/// reproduce that order. List and tuple order are the caller's order.
pub const SET_SNAPSHOT_ORDER_DEVIATION: &str = "Coverage set snapshots keep caller order after equality dedupe. CPython set order follows the process hash seed and is not reproduced. List and tuple order are the caller order";

/// Binding-key sort matches CPython 3.11 `list.sort` for sequences shorter
/// than 64 (`count_run`, then binary insertion). Longer mixed-type key lists
/// can name a different `TypeError` pair. All-string keys still sort by code point.
pub const BINDING_SORT_DEVIATION: &str = "Coverage adapter and profile sorts match CPython 3.11 count_run plus binary insertion, which is list.sort below 64 keys. Longer mixed-type key lists can name a different TypeError pair";

/// Repr nesting past this depth is rendered as `...`.
///
/// Count maps in this module are flat. The cap only stops a hostile nested
/// value from growing the stack while an error string is built.
const MAX_REPR_DEPTH: usize = 32;

enum Stage {
    A0,
    A1,
    A2,
    A3,
    A4,
}

fn assurance_pair(stage: Stage) -> (&'static str, &'static str) {
    match stage {
        Stage::A0 => ASSURANCE_LIMITATIONS[0],
        Stage::A1 => ASSURANCE_LIMITATIONS[1],
        Stage::A2 => ASSURANCE_LIMITATIONS[2],
        Stage::A3 => ASSURANCE_LIMITATIONS[3],
        Stage::A4 => ASSURANCE_LIMITATIONS[4],
    }
}

/// Python: `compute_assurance`.
///
/// `events` is `None` for Python `None` and a slice for a sequence. Only
/// `is None` and `len(events) == 0` are observed; element values are not read.
///
/// Python defaults, which Rust does not infer: `has_profile_replay=True`,
/// `reference_equivalent=False`.
///
/// Staged result, first match wins:
/// - A0 when there are no events, or a finding code is `SL001` or `SL002`
/// - A1 when a finding severity is error or fatal
/// - A2 when a finding severity is warning, or profile replay was not exercised
/// - A4 when `reference_equivalent` is set
/// - A3 otherwise
#[must_use]
pub fn compute_assurance<T>(
    events: Option<&[T]>,
    findings: &[Finding],
    has_profile_replay: bool,
    reference_equivalent: bool,
) -> (&'static str, &'static str) {
    let has_error = findings
        .iter()
        .any(|finding| matches!(finding.severity(), Severity::Error | Severity::Fatal));
    let has_warning = findings
        .iter()
        .any(|finding| finding.severity() == Severity::Warning);

    if events.is_none() || events.is_some_and(|batch| batch.is_empty()) {
        return assurance_pair(Stage::A0);
    }
    if findings
        .iter()
        .any(|finding| finding.code() == SL001 || finding.code() == SL002)
    {
        return assurance_pair(Stage::A0);
    }
    if has_error {
        return assurance_pair(Stage::A1);
    }
    if has_warning || !has_profile_replay {
        return assurance_pair(Stage::A2);
    }
    if reference_equivalent {
        return assurance_pair(Stage::A4);
    }
    assurance_pair(Stage::A3)
}

/// Hashable key `Counts` can see inside a mapping.
///
/// Python `dict` also accepts tuples, floats, and bytes. Those are not
/// representable here: a caller that has one must refuse instead of dropping
/// the key. Bool and int keys still compare equal when Python would (`True`
/// with `1`, `False` with `0`). The first key object is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountKey {
    None,
    Bool(bool),
    Int(i64),
    Str(String),
}

impl CountKey {
    pub fn bool_value(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn int(value: i64) -> Self {
        Self::Int(value)
    }

    pub fn str_key(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }
}

/// Python object inspected by `Counts.__post_init__`.
///
/// Wrong types stay representable so the `isinstance` checks can fail closed.
/// [`CountValue::Other`] is a type this enum does not model (`float`, a custom
/// object). `rendered` is that object's Python `repr`, and `type_name` is
/// `type(obj).__name__`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountValue {
    None,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<CountValue>),
    Tuple(Vec<CountValue>),
    Dict(Vec<(CountKey, CountValue)>),
    Other { type_name: String, rendered: String },
}

impl CountValue {
    pub fn none() -> Self {
        Self::None
    }

    pub fn bool_value(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn int(value: i64) -> Self {
        Self::Int(value)
    }

    pub fn str_value(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn list(items: Vec<Self>) -> Self {
        Self::List(items)
    }

    pub fn tuple(items: Vec<Self>) -> Self {
        Self::Tuple(items)
    }

    pub fn dict(entries: Vec<(CountKey, Self)>) -> Self {
        Self::Dict(entries)
    }

    pub fn other(type_name: impl Into<String>, rendered: impl Into<String>) -> Self {
        Self::Other {
            type_name: type_name.into(),
            rendered: rendered.into(),
        }
    }
}

/// Python: `Counts`.
///
/// Stored maps keep only keys that were present. A missing required severity
/// is not the same object as an explicit zero; [`Counts::to_dict`] fills the
/// zero. `by_code` equality matches Python `dict` equality and ignores
/// insertion order. [`Counts::code_items`] keeps that order for the report
/// mismatch text (`dict(self.counts.by_code)`).
#[derive(Debug, Clone)]
pub struct Counts {
    by_severity: BTreeMap<String, i64>,
    by_code: BTreeMap<String, i64>,
    code_order: Vec<(String, i64)>,
    total: i64,
}

impl PartialEq for Counts {
    fn eq(&self, other: &Self) -> bool {
        self.total == other.total
            && self.by_severity == other.by_severity
            && self.by_code == other.by_code
    }
}

impl Eq for Counts {}

/// Python: `Counts.to_dict()`.
///
/// `by_severity` follows [`REQUIRED_SEVERITIES`], not map order. `by_code` is
/// sorted by code point. Field order is the Python insertion order
/// `by_severity`, `by_code`, `total`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountsDict {
    pub by_severity: [(&'static str, i64); 4],
    pub by_code: Vec<(String, i64)>,
    pub total: i64,
}

impl Counts {
    /// Validate in the pinned `__post_init__` order.
    ///
    /// Mapping entries use Python `dict` semantics: insertion order, last
    /// value wins, and the first key object is the one later errors render.
    pub fn try_new(
        by_severity: &CountValue,
        by_code: &CountValue,
        total: &CountValue,
    ) -> Result<Self, SchemaError> {
        let total = require_total(total)?;
        let by_severity = require_severity_map(by_severity)?;
        let stored_codes = require_code_map(by_code)?;
        let by_code = stored_codes.by_code;
        let code_order = stored_codes.order;
        Ok(Self {
            by_severity,
            by_code,
            code_order,
            total,
        })
    }

    pub fn total(&self) -> i64 {
        self.total
    }

    /// Stored severity count. `None` means the key was absent, not zero.
    #[must_use]
    pub fn severity_count(&self, name: &str) -> Option<i64> {
        self.by_severity.get(name).copied()
    }

    /// Stored code count. `None` means the key was absent.
    #[must_use]
    pub fn code_count(&self, code: &str) -> Option<i64> {
        self.by_code.get(code).copied()
    }

    /// `by_code` pairs in the caller's insertion order, after duplicate keys collapse.
    ///
    /// [`Counts::to_dict`] still emits code-point order. Equality ignores this order.
    #[must_use]
    pub fn code_items(&self) -> &[(String, i64)] {
        &self.code_order
    }

    #[must_use]
    pub fn to_dict(&self) -> CountsDict {
        let by_severity = REQUIRED_SEVERITIES.map(|name| {
            let count = match self.by_severity.get(name) {
                Some(count) => *count,
                None => 0,
            };
            (name, count)
        });
        let by_code = self
            .by_code
            .iter()
            .map(|(code, count)| (code.clone(), *count))
            .collect();
        CountsDict {
            by_severity,
            by_code,
            total: self.total,
        }
    }
}

fn require_total(total: &CountValue) -> Result<i64, SchemaError> {
    match non_negative(total) {
        Ok(value) => Ok(value),
        Err(()) => Err(schema(format!(
            "Counts.total must be a non-negative integer, got {}",
            python_repr_value(total)
        ))),
    }
}

fn require_severity_map(value: &CountValue) -> Result<BTreeMap<String, i64>, SchemaError> {
    let Some(entries) = mapping_entries(value) else {
        return Err(schema(format!(
            "Counts.by_severity must be a Mapping, got {}",
            type_name(value)
        )));
    };
    let collapsed = collapse(entries);
    for name in REQUIRED_SEVERITIES {
        if let Some(entry) = find_key(&collapsed, &CountKey::str_key(name)) {
            if non_negative(&entry.value).is_err() {
                return Err(schema(format!(
                    "Counts.by_severity[{}] must be non-negative int, got {}",
                    python_str_repr(name),
                    python_repr_value(&entry.value)
                )));
            }
        }
    }
    for entry in &collapsed {
        if !is_required_severity(&entry.key) {
            return Err(schema(format!(
                "Counts.by_severity contains unknown severity: {}",
                python_repr_key(&entry.key)
            )));
        }
    }
    let mut by_severity = BTreeMap::new();
    for entry in &collapsed {
        let CountKey::Str(name) = &entry.key else {
            return Err(schema(format!(
                "Counts.by_severity contains unknown severity: {}",
                python_repr_key(&entry.key)
            )));
        };
        let count = match non_negative(&entry.value) {
            Ok(count) => count,
            Err(()) => {
                return Err(schema(format!(
                    "Counts.by_severity[{}] must be non-negative int, got {}",
                    python_str_repr(name),
                    python_repr_value(&entry.value)
                )));
            }
        };
        by_severity.insert(name.clone(), count);
    }
    Ok(by_severity)
}

struct StoredCodes {
    by_code: BTreeMap<String, i64>,
    order: Vec<(String, i64)>,
}

fn require_code_map(value: &CountValue) -> Result<StoredCodes, SchemaError> {
    let Some(entries) = mapping_entries(value) else {
        return Err(schema(format!(
            "Counts.by_code must be a Mapping, got {}",
            type_name(value)
        )));
    };
    let collapsed = collapse(entries);
    let mut by_code = BTreeMap::new();
    let mut code_order = Vec::new();
    for entry in &collapsed {
        let CountKey::Str(code) = &entry.key else {
            return Err(schema(format!(
                "Counts.by_code key must be str, got {}",
                python_repr_key(&entry.key)
            )));
        };
        let count = match non_negative(&entry.value) {
            Ok(count) => count,
            Err(()) => {
                return Err(schema(format!(
                    "Counts.by_code[{}] must be non-negative int, got {}",
                    python_str_repr(code),
                    python_repr_value(&entry.value)
                )));
            }
        };
        by_code.insert(code.clone(), count);
        code_order.push((code.clone(), count));
    }
    Ok(StoredCodes {
        by_code,
        order: code_order,
    })
}

struct MapEntry {
    key: CountKey,
    value: CountValue,
}

fn mapping_entries(value: &CountValue) -> Option<&[(CountKey, CountValue)]> {
    match value {
        CountValue::Dict(entries) => Some(entries),
        _ => None,
    }
}

fn collapse(entries: &[(CountKey, CountValue)]) -> Vec<MapEntry> {
    let mut collapsed: Vec<MapEntry> = Vec::new();
    for (key, value) in entries {
        let mut replaced = false;
        for existing in &mut collapsed {
            if py_key_eq(&existing.key, key) {
                existing.value = value.clone();
                replaced = true;
                break;
            }
        }
        if !replaced {
            collapsed.push(MapEntry {
                key: key.clone(),
                value: value.clone(),
            });
        }
    }
    collapsed
}

fn find_key<'a>(entries: &'a [MapEntry], needle: &CountKey) -> Option<&'a MapEntry> {
    entries.iter().find(|entry| py_key_eq(&entry.key, needle))
}

fn py_key_eq(left: &CountKey, right: &CountKey) -> bool {
    if let (Some(left_number), Some(right_number)) = (numeric_key(left), numeric_key(right)) {
        return left_number == right_number;
    }
    match (left, right) {
        (CountKey::None, CountKey::None) => true,
        (CountKey::Str(left_text), CountKey::Str(right_text)) => left_text == right_text,
        _ => false,
    }
}

fn numeric_key(key: &CountKey) -> Option<i64> {
    match key {
        CountKey::Int(number) => Some(*number),
        CountKey::Bool(true) => Some(1),
        CountKey::Bool(false) => Some(0),
        CountKey::None | CountKey::Str(_) => None,
    }
}

fn is_required_severity(key: &CountKey) -> bool {
    match key {
        CountKey::Str(text) => REQUIRED_SEVERITIES.contains(&text.as_str()),
        CountKey::None | CountKey::Bool(_) | CountKey::Int(_) => false,
    }
}

fn non_negative(value: &CountValue) -> Result<i64, ()> {
    match value {
        CountValue::Int(number) if *number >= 0 => Ok(*number),
        _ => Err(()),
    }
}

fn type_name(value: &CountValue) -> &str {
    match value {
        CountValue::None => "NoneType",
        CountValue::Bool(_) => "bool",
        CountValue::Int(_) => "int",
        CountValue::Str(_) => "str",
        CountValue::List(_) => "list",
        CountValue::Tuple(_) => "tuple",
        CountValue::Dict(_) => "dict",
        CountValue::Other { type_name, .. } => type_name.as_str(),
    }
}

fn schema(message: String) -> SchemaError {
    SchemaError::new(message)
}

fn python_repr_value(value: &CountValue) -> String {
    repr_value(value, 0)
}

fn repr_value(value: &CountValue, depth: usize) -> String {
    if depth >= MAX_REPR_DEPTH {
        return "...".to_owned();
    }
    match value {
        CountValue::None => "None".to_owned(),
        CountValue::Bool(true) => "True".to_owned(),
        CountValue::Bool(false) => "False".to_owned(),
        CountValue::Int(number) => number.to_string(),
        CountValue::Str(text) => python_str_repr(text),
        CountValue::List(items) => render_sequence(items, depth, '[', ']', false),
        CountValue::Tuple(items) => render_sequence(items, depth, '(', ')', true),
        CountValue::Dict(entries) => render_dict(entries, depth),
        CountValue::Other { rendered, .. } => rendered.clone(),
    }
}

fn render_sequence(
    items: &[CountValue],
    depth: usize,
    open: char,
    close: char,
    tuple: bool,
) -> String {
    let mut out = String::new();
    out.push(open);
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&repr_value(item, depth + 1));
    }
    if tuple && items.len() == 1 {
        out.push(',');
    }
    out.push(close);
    out
}

fn render_dict(entries: &[(CountKey, CountValue)], depth: usize) -> String {
    let mut out = String::from("{");
    for (index, (key, value)) in entries.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_repr_key(key));
        out.push_str(": ");
        out.push_str(&repr_value(value, depth + 1));
    }
    out.push('}');
    out
}

fn python_repr_key(key: &CountKey) -> String {
    match key {
        CountKey::None => "None".to_owned(),
        CountKey::Bool(true) => "True".to_owned(),
        CountKey::Bool(false) => "False".to_owned(),
        CountKey::Int(number) => number.to_string(),
        CountKey::Str(text) => python_str_repr(text),
    }
}

fn python_str_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in text.chars() {
        if ch == '\\' {
            out.push_str("\\\\");
        } else if ch == quote {
            out.push('\\');
            out.push(quote);
        } else if ch == '\t' {
            out.push_str("\\t");
        } else if ch == '\n' {
            out.push_str("\\n");
        } else if ch == '\r' {
            out.push_str("\\r");
        } else if is_repr_printable(ch) {
            out.push(ch);
        } else {
            push_escaped(&mut out, ch);
        }
    }
    out.push(quote);
    out
}

fn is_repr_printable(ch: char) -> bool {
    if ch == ' ' {
        return true;
    }
    if ch.is_ascii() {
        return ch.is_ascii_graphic();
    }
    !ch.is_control() && !ch.is_whitespace() && !is_private_use(ch) && !is_format_char(ch)
}

fn is_private_use(ch: char) -> bool {
    matches!(
        u32::from(ch),
        0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD
    )
}

fn is_format_char(ch: char) -> bool {
    matches!(
        u32::from(ch),
        0x00AD
            | 0x061C
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
    )
}

fn push_escaped(out: &mut String, ch: char) {
    let code = u32::from(ch);
    if code < 0x100 {
        push_hex(out, "\\x", code, 2);
    } else if code < 0x10000 {
        push_hex(out, "\\u", code, 4);
    } else {
        push_hex(out, "\\U", code, 8);
    }
}

fn push_hex(out: &mut String, prefix: &str, code: u32, width: usize) {
    out.push_str(prefix);
    let digits = format!("{code:x}");
    let pad = width.saturating_sub(digits.len());
    for _ in 0..pad {
        out.push('0');
    }
    out.push_str(&digits);
}

/// The three strings `_skip_sort_key` reads.
///
/// [`skip_sort_key`] does not validate them. [`CoverageSkip::try_new`] does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkipSortFields<'a> {
    pub check: &'a str,
    pub reason: &'a str,
    pub detail: &'a str,
}

/// Python: `_skip_sort_key`.
///
/// The tuple order is `check`, then `reason`, then `detail`.
#[must_use]
pub fn skip_sort_key(skip: SkipSortFields<'_>) -> (&str, &str, &str) {
    (skip.check, skip.reason, skip.detail)
}

/// Failure from [`CoverageSkip::try_new`], [`Coverage::try_new`], [`Report::try_new`],
/// [`default_coverage`], [`RepairAction::try_new`], [`RevalidationSummary::try_new`],
/// [`RepairManifest::try_new`], or [`build_report`].
///
/// [`Display`](fmt::Display) is the Python exception message. [`Self::Unavailable`]
/// displays `{module.function} is not available`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    Schema(SchemaError),
    Version(VersionError),
    Assurance(AssuranceError),
    ContentLeak(ContentLeakError),
    /// Python `TypeError` from sorting mixed binding keys. The string is `str(exc)`.
    TypeMismatch(String),
    /// Late import that this crate cannot call. The string is `module.function`.
    Unavailable(&'static str),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(error) => write!(formatter, "{error}"),
            Self::Version(error) => write!(formatter, "{error}"),
            Self::Assurance(error) => write!(formatter, "{error}"),
            Self::ContentLeak(error) => write!(formatter, "{error}"),
            Self::TypeMismatch(message) => formatter.write_str(message),
            Self::Unavailable(name) => write!(formatter, "{name} is not available"),
        }
    }
}

impl Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Schema(error) => Some(error),
            Self::Version(error) => Some(error),
            Self::Assurance(error) => Some(error),
            Self::ContentLeak(error) => Some(error),
            Self::TypeMismatch(_) | Self::Unavailable(_) => None,
        }
    }
}

impl EnvelopeError {
    fn unavailable() -> Self {
        Self::Unavailable(PROFILES_BUILTIN_ALL_RULES)
    }
}

/// Python object passed into coverage and report constructors.
///
/// Wrong types stay representable so the `isinstance` checks can fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputValue {
    None,
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<InputValue>),
    Tuple(Vec<InputValue>),
    Set(Vec<InputValue>),
    FrozenSet(Vec<InputValue>),
    Dict(Vec<(InputKey, InputValue)>),
    Other { type_name: String, rendered: String },
}

/// Hashable key [`InputValue::Dict`] can see.
///
/// Bool and int keys compare equal when Python would (`True` with `1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputKey {
    None,
    Bool(bool),
    Int(i64),
    Str(String),
}

impl InputKey {
    pub fn bool_value(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn int(value: i64) -> Self {
        Self::Int(value)
    }

    pub fn str_key(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }
}

impl InputValue {
    pub fn bool_value(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn int(value: i64) -> Self {
        Self::Int(value)
    }

    pub fn str_value(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn list(items: Vec<Self>) -> Self {
        Self::List(items)
    }

    pub fn tuple(items: Vec<Self>) -> Self {
        Self::Tuple(items)
    }

    pub fn set(items: Vec<Self>) -> Self {
        Self::Set(items)
    }

    pub fn dict(entries: Vec<(InputKey, Self)>) -> Self {
        Self::Dict(entries)
    }

    pub fn other(type_name: impl Into<String>, rendered: impl Into<String>) -> Self {
        Self::Other {
            type_name: type_name.into(),
            rendered: rendered.into(),
        }
    }
}

/// One skipped entry. A non-skip keeps the value so set dedupe can use Python equality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipElem {
    Skip(CoverageSkip),
    Wrong(InputValue),
}

/// `Coverage.skipped`: list, tuple, or set. Anything else is [`SkipSeq::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipSeq {
    List(Vec<SkipElem>),
    Tuple(Vec<SkipElem>),
    Set(Vec<SkipElem>),
    Other { type_name: String },
}

/// `Report.findings`. Only a tuple is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingsInput {
    Tuple(Vec<FindingElem>),
    WrongType { type_name: String },
}

/// One findings element. The error text uses the type name only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingElem {
    Finding(Finding),
    Wrong { type_name: String },
}

/// `Report.counts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CountsInput {
    Value(Counts),
    WrongType { type_name: String },
}

/// `Report.coverage`. [`CoverageInput::Default`] calls [`default_coverage`]
/// before the other checks, matching the dataclass default factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageInput<'a> {
    Value(&'a Coverage),
    WrongType { type_name: &'a str },
    Default,
}

/// Fields for [`Report::try_new`]. Rust has no dataclass defaults; pass
/// [`CoverageInput::Default`] to take the Python default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportParts<'a> {
    pub schema_version: &'a InputValue,
    pub session_id: &'a InputValue,
    pub source_fingerprint: &'a InputValue,
    pub tool_version: &'a InputValue,
    pub findings: &'a FindingsInput,
    pub counts: &'a CountsInput,
    pub assurance: &'a InputValue,
    pub limitation: &'a InputValue,
    pub coverage: CoverageInput<'a>,
}

/// Python: `CoverageSkip.to_dict` field order (`check`, `detail`, `reason`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageSkipDict {
    pub check: String,
    pub detail: String,
    pub reason: String,
}

/// Python: `Coverage.to_dict` field order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageDict {
    pub adapter: Vec<(String, InputValue)>,
    pub performed: Vec<String>,
    pub profile: Vec<(String, InputValue)>,
    pub skipped: Vec<CoverageSkipDict>,
}

/// Python: `Report.to_dict` field order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportDict {
    pub assurance: String,
    pub counts: CountsDict,
    pub coverage: CoverageDict,
    pub findings: Vec<Vec<(&'static str, DictValue)>>,
    pub limitation: String,
    pub schema_version: String,
    pub session_id: String,
    pub source_fingerprint: String,
    pub tool_version: String,
}

/// Python: `CoverageSkip`.
///
/// `check` and `detail` are stored stripped. `reason` is stored unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageSkip {
    check: String,
    reason: String,
    detail: String,
}

impl CoverageSkip {
    /// Validate in the pinned `__post_init__` order.
    pub fn try_new(
        check: &InputValue,
        reason: &InputValue,
        detail: &InputValue,
    ) -> Result<Self, EnvelopeError> {
        let InputValue::Str(raw_check) = check else {
            return Err(schema_env(format!(
                "CoverageSkip.check must be a non-empty string, got {}",
                input_repr(check)
            )));
        };
        if python_strip(raw_check).is_empty() {
            return Err(schema_env(format!(
                "CoverageSkip.check must be a non-empty string, got {}",
                input_repr(check)
            )));
        }
        let InputValue::Str(raw_reason) = reason else {
            return Err(invalid_reason(reason));
        };
        if !VALID_COVERAGE_SKIP_REASONS.contains(&raw_reason.as_str()) {
            return Err(invalid_reason(reason));
        }
        let InputValue::Str(raw_detail) = detail else {
            return Err(schema_env(format!(
                "CoverageSkip.detail must be a string, got {}",
                input_type_name(detail)
            )));
        };
        let norm_check = python_strip(raw_check).to_owned();
        let norm_detail = python_strip(raw_detail).to_owned();
        reject_intrinsic_leak(&norm_check, "CoverageSkip.check")?;
        reject_intrinsic_leak(&norm_detail, "CoverageSkip.detail")?;
        Ok(Self {
            check: norm_check,
            reason: raw_reason.clone(),
            detail: norm_detail,
        })
    }

    #[must_use]
    pub fn check(&self) -> &str {
        &self.check
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    #[must_use]
    pub fn to_dict(&self) -> CoverageSkipDict {
        CoverageSkipDict {
            check: self.check.clone(),
            detail: self.detail.clone(),
            reason: self.reason.clone(),
        }
    }

    fn sort_fields(&self) -> (&str, &str, &str) {
        skip_sort_key(SkipSortFields {
            check: &self.check,
            reason: &self.reason,
            detail: &self.detail,
        })
    }
}

impl PartialOrd for CoverageSkip {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CoverageSkip {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sort_fields().cmp(&other.sort_fields())
    }
}

/// Python: `Coverage`.
///
/// `performed` is sorted code point order and keeps duplicates from a list or
/// tuple. A set drops values that compare equal. `skipped` is sorted by
/// [`skip_sort_key`]. Adapter and profile keep caller order unless `id` was
/// copied from `name`, in which case the pairs are sorted.
#[derive(Debug, Clone)]
pub struct Coverage {
    performed: Vec<String>,
    skipped: Vec<CoverageSkip>,
    adapter: Vec<(InputKey, InputValue)>,
    profile: Vec<(InputKey, InputValue)>,
}

impl PartialEq for Coverage {
    fn eq(&self, other: &Self) -> bool {
        self.performed == other.performed
            && self.skipped == other.skipped
            && bindings_eq(&self.adapter, &other.adapter)
            && bindings_eq(&self.profile, &other.profile)
    }
}

impl Eq for Coverage {}

impl Coverage {
    /// Validate in the pinned `__post_init__` order.
    pub fn try_new(
        performed: &InputValue,
        skipped: &SkipSeq,
        adapter: &InputValue,
        profile: &InputValue,
    ) -> Result<Self, EnvelopeError> {
        let performed = normalize_performed(performed)?;
        let skipped = normalize_skipped(skipped)?;
        let adapter = normalize_binding(adapter, "Coverage.adapter")?;
        let profile = normalize_binding(profile, "Coverage.profile")?;
        Ok(Self {
            performed,
            skipped,
            adapter,
            profile,
        })
    }

    #[must_use]
    pub fn performed(&self) -> &[String] {
        &self.performed
    }

    #[must_use]
    pub fn skipped(&self) -> &[CoverageSkip] {
        &self.skipped
    }

    /// Stored adapter pairs. Order matches Python when every key is a string
    /// and `id` was not synthesized. See [`BINDING_SORT_DEVIATION`].
    #[must_use]
    pub fn adapter_items(&self) -> &[(InputKey, InputValue)] {
        &self.adapter
    }

    #[must_use]
    pub fn profile_items(&self) -> &[(InputKey, InputValue)] {
        &self.profile
    }

    #[must_use]
    pub fn to_dict(&self) -> CoverageDict {
        let mut skipped = self.skipped.clone();
        skipped.sort();
        CoverageDict {
            adapter: public_binding(&self.adapter),
            performed: self.performed.clone(),
            profile: public_binding(&self.profile),
            skipped: skipped.iter().map(CoverageSkip::to_dict).collect(),
        }
    }
}

/// Python: `_default_coverage`.
///
/// The body starts with `from sesslint.profiles.builtin import ALL_RULES`.
/// That symbol is not callable from this crate, so this returns
/// [`EnvelopeError::Unavailable`] and does not invent a rule list.
pub fn default_coverage() -> Result<Coverage, EnvelopeError> {
    Err(EnvelopeError::unavailable())
}

/// Python: `Report`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    schema_version: String,
    session_id: String,
    source_fingerprint: String,
    tool_version: String,
    findings: Vec<Finding>,
    counts: Counts,
    assurance: String,
    limitation: String,
    coverage: Coverage,
}

impl Report {
    /// Validate in the pinned `__post_init__` order.
    ///
    /// [`CoverageInput::Default`] fails closed before those checks.
    pub fn try_new(parts: ReportParts<'_>) -> Result<Self, EnvelopeError> {
        if matches!(parts.coverage, CoverageInput::Default) {
            return Err(EnvelopeError::unavailable());
        }
        let schema_version = require_schema_version(parts.schema_version)?;
        let session_id = require_non_empty_str(parts.session_id, "Report.session_id")?;
        let source_fingerprint =
            require_non_empty_str(parts.source_fingerprint, "Report.source_fingerprint")?;
        let tool_version = require_non_empty_str(parts.tool_version, "Report.tool_version")?;
        let assurance = require_assurance(parts.assurance)?;
        let limitation = require_limitation(parts.limitation, &assurance)?;
        let coverage = match parts.coverage {
            CoverageInput::Value(coverage) => coverage.clone(),
            CoverageInput::WrongType { type_name } => {
                return Err(schema_env(format!(
                    "Report.coverage must be a Coverage instance, got {type_name}"
                )));
            }
            CoverageInput::Default => return Err(EnvelopeError::unavailable()),
        };
        let findings = require_findings(parts.findings)?;
        let counts = require_counts(parts.counts, &findings)?;
        Ok(Self {
            schema_version,
            session_id,
            source_fingerprint,
            tool_version,
            findings,
            counts,
            assurance,
            limitation,
            coverage,
        })
    }

    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    #[must_use]
    pub fn tool_version(&self) -> &str {
        &self.tool_version
    }

    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    #[must_use]
    pub fn counts(&self) -> &Counts {
        &self.counts
    }

    #[must_use]
    pub fn assurance(&self) -> &str {
        &self.assurance
    }

    #[must_use]
    pub fn limitation(&self) -> &str {
        &self.limitation
    }

    #[must_use]
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    #[must_use]
    pub fn to_dict(&self) -> ReportDict {
        ReportDict {
            assurance: self.assurance.clone(),
            counts: self.counts.to_dict(),
            coverage: self.coverage.to_dict(),
            findings: self.findings.iter().map(Finding::to_dict).collect(),
            limitation: self.limitation.clone(),
            schema_version: self.schema_version.clone(),
            session_id: self.session_id.clone(),
            source_fingerprint: self.source_fingerprint.clone(),
            tool_version: self.tool_version.clone(),
        }
    }
}

/// The four strings `_action_sort_key` reads.
///
/// [`action_sort_key`] does not validate them. [`RepairAction::try_new`] does.
/// `None` and `Some("")` stay distinct: only `None` uses the `(0, "")` record
/// key. A constructed [`RepairAction`] never stores an empty `record_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionSortFields<'a> {
    pub kind: &'a str,
    pub record_id: Option<&'a str>,
    pub detail: &'a str,
}

/// Python: `_action_sort_key`.
///
/// The tuple is `kind`, then `0` when `record_id` is `None` or `1` otherwise,
/// then the record id or `""`, then `detail`.
#[must_use]
pub fn action_sort_key(action: ActionSortFields<'_>) -> (&str, i64, &str, &str) {
    match action.record_id {
        None => (action.kind, 0, "", action.detail),
        Some(record_id) => (action.kind, 1, record_id, action.detail),
    }
}

/// Python: `RepairAction.to_dict` field order (`kind`, `record_id`, `detail`).
///
/// `record_id` is present even when it is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairActionDict {
    pub kind: String,
    pub record_id: Option<String>,
    pub detail: String,
}

/// Python: `RepairAction`.
///
/// `kind`, `record_id`, and `detail` are stored stripped. `record_id` stays
/// `None` when the caller passes `None`. Ordering uses [`action_sort_key`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairAction {
    kind: String,
    record_id: Option<String>,
    detail: String,
}

impl RepairAction {
    /// Validate in the pinned `__post_init__` order.
    ///
    /// Python defaults, which Rust does not infer: `record_id` is `None` and
    /// `detail` is `""`. Pass [`InputValue::None`] and an empty string for those.
    pub fn try_new(
        kind: &InputValue,
        record_id: &InputValue,
        detail: &InputValue,
    ) -> Result<Self, EnvelopeError> {
        let kind = match kind {
            InputValue::Str(text) if !python_strip(text).is_empty() => {
                python_strip(text).to_owned()
            }
            other => {
                return Err(schema_env(format!(
                    "RepairAction.kind must be a non-empty string, got {}",
                    input_repr(other)
                )));
            }
        };
        reject_intrinsic_leak(&kind, "RepairAction.kind")?;

        let record_id = if matches!(record_id, InputValue::None) {
            None
        } else {
            let normalized = match record_id {
                InputValue::Str(text) if !python_strip(text).is_empty() => {
                    python_strip(text).to_owned()
                }
                other => {
                    return Err(schema_env(format!(
                        "RepairAction.record_id must be non-empty string or None, got {}",
                        input_repr(other)
                    )));
                }
            };
            reject_intrinsic_leak(&normalized, "RepairAction.record_id")?;
            Some(normalized)
        };

        let detail = match detail {
            InputValue::Str(text) => python_strip(text).to_owned(),
            other => {
                return Err(schema_env(format!(
                    "RepairAction.detail must be a string, got {}",
                    input_type_name(other)
                )));
            }
        };
        reject_intrinsic_leak(&detail, "RepairAction.detail")?;

        Ok(Self {
            kind,
            record_id,
            detail,
        })
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn record_id(&self) -> Option<&str> {
        self.record_id.as_deref()
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    #[must_use]
    pub fn to_dict(&self) -> RepairActionDict {
        RepairActionDict {
            kind: self.kind.clone(),
            record_id: self.record_id.clone(),
            detail: self.detail.clone(),
        }
    }

    fn sort_key(&self) -> (&str, i64, &str, &str) {
        action_sort_key(ActionSortFields {
            kind: &self.kind,
            record_id: self.record_id.as_deref(),
            detail: &self.detail,
        })
    }
}

impl PartialOrd for RepairAction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RepairAction {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

/// Python: `RevalidationSummary.to_dict` insertion order.
///
/// `warning_count` stays before an optional `report_fingerprint`. `None` means
/// the Python dict omits `report_fingerprint`. The keys are not re-sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevalidationSummaryDict {
    pub assurance: String,
    pub error_count: i64,
    pub profile_id: String,
    pub profile_version: String,
    pub warning_count: i64,
    pub report_fingerprint: Option<String>,
}

/// Python: `RevalidationSummary`.
///
/// Assurance is an exact [`VALID_ASSURANCE_LEVELS`] member. Counts are Python
/// `int` values in the `i64` range, and `bool` is rejected. Profile strings and
/// `report_fingerprint` are stored unchanged when `strip()` is non-empty.
/// This class does not call [`enforce_content_free_text`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevalidationSummary {
    assurance: String,
    error_count: i64,
    warning_count: i64,
    profile_id: String,
    profile_version: String,
    report_fingerprint: Option<String>,
}

impl RevalidationSummary {
    /// Validate in the pinned `__post_init__` order.
    ///
    /// Python default, which Rust does not infer: `report_fingerprint` is
    /// `None`. Pass [`InputValue::None`] for that default.
    pub fn try_new(
        assurance: &InputValue,
        error_count: &InputValue,
        warning_count: &InputValue,
        profile_id: &InputValue,
        profile_version: &InputValue,
        report_fingerprint: &InputValue,
    ) -> Result<Self, EnvelopeError> {
        let assurance = match assurance {
            InputValue::Str(text) if VALID_ASSURANCE_LEVELS.contains(&text.as_str()) => {
                text.clone()
            }
            other => {
                return Err(EnvelopeError::Assurance(AssuranceError::new(format!(
                    "Invalid revalidation assurance {}. Must be one of {}",
                    input_repr(other),
                    sorted_assurance_repr()
                ))));
            }
        };
        let error_count = Self::non_negative_count(error_count, "error_count")?;
        let warning_count = Self::non_negative_count(warning_count, "warning_count")?;
        let profile_id = Self::kept_non_empty(profile_id, "profile_id")?;
        let profile_version = Self::kept_non_empty(profile_version, "profile_version")?;
        let report_fingerprint = Self::optional_fingerprint(report_fingerprint)?;
        Ok(Self {
            assurance,
            error_count,
            warning_count,
            profile_id,
            profile_version,
            report_fingerprint,
        })
    }

    #[must_use]
    pub fn assurance(&self) -> &str {
        &self.assurance
    }

    #[must_use]
    pub fn error_count(&self) -> i64 {
        self.error_count
    }

    #[must_use]
    pub fn warning_count(&self) -> i64 {
        self.warning_count
    }

    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    #[must_use]
    pub fn profile_version(&self) -> &str {
        &self.profile_version
    }

    /// `None` when the caller passed `None`. The stored string is not stripped.
    #[must_use]
    pub fn report_fingerprint(&self) -> Option<&str> {
        self.report_fingerprint.as_deref()
    }

    #[must_use]
    pub fn to_dict(&self) -> RevalidationSummaryDict {
        RevalidationSummaryDict {
            assurance: self.assurance.clone(),
            error_count: self.error_count,
            profile_id: self.profile_id.clone(),
            profile_version: self.profile_version.clone(),
            warning_count: self.warning_count,
            report_fingerprint: self.report_fingerprint.clone(),
        }
    }

    fn non_negative_count(value: &InputValue, field: &str) -> Result<i64, EnvelopeError> {
        match value {
            InputValue::Int(number) if *number >= 0 => Ok(*number),
            other => Err(schema_env(format!(
                "RevalidationSummary.{field} must be non-negative integer, got {}",
                input_repr(other)
            ))),
        }
    }

    fn kept_non_empty(value: &InputValue, field: &str) -> Result<String, EnvelopeError> {
        match value {
            InputValue::Str(text) if !python_strip(text).is_empty() => Ok(text.clone()),
            other => Err(schema_env(format!(
                "RevalidationSummary.{field} must be a non-empty string, got {}",
                input_repr(other)
            ))),
        }
    }

    fn optional_fingerprint(value: &InputValue) -> Result<Option<String>, EnvelopeError> {
        match value {
            InputValue::None => Ok(None),
            InputValue::Str(text) if !python_strip(text).is_empty() => Ok(Some(text.clone())),
            _ => Err(schema_env(
                "RevalidationSummary.report_fingerprint must be a non-empty string or None"
                    .to_owned(),
            )),
        }
    }
}

fn invalid_reason(reason: &InputValue) -> EnvelopeError {
    schema_env(format!(
        "CoverageSkip.reason must be one of {}, got {}",
        sorted_reasons_repr(),
        input_repr(reason)
    ))
}

fn reject_intrinsic_leak(text: &str, field: &str) -> Result<(), EnvelopeError> {
    match enforce_content_free_text(text, field) {
        Ok(()) => Ok(()),
        Err(error) => Err(EnvelopeError::ContentLeak(ContentLeakError::new(format!(
            "Intrinsic content leak in {field}: {error}"
        )))),
    }
}

fn normalize_performed(value: &InputValue) -> Result<Vec<String>, EnvelopeError> {
    let items = match value {
        InputValue::List(items) | InputValue::Tuple(items) => items.clone(),
        InputValue::Set(items) => dedupe_values(items),
        other => {
            return Err(schema_env(format!(
                "Coverage.performed must be a sequence of strings, got {}",
                input_type_name(other)
            )));
        }
    };
    let mut performed = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match item {
            InputValue::Str(text) if !python_strip(text).is_empty() => {
                performed.push(text.clone());
            }
            other => {
                return Err(schema_env(format!(
                    "Coverage.performed[{index}] must be a non-empty string, got {}",
                    input_repr(other)
                )));
            }
        }
    }
    performed.sort();
    Ok(performed)
}

fn normalize_skipped(value: &SkipSeq) -> Result<Vec<CoverageSkip>, EnvelopeError> {
    let items = match value {
        SkipSeq::List(items) | SkipSeq::Tuple(items) => items.clone(),
        SkipSeq::Set(items) => dedupe_skips(items),
        SkipSeq::Other { type_name } => {
            return Err(schema_env(format!(
                "Coverage.skipped must be a sequence of CoverageSkip, got {type_name}"
            )));
        }
    };
    let mut skipped = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match item {
            SkipElem::Skip(skip) => skipped.push(skip.clone()),
            SkipElem::Wrong(wrong) => {
                return Err(schema_env(format!(
                    "Coverage.skipped[{index}] must be a CoverageSkip instance, got {}",
                    input_type_name(wrong)
                )));
            }
        }
    }
    skipped.sort();
    Ok(skipped)
}

fn normalize_binding(
    value: &InputValue,
    label: &str,
) -> Result<Vec<(InputKey, InputValue)>, EnvelopeError> {
    let InputValue::Dict(entries) = value else {
        return Err(schema_env(format!(
            "{label} must be a Mapping, got {}",
            input_type_name(value)
        )));
    };
    let mut collapsed = collapse_pairs(entries);
    let mut added_id = false;
    if str_key_index(&collapsed, "id").is_none() {
        if let Some(index) = str_key_index(&collapsed, "name") {
            let name_value = collapsed[index].1.clone();
            collapsed.push((InputKey::str_key("id"), name_value));
            added_id = true;
        }
    }
    if str_key_index(&collapsed, "id").is_none() {
        return Err(schema_env(format!("{label} must contain 'id'")));
    }
    if str_key_index(&collapsed, "version").is_none() {
        return Err(schema_env(format!("{label} must contain 'version'")));
    }
    if added_id {
        python_sort_pairs(&mut collapsed).map_err(EnvelopeError::TypeMismatch)?;
    }
    Ok(collapsed)
}

fn require_schema_version(value: &InputValue) -> Result<String, EnvelopeError> {
    if let InputValue::Str(text) = value {
        if text == REPORT_SCHEMA_VERSION {
            return Ok(text.clone());
        }
    }
    let version = match value {
        InputValue::Str(text) => Some(text.clone()),
        _ => None,
    };
    let message = format!(
        "Report.schema_version must be {}, got {}",
        python_str_repr(REPORT_SCHEMA_VERSION),
        input_repr(value)
    );
    Err(EnvelopeError::Version(VersionError::new(message, version)))
}

fn require_non_empty_str(value: &InputValue, label: &str) -> Result<String, EnvelopeError> {
    match value {
        InputValue::Str(text) if !python_strip(text).is_empty() => Ok(text.clone()),
        other => Err(schema_env(format!(
            "{label} must be a non-empty string, got {}",
            input_repr(other)
        ))),
    }
}

fn require_assurance(value: &InputValue) -> Result<String, EnvelopeError> {
    if let InputValue::Str(text) = value {
        if VALID_ASSURANCE_LEVELS.contains(&text.as_str()) {
            return Ok(text.clone());
        }
    }
    Err(EnvelopeError::Assurance(AssuranceError::new(format!(
        "Report.assurance must be one of {}, got {}",
        sorted_assurance_repr(),
        input_repr(value)
    ))))
}

fn require_limitation(value: &InputValue, assurance: &str) -> Result<String, EnvelopeError> {
    match value {
        InputValue::Str(text) if !python_strip(text).is_empty() => Ok(text.clone()),
        _ => Err(EnvelopeError::Assurance(AssuranceError::new(format!(
            "Report.limitation is required and must be non-empty for assurance level {}",
            python_str_repr(assurance)
        )))),
    }
}

fn require_findings(value: &FindingsInput) -> Result<Vec<Finding>, EnvelopeError> {
    let FindingsInput::Tuple(items) = value else {
        let type_name = match value {
            FindingsInput::WrongType { type_name } => type_name.as_str(),
            FindingsInput::Tuple(_) => "tuple",
        };
        return Err(schema_env(format!(
            "Report.findings must be a tuple, got {type_name}"
        )));
    };
    let mut findings = Vec::new();
    for (index, item) in items.iter().enumerate() {
        match item {
            FindingElem::Finding(finding) => findings.push(finding.clone()),
            FindingElem::Wrong { type_name } => {
                return Err(schema_env(format!(
                    "Report.findings[{index}] must be a Finding instance, got {type_name}"
                )));
            }
        }
    }
    Ok(findings)
}

fn require_counts(value: &CountsInput, findings: &[Finding]) -> Result<Counts, EnvelopeError> {
    let CountsInput::Value(counts) = value else {
        let type_name = match value {
            CountsInput::WrongType { type_name } => type_name.as_str(),
            CountsInput::Value(_) => "Counts",
        };
        return Err(schema_env(format!(
            "Report.counts must be a Counts instance, got {type_name}"
        )));
    };
    let found = match i64::try_from(findings.len()) {
        Ok(found) => found,
        Err(_) => {
            return Err(schema_env(format!(
                "Counts.total ({}) does not match findings count ({})",
                counts.total(),
                findings.len()
            )));
        }
    };
    if counts.total() != found {
        return Err(schema_env(format!(
            "Counts.total ({}) does not match findings count ({found})",
            counts.total()
        )));
    }
    let mut expected_sev = [0_i64; 4];
    let mut expected_codes: BTreeMap<String, i64> = BTreeMap::new();
    for finding in findings {
        let slot = severity_slot(finding.severity());
        match expected_sev[slot].checked_add(1) {
            Some(next) => expected_sev[slot] = next,
            None => {
                return Err(schema_env(
                    "finding severity count does not fit in i64".to_owned(),
                ));
            }
        }
        let code = finding.code().to_owned();
        let next = match expected_codes.get(&code).copied() {
            Some(count) => match count.checked_add(1) {
                Some(next) => next,
                None => {
                    return Err(schema_env(
                        "finding code count does not fit in i64".to_owned(),
                    ));
                }
            },
            None => 1,
        };
        expected_codes.insert(code, next);
    }
    let actual_sev =
        REQUIRED_SEVERITIES.map(|name| counts.severity_count(name).unwrap_or_default());
    if actual_sev != expected_sev {
        return Err(schema_env(format!(
            "Counts.by_severity ({}) does not match findings severity distribution ({})",
            format_severity_counts(actual_sev),
            format_severity_counts(expected_sev)
        )));
    }
    if !same_code_counts(counts.code_items(), &expected_codes) {
        return Err(schema_env(format!(
            "Counts.by_code ({}) does not match findings code distribution ({})",
            format_code_counts(counts.code_items()),
            format_code_counts_map(&expected_codes)
        )));
    }
    Ok(counts.clone())
}

fn severity_slot(severity: Severity) -> usize {
    match severity {
        Severity::Fatal => 0,
        Severity::Error => 1,
        Severity::Warning => 2,
        Severity::Info => 3,
    }
}

fn same_code_counts(actual: &[(String, i64)], expected: &BTreeMap<String, i64>) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .iter()
        .all(|(code, count)| expected.get(code) == Some(count))
}

fn format_severity_counts(counts: [i64; 4]) -> String {
    let mut out = String::from("{");
    for (index, name) in REQUIRED_SEVERITIES.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(name));
        out.push_str(": ");
        out.push_str(&counts[index].to_string());
    }
    out.push('}');
    out
}

fn format_code_counts(pairs: &[(String, i64)]) -> String {
    if pairs.is_empty() {
        return "{}".to_owned();
    }
    let mut out = String::from("{");
    for (index, (code, count)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(code));
        out.push_str(": ");
        out.push_str(&count.to_string());
    }
    out.push('}');
    out
}

fn format_code_counts_map(pairs: &BTreeMap<String, i64>) -> String {
    let owned: Vec<(String, i64)> = pairs
        .iter()
        .map(|(code, count)| (code.clone(), *count))
        .collect();
    format_code_counts(&owned)
}

fn public_binding(entries: &[(InputKey, InputValue)]) -> Vec<(String, InputValue)> {
    let mut out = Vec::new();
    for name in ["id", "version", "name"] {
        if let Some(value) = lookup_str(entries, name) {
            out.push((name.to_owned(), value));
        }
    }
    out.sort_by(|left, right| left.0.cmp(&right.0));
    out
}

fn lookup_str(entries: &[(InputKey, InputValue)], name: &str) -> Option<InputValue> {
    let index = str_key_index(entries, name)?;
    Some(entries[index].1.clone())
}

fn str_key_index(entries: &[(InputKey, InputValue)], name: &str) -> Option<usize> {
    entries
        .iter()
        .position(|(key, _)| matches!(key, InputKey::Str(text) if text == name))
}

fn dedupe_values(items: &[InputValue]) -> Vec<InputValue> {
    let mut unique = Vec::new();
    for item in items {
        if unique.iter().any(|existing| py_eq(existing, item)) {
            continue;
        }
        unique.push(item.clone());
    }
    unique
}

fn dedupe_skips(items: &[SkipElem]) -> Vec<SkipElem> {
    let mut unique = Vec::new();
    for item in items {
        if unique.iter().any(|existing| skip_eq(existing, item)) {
            continue;
        }
        unique.push(item.clone());
    }
    unique
}

fn skip_eq(left: &SkipElem, right: &SkipElem) -> bool {
    match (left, right) {
        (SkipElem::Skip(left_skip), SkipElem::Skip(right_skip)) => left_skip == right_skip,
        (SkipElem::Wrong(left_value), SkipElem::Wrong(right_value)) => {
            py_eq(left_value, right_value)
        }
        _ => false,
    }
}

fn collapse_pairs(entries: &[(InputKey, InputValue)]) -> Vec<(InputKey, InputValue)> {
    let mut collapsed: Vec<(InputKey, InputValue)> = Vec::new();
    for (key, value) in entries {
        let mut replaced = false;
        for existing in &mut collapsed {
            if input_key_eq(&existing.0, key) {
                existing.1 = value.clone();
                replaced = true;
                break;
            }
        }
        if !replaced {
            collapsed.push((key.clone(), value.clone()));
        }
    }
    collapsed
}

fn bindings_eq(left: &[(InputKey, InputValue)], right: &[(InputKey, InputValue)]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    pairs_cover(left, right) && pairs_cover(right, left)
}

fn pairs_cover(left: &[(InputKey, InputValue)], right: &[(InputKey, InputValue)]) -> bool {
    left.iter().all(|(key, value)| {
        right.iter().any(|(other_key, other_value)| {
            input_key_eq(key, other_key) && py_eq(value, other_value)
        })
    })
}

fn input_key_eq(left: &InputKey, right: &InputKey) -> bool {
    if let (Some(left_number), Some(right_number)) =
        (numeric_input_key(left), numeric_input_key(right))
    {
        return left_number == right_number;
    }
    match (left, right) {
        (InputKey::None, InputKey::None) => true,
        (InputKey::Str(left_text), InputKey::Str(right_text)) => left_text == right_text,
        _ => false,
    }
}

fn numeric_input_key(key: &InputKey) -> Option<i64> {
    match key {
        InputKey::Int(number) => Some(*number),
        InputKey::Bool(true) => Some(1),
        InputKey::Bool(false) => Some(0),
        InputKey::None | InputKey::Str(_) => None,
    }
}

fn py_eq(left: &InputValue, right: &InputValue) -> bool {
    if let (Some(left_number), Some(right_number)) =
        (numeric_input_value(left), numeric_input_value(right))
    {
        return left_number == right_number;
    }
    match (left, right) {
        (InputValue::None, InputValue::None) => true,
        (InputValue::Str(left_text), InputValue::Str(right_text)) => left_text == right_text,
        (InputValue::List(left_items), InputValue::List(right_items))
        | (InputValue::Tuple(left_items), InputValue::Tuple(right_items)) => {
            left_items.len() == right_items.len()
                && left_items
                    .iter()
                    .zip(right_items.iter())
                    .all(|(left_item, right_item)| py_eq(left_item, right_item))
        }
        (InputValue::Set(left_items), InputValue::Set(right_items))
        | (InputValue::FrozenSet(left_items), InputValue::FrozenSet(right_items)) => {
            set_covers(left_items, right_items) && set_covers(right_items, left_items)
        }
        (InputValue::Dict(left_entries), InputValue::Dict(right_entries)) => {
            bindings_eq(left_entries, right_entries)
        }
        (
            InputValue::Other {
                type_name: left_type,
                rendered: left_rendered,
            },
            InputValue::Other {
                type_name: right_type,
                rendered: right_rendered,
            },
        ) => left_type == right_type && left_rendered == right_rendered,
        _ => false,
    }
}

fn set_covers(left: &[InputValue], right: &[InputValue]) -> bool {
    left.iter()
        .all(|item| right.iter().any(|other| py_eq(item, other)))
}

fn numeric_input_value(value: &InputValue) -> Option<i64> {
    match value {
        InputValue::Int(number) => Some(*number),
        InputValue::Bool(true) => Some(1),
        InputValue::Bool(false) => Some(0),
        InputValue::None
        | InputValue::Str(_)
        | InputValue::List(_)
        | InputValue::Tuple(_)
        | InputValue::Set(_)
        | InputValue::FrozenSet(_)
        | InputValue::Dict(_)
        | InputValue::Other { .. } => None,
    }
}

fn python_sort_pairs(items: &mut [(InputKey, InputValue)]) -> Result<(), String> {
    if items.len() < 2 {
        return Ok(());
    }
    let run = count_run(items)?;
    binary_sort(items, run)
}

fn count_run(items: &mut [(InputKey, InputValue)]) -> Result<usize, String> {
    let descending = key_is_lt(&items[1].0, &items[0].0)?;
    if descending {
        let mut end = 2;
        while end < items.len() && key_is_lt(&items[end].0, &items[end - 1].0)? {
            end += 1;
        }
        items[..end].reverse();
        Ok(end)
    } else {
        let mut end = 2;
        while end < items.len() {
            if key_is_lt(&items[end].0, &items[end - 1].0)? {
                break;
            }
            end += 1;
        }
        Ok(end)
    }
}

fn binary_sort(items: &mut [(InputKey, InputValue)], start: usize) -> Result<(), String> {
    let mut cursor = if start == 0 { 1 } else { start };
    while cursor < items.len() {
        let mut left = 0;
        let mut right = cursor;
        while left < right {
            let mid = left + ((right - left) >> 1);
            if key_is_lt(&items[cursor].0, &items[mid].0)? {
                right = mid;
            } else {
                left = mid + 1;
            }
        }
        items[left..=cursor].rotate_right(1);
        cursor += 1;
    }
    Ok(())
}

fn key_is_lt(left: &InputKey, right: &InputKey) -> Result<bool, String> {
    match cmp_keys(left, right) {
        Ok(Ordering::Less) => Ok(true),
        Ok(Ordering::Equal | Ordering::Greater) => Ok(false),
        Err(message) => Err(message),
    }
}

fn cmp_keys(left: &InputKey, right: &InputKey) -> Result<Ordering, String> {
    if let (Some(left_number), Some(right_number)) =
        (numeric_input_key(left), numeric_input_key(right))
    {
        return Ok(left_number.cmp(&right_number));
    }
    match (left, right) {
        (InputKey::Str(left_text), InputKey::Str(right_text)) => Ok(left_text.cmp(right_text)),
        (InputKey::None, InputKey::None) => Ok(Ordering::Equal),
        _ => Err(type_order_message(
            input_key_type(left),
            input_key_type(right),
        )),
    }
}

fn type_order_message(left: &str, right: &str) -> String {
    format!("'<' not supported between instances of '{left}' and '{right}'")
}

fn input_key_type(key: &InputKey) -> &'static str {
    match key {
        InputKey::None => "NoneType",
        InputKey::Bool(_) => "bool",
        InputKey::Int(_) => "int",
        InputKey::Str(_) => "str",
    }
}

fn schema_env(message: String) -> EnvelopeError {
    EnvelopeError::Schema(schema(message))
}

fn sorted_reasons_repr() -> String {
    let mut reasons = VALID_COVERAGE_SKIP_REASONS;
    reasons.sort_unstable();
    python_str_list(&reasons)
}

fn sorted_assurance_repr() -> String {
    let mut levels = VALID_ASSURANCE_LEVELS;
    levels.sort_unstable();
    python_str_list(&levels)
}

fn python_str_list(items: &[&str]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(item));
    }
    out.push(']');
    out
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

fn is_python_space(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{001C}'..='\u{001F}')
}

fn input_type_name(value: &InputValue) -> &str {
    match value {
        InputValue::None => "NoneType",
        InputValue::Bool(_) => "bool",
        InputValue::Int(_) => "int",
        InputValue::Str(_) => "str",
        InputValue::List(_) => "list",
        InputValue::Tuple(_) => "tuple",
        InputValue::Set(_) => "set",
        InputValue::FrozenSet(_) => "frozenset",
        InputValue::Dict(_) => "dict",
        InputValue::Other { type_name, .. } => type_name.as_str(),
    }
}

fn input_repr(value: &InputValue) -> String {
    input_repr_depth(value, 0)
}

fn input_repr_depth(value: &InputValue, depth: usize) -> String {
    if depth >= MAX_REPR_DEPTH {
        return "...".to_owned();
    }
    match value {
        InputValue::None => "None".to_owned(),
        InputValue::Bool(true) => "True".to_owned(),
        InputValue::Bool(false) => "False".to_owned(),
        InputValue::Int(number) => number.to_string(),
        InputValue::Str(text) => python_str_repr(text),
        InputValue::List(items) => input_sequence(items, depth, '[', ']', false),
        InputValue::Tuple(items) => input_sequence(items, depth, '(', ')', true),
        InputValue::Set(items) => input_braced("set", items, depth),
        InputValue::FrozenSet(items) => input_braced("frozenset", items, depth),
        InputValue::Dict(entries) => input_dict(entries, depth),
        InputValue::Other { rendered, .. } => rendered.clone(),
    }
}

fn input_sequence(
    items: &[InputValue],
    depth: usize,
    open: char,
    close: char,
    tuple: bool,
) -> String {
    let mut out = String::new();
    out.push(open);
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&input_repr_depth(item, depth + 1));
    }
    if tuple && items.len() == 1 {
        out.push(',');
    }
    out.push(close);
    out
}

fn input_braced(empty_name: &str, items: &[InputValue], depth: usize) -> String {
    if items.is_empty() {
        return format!("{empty_name}()");
    }
    let mut out = String::from("{");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&input_repr_depth(item, depth + 1));
    }
    out.push('}');
    out
}

fn input_dict(entries: &[(InputKey, InputValue)], depth: usize) -> String {
    if entries.is_empty() {
        return "{}".to_owned();
    }
    let mut out = String::from("{");
    for (index, (key, value)) in entries.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&input_key_repr(key));
        out.push_str(": ");
        out.push_str(&input_repr_depth(value, depth + 1));
    }
    out.push('}');
    out
}

fn input_key_repr(key: &InputKey) -> String {
    match key {
        InputKey::None => "None".to_owned(),
        InputKey::Bool(true) => "True".to_owned(),
        InputKey::Bool(false) => "False".to_owned(),
        InputKey::Int(number) => number.to_string(),
        InputKey::Str(text) => python_str_repr(text),
    }
}

/// Python: `VALID_POLICIES`. Error text sorts this set.
const VALID_POLICIES: [&str; 2] = ["conservative", "salvage"];

/// `RepairManifest.actions`. Only a tuple is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionSeq {
    Tuple(Vec<ActionElem>),
    Wrong { type_name: String },
}

/// One actions element. The error text uses the type name only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionElem {
    Action(RepairAction),
    Wrong { type_name: String },
}

/// `RepairManifest.revalidation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevalidationInput {
    Summary(RevalidationSummary),
    Wrong { type_name: String },
}

/// Fields for [`RepairManifest::try_new`].
///
/// Python defaults, which Rust does not infer: `plan_fingerprint`, `assurance`,
/// `profile_version`, `adapter_id`, and `adapter_version` are `None`.
/// `recipe_versions`, `byte_counts`, and `record_counts` are empty mappings.
/// Pass [`InputValue::None`] and [`InputValue::dict`] with no entries for those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairManifestParts<'a> {
    pub schema_version: &'a InputValue,
    pub input_fingerprint: &'a InputValue,
    pub output_fingerprint: &'a InputValue,
    pub policy: &'a InputValue,
    pub actions: &'a ActionSeq,
    pub declared_loss: &'a InputValue,
    pub revalidate_report: &'a InputValue,
    pub idempotency_key: &'a InputValue,
    pub revalidation: &'a RevalidationInput,
    pub assurance_ceiling: &'a InputValue,
    pub plan_fingerprint: &'a InputValue,
    pub assurance: &'a InputValue,
    pub recipe_versions: &'a InputValue,
    pub profile_version: &'a InputValue,
    pub adapter_id: &'a InputValue,
    pub adapter_version: &'a InputValue,
    pub byte_counts: &'a InputValue,
    pub record_counts: &'a InputValue,
}

/// Python: `RepairManifest.to_dict` field order.
///
/// `revalidate_report` is always emitted. `None` there is JSON null.
/// `plan_fingerprint`, `assurance`, `profile_version`, `adapter_id`, and
/// `adapter_version` are omitted when `None`. A mapping field is omitted
/// when `None`; that is an empty mapping. A present mapping is sorted by key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairManifestDict {
    pub actions: Vec<RepairActionDict>,
    pub assurance_ceiling: String,
    pub declared_loss: Vec<String>,
    pub idempotency_key: String,
    pub input_fingerprint: String,
    pub output_fingerprint: String,
    pub policy: String,
    pub revalidate_report: Option<String>,
    pub revalidation: RevalidationSummaryDict,
    pub schema_version: String,
    pub plan_fingerprint: Option<String>,
    pub assurance: Option<String>,
    pub recipe_versions: Option<Vec<(InputKey, InputValue)>>,
    pub profile_version: Option<String>,
    pub adapter_id: Option<String>,
    pub adapter_version: Option<String>,
    pub byte_counts: Option<Vec<(InputKey, InputValue)>>,
    pub record_counts: Option<Vec<(InputKey, InputValue)>>,
}

/// Python: `RepairManifest`.
///
/// Checks follow `__post_init__`. The first failure wins. Fingerprints and
/// other accepted strings are stored unchanged. This type does not call
/// [`enforce_content_free_text`] and does not strip fingerprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairManifest {
    schema_version: String,
    input_fingerprint: String,
    output_fingerprint: String,
    policy: String,
    actions: Vec<RepairAction>,
    declared_loss: Vec<String>,
    revalidate_report: Option<String>,
    idempotency_key: String,
    revalidation: RevalidationSummary,
    assurance_ceiling: String,
    plan_fingerprint: Option<String>,
    assurance: Option<String>,
    recipe_versions: Vec<(InputKey, InputValue)>,
    profile_version: Option<String>,
    adapter_id: Option<String>,
    adapter_version: Option<String>,
    byte_counts: Vec<(InputKey, InputValue)>,
    record_counts: Vec<(InputKey, InputValue)>,
}

impl RepairManifest {
    /// Validate in the pinned `__post_init__` order.
    pub fn try_new(parts: RepairManifestParts<'_>) -> Result<Self, EnvelopeError> {
        let schema_version = manifest_version(parts.schema_version)?;
        let input_fingerprint = manifest_kept_text(parts.input_fingerprint, "input_fingerprint")?;
        let output_fingerprint =
            manifest_kept_text(parts.output_fingerprint, "output_fingerprint")?;
        let policy = manifest_policy(parts.policy)?;
        let actions = manifest_actions(parts.actions)?;
        let declared_loss = manifest_loss(parts.declared_loss)?;
        let revalidate_report = manifest_revalidate(parts.revalidate_report)?;
        let idempotency_key = manifest_idempotency(parts.idempotency_key)?;
        let revalidation = manifest_revalidation(parts.revalidation)?;
        let assurance_ceiling = manifest_ceiling(parts.assurance_ceiling)?;
        let plan_fingerprint = manifest_optional_text(parts.plan_fingerprint, "plan_fingerprint")?;
        let assurance = manifest_optional_text(parts.assurance, "assurance")?;
        let recipe_versions = manifest_mapping(parts.recipe_versions, "recipe_versions")?;
        let profile_version = manifest_optional_text(parts.profile_version, "profile_version")?;
        let adapter_id = manifest_optional_text(parts.adapter_id, "adapter_id")?;
        let adapter_version = manifest_optional_text(parts.adapter_version, "adapter_version")?;
        let byte_counts = manifest_mapping(parts.byte_counts, "byte_counts")?;
        let record_counts = manifest_mapping(parts.record_counts, "record_counts")?;
        Ok(Self {
            schema_version,
            input_fingerprint,
            output_fingerprint,
            policy,
            actions,
            declared_loss,
            revalidate_report,
            idempotency_key,
            revalidation,
            assurance_ceiling,
            plan_fingerprint,
            assurance,
            recipe_versions,
            profile_version,
            adapter_id,
            adapter_version,
            byte_counts,
            record_counts,
        })
    }

    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    #[must_use]
    pub fn input_fingerprint(&self) -> &str {
        &self.input_fingerprint
    }

    #[must_use]
    pub fn output_fingerprint(&self) -> &str {
        &self.output_fingerprint
    }

    #[must_use]
    pub fn policy(&self) -> &str {
        &self.policy
    }

    #[must_use]
    pub fn actions(&self) -> &[RepairAction] {
        &self.actions
    }

    #[must_use]
    pub fn declared_loss(&self) -> &[String] {
        &self.declared_loss
    }

    /// `None` when the caller passed `None`. The stored string is not stripped.
    #[must_use]
    pub fn revalidate_report(&self) -> Option<&str> {
        self.revalidate_report.as_deref()
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    #[must_use]
    pub fn revalidation(&self) -> &RevalidationSummary {
        &self.revalidation
    }

    #[must_use]
    pub fn assurance_ceiling(&self) -> &str {
        &self.assurance_ceiling
    }

    /// `None` when the caller passed `None`. The stored string is not stripped.
    #[must_use]
    pub fn plan_fingerprint(&self) -> Option<&str> {
        self.plan_fingerprint.as_deref()
    }

    /// `None` when the caller passed `None`. Not required to be an assurance level.
    #[must_use]
    pub fn assurance(&self) -> Option<&str> {
        self.assurance.as_deref()
    }

    #[must_use]
    pub fn recipe_versions(&self) -> &[(InputKey, InputValue)] {
        &self.recipe_versions
    }

    #[must_use]
    pub fn profile_version(&self) -> Option<&str> {
        self.profile_version.as_deref()
    }

    #[must_use]
    pub fn adapter_id(&self) -> Option<&str> {
        self.adapter_id.as_deref()
    }

    #[must_use]
    pub fn adapter_version(&self) -> Option<&str> {
        self.adapter_version.as_deref()
    }

    #[must_use]
    pub fn byte_counts(&self) -> &[(InputKey, InputValue)] {
        &self.byte_counts
    }

    #[must_use]
    pub fn record_counts(&self) -> &[(InputKey, InputValue)] {
        &self.record_counts
    }

    /// Convert to the pinned dictionary shape.
    ///
    /// Sorting a mapping can raise Python `TypeError` for mixed key types.
    /// That string is [`EnvelopeError::TypeMismatch`].
    pub fn to_dict(&self) -> Result<RepairManifestDict, EnvelopeError> {
        Ok(RepairManifestDict {
            actions: self.actions.iter().map(RepairAction::to_dict).collect(),
            assurance_ceiling: self.assurance_ceiling.clone(),
            declared_loss: self.declared_loss.clone(),
            idempotency_key: self.idempotency_key.clone(),
            input_fingerprint: self.input_fingerprint.clone(),
            output_fingerprint: self.output_fingerprint.clone(),
            policy: self.policy.clone(),
            revalidate_report: self.revalidate_report.clone(),
            revalidation: self.revalidation.to_dict(),
            schema_version: self.schema_version.clone(),
            plan_fingerprint: self.plan_fingerprint.clone(),
            assurance: self.assurance.clone(),
            recipe_versions: emitted_mapping(&self.recipe_versions)?,
            profile_version: self.profile_version.clone(),
            adapter_id: self.adapter_id.clone(),
            adapter_version: self.adapter_version.clone(),
            byte_counts: emitted_mapping(&self.byte_counts)?,
            record_counts: emitted_mapping(&self.record_counts)?,
        })
    }
}

fn manifest_version(value: &InputValue) -> Result<String, EnvelopeError> {
    if let InputValue::Str(text) = value {
        if text == MANIFEST_SCHEMA_VERSION {
            return Ok(text.clone());
        }
    }
    let version = match value {
        InputValue::Str(text) => Some(text.clone()),
        _ => None,
    };
    let message = format!(
        "RepairManifest.schema_version must be {}, got {}",
        python_str_repr(MANIFEST_SCHEMA_VERSION),
        input_repr(value)
    );
    Err(EnvelopeError::Version(VersionError::new(message, version)))
}

fn manifest_kept_text(value: &InputValue, label: &str) -> Result<String, EnvelopeError> {
    match value {
        InputValue::Str(text) if !python_strip(text).is_empty() => Ok(text.clone()),
        other => Err(schema_env(format!(
            "RepairManifest.{label} must be a non-empty string, got {}",
            input_repr(other)
        ))),
    }
}

fn manifest_policy(value: &InputValue) -> Result<String, EnvelopeError> {
    match value {
        InputValue::Str(text) if VALID_POLICIES.contains(&text.as_str()) => Ok(text.clone()),
        other => Err(schema_env(format!(
            "RepairManifest.policy must be one of {}, got {}",
            sorted_policies_repr(),
            input_repr(other)
        ))),
    }
}

fn manifest_actions(value: &ActionSeq) -> Result<Vec<RepairAction>, EnvelopeError> {
    let items = match value {
        ActionSeq::Tuple(items) => items,
        ActionSeq::Wrong { type_name } => {
            return Err(schema_env(format!(
                "RepairManifest.actions must be a tuple, got {type_name}"
            )));
        }
    };
    let mut actions = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        match item {
            ActionElem::Action(action) => actions.push(action.clone()),
            ActionElem::Wrong { type_name } => {
                return Err(schema_env(format!(
                    "RepairManifest.actions[{index}] must be a RepairAction, got {type_name}"
                )));
            }
        }
    }
    Ok(actions)
}

fn manifest_loss(value: &InputValue) -> Result<Vec<String>, EnvelopeError> {
    let InputValue::Tuple(items) = value else {
        return Err(schema_env(format!(
            "RepairManifest.declared_loss must be a tuple, got {}",
            input_type_name(value)
        )));
    };
    let mut loss = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        match item {
            InputValue::Str(text) if !python_strip(text).is_empty() => loss.push(text.clone()),
            other => {
                return Err(schema_env(format!(
                    "RepairManifest.declared_loss[{index}] must be a non-empty string, got {}",
                    input_repr(other)
                )));
            }
        }
    }
    Ok(loss)
}

fn manifest_revalidate(value: &InputValue) -> Result<Option<String>, EnvelopeError> {
    match value {
        InputValue::None => Ok(None),
        InputValue::Str(text) if !python_strip(text).is_empty() => Ok(Some(text.clone())),
        other => Err(schema_env(format!(
            "RepairManifest.revalidate_report must be a non-empty string path or None, got {}",
            input_repr(other)
        ))),
    }
}

fn manifest_idempotency(value: &InputValue) -> Result<String, EnvelopeError> {
    match value {
        InputValue::Str(text) if is_sha256_hex(text) => Ok(text.clone()),
        other => Err(schema_env(format!(
            "RepairManifest.idempotency_key must be a 64-character lowercase hex string, got {}",
            input_repr(other)
        ))),
    }
}

fn manifest_revalidation(value: &RevalidationInput) -> Result<RevalidationSummary, EnvelopeError> {
    match value {
        RevalidationInput::Summary(summary) => Ok(summary.clone()),
        RevalidationInput::Wrong { type_name } => Err(schema_env(format!(
            "RepairManifest.revalidation must be a RevalidationSummary, got {type_name}"
        ))),
    }
}

fn manifest_ceiling(value: &InputValue) -> Result<String, EnvelopeError> {
    match value {
        InputValue::Str(text) if VALID_ASSURANCE_LEVELS.contains(&text.as_str()) => {
            Ok(text.clone())
        }
        other => Err(EnvelopeError::Assurance(AssuranceError::new(format!(
            "RepairManifest.assurance_ceiling must be one of {}, got {}",
            sorted_assurance_repr(),
            input_repr(other)
        )))),
    }
}

fn manifest_optional_text(
    value: &InputValue,
    label: &str,
) -> Result<Option<String>, EnvelopeError> {
    match value {
        InputValue::None => Ok(None),
        InputValue::Str(text) if !python_strip(text).is_empty() => Ok(Some(text.clone())),
        _ => Err(schema_env(format!(
            "RepairManifest.{label} must be a non-empty string"
        ))),
    }
}

fn manifest_mapping(
    value: &InputValue,
    label: &str,
) -> Result<Vec<(InputKey, InputValue)>, EnvelopeError> {
    match value {
        InputValue::Dict(entries) => Ok(entries.clone()),
        _ => Err(schema_env(format!(
            "RepairManifest.{label} must be a Mapping"
        ))),
    }
}

/// Coverage argument for [`build_report`].
///
/// [`BuildCoverage::Omitted`] is Python `coverage=None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildCoverage<'a> {
    Omitted,
    Value(&'a Coverage),
    Wrong { type_name: &'a str },
}

/// Fields for [`build_report`]. Counts are not a field: they are derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildReportParts<'a> {
    pub session_id: &'a InputValue,
    pub source_fingerprint: &'a InputValue,
    pub tool_version: &'a InputValue,
    pub findings: &'a [Finding],
    pub assurance: &'a InputValue,
    pub limitation: &'a InputValue,
    pub coverage: BuildCoverage<'a>,
}

/// Python: `build_report`.
///
/// Check order is session id, source fingerprint, tool version, assurance,
/// then limitation. Omitted coverage calls [`default_coverage`] and returns
/// before `model::finding::sort_findings`. A [`Coverage`] value is sorted,
/// counted, and passed to [`Report::try_new`]. The caller cannot supply counts.
pub fn build_report(parts: BuildReportParts<'_>) -> Result<Report, EnvelopeError> {
    let session_id = build_text(parts.session_id, "session_id")?;
    let source_fingerprint = build_text(parts.source_fingerprint, "source_fingerprint")?;
    let tool_version = build_text(parts.tool_version, "tool_version")?;
    let assurance = build_assurance(parts.assurance)?;
    let limitation = build_limitation(parts.limitation, &assurance)?;
    let coverage = match parts.coverage {
        BuildCoverage::Omitted => default_coverage()?,
        BuildCoverage::Wrong { type_name } => {
            return Err(schema_env(format!(
                "coverage must be a Coverage instance, got {type_name}"
            )));
        }
        BuildCoverage::Value(coverage) => coverage.clone(),
    };
    let sorted = model::finding::sort_findings(parts.findings);
    let counts = counts_from_findings(&sorted)?;
    let schema_version = InputValue::str_value(REPORT_SCHEMA_VERSION);
    let session_value = InputValue::str_value(session_id);
    let fingerprint_value = InputValue::str_value(source_fingerprint);
    let tool_value = InputValue::str_value(tool_version);
    let assurance_value = InputValue::str_value(assurance);
    let limitation_value = InputValue::str_value(limitation);
    let findings = FindingsInput::Tuple(sorted.into_iter().map(FindingElem::Finding).collect());
    let counts_input = CountsInput::Value(counts);
    Report::try_new(ReportParts {
        schema_version: &schema_version,
        session_id: &session_value,
        source_fingerprint: &fingerprint_value,
        tool_version: &tool_value,
        findings: &findings,
        counts: &counts_input,
        assurance: &assurance_value,
        limitation: &limitation_value,
        coverage: CoverageInput::Value(&coverage),
    })
}

fn build_text(value: &InputValue, label: &str) -> Result<String, EnvelopeError> {
    if let InputValue::Str(text) = value {
        let stripped = python_strip(text);
        if !stripped.is_empty() {
            return Ok(stripped.to_owned());
        }
    }
    Err(schema_env(format!(
        "{label} must be a non-empty string, got {}",
        input_repr(value)
    )))
}

fn build_assurance(value: &InputValue) -> Result<String, EnvelopeError> {
    match value {
        InputValue::Str(text) if VALID_ASSURANCE_LEVELS.contains(&text.as_str()) => {
            Ok(text.clone())
        }
        other => Err(EnvelopeError::Assurance(AssuranceError::new(format!(
            "Invalid assurance level {}. Must be one of {}",
            input_repr(other),
            sorted_assurance_repr()
        )))),
    }
}

fn build_limitation(value: &InputValue, assurance: &str) -> Result<String, EnvelopeError> {
    if let InputValue::Str(text) = value {
        let stripped = python_strip(text);
        if !stripped.is_empty() {
            return Ok(stripped.to_owned());
        }
    }
    Err(EnvelopeError::Assurance(AssuranceError::new(format!(
        "limitation is required and must be non-empty for assurance level {}",
        python_str_repr(assurance)
    ))))
}

fn counts_from_findings(findings: &[Finding]) -> Result<Counts, EnvelopeError> {
    let total = match i64::try_from(findings.len()) {
        Ok(total) => total,
        Err(_) => return Err(schema_env("Counts.total does not fit in i64".to_owned())),
    };
    let mut by_severity = [0_i64; REQUIRED_SEVERITIES.len()];
    let mut by_code: Vec<(String, i64)> = Vec::new();
    for finding in findings {
        let severity_name = finding.severity().as_str();
        if let Some(slot) = REQUIRED_SEVERITIES
            .iter()
            .position(|name| *name == severity_name)
        {
            by_severity[slot] = match by_severity[slot].checked_add(1) {
                Some(count) => count,
                None => {
                    return Err(schema_env(
                        "finding severity count does not fit in i64".to_owned(),
                    ));
                }
            };
        }
        add_code_count(&mut by_code, finding.code())?;
    }
    by_code.sort_by(|left, right| left.0.cmp(&right.0));
    let severity_map = CountValue::dict(
        REQUIRED_SEVERITIES
            .iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    CountKey::str_key(*name),
                    CountValue::int(by_severity[index]),
                )
            })
            .collect(),
    );
    let code_map = CountValue::dict(
        by_code
            .iter()
            .map(|(code, count)| (CountKey::str_key(code.clone()), CountValue::int(*count)))
            .collect(),
    );
    Counts::try_new(&severity_map, &code_map, &CountValue::int(total))
        .map_err(EnvelopeError::Schema)
}

fn add_code_count(pairs: &mut Vec<(String, i64)>, code: &str) -> Result<(), EnvelopeError> {
    for pair in pairs.iter_mut() {
        if pair.0 == code {
            pair.1 = match pair.1.checked_add(1) {
                Some(count) => count,
                None => {
                    return Err(schema_env(
                        "finding code count does not fit in i64".to_owned(),
                    ));
                }
            };
            return Ok(());
        }
    }
    pairs.push((code.to_owned(), 1));
    Ok(())
}

/// Failure from [`compute_manifest_idempotency_key`].
///
/// [`Display`](fmt::Display) is the inner Python message. [`Self::Canonical`]
/// displays `sesslint._canonical_codec.canonical_json_bytes is not available`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyError {
    Schema(SchemaError),
    Canonical(CanonicalUnavailable),
}

impl fmt::Display for IdempotencyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(error) => write!(formatter, "{error}"),
            Self::Canonical(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for IdempotencyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Schema(error) => Some(error),
            Self::Canonical(error) => Some(error),
        }
    }
}

/// Python: `compute_manifest_idempotency_key`.
///
/// Checks `input_fingerprint`, then policy membership on the raw value.
/// Actions are sorted with [`action_sort_key`]. The payload is those actions,
/// the stripped fingerprint, and the stripped policy.
/// `model::canonical::to_canonical_json` then returns [`CanonicalUnavailable`].
/// sha256 runs only on that canonical string. This crate cannot produce one,
/// so it does not hash a substitute and does not invent a digest.
pub fn compute_manifest_idempotency_key(
    input_fingerprint: &InputValue,
    policy: &InputValue,
    actions: &[RepairAction],
) -> Result<String, IdempotencyError> {
    let raw_input = match input_fingerprint {
        InputValue::Str(text) if !python_strip(text).is_empty() => text.as_str(),
        other => {
            return Err(IdempotencyError::Schema(schema(format!(
                "input_fingerprint must be a non-empty string, got {}",
                input_repr(other)
            ))));
        }
    };
    let raw_policy = match policy {
        InputValue::Str(text) if VALID_POLICIES.contains(&text.as_str()) => text.as_str(),
        other => {
            return Err(IdempotencyError::Schema(schema(format!(
                "policy must be one of {}, got {}",
                sorted_policies_repr(),
                input_repr(other)
            ))));
        }
    };
    let sorted = sort_repair_actions(actions);
    let action_dicts: Vec<RepairActionDict> = sorted.iter().map(RepairAction::to_dict).collect();
    let stripped_input = python_strip(raw_input).to_owned();
    let stripped_policy = python_strip(raw_policy).to_owned();
    // Insertion order: actions, stripped input_fingerprint, stripped policy.
    let payload = (action_dicts, stripped_input, stripped_policy);
    match model::canonical::to_canonical_json(&payload) {
        Ok(canonical) => Ok(sha256_hex(canonical.as_bytes())),
        Err(error) => Err(IdempotencyError::Canonical(error)),
    }
}

fn sort_repair_actions(actions: &[RepairAction]) -> Vec<RepairAction> {
    let mut sorted = actions.to_vec();
    sorted.sort_by(|left, right| {
        action_sort_key(ActionSortFields {
            kind: left.kind(),
            record_id: left.record_id(),
            detail: left.detail(),
        })
        .cmp(&action_sort_key(ActionSortFields {
            kind: right.kind(),
            record_id: right.record_id(),
            detail: right.detail(),
        }))
    });
    sorted
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn is_sha256_hex(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return false;
    }
    bytes
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn sorted_policies_repr() -> String {
    let mut policies = VALID_POLICIES;
    policies.sort_unstable();
    python_str_list(&policies)
}

fn emitted_mapping(
    entries: &[(InputKey, InputValue)],
) -> Result<Option<Vec<(InputKey, InputValue)>>, EnvelopeError> {
    if entries.is_empty() {
        return Ok(None);
    }
    let mut ordered = entries.to_vec();
    python_sort_pairs(&mut ordered).map_err(EnvelopeError::TypeMismatch)?;
    Ok(Some(collapse_equal_keys(ordered)))
}

fn collapse_equal_keys(entries: Vec<(InputKey, InputValue)>) -> Vec<(InputKey, InputValue)> {
    let mut collapsed = Vec::new();
    for (key, value) in entries {
        if let Some((last_key, last_value)) = collapsed.last_mut() {
            if input_key_eq(last_key, &key) {
                *last_value = value;
                continue;
            }
        }
        collapsed.push((key, value));
    }
    collapsed
}

/// Late import. This crate does not depend on `sesslint.repair`.
pub const COMPUTE_ASSURANCE_CEILING: &str = "sesslint.repair.assurance.compute_assurance_ceiling";

/// `build_manifest` revalidation value.
///
/// [`Self::None`] is Python `None`. [`Self::Summary`] is kept as-is.
/// [`Self::Mapping`] is a mapping. [`Self::Wrong`] is any other type, and
/// `type_name` is `type(value).__name__`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildRevalidation<'a> {
    None,
    Summary(&'a RevalidationSummary),
    Mapping(&'a [(InputKey, InputValue)]),
    Wrong { type_name: &'a str },
}

/// Fields for [`build_manifest`].
///
/// Python defaults, which Rust does not infer: `actions` and `declared_loss`
/// are empty, and `revalidate_report`, `assurance_ceiling`, `plan_fingerprint`,
/// `assurance`, `profile_version`, `adapter_id`, and `adapter_version` are
/// `None`. `revalidation` is [`BuildRevalidation::None`]. `recipe_versions`,
/// `byte_counts`, and `record_counts` are empty mappings.
///
/// `plan_fingerprint`, `assurance`, `recipe_versions`, `profile_version`,
/// `adapter_version`, `byte_counts`, and `record_counts` are applied only when
/// a [`RepairManifest`] is built. This function does not build one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildManifestParts<'a> {
    pub input_fingerprint: &'a InputValue,
    pub output_fingerprint: &'a InputValue,
    pub policy: &'a InputValue,
    pub actions: &'a [RepairAction],
    pub declared_loss: &'a [InputValue],
    pub revalidate_report: &'a InputValue,
    pub revalidation: BuildRevalidation<'a>,
    pub assurance_ceiling: &'a InputValue,
    pub plan_fingerprint: &'a InputValue,
    pub assurance: &'a InputValue,
    pub recipe_versions: &'a InputValue,
    pub profile_version: &'a InputValue,
    pub adapter_id: &'a InputValue,
    pub adapter_version: &'a InputValue,
    pub byte_counts: &'a InputValue,
    pub record_counts: &'a InputValue,
}

/// Failure from [`build_manifest`].
///
/// [`Display`](fmt::Display) is the Python exception message.
/// [`Self::Unavailable`] displays `{name} is not available`.
/// [`Self::Idempotency`] displays the idempotency error. The canonical arm is
/// `sesslint._canonical_codec.canonical_json_bytes is not available`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildManifestError {
    Schema(SchemaError),
    Assurance(AssuranceError),
    ContentLeak(ContentLeakError),
    /// Python `TypeError`. The string is `str(exc)`.
    Type(String),
    /// Python `ValueError` from `int()`. The string is `str(exc)`.
    Value(String),
    /// Late import named by the string, without the ` is not available` suffix.
    Unavailable(&'static str),
    Idempotency(IdempotencyError),
}

impl fmt::Display for BuildManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(error) => write!(formatter, "{error}"),
            Self::Assurance(error) => write!(formatter, "{error}"),
            Self::ContentLeak(error) => write!(formatter, "{error}"),
            Self::Type(message) | Self::Value(message) => formatter.write_str(message),
            Self::Unavailable(name) => write!(formatter, "{name} is not available"),
            Self::Idempotency(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for BuildManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Schema(error) => Some(error),
            Self::Assurance(error) => Some(error),
            Self::ContentLeak(error) => Some(error),
            Self::Idempotency(error) => Some(error),
            Self::Type(_) | Self::Value(_) | Self::Unavailable(_) => None,
        }
    }
}

/// Argument for [`dump_report`].
///
/// [`Self::Wrong`] carries `type(value).__name__`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpReportInput<'a> {
    Report(&'a Report),
    Wrong { type_name: &'a str },
}

/// Failure from [`dump_report`].
///
/// [`Self::Type`] is Python `TypeError`. [`Self::Canonical`] displays
/// `sesslint._canonical_codec.canonical_json_bytes is not available`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpReportError {
    Type(String),
    Canonical(CanonicalUnavailable),
}

impl fmt::Display for DumpReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(message) => formatter.write_str(message),
            Self::Canonical(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for DumpReportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Type(_) => None,
        }
    }
}

/// Python: `build_manifest`.
///
/// The first failure wins. Actions are sorted with [`action_sort_key`].
/// Declared loss is stripped in input order and is not sorted. `None` for
/// `assurance_ceiling` returns [`BuildManifestError::Unavailable`] for
/// [`COMPUTE_ASSURANCE_CEILING`] and does not run the metadata content checks
/// or [`compute_manifest_idempotency_key`]. A provided ceiling must be an exact
/// [`VALID_ASSURANCE_LEVELS`] member. Metadata checks call
/// [`enforce_content_free_text`]. The idempotency call is then propagated.
/// This function does not build a [`RepairManifest`], does not invent an
/// idempotency key, and does not hash a substitute.
pub fn build_manifest(parts: BuildManifestParts<'_>) -> Result<RepairManifest, BuildManifestError> {
    let input_fingerprint = require_stripped(parts.input_fingerprint, "input_fingerprint")?;
    let _output_fingerprint = require_stripped(parts.output_fingerprint, "output_fingerprint")?;
    require_raw_policy(parts.policy)?;
    let sorted_actions = sort_repair_actions(parts.actions);
    // Pin name `sorted_loss`: stripped items in input order. Not sorted.
    let _sorted_loss = normalize_declared_loss(parts.declared_loss)?;
    let _revalidate_report = normalize_revalidate_report(parts.revalidate_report)?;
    let revalidation = normalize_revalidation(parts.revalidation)?;
    if matches!(parts.assurance_ceiling, InputValue::None) {
        return Err(BuildManifestError::Unavailable(COMPUTE_ASSURANCE_CEILING));
    }
    let _assurance_ceiling = require_provided_ceiling(parts.assurance_ceiling)?;
    check_manifest_metadata(&revalidation, parts.adapter_id)?;
    let fingerprint = InputValue::str_value(input_fingerprint);
    match compute_manifest_idempotency_key(&fingerprint, parts.policy, &sorted_actions) {
        Err(error) => Err(BuildManifestError::Idempotency(error)),
        Ok(_digest) => Err(BuildManifestError::Idempotency(
            IdempotencyError::Canonical(CanonicalUnavailable::canonical_json_bytes()),
        )),
    }
}

/// Python: `dump_report`.
///
/// A value that is not a [`Report`] returns `TypeError` text
/// `Expected Report instance, got {type}`. A [`Report`] calls
/// `model::canonical::to_canonical_json` on [`Report::to_dict`] and returns
/// [`CanonicalUnavailable`]. This function does not emit JSON.
pub fn dump_report(report: DumpReportInput<'_>) -> Result<String, DumpReportError> {
    let report = match report {
        DumpReportInput::Report(report) => report,
        DumpReportInput::Wrong { type_name } => {
            return Err(DumpReportError::Type(format!(
                "Expected Report instance, got {type_name}"
            )));
        }
    };
    let rendered = report.to_dict();
    match model::canonical::to_canonical_json(&rendered) {
        Err(error) => Err(DumpReportError::Canonical(error)),
        Ok(_json) => Err(DumpReportError::Canonical(
            CanonicalUnavailable::canonical_json_bytes(),
        )),
    }
}

fn require_stripped(value: &InputValue, label: &str) -> Result<String, BuildManifestError> {
    if let InputValue::Str(text) = value {
        let stripped = python_strip(text);
        if !stripped.is_empty() {
            return Ok(stripped.to_owned());
        }
    }
    Err(BuildManifestError::Schema(schema(format!(
        "{label} must be a non-empty string, got {}",
        input_repr(value)
    ))))
}

fn require_raw_policy(value: &InputValue) -> Result<(), BuildManifestError> {
    if let InputValue::Str(text) = value {
        if VALID_POLICIES.contains(&text.as_str()) {
            return Ok(());
        }
    }
    Err(BuildManifestError::Schema(schema(format!(
        "policy must be one of {}, got {}",
        sorted_policies_repr(),
        input_repr(value)
    ))))
}

fn normalize_declared_loss(items: &[InputValue]) -> Result<Vec<String>, BuildManifestError> {
    let mut sorted_loss = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let InputValue::Str(text) = item else {
            return Err(declared_loss_type(index, item));
        };
        let stripped = python_strip(text);
        if stripped.is_empty() {
            return Err(declared_loss_type(index, item));
        }
        match enforce_content_free_text(stripped, "declared_loss") {
            Ok(()) => sorted_loss.push(stripped.to_owned()),
            Err(error) => {
                return Err(BuildManifestError::ContentLeak(ContentLeakError::new(
                    format!("Content leak in declared_loss[{index}]: {error}"),
                )));
            }
        }
    }
    Ok(sorted_loss)
}

fn declared_loss_type(index: usize, item: &InputValue) -> BuildManifestError {
    BuildManifestError::Schema(schema(format!(
        "declared_loss[{index}] must be a non-empty string, got {}",
        input_repr(item)
    )))
}

fn normalize_revalidate_report(value: &InputValue) -> Result<Option<String>, BuildManifestError> {
    match value {
        InputValue::None => Ok(None),
        InputValue::Str(text) => {
            let stripped = python_strip(text);
            if stripped.is_empty() {
                return Err(revalidate_type(value));
            }
            let normalized = stripped.replace('\\', "/");
            match enforce_content_free_text(&normalized, "revalidate_report") {
                Ok(()) => Ok(Some(normalized)),
                Err(error) => Err(BuildManifestError::ContentLeak(ContentLeakError::new(
                    format!("Content leak in revalidate_report: {error}"),
                ))),
            }
        }
        other => Err(revalidate_type(other)),
    }
}

fn revalidate_type(value: &InputValue) -> BuildManifestError {
    BuildManifestError::Schema(schema(format!(
        "revalidate_report must be a non-empty string path or None, got {}",
        input_repr(value)
    )))
}

fn normalize_revalidation(
    value: BuildRevalidation<'_>,
) -> Result<RevalidationSummary, BuildManifestError> {
    match value {
        BuildRevalidation::None => default_revalidation(),
        BuildRevalidation::Summary(summary) => Ok(summary.clone()),
        BuildRevalidation::Mapping(entries) => summary_from_mapping(entries),
        BuildRevalidation::Wrong { type_name } => Err(BuildManifestError::Schema(schema(format!(
            "revalidation must be a RevalidationSummary or Mapping, got {type_name}"
        )))),
    }
}

fn default_revalidation() -> Result<RevalidationSummary, BuildManifestError> {
    let assurance = InputValue::str_value("A3");
    let error_count = InputValue::int(0);
    let warning_count = InputValue::int(0);
    let profile_id = InputValue::str_value("neutral");
    let profile_version = InputValue::str_value("1.0.0");
    let report_fingerprint = InputValue::None;
    lift_summary(RevalidationSummary::try_new(
        &assurance,
        &error_count,
        &warning_count,
        &profile_id,
        &profile_version,
        &report_fingerprint,
    ))
}

fn summary_from_mapping(
    entries: &[(InputKey, InputValue)],
) -> Result<RevalidationSummary, BuildManifestError> {
    let assurance = require_mapping_field(entries, "assurance")?;
    let error_raw = require_mapping_field(entries, "error_count")?;
    let warning_raw = require_mapping_field(entries, "warning_count")?;
    let profile_raw = require_mapping_field(entries, "profile_id")?;
    let version_raw = require_mapping_field(entries, "profile_version")?;
    let error_count = mapping_count(error_raw, "error_count")?;
    let warning_count = mapping_count(warning_raw, "warning_count")?;
    let profile_id = InputValue::str_value(python_str_value(profile_raw));
    let profile_version = InputValue::str_value(python_str_value(version_raw));
    let report_fingerprint = match mapping_last(entries, "report_fingerprint") {
        None | Some(InputValue::None) => InputValue::None,
        Some(value) => InputValue::str_value(python_str_value(value)),
    };
    lift_summary(RevalidationSummary::try_new(
        assurance,
        &error_count,
        &warning_count,
        &profile_id,
        &profile_version,
        &report_fingerprint,
    ))
}

fn require_mapping_field<'a>(
    entries: &'a [(InputKey, InputValue)],
    field: &str,
) -> Result<&'a InputValue, BuildManifestError> {
    mapping_last(entries, field).ok_or_else(|| {
        BuildManifestError::Schema(schema(format!(
            "revalidation missing required field '{field}'"
        )))
    })
}

fn mapping_last<'a>(entries: &'a [(InputKey, InputValue)], name: &str) -> Option<&'a InputValue> {
    entries.iter().rev().find_map(|(key, value)| match key {
        InputKey::Str(text) if text == name => Some(value),
        _ => None,
    })
}

/// Python `int` is unbounded. [`RevalidationSummary`] stores `i64`.
/// A mapping count outside that range is refused and is not truncated.
fn mapping_count(value: &InputValue, field: &str) -> Result<InputValue, BuildManifestError> {
    match python_int(value)? {
        Some(number) => Ok(InputValue::int(number)),
        None => Err(BuildManifestError::Schema(schema(format!(
            "revalidation {field} does not fit in i64"
        )))),
    }
}

fn python_int(value: &InputValue) -> Result<Option<i64>, BuildManifestError> {
    match value {
        InputValue::Bool(false) => Ok(Some(0)),
        InputValue::Bool(true) => Ok(Some(1)),
        InputValue::Int(number) => Ok(Some(*number)),
        InputValue::Str(text) => parse_int_literal(text),
        other => Err(BuildManifestError::Type(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            input_type_name(other)
        ))),
    }
}

fn parse_int_literal(original: &str) -> Result<Option<i64>, BuildManifestError> {
    let stripped = python_strip(original);
    if !is_python_int_literal(stripped) {
        return Err(BuildManifestError::Value(format!(
            "invalid literal for int() with base 10: {}",
            python_str_repr(original)
        )));
    }
    let negative = stripped.starts_with('-');
    let digits = stripped
        .strip_prefix(['+', '-'].as_slice())
        .unwrap_or(stripped);
    let mut normalized = String::new();
    if negative {
        normalized.push('-');
    }
    for ch in digits.chars() {
        if ch != '_' {
            normalized.push(ch);
        }
    }
    match normalized.parse::<i64>() {
        Ok(number) => Ok(Some(number)),
        Err(_) => Ok(None),
    }
}

fn is_python_int_literal(stripped: &str) -> bool {
    let rest = stripped
        .strip_prefix(['+', '-'].as_slice())
        .unwrap_or(stripped);
    if rest.is_empty() {
        return false;
    }
    let mut previous_underscore = false;
    let mut saw_digit = false;
    for ch in rest.chars() {
        if ch == '_' {
            if !saw_digit || previous_underscore {
                return false;
            }
            previous_underscore = true;
        } else if ch.is_ascii_digit() {
            saw_digit = true;
            previous_underscore = false;
        } else {
            return false;
        }
    }
    saw_digit && !previous_underscore
}

fn python_str_value(value: &InputValue) -> String {
    match value {
        InputValue::Str(text) => text.clone(),
        InputValue::None => "None".to_owned(),
        InputValue::Bool(true) => "True".to_owned(),
        InputValue::Bool(false) => "False".to_owned(),
        InputValue::Int(number) => number.to_string(),
        InputValue::List(items) => input_sequence(items, 0, '[', ']', false),
        InputValue::Tuple(items) => input_sequence(items, 0, '(', ')', true),
        InputValue::Set(items) => input_braced("set", items, 0),
        InputValue::FrozenSet(items) => {
            if items.is_empty() {
                "frozenset()".to_owned()
            } else {
                format!("frozenset({})", input_braced("frozenset", items, 0))
            }
        }
        InputValue::Dict(entries) => input_dict(entries, 0),
        InputValue::Other { rendered, .. } => rendered.clone(),
    }
}

fn lift_summary(
    result: Result<RevalidationSummary, EnvelopeError>,
) -> Result<RevalidationSummary, BuildManifestError> {
    result.map_err(|error| match error {
        EnvelopeError::Schema(error) => BuildManifestError::Schema(error),
        EnvelopeError::Version(error) => BuildManifestError::Schema(SchemaError::from(error)),
        EnvelopeError::Assurance(error) => BuildManifestError::Assurance(error),
        EnvelopeError::ContentLeak(error) => BuildManifestError::ContentLeak(error),
        EnvelopeError::TypeMismatch(message) => BuildManifestError::Type(message),
        EnvelopeError::Unavailable(name) => BuildManifestError::Unavailable(name),
    })
}

fn require_provided_ceiling(value: &InputValue) -> Result<&str, BuildManifestError> {
    match value {
        InputValue::Str(text) if VALID_ASSURANCE_LEVELS.contains(&text.as_str()) => {
            Ok(text.as_str())
        }
        other => Err(BuildManifestError::Assurance(AssuranceError::new(format!(
            "Invalid assurance_ceiling {}. Must be one of {}",
            input_repr(other),
            sorted_assurance_repr()
        )))),
    }
}

fn check_manifest_metadata(
    summary: &RevalidationSummary,
    adapter_id: &InputValue,
) -> Result<(), BuildManifestError> {
    metadata_leak(summary.profile_id(), "revalidation.profile_id")?;
    metadata_leak(summary.profile_version(), "revalidation.profile_version")?;
    if let Some(fingerprint) = summary.report_fingerprint() {
        metadata_leak(fingerprint, "revalidation.report_fingerprint")?;
    }
    match adapter_id {
        InputValue::None => Ok(()),
        InputValue::Str(text) => metadata_leak(text, "adapter_id"),
        other => Err(BuildManifestError::Type(format!(
            "expected string or bytes-like object, got '{}'",
            input_type_name(other)
        ))),
    }
}

fn metadata_leak(text: &str, context: &str) -> Result<(), BuildManifestError> {
    match enforce_content_free_text(text, context) {
        Ok(()) => Ok(()),
        Err(error) => Err(BuildManifestError::ContentLeak(ContentLeakError::new(
            format!("Content leak in manifest metadata: {error}"),
        ))),
    }
}

/// `REQUIRED_REPORT_FIELDS` is a frozenset. Missing-field checks follow the
/// literal order. CPython frozenset order follows the process hash seed and
/// is not reproduced.
pub const REQUIRED_REPORT_FIELD_ORDER_DEVIATION: &str = "REQUIRED_REPORT_FIELDS is a frozenset. Missing-field checks follow the literal order. CPython frozenset order follows the process hash seed and is not reproduced";

/// A custom object nested in finding evidence cannot be passed to
/// [`parse_finding_dict`]. [`PyValue`] has no custom-object variant. No
/// substitute evidence value is parsed.
pub const FINDING_EVIDENCE_OBJECT: &str = "A custom object nested in finding evidence is not representable. PyValue has no custom object. parse_finding_dict is not called on a substitute value";

const KNOWN_REPORT_FIELDS: [&str; 12] = [
    "schema_version",
    "session_id",
    "source_fingerprint",
    "tool_version",
    "findings",
    "counts",
    "assurance",
    "limitation",
    "coverage",
    "repro",
    "content_warning",
    "included_content",
];

const REQUIRED_REPORT_FIELDS: [&str; 9] = [
    "schema_version",
    "session_id",
    "source_fingerprint",
    "tool_version",
    "findings",
    "counts",
    "assurance",
    "limitation",
    "coverage",
];

const COUNT_FIELDS: [&str; 3] = ["by_severity", "by_code", "total"];

const COVERAGE_FIELDS: [&str; 4] = ["performed", "skipped", "adapter", "profile"];

const SKIP_FIELDS: [&str; 3] = ["check", "reason", "detail"];

const BINDING_FIELDS: [&str; 3] = ["id", "name", "version"];

const FINDING_SLOTS: [&str; 10] = [
    "schema_version",
    "code",
    "severity",
    "repairability",
    "message",
    "source",
    "related_ids",
    "fingerprint",
    "message_template",
    "evidence",
];

const READ_FINDING_KEYS: [&str; 12] = [
    "schema_version",
    "code",
    "severity",
    "repairability",
    "message",
    "remediation",
    "source",
    "span",
    "related_ids",
    "fingerprint",
    "message_template",
    "evidence",
];

/// `json.loads` is not available in this crate.
///
/// [`Display`](fmt::Display) is exactly `json.loads is not available`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonLoadsUnavailable;

impl JsonLoadsUnavailable {
    pub const MESSAGE: &'static str = "json.loads is not available";
}

impl fmt::Display for JsonLoadsUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::MESSAGE)
    }
}

impl Error for JsonLoadsUnavailable {}

/// Failure from [`parse_report`].
///
/// [`Display`](fmt::Display) is the Python exception message.
/// [`Self::Json`] displays [`JsonLoadsUnavailable::MESSAGE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseReportError {
    Schema(SchemaError),
    Version(VersionError),
    UnknownField(UnknownFieldError),
    Assurance(AssuranceError),
    ContentLeak(ContentLeakError),
    Finding(FindingError),
    /// Python `TypeError`. The string is `str(exc)`.
    Type(String),
    /// Late import named by the string, without the ` is not available` suffix.
    Unavailable(&'static str),
    Json(JsonLoadsUnavailable),
}

impl fmt::Display for ParseReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(error) => write!(formatter, "{error}"),
            Self::Version(error) => write!(formatter, "{error}"),
            Self::UnknownField(error) => write!(formatter, "{error}"),
            Self::Assurance(error) => write!(formatter, "{error}"),
            Self::ContentLeak(error) => write!(formatter, "{error}"),
            Self::Finding(error) => write!(formatter, "{error}"),
            Self::Type(message) => formatter.write_str(message),
            Self::Unavailable(name) => write!(formatter, "{name} is not available"),
            Self::Json(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for ParseReportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Schema(error) => Some(error),
            Self::Version(error) => Some(error),
            Self::UnknownField(error) => Some(error),
            Self::Assurance(error) => Some(error),
            Self::ContentLeak(error) => Some(error),
            Self::Finding(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Type(_) | Self::Unavailable(_) => None,
        }
    }
}

/// Argument for [`dump_manifest`].
///
/// [`Self::Wrong`] carries `type(value).__name__`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpManifestInput<'a> {
    Manifest(&'a RepairManifest),
    Wrong { type_name: &'a str },
}

/// Failure from [`dump_manifest`].
///
/// [`Self::Type`] is Python `TypeError`. [`Self::Canonical`] displays
/// `sesslint._canonical_codec.canonical_json_bytes is not available`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DumpManifestError {
    Type(String),
    Canonical(CanonicalUnavailable),
}

impl fmt::Display for DumpManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(message) => formatter.write_str(message),
            Self::Canonical(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for DumpManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Type(_) => None,
        }
    }
}

/// Python: `parse_report`.
///
/// A string is the `json.loads` branch. This crate has no JSON parser, so
/// every string returns [`JsonLoadsUnavailable`] and is not inspected.
/// A non-string, non-mapping returns
/// `Report must be a Mapping or JSON string, got {type}`.
///
/// A mapping checks unknown top-level fields, then missing required fields
/// in literal order ([`REQUIRED_REPORT_FIELD_ORDER_DEVIATION`]), then
/// `schema_version`, then the remaining fields. Findings call
/// [`parse_finding_dict`] and [`sort_findings`]. `Counts`, `CoverageSkip`,
/// `Coverage`, and [`Report::try_new`] run at the same points as the pin.
/// The first failure wins.
pub fn parse_report(obj: &InputValue) -> Result<Report, ParseReportError> {
    match obj {
        InputValue::Str(_) => Err(ParseReportError::Json(JsonLoadsUnavailable)),
        InputValue::Dict(entries) => parse_report_mapping(entries),
        other => Err(schema_parse(format!(
            "Report must be a Mapping or JSON string, got {}",
            input_type_name(other)
        ))),
    }
}

/// Python: `dump_manifest`.
///
/// A value that is not a [`RepairManifest`] returns `TypeError` text
/// `Expected RepairManifest instance, got {type}`. A [`RepairManifest`]
/// calls [`RepairManifest::to_dict`] and then
/// `model::canonical::to_canonical_json`. That returns
/// [`CanonicalUnavailable`]. This function does not emit JSON and does not
/// hash a substitute.
pub fn dump_manifest(manifest: DumpManifestInput<'_>) -> Result<String, DumpManifestError> {
    let manifest = match manifest {
        DumpManifestInput::Manifest(manifest) => manifest,
        DumpManifestInput::Wrong { type_name } => {
            return Err(DumpManifestError::Type(format!(
                "Expected RepairManifest instance, got {type_name}"
            )));
        }
    };
    let rendered = match manifest.to_dict() {
        Ok(rendered) => rendered,
        Err(error) => return Err(DumpManifestError::Type(error.to_string())),
    };
    match model::canonical::to_canonical_json(&rendered) {
        Err(error) => Err(DumpManifestError::Canonical(error)),
        Ok(_json) => Err(DumpManifestError::Canonical(
            CanonicalUnavailable::canonical_json_bytes(),
        )),
    }
}

fn parse_report_mapping(entries: &[(InputKey, InputValue)]) -> Result<Report, ParseReportError> {
    reject_unknown(
        entries,
        &KNOWN_REPORT_FIELDS,
        "Unknown top-level field in report:",
    )?;
    require_present(entries, &REQUIRED_REPORT_FIELDS, |name| {
        format!("Missing required field in report: '{name}'")
    })?;
    let schema_version = required_value(entries, "schema_version")?;
    if !matches!(schema_version, InputValue::Str(text) if text == REPORT_SCHEMA_VERSION) {
        return Err(ParseReportError::Version(VersionError::new(
            format!(
                "Unsupported report schema version: {}",
                input_repr(schema_version)
            ),
            Some(python_str_value(schema_version)),
        )));
    }
    let session_id =
        require_report_text(required_value(entries, "session_id")?, "Report.session_id")?;
    let source_fingerprint = require_report_text(
        required_value(entries, "source_fingerprint")?,
        "Report.source_fingerprint",
    )?;
    let tool_version = require_report_text(
        required_value(entries, "tool_version")?,
        "Report.tool_version",
    )?;
    let findings = parse_findings(required_value(entries, "findings")?)?;
    let counts = parse_counts(required_value(entries, "counts")?)?;
    let assurance = require_parse_assurance(required_value(entries, "assurance")?)?;
    let limitation = require_parse_limitation(required_value(entries, "limitation")?)?;
    let coverage = parse_coverage(required_value(entries, "coverage")?)?;
    finish_report(ParsedReport {
        session_id: &session_id,
        source_fingerprint: &source_fingerprint,
        tool_version: &tool_version,
        findings: &findings,
        counts: &counts,
        assurance: &assurance,
        limitation: &limitation,
        coverage: &coverage,
    })
}

struct ParsedReport<'a> {
    session_id: &'a str,
    source_fingerprint: &'a str,
    tool_version: &'a str,
    findings: &'a [Finding],
    counts: &'a Counts,
    assurance: &'a str,
    limitation: &'a str,
    coverage: &'a Coverage,
}

fn finish_report(parsed: ParsedReport<'_>) -> Result<Report, ParseReportError> {
    let schema_version = InputValue::str_value(REPORT_SCHEMA_VERSION);
    let session_id = InputValue::str_value(parsed.session_id);
    let source_fingerprint = InputValue::str_value(parsed.source_fingerprint);
    let tool_version = InputValue::str_value(parsed.tool_version);
    let assurance = InputValue::str_value(parsed.assurance);
    let limitation = InputValue::str_value(parsed.limitation);
    let findings_input = FindingsInput::Tuple(
        parsed
            .findings
            .iter()
            .cloned()
            .map(FindingElem::Finding)
            .collect(),
    );
    let counts_input = CountsInput::Value(parsed.counts.clone());
    Report::try_new(ReportParts {
        schema_version: &schema_version,
        session_id: &session_id,
        source_fingerprint: &source_fingerprint,
        tool_version: &tool_version,
        findings: &findings_input,
        counts: &counts_input,
        assurance: &assurance,
        limitation: &limitation,
        coverage: CoverageInput::Value(parsed.coverage),
    })
    .map_err(lift_envelope)
}

fn parse_findings(value: &InputValue) -> Result<Vec<Finding>, ParseReportError> {
    let items = list_or_tuple(value, "findings")?;
    let mut parsed = Vec::with_capacity(items.len());
    for item in items {
        parsed.push(parse_one_finding(item)?);
    }
    Ok(sort_findings(&parsed))
}

fn parse_one_finding(value: &InputValue) -> Result<Finding, ParseReportError> {
    match value {
        InputValue::Dict(entries) => parse_finding_entries(entries),
        other => parse_non_mapping_finding(other),
    }
}

fn parse_non_mapping_finding(value: &InputValue) -> Result<Finding, ParseReportError> {
    if !contains_other(value) {
        if let Ok(py) = to_py(value) {
            return parse_finding_dict(&py).map_err(ParseReportError::Finding);
        }
    }
    Err(ParseReportError::Finding(FindingError::new(format!(
        "Finding object must be a mapping, got {}",
        input_type_name(value)
    ))))
}

fn parse_finding_entries(entries: &[(InputKey, InputValue)]) -> Result<Finding, ParseReportError> {
    if let Some((slot, value)) = first_custom_slot(entries) {
        probe_before(entries, slot)?;
        return Err(ParseReportError::Finding(custom_error(
            entries, slot, &value,
        )));
    }
    parse_finding_dict(&build_finding_py(entries)).map_err(ParseReportError::Finding)
}

fn first_custom_slot(entries: &[(InputKey, InputValue)]) -> Option<(&'static str, InputValue)> {
    for slot in FINDING_SLOTS {
        if let Some(value) = resolved_slot(entries, slot) {
            if slot_blocks(slot, value) {
                return Some((slot, value.clone()));
            }
        }
    }
    None
}

fn resolved_slot<'a>(entries: &'a [(InputKey, InputValue)], slot: &str) -> Option<&'a InputValue> {
    match slot {
        "message" => mapped_ref(entries, "message").or_else(|| mapped_ref(entries, "remediation")),
        "source" => match mapped_ref(entries, "source") {
            Some(InputValue::None) | None => mapped_ref(entries, "span"),
            Some(value) => Some(value),
        },
        other => mapped_ref(entries, other),
    }
}

fn slot_blocks(slot: &str, value: &InputValue) -> bool {
    if slot == "source" {
        source_blocks(value)
    } else {
        contains_other(value)
    }
}

fn source_blocks(value: &InputValue) -> bool {
    match value {
        InputValue::Dict(entries) => ["path", "line", "record_id"]
            .iter()
            .any(|name| mapped_ref(entries, name).is_some_and(contains_other)),
        other => contains_other(other),
    }
}

fn probe_before(entries: &[(InputKey, InputValue)], slot: &str) -> Result<(), ParseReportError> {
    let stop = slot_index(slot);
    let mut pairs = Vec::new();
    for (key, value) in entries {
        if let InputKey::Str(name) = key {
            if key_slot(name).is_some_and(|index| index >= stop) {
                continue;
            }
        }
        if let Some(py) = convertible_probe(key, value) {
            pairs.push((to_py_key(key), py));
        }
    }
    pairs.extend(placeholder_from(stop));
    parse_finding_dict(&PyValue::map(pairs))
        .map(|_| ())
        .map_err(ParseReportError::Finding)
}

fn convertible_probe(key: &InputKey, value: &InputValue) -> Option<PyValue> {
    let converted = match key {
        InputKey::Str(name) if name == "source" || name == "span" => to_py_source(value),
        _ => to_py(value),
    };
    converted.ok()
}

fn placeholder_from(stop: usize) -> Vec<(PyValue, PyValue)> {
    let mut pairs = Vec::new();
    if stop == 0 {
        pairs.push(py_pair(
            "schema_version",
            PyValue::string(FINDING_SCHEMA_VERSION),
        ));
    }
    if stop <= 1 {
        pairs.push(py_pair("code", PyValue::string("SL001")));
    }
    if stop <= 2 {
        pairs.push(py_pair("severity", PyValue::string("error")));
    }
    if stop <= 3 {
        pairs.push(py_pair("repairability", PyValue::string("manual")));
    }
    if stop <= 4 {
        pairs.push(py_pair("message", PyValue::string("synthetic marker")));
    }
    if stop <= 5 {
        pairs.push(py_pair("source", source_placeholder()));
    }
    if stop <= 6 {
        pairs.push(py_pair("related_ids", PyValue::list(Vec::new())));
    }
    if stop <= 7 {
        pairs.push(py_pair("fingerprint", PyValue::string("0123456789abcdef")));
    }
    pairs
}

fn source_placeholder() -> PyValue {
    PyValue::map(vec![
        py_pair("path", PyValue::string("probe.jsonl")),
        py_pair("line", PyValue::int(1)),
    ])
}

fn py_pair(name: &str, value: PyValue) -> (PyValue, PyValue) {
    (PyValue::string(name), value)
}

fn build_finding_py(entries: &[(InputKey, InputValue)]) -> PyValue {
    let mut pairs = Vec::new();
    for name in READ_FINDING_KEYS {
        let Some(value) = mapped_ref(entries, name) else {
            continue;
        };
        let converted = if name == "source" || name == "span" {
            to_py_source(value)
        } else {
            to_py(value)
        };
        if let Ok(py) = converted {
            pairs.push((PyValue::string(name), py));
        }
    }
    PyValue::map(pairs)
}

fn custom_error(
    entries: &[(InputKey, InputValue)],
    slot: &str,
    value: &InputValue,
) -> FindingError {
    match slot {
        "schema_version" => FindingError::new(format!(
            "Unsupported finding schema_version {}, expected '{FINDING_SCHEMA_VERSION}'",
            input_repr(value)
        )),
        "code" => FindingError::new(format!(
            "Invalid finding code in dictionary: {}",
            input_repr(value)
        )),
        "severity" => FindingError::new(format!(
            "Missing or non-string severity in finding dictionary: {}",
            input_repr(value)
        )),
        "repairability" => FindingError::new(format!(
            "Missing or non-string repairability in finding dictionary: {}",
            input_repr(value)
        )),
        "message" => message_slot_error(entries, value),
        "source" => source_slot_error(value),
        "related_ids" => related_slot_error(value),
        "fingerprint" => FindingError::new(format!(
            "Missing or invalid fingerprint in finding dictionary: {}",
            input_repr(value)
        )),
        "message_template" => FindingError::new(format!(
            "message_template must be a non-empty string or None, got {}",
            input_type_name(value)
        )),
        _ => evidence_slot_error(value),
    }
}

fn message_slot_error(entries: &[(InputKey, InputValue)], value: &InputValue) -> FindingError {
    if mapped_ref(entries, "message").is_some() {
        FindingError::new(format!(
            "Missing or non-string message in finding dictionary: {}",
            input_repr(value)
        ))
    } else {
        FindingError::new("Missing required field 'message' in finding dictionary".to_owned())
    }
}

fn source_slot_error(value: &InputValue) -> FindingError {
    let InputValue::Dict(entries) = value else {
        return FindingError::new(format!(
            "Missing or invalid source in finding dictionary: {}",
            input_repr(value)
        ));
    };
    match mapped_ref(entries, "path") {
        Some(InputValue::Str(text)) if !python_strip(text).is_empty() => {}
        Some(other) => {
            return FindingError::new(format!(
                "Missing or non-string source.path: {}",
                input_repr(other)
            ));
        }
        None => {
            return FindingError::new(format!(
                "Missing or non-string source.path: {}",
                input_repr(&InputValue::None)
            ));
        }
    }
    match mapped_ref(entries, "line") {
        None | Some(InputValue::None) | Some(InputValue::Int(_)) | Some(InputValue::Bool(_)) => {}
        Some(other) => {
            return FindingError::new(format!(
                "SourceRef.line must be a positive integer or None, got {}",
                input_repr(other)
            ));
        }
    }
    match mapped_ref(entries, "record_id") {
        None | Some(InputValue::None) | Some(InputValue::Str(_)) => {}
        Some(other) => {
            return FindingError::new(format!(
                "SourceRef.record_id must be non-empty string or None, got {}",
                input_repr(other)
            ));
        }
    }
    FindingError::new(format!(
        "Missing or invalid source in finding dictionary: {}",
        input_repr(value)
    ))
}

fn related_slot_error(value: &InputValue) -> FindingError {
    let items = match value {
        InputValue::List(items) | InputValue::Tuple(items) => items.as_slice(),
        other => {
            return FindingError::new(format!(
                "related_ids must be a list or tuple, got {}",
                input_type_name(other)
            ));
        }
    };
    for item in items {
        if let InputValue::Str(text) = item {
            if !python_strip(text).is_empty() {
                continue;
            }
        }
        return FindingError::new(format!(
            "related_ids elements must be non-empty strings, got {}",
            input_repr(item)
        ));
    }
    FindingError::new(format!(
        "related_ids must be a list or tuple, got {}",
        input_type_name(value)
    ))
}

fn evidence_slot_error(value: &InputValue) -> FindingError {
    let InputValue::Dict(entries) = value else {
        return FindingError::new(format!(
            "Finding.evidence must be a mapping or None, got {}",
            input_type_name(value)
        ));
    };
    match evidence_map_failure(entries) {
        Ok(()) => FindingError::new(FINDING_EVIDENCE_OBJECT),
        Err(error) => error,
    }
}

fn evidence_map_failure(entries: &[(InputKey, InputValue)]) -> Result<(), FindingError> {
    for (key, child) in entries {
        let InputKey::Str(text) = key else {
            return Err(FindingError::new(
                "Finding.evidence keys must be non-empty strings".to_owned(),
            ));
        };
        if python_strip(text).is_empty() {
            return Err(FindingError::new(
                "Finding.evidence keys must be non-empty strings".to_owned(),
            ));
        }
        let key_repr = python_str_repr(text);
        enforce_content_free_text(text, &format!("Finding.evidence key {key_repr}"))?;
        check_evidence_tree(child, &format!("Finding.evidence value for {key_repr}"))?;
    }
    Ok(())
}

fn check_evidence_tree(value: &InputValue, context: &str) -> Result<(), FindingError> {
    if matches!(value, InputValue::Other { .. }) {
        return Err(FindingError::new(FINDING_EVIDENCE_OBJECT));
    }
    if !contains_other(value) {
        return enforce_content_free_evidence_recursive(&evidence_from_input(value), context);
    }
    match value {
        InputValue::List(items)
        | InputValue::Tuple(items)
        | InputValue::Set(items)
        | InputValue::FrozenSet(items) => {
            for item in items {
                check_evidence_tree(item, context)?;
            }
            Ok(())
        }
        InputValue::Dict(entries) => {
            for (key, child) in entries {
                let InputKey::Str(text) = key else {
                    return Err(FindingError::new(format!(
                        "{context} keys must be non-empty strings"
                    )));
                };
                if python_strip(text).is_empty() {
                    return Err(FindingError::new(format!(
                        "{context} keys must be non-empty strings"
                    )));
                }
                let key_repr = python_str_repr(text);
                enforce_content_free_text(text, &format!("{context} key {key_repr}"))?;
                check_evidence_tree(child, &format!("{context}[{key_repr}]"))?;
            }
            Ok(())
        }
        InputValue::None
        | InputValue::Bool(_)
        | InputValue::Int(_)
        | InputValue::Str(_)
        | InputValue::Other { .. } => Err(FindingError::new(FINDING_EVIDENCE_OBJECT)),
    }
}

fn evidence_from_input(value: &InputValue) -> Evidence {
    match value {
        InputValue::None => Evidence::none_value(),
        InputValue::Bool(flag) => Evidence::bool_value(*flag),
        InputValue::Int(number) => Evidence::int(*number),
        InputValue::Str(text) => Evidence::string(text.clone()),
        InputValue::List(items) => Evidence::list(items.iter().map(evidence_from_input).collect()),
        InputValue::Tuple(items) => {
            Evidence::tuple(items.iter().map(evidence_from_input).collect())
        }
        InputValue::Set(items) => Evidence::set(items.iter().map(evidence_from_input).collect()),
        InputValue::FrozenSet(items) => {
            Evidence::frozenset(items.iter().map(evidence_from_input).collect())
        }
        InputValue::Dict(entries) => {
            let mapped = entries
                .iter()
                .map(|(key, child)| {
                    let evidence_key = match key {
                        InputKey::Str(text) => EvidenceKey::text(text.clone()),
                        InputKey::None | InputKey::Bool(_) | InputKey::Int(_) => {
                            EvidenceKey::NonString
                        }
                    };
                    (evidence_key, evidence_from_input(child))
                })
                .collect();
            Evidence::map(mapped)
        }
        InputValue::Other { .. } => Evidence::ignored(),
    }
}

fn to_py(value: &InputValue) -> Result<PyValue, ()> {
    match value {
        InputValue::None => Ok(PyValue::None),
        InputValue::Bool(flag) => Ok(PyValue::bool_value(*flag)),
        InputValue::Int(number) => Ok(PyValue::int(*number)),
        InputValue::Str(text) => Ok(PyValue::string(text.clone())),
        InputValue::List(items) => Ok(PyValue::list(map_py(items)?)),
        InputValue::Tuple(items) => Ok(PyValue::tuple(map_py(items)?)),
        InputValue::Set(items) => Ok(PyValue::set(map_py(items)?)),
        InputValue::FrozenSet(items) => Ok(PyValue::FrozenSet(map_py(items)?)),
        InputValue::Dict(entries) => {
            let mut pairs = Vec::with_capacity(entries.len());
            for (key, child) in entries {
                pairs.push((to_py_key(key), to_py(child)?));
            }
            Ok(PyValue::map(pairs))
        }
        InputValue::Other { .. } => Err(()),
    }
}

fn map_py(items: &[InputValue]) -> Result<Vec<PyValue>, ()> {
    items.iter().map(to_py).collect()
}

fn to_py_source(value: &InputValue) -> Result<PyValue, ()> {
    match value {
        InputValue::Dict(entries) => {
            let mut pairs = Vec::new();
            for name in ["path", "line", "record_id"] {
                if let Some(child) = mapped_ref(entries, name) {
                    pairs.push((PyValue::string(name), to_py(child)?));
                }
            }
            Ok(PyValue::map(pairs))
        }
        other => to_py(other),
    }
}

fn to_py_key(key: &InputKey) -> PyValue {
    match key {
        InputKey::None => PyValue::None,
        InputKey::Bool(flag) => PyValue::bool_value(*flag),
        InputKey::Int(number) => PyValue::int(*number),
        InputKey::Str(text) => PyValue::string(text.clone()),
    }
}

fn contains_other(value: &InputValue) -> bool {
    match value {
        InputValue::Other { .. } => true,
        InputValue::List(items)
        | InputValue::Tuple(items)
        | InputValue::Set(items)
        | InputValue::FrozenSet(items) => items.iter().any(contains_other),
        InputValue::Dict(entries) => entries.iter().any(|(_, child)| contains_other(child)),
        InputValue::None | InputValue::Bool(_) | InputValue::Int(_) | InputValue::Str(_) => false,
    }
}

fn slot_index(slot: &str) -> usize {
    FINDING_SLOTS
        .iter()
        .position(|name| *name == slot)
        .unwrap_or(FINDING_SLOTS.len())
}

fn key_slot(name: &str) -> Option<usize> {
    match name {
        "remediation" => FINDING_SLOTS.iter().position(|slot| *slot == "message"),
        "span" => FINDING_SLOTS.iter().position(|slot| *slot == "source"),
        other => FINDING_SLOTS.iter().position(|slot| *slot == other),
    }
}

fn parse_counts(value: &InputValue) -> Result<Counts, ParseReportError> {
    let entries = as_dict(value, "counts")?;
    reject_unknown(entries, &COUNT_FIELDS, "Unknown field in counts:")?;
    require_present(entries, &COUNT_FIELDS, |name| {
        format!("Missing required field in counts: '{name}'")
    })?;
    let raw_sev = required_value(entries, "by_severity")?;
    let sev_entries = as_dict(raw_sev, "counts.by_severity")?;
    reject_unknown(
        sev_entries,
        &REQUIRED_SEVERITIES,
        "Unknown severity in counts.by_severity:",
    )?;
    require_present(sev_entries, &REQUIRED_SEVERITIES, |name| {
        format!("Missing required severity in counts.by_severity: '{name}'")
    })?;
    let raw_by_code = required_value(entries, "by_code")?;
    let _code_entries = as_dict(raw_by_code, "counts.by_code")?;
    let raw_total = required_value(entries, "total")?;
    require_count_total(raw_total)?;
    Counts::try_new(
        &to_count(raw_sev),
        &to_count(raw_by_code),
        &to_count(raw_total),
    )
    .map_err(ParseReportError::Schema)
}

fn require_count_total(value: &InputValue) -> Result<(), ParseReportError> {
    match value {
        InputValue::Int(number) if *number >= 0 => Ok(()),
        other => Err(schema_parse(format!(
            "counts.total must be a non-negative integer, got {}",
            input_repr(other)
        ))),
    }
}

fn to_count(value: &InputValue) -> CountValue {
    match value {
        InputValue::None => CountValue::none(),
        InputValue::Bool(flag) => CountValue::bool_value(*flag),
        InputValue::Int(number) => CountValue::int(*number),
        InputValue::Str(text) => CountValue::str_value(text.clone()),
        InputValue::List(items) => CountValue::list(items.iter().map(to_count).collect()),
        InputValue::Tuple(items) => CountValue::tuple(items.iter().map(to_count).collect()),
        InputValue::Dict(entries) => CountValue::dict(
            entries
                .iter()
                .map(|(key, child)| (to_count_key(key), to_count(child)))
                .collect(),
        ),
        InputValue::Set(_) => CountValue::other("set", input_repr(value)),
        InputValue::FrozenSet(_) => CountValue::other("frozenset", input_repr(value)),
        InputValue::Other {
            type_name,
            rendered,
        } => CountValue::other(type_name.clone(), rendered.clone()),
    }
}

fn to_count_key(key: &InputKey) -> CountKey {
    match key {
        InputKey::None => CountKey::None,
        InputKey::Bool(flag) => CountKey::bool_value(*flag),
        InputKey::Int(number) => CountKey::int(*number),
        InputKey::Str(text) => CountKey::str_key(text.clone()),
    }
}

fn require_parse_assurance(value: &InputValue) -> Result<String, ParseReportError> {
    if let InputValue::Str(text) = value {
        if VALID_ASSURANCE_LEVELS.contains(&text.as_str()) {
            return Ok(text.clone());
        }
    }
    Err(ParseReportError::Assurance(AssuranceError::new(format!(
        "Invalid assurance level {}. Must be one of {}",
        input_repr(value),
        sorted_assurance_repr()
    ))))
}

fn require_parse_limitation(value: &InputValue) -> Result<String, ParseReportError> {
    if let InputValue::Str(text) = value {
        let stripped = python_strip(text);
        if !stripped.is_empty() {
            return Ok(stripped.to_owned());
        }
    }
    Err(ParseReportError::Assurance(AssuranceError::new(format!(
        "Report limitation must be a non-empty string, got {}",
        input_repr(value)
    ))))
}

fn parse_coverage(value: &InputValue) -> Result<Coverage, ParseReportError> {
    let entries = as_dict(value, "Report.coverage")?;
    reject_unknown(entries, &COVERAGE_FIELDS, "Unknown field in coverage:")?;
    require_present(entries, &COVERAGE_FIELDS, |name| {
        format!("Missing required field in coverage: '{name}'")
    })?;
    let performed = parse_performed(required_value(entries, "performed")?)?;
    let skipped = parse_skipped(required_value(entries, "skipped")?)?;
    let adapter = parse_binding(required_value(entries, "adapter")?, "coverage.adapter")?;
    let profile = parse_binding(required_value(entries, "profile")?, "coverage.profile")?;
    let performed_value = InputValue::list(
        performed
            .iter()
            .map(|item| InputValue::str_value(item.clone()))
            .collect(),
    );
    let skipped_value = SkipSeq::List(skipped.into_iter().map(SkipElem::Skip).collect());
    Coverage::try_new(&performed_value, &skipped_value, &adapter, &profile).map_err(lift_envelope)
}

fn parse_performed(value: &InputValue) -> Result<Vec<String>, ParseReportError> {
    let items = list_or_tuple(value, "coverage.performed")?;
    let mut parsed = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        match item {
            InputValue::Str(text) if !python_strip(text).is_empty() => {
                parsed.push(python_strip(text).to_owned());
            }
            other => {
                return Err(schema_parse(format!(
                    "coverage.performed[{index}] must be a non-empty string, got {}",
                    input_repr(other)
                )));
            }
        }
    }
    Ok(parsed)
}

fn parse_skipped(value: &InputValue) -> Result<Vec<CoverageSkip>, ParseReportError> {
    let items = list_or_tuple(value, "coverage.skipped")?;
    let mut parsed = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        parsed.push(parse_skip(index, item)?);
    }
    Ok(parsed)
}

fn parse_skip(index: usize, item: &InputValue) -> Result<CoverageSkip, ParseReportError> {
    let entries = as_dict(item, &format!("coverage.skipped[{index}]"))?;
    reject_unknown(
        entries,
        &SKIP_FIELDS,
        &format!("Unknown field in coverage.skipped[{index}]:"),
    )?;
    if mapped_ref(entries, "check").is_none() {
        return Err(schema_parse(format!(
            "coverage.skipped[{index}] missing required field 'check'"
        )));
    }
    if mapped_ref(entries, "reason").is_none() {
        return Err(schema_parse(format!(
            "coverage.skipped[{index}] missing required field 'reason'"
        )));
    }
    let check = match required_value(entries, "check")? {
        InputValue::Str(text) if !python_strip(text).is_empty() => python_strip(text).to_owned(),
        other => {
            return Err(schema_parse(format!(
                "coverage.skipped[{index}].check must be a non-empty string, got {}",
                input_repr(other)
            )));
        }
    };
    let reason = match required_value(entries, "reason")? {
        InputValue::Str(text) if VALID_COVERAGE_SKIP_REASONS.contains(&text.as_str()) => {
            text.clone()
        }
        other => {
            return Err(schema_parse(format!(
                "Invalid coverage skip reason '{}' in skipped[{index}]. Must be one of {}",
                python_str_value(other),
                sorted_reasons_repr()
            )));
        }
    };
    let detail = match mapped_ref(entries, "detail") {
        None => String::new(),
        Some(InputValue::Str(text)) => python_strip(text).to_owned(),
        Some(other) => {
            return Err(schema_parse(format!(
                "coverage.skipped[{index}].detail must be a string, got {}",
                input_type_name(other)
            )));
        }
    };
    let check_value = InputValue::str_value(check);
    let reason_value = InputValue::str_value(reason);
    let detail_value = InputValue::str_value(detail);
    CoverageSkip::try_new(&check_value, &reason_value, &detail_value).map_err(lift_envelope)
}

fn parse_binding(value: &InputValue, label: &str) -> Result<InputValue, ParseReportError> {
    let entries = as_dict(value, label)?;
    reject_unknown(
        entries,
        &BINDING_FIELDS,
        &format!("Unknown field in {label}:"),
    )?;
    let id = match id_or_name(entries) {
        Some(InputValue::Str(text)) if !python_strip(&text).is_empty() => {
            python_strip(&text).to_owned()
        }
        _ => {
            return Err(schema_parse(format!("{label} must contain non-empty 'id'")));
        }
    };
    let version = match mapped_ref(entries, "version") {
        Some(InputValue::Str(text)) if !python_strip(text).is_empty() => {
            python_strip(text).to_owned()
        }
        _ => {
            return Err(schema_parse(format!(
                "{label} must contain non-empty 'version'"
            )));
        }
    };
    let mut pairs = vec![
        (InputKey::str_key("id"), InputValue::str_value(id)),
        (InputKey::str_key("version"), InputValue::str_value(version)),
    ];
    if let Some(InputValue::Str(text)) = mapped_ref(entries, "name") {
        pairs.push((
            InputKey::str_key("name"),
            InputValue::str_value(python_strip(text).to_owned()),
        ));
    }
    Ok(InputValue::dict(pairs))
}

fn id_or_name(entries: &[(InputKey, InputValue)]) -> Option<InputValue> {
    match mapped_value(entries, "id") {
        Some(value) if !is_falsy(&value) => Some(value),
        _ => mapped_value(entries, "name"),
    }
}

fn is_falsy(value: &InputValue) -> bool {
    match value {
        InputValue::None | InputValue::Bool(false) | InputValue::Int(0) => true,
        InputValue::Str(text) => text.is_empty(),
        InputValue::List(items)
        | InputValue::Tuple(items)
        | InputValue::Set(items)
        | InputValue::FrozenSet(items) => items.is_empty(),
        InputValue::Dict(entries) => entries.is_empty(),
        InputValue::Bool(true) | InputValue::Int(_) | InputValue::Other { .. } => false,
    }
}

fn require_report_text(value: &InputValue, label: &str) -> Result<String, ParseReportError> {
    match value {
        InputValue::Str(text) if !python_strip(text).is_empty() => {
            Ok(python_strip(text).to_owned())
        }
        other => Err(schema_parse(format!(
            "{label} must be a non-empty string, got {}",
            input_repr(other)
        ))),
    }
}

fn list_or_tuple<'a>(
    value: &'a InputValue,
    label: &str,
) -> Result<&'a [InputValue], ParseReportError> {
    match value {
        InputValue::List(items) | InputValue::Tuple(items) => Ok(items.as_slice()),
        other => Err(schema_parse(format!(
            "{label} must be a list or tuple, got {}",
            input_type_name(other)
        ))),
    }
}

fn as_dict<'a>(
    value: &'a InputValue,
    what: &str,
) -> Result<&'a [(InputKey, InputValue)], ParseReportError> {
    match value {
        InputValue::Dict(entries) => Ok(entries.as_slice()),
        other => Err(schema_parse(format!(
            "{what} must be a mapping, got {}",
            input_type_name(other)
        ))),
    }
}

fn reject_unknown(
    entries: &[(InputKey, InputValue)],
    allowed: &[&str],
    describe: &str,
) -> Result<(), ParseReportError> {
    for (key, _) in entries {
        if string_allowed(key, allowed) {
            continue;
        }
        let name = key_text(key);
        return Err(ParseReportError::UnknownField(UnknownFieldError::new(
            format!("{describe} '{name}'"),
            Some(name),
        )));
    }
    Ok(())
}

fn require_present(
    entries: &[(InputKey, InputValue)],
    names: &[&str],
    missing: impl Fn(&str) -> String,
) -> Result<(), ParseReportError> {
    for name in names {
        if mapped_ref(entries, name).is_none() {
            return Err(schema_parse(missing(name)));
        }
    }
    Ok(())
}

fn required_value<'a>(
    entries: &'a [(InputKey, InputValue)],
    name: &str,
) -> Result<&'a InputValue, ParseReportError> {
    match mapped_ref(entries, name) {
        Some(value) => Ok(value),
        None => Err(schema_parse(format!(
            "Missing required field in report: '{name}'"
        ))),
    }
}

fn string_allowed(key: &InputKey, allowed: &[&str]) -> bool {
    matches!(key, InputKey::Str(text) if allowed.contains(&text.as_str()))
}

fn key_text(key: &InputKey) -> String {
    match key {
        InputKey::Str(text) => text.clone(),
        InputKey::None => "None".to_owned(),
        InputKey::Bool(true) => "True".to_owned(),
        InputKey::Bool(false) => "False".to_owned(),
        InputKey::Int(number) => number.to_string(),
    }
}

fn mapped_ref<'a>(entries: &'a [(InputKey, InputValue)], name: &str) -> Option<&'a InputValue> {
    entries
        .iter()
        .rev()
        .find(|(key, _)| matches!(key, InputKey::Str(text) if text == name))
        .map(|(_, value)| value)
}

fn mapped_value(entries: &[(InputKey, InputValue)], name: &str) -> Option<InputValue> {
    mapped_ref(entries, name).cloned()
}

fn schema_parse(message: String) -> ParseReportError {
    ParseReportError::Schema(schema(message))
}

fn lift_envelope(error: EnvelopeError) -> ParseReportError {
    match error {
        EnvelopeError::Schema(error) => ParseReportError::Schema(error),
        EnvelopeError::Version(error) => ParseReportError::Version(error),
        EnvelopeError::Assurance(error) => ParseReportError::Assurance(error),
        EnvelopeError::ContentLeak(error) => ParseReportError::ContentLeak(error),
        EnvelopeError::TypeMismatch(message) => ParseReportError::Type(message),
        EnvelopeError::Unavailable(name) => ParseReportError::Unavailable(name),
    }
}

/// `REQUIRED_MANIFEST_FIELDS` and `KNOWN_MANIFEST_FIELDS` are frozensets.
///
/// Missing-field checks walk the source literal order. CPython frozenset
/// iteration is not reproduced. This walk is not a hash-seed order.
pub const MANIFEST_FIELD_ORDER_DEVIATION: &str = "REQUIRED_MANIFEST_FIELDS and KNOWN_MANIFEST_FIELDS are frozensets. Missing-field checks walk the source literal order. CPython frozenset iteration is not reproduced";

/// Pin tuple order. The first present name wins, before the unknown-key scan.
const FORBIDDEN_MANIFEST_FIELDS: [&str; 4] = ["success", "passed", "ok", "healthy"];

/// Source literal order of `KNOWN_MANIFEST_FIELDS`. Membership only.
///
/// The pin stores a frozenset. See [`MANIFEST_FIELD_ORDER_DEVIATION`].
const KNOWN_MANIFEST_FIELDS: [&str; 18] = [
    "schema_version",
    "input_fingerprint",
    "output_fingerprint",
    "plan_fingerprint",
    "assurance",
    "assurance_ceiling",
    "recipe_versions",
    "profile_version",
    "adapter_id",
    "adapter_version",
    "byte_counts",
    "record_counts",
    "policy",
    "actions",
    "declared_loss",
    "revalidate_report",
    "revalidation",
    "idempotency_key",
];

/// Source literal order of `REQUIRED_MANIFEST_FIELDS`.
///
/// The pin stores a frozenset. Missing-field checks walk this order.
/// See [`MANIFEST_FIELD_ORDER_DEVIATION`].
const REQUIRED_MANIFEST_FIELDS: [&str; 10] = [
    "schema_version",
    "input_fingerprint",
    "output_fingerprint",
    "policy",
    "actions",
    "declared_loss",
    "revalidate_report",
    "idempotency_key",
    "revalidation",
    "assurance_ceiling",
];

const ACTION_FIELDS: [&str; 3] = ["kind", "record_id", "detail"];

const REVALIDATION_FIELDS: [&str; 6] = [
    "assurance",
    "error_count",
    "warning_count",
    "profile_id",
    "profile_version",
    "report_fingerprint",
];

const REQUIRED_REVALIDATION_FIELDS: [&str; 5] = [
    "assurance",
    "error_count",
    "warning_count",
    "profile_id",
    "profile_version",
];

/// Failure from [`parse_manifest`].
///
/// [`Display`](fmt::Display) is the Python exception message.
/// [`Self::Json`] displays [`JsonLoadsUnavailable::MESSAGE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseManifestError {
    Schema(SchemaError),
    Version(VersionError),
    UnknownField(UnknownFieldError),
    Assurance(AssuranceError),
    ContentLeak(ContentLeakError),
    /// Python `TypeError`. The string is `str(exc)`.
    Type(String),
    /// Late import named by the string, without the ` is not available` suffix.
    Unavailable(&'static str),
    Json(JsonLoadsUnavailable),
}

impl fmt::Display for ParseManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(error) => write!(formatter, "{error}"),
            Self::Version(error) => write!(formatter, "{error}"),
            Self::UnknownField(error) => write!(formatter, "{error}"),
            Self::Assurance(error) => write!(formatter, "{error}"),
            Self::ContentLeak(error) => write!(formatter, "{error}"),
            Self::Type(message) => formatter.write_str(message),
            Self::Unavailable(name) => write!(formatter, "{name} is not available"),
            Self::Json(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for ParseManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Schema(error) => Some(error),
            Self::Version(error) => Some(error),
            Self::UnknownField(error) => Some(error),
            Self::Assurance(error) => Some(error),
            Self::ContentLeak(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Type(_) | Self::Unavailable(_) => None,
        }
    }
}

/// Python: `parse_manifest`.
///
/// A string is the `json.loads` branch. This crate has no JSON parser, so
/// every string returns [`JsonLoadsUnavailable`] and is not inspected.
/// A non-string, non-mapping returns
/// `Manifest must be a Mapping or JSON string, got {type}`.
///
/// A mapping checks synthetic success fields, then unknown keys in insertion
/// order, then missing required fields in literal order
/// ([`MANIFEST_FIELD_ORDER_DEVIATION`]). `schema_version` uses the pin
/// `repr` in [`VersionError`]. Actions are a list or tuple and are sorted
/// with [`action_sort_key`]. `declared_loss` keeps input order.
/// [`RepairManifest::try_new`] runs after the field checks. Its error is
/// returned unchanged. The first failure wins.
pub fn parse_manifest(obj: &InputValue) -> Result<RepairManifest, ParseManifestError> {
    match obj {
        InputValue::Str(_) => Err(ParseManifestError::Json(JsonLoadsUnavailable)),
        InputValue::Dict(entries) => parse_manifest_mapping(entries),
        other => Err(schema_manifest(format!(
            "Manifest must be a Mapping or JSON string, got {}",
            input_type_name(other)
        ))),
    }
}

fn parse_manifest_mapping(
    entries: &[(InputKey, InputValue)],
) -> Result<RepairManifest, ParseManifestError> {
    reject_synthetic_success(entries)?;
    reject_manifest_unknown(entries)?;
    require_manifest_fields(entries)?;
    manifest_schema_version(manifest_field(entries, "schema_version")?)?;
    let input_fingerprint =
        manifest_fingerprint(manifest_field(entries, "input_fingerprint")?, "input_fingerprint")?;
    let output_fingerprint = manifest_fingerprint(
        manifest_field(entries, "output_fingerprint")?,
        "output_fingerprint",
    )?;
    let policy = parse_manifest_policy(manifest_field(entries, "policy")?)?;
    let actions = parse_manifest_actions(manifest_field(entries, "actions")?)?;
    let declared_loss = parse_declared_loss(manifest_field(entries, "declared_loss")?)?;
    let revalidate_report = parse_revalidate_report(manifest_field(entries, "revalidate_report")?)?;
    let idempotency_key = parse_idempotency(manifest_field(entries, "idempotency_key")?)?;
    let plan_fingerprint = optional_text(
        entries,
        "plan_fingerprint",
        "RepairManifest.plan_fingerprint must be a non-empty string",
    )?;
    let assurance = optional_text(
        entries,
        "assurance",
        "RepairManifest.assurance must be a non-empty string",
    )?;
    let recipe_versions = copied_mapping(
        entries,
        "recipe_versions",
        "RepairManifest.recipe_versions must be a mapping",
    )?;
    let profile_version = optional_text(
        entries,
        "profile_version",
        "RepairManifest.profile_version must be a non-empty string",
    )?;
    let adapter_id = optional_text(
        entries,
        "adapter_id",
        "RepairManifest.adapter_id must be a non-empty string",
    )?;
    let adapter_version = optional_text(
        entries,
        "adapter_version",
        "RepairManifest.adapter_version must be a non-empty string",
    )?;
    let byte_counts = copied_mapping(
        entries,
        "byte_counts",
        "RepairManifest.byte_counts must be a mapping",
    )?;
    let record_counts = copied_mapping(
        entries,
        "record_counts",
        "RepairManifest.record_counts must be a mapping",
    )?;
    let revalidation = parse_revalidation_block(manifest_field(entries, "revalidation")?)?;
    let assurance_ceiling = parse_ceiling(manifest_field(entries, "assurance_ceiling")?)?;
    finish_manifest(ParsedManifest {
        input_fingerprint,
        output_fingerprint,
        policy,
        actions,
        declared_loss,
        revalidate_report,
        idempotency_key,
        plan_fingerprint,
        assurance,
        recipe_versions,
        profile_version,
        adapter_id,
        adapter_version,
        byte_counts,
        record_counts,
        revalidation,
        assurance_ceiling,
    })
}

struct ParsedManifest {
    input_fingerprint: String,
    output_fingerprint: String,
    policy: String,
    actions: Vec<RepairAction>,
    declared_loss: Vec<String>,
    revalidate_report: Option<String>,
    idempotency_key: String,
    plan_fingerprint: Option<String>,
    assurance: Option<String>,
    recipe_versions: Vec<(InputKey, InputValue)>,
    profile_version: Option<String>,
    adapter_id: Option<String>,
    adapter_version: Option<String>,
    byte_counts: Vec<(InputKey, InputValue)>,
    record_counts: Vec<(InputKey, InputValue)>,
    revalidation: RevalidationSummary,
    assurance_ceiling: String,
}

fn finish_manifest(parsed: ParsedManifest) -> Result<RepairManifest, ParseManifestError> {
    let schema_version = InputValue::str_value(MANIFEST_SCHEMA_VERSION);
    let input_fingerprint = InputValue::str_value(parsed.input_fingerprint);
    let output_fingerprint = InputValue::str_value(parsed.output_fingerprint);
    let policy = InputValue::str_value(parsed.policy);
    let actions = ActionSeq::Tuple(parsed.actions.into_iter().map(ActionElem::Action).collect());
    let declared_loss = InputValue::tuple(
        parsed
            .declared_loss
            .into_iter()
            .map(InputValue::str_value)
            .collect(),
    );
    let revalidate_report = present_text(parsed.revalidate_report);
    let idempotency_key = InputValue::str_value(parsed.idempotency_key);
    let revalidation = RevalidationInput::Summary(parsed.revalidation);
    let assurance_ceiling = InputValue::str_value(parsed.assurance_ceiling);
    let plan_fingerprint = present_text(parsed.plan_fingerprint);
    let assurance = present_text(parsed.assurance);
    let recipe_versions = InputValue::dict(parsed.recipe_versions);
    let profile_version = present_text(parsed.profile_version);
    let adapter_id = present_text(parsed.adapter_id);
    let adapter_version = present_text(parsed.adapter_version);
    let byte_counts = InputValue::dict(parsed.byte_counts);
    let record_counts = InputValue::dict(parsed.record_counts);
    RepairManifest::try_new(RepairManifestParts {
        schema_version: &schema_version,
        input_fingerprint: &input_fingerprint,
        output_fingerprint: &output_fingerprint,
        policy: &policy,
        actions: &actions,
        declared_loss: &declared_loss,
        revalidate_report: &revalidate_report,
        idempotency_key: &idempotency_key,
        revalidation: &revalidation,
        assurance_ceiling: &assurance_ceiling,
        plan_fingerprint: &plan_fingerprint,
        assurance: &assurance,
        recipe_versions: &recipe_versions,
        profile_version: &profile_version,
        adapter_id: &adapter_id,
        adapter_version: &adapter_version,
        byte_counts: &byte_counts,
        record_counts: &record_counts,
    })
    .map_err(lift_manifest)
}

fn present_text(value: Option<String>) -> InputValue {
    match value {
        Some(text) => InputValue::str_value(text),
        None => InputValue::None,
    }
}

fn reject_synthetic_success(entries: &[(InputKey, InputValue)]) -> Result<(), ParseManifestError> {
    for name in FORBIDDEN_MANIFEST_FIELDS {
        if mapped_ref(entries, name).is_some() {
            return Err(schema_manifest(format!(
                "Manifest must not contain synthetic '{name}' field (never-synthetic-success invariant)"
            )));
        }
    }
    Ok(())
}

fn reject_manifest_unknown(entries: &[(InputKey, InputValue)]) -> Result<(), ParseManifestError> {
    for (key, _) in entries {
        if string_allowed(key, &KNOWN_MANIFEST_FIELDS) {
            continue;
        }
        let name = key_text(key);
        return Err(ParseManifestError::UnknownField(UnknownFieldError::new(
            format!("Unknown top-level field in manifest: '{name}'"),
            Some(name),
        )));
    }
    Ok(())
}

fn require_manifest_fields(entries: &[(InputKey, InputValue)]) -> Result<(), ParseManifestError> {
    for name in REQUIRED_MANIFEST_FIELDS {
        if mapped_ref(entries, name).is_none() {
            return Err(schema_manifest(format!(
                "Missing required field in manifest: '{name}'"
            )));
        }
    }
    Ok(())
}

fn manifest_field<'a>(
    entries: &'a [(InputKey, InputValue)],
    name: &str,
) -> Result<&'a InputValue, ParseManifestError> {
    match mapped_ref(entries, name) {
        Some(value) => Ok(value),
        None => Err(schema_manifest(format!(
            "Missing required field in manifest: '{name}'"
        ))),
    }
}

fn manifest_schema_version(value: &InputValue) -> Result<(), ParseManifestError> {
    if matches!(value, InputValue::Str(text) if text == MANIFEST_SCHEMA_VERSION) {
        return Ok(());
    }
    Err(ParseManifestError::Version(VersionError::new(
        format!(
            "Unsupported manifest schema version: {}",
            input_repr(value)
        ),
        Some(python_str_value(value)),
    )))
}

fn manifest_fingerprint(value: &InputValue, label: &str) -> Result<String, ParseManifestError> {
    match value {
        InputValue::Str(text) if !python_strip(text).is_empty() => {
            Ok(python_strip(text).to_owned())
        }
        other => Err(schema_manifest(format!(
            "RepairManifest.{label} must be a non-empty string, got {}",
            input_repr(other)
        ))),
    }
}

fn parse_manifest_policy(value: &InputValue) -> Result<String, ParseManifestError> {
    match value {
        InputValue::Str(text) if VALID_POLICIES.contains(&text.as_str()) => Ok(text.clone()),
        other => Err(schema_manifest(format!(
            "Invalid manifest policy: {}",
            input_repr(other)
        ))),
    }
}

fn parse_manifest_actions(value: &InputValue) -> Result<Vec<RepairAction>, ParseManifestError> {
    let items = match value {
        InputValue::List(items) | InputValue::Tuple(items) => items,
        other => {
            return Err(schema_manifest(format!(
                "actions must be a list or tuple, got {}",
                input_type_name(other)
            )));
        }
    };
    let mut actions = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        actions.push(parse_manifest_action(index, item)?);
    }
    sort_parsed_actions(&mut actions);
    Ok(actions)
}

fn sort_parsed_actions(actions: &mut [RepairAction]) {
    actions.sort_by(|left, right| {
        action_sort_key(ActionSortFields {
            kind: left.kind(),
            record_id: left.record_id(),
            detail: left.detail(),
        })
        .cmp(&action_sort_key(ActionSortFields {
            kind: right.kind(),
            record_id: right.record_id(),
            detail: right.detail(),
        }))
    });
}

fn parse_manifest_action(
    index: usize,
    item: &InputValue,
) -> Result<RepairAction, ParseManifestError> {
    let InputValue::Dict(entries) = item else {
        return Err(schema_manifest(format!(
            "actions[{index}] must be a mapping, got {}",
            input_type_name(item)
        )));
    };
    let Some(kind_value) = mapped_ref(entries, "kind") else {
        return Err(schema_manifest(format!(
            "actions[{index}] missing required field 'kind'"
        )));
    };
    reject_action_unknown(index, entries)?;
    let kind = action_kind(index, kind_value)?;
    let record_id = action_record_id(index, entries)?;
    let detail = action_detail(index, entries)?;
    let kind_input = InputValue::str_value(kind);
    let record_input = present_text(record_id);
    let detail_input = InputValue::str_value(detail);
    RepairAction::try_new(&kind_input, &record_input, &detail_input).map_err(lift_manifest)
}

fn reject_action_unknown(
    index: usize,
    entries: &[(InputKey, InputValue)],
) -> Result<(), ParseManifestError> {
    for (key, _) in entries {
        if string_allowed(key, &ACTION_FIELDS) {
            continue;
        }
        let name = key_text(key);
        return Err(ParseManifestError::UnknownField(UnknownFieldError::new(
            format!("Unknown field in action[{index}]: '{name}'"),
            Some(name),
        )));
    }
    Ok(())
}

fn action_kind(index: usize, value: &InputValue) -> Result<String, ParseManifestError> {
    match value {
        InputValue::Str(text) if !python_strip(text).is_empty() => Ok(python_strip(text).to_owned()),
        other => Err(schema_manifest(format!(
            "actions[{index}].kind must be a non-empty string, got {}",
            input_repr(other)
        ))),
    }
}

fn action_record_id(
    index: usize,
    entries: &[(InputKey, InputValue)],
) -> Result<Option<String>, ParseManifestError> {
    match mapped_ref(entries, "record_id") {
        None | Some(InputValue::None) => Ok(None),
        Some(InputValue::Str(text)) if !python_strip(text).is_empty() => {
            Ok(Some(python_strip(text).to_owned()))
        }
        Some(other) => Err(schema_manifest(format!(
            "actions[{index}].record_id must be non-empty string or None, got {}",
            input_repr(other)
        ))),
    }
}

fn action_detail(
    index: usize,
    entries: &[(InputKey, InputValue)],
) -> Result<String, ParseManifestError> {
    match mapped_ref(entries, "detail") {
        None => Ok(String::new()),
        Some(InputValue::Str(text)) => Ok(python_strip(text).to_owned()),
        Some(other) => Err(schema_manifest(format!(
            "actions[{index}].detail must be a string, got {}",
            input_type_name(other)
        ))),
    }
}

fn parse_declared_loss(value: &InputValue) -> Result<Vec<String>, ParseManifestError> {
    let items = match value {
        InputValue::List(items) | InputValue::Tuple(items) => items,
        other => {
            return Err(schema_manifest(format!(
                "declared_loss must be a list or tuple, got {}",
                input_type_name(other)
            )));
        }
    };
    let mut loss = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        match item {
            InputValue::Str(text) if !python_strip(text).is_empty() => {
                loss.push(python_strip(text).to_owned());
            }
            other => {
                return Err(schema_manifest(format!(
                    "declared_loss[{index}] must be a non-empty string, got {}",
                    input_repr(other)
                )));
            }
        }
    }
    Ok(loss)
}

fn parse_revalidate_report(value: &InputValue) -> Result<Option<String>, ParseManifestError> {
    match value {
        InputValue::None => Ok(None),
        InputValue::Str(text) if !python_strip(text).is_empty() => {
            Ok(Some(python_strip(text).replace('\\', "/")))
        }
        other => Err(schema_manifest(format!(
            "RepairManifest.revalidate_report must be a non-empty string path or None, got {}",
            input_repr(other)
        ))),
    }
}

fn parse_idempotency(value: &InputValue) -> Result<String, ParseManifestError> {
    match value {
        InputValue::Str(text) if is_sha256_hex(text) => Ok(text.clone()),
        other => Err(schema_manifest(format!(
            "RepairManifest.idempotency_key must be a 64-character lowercase hex string, got {}",
            input_repr(other)
        ))),
    }
}

fn optional_text(
    entries: &[(InputKey, InputValue)],
    name: &str,
    message: &str,
) -> Result<Option<String>, ParseManifestError> {
    match mapped_ref(entries, name) {
        None | Some(InputValue::None) => Ok(None),
        Some(InputValue::Str(text)) if !python_strip(text).is_empty() => {
            Ok(Some(python_strip(text).to_owned()))
        }
        Some(_) => Err(schema_manifest(message.to_owned())),
    }
}

fn copied_mapping(
    entries: &[(InputKey, InputValue)],
    name: &str,
    message: &str,
) -> Result<Vec<(InputKey, InputValue)>, ParseManifestError> {
    match mapped_ref(entries, name) {
        None => Ok(Vec::new()),
        Some(InputValue::Dict(pairs)) => Ok(collapse_pairs(pairs)),
        Some(_) => Err(schema_manifest(message.to_owned())),
    }
}

fn parse_revalidation_block(
    value: &InputValue,
) -> Result<RevalidationSummary, ParseManifestError> {
    let entries = match value {
        InputValue::Dict(entries) => entries.as_slice(),
        other => {
            return Err(schema_manifest(format!(
                "RepairManifest.revalidation must be a mapping, got {}",
                input_type_name(other)
            )));
        }
    };
    reject_revalidation_unknown(entries)?;
    require_revalidation_fields(entries)?;
    let assurance = revalidation_assurance(revalidation_field(entries, "assurance")?)?;
    let error_count = revalidation_count(revalidation_field(entries, "error_count")?, "error_count")?;
    let warning_count =
        revalidation_count(revalidation_field(entries, "warning_count")?, "warning_count")?;
    let profile_id = revalidation_text(revalidation_field(entries, "profile_id")?, "profile_id")?;
    let profile_version = revalidation_text(
        revalidation_field(entries, "profile_version")?,
        "profile_version",
    )?;
    let report_fingerprint = revalidation_fingerprint(entries)?;
    let assurance_input = InputValue::str_value(assurance);
    let error_input = InputValue::int(error_count);
    let warning_input = InputValue::int(warning_count);
    let profile_input = InputValue::str_value(profile_id);
    let version_input = InputValue::str_value(profile_version);
    let fingerprint_input = present_text(report_fingerprint);
    RevalidationSummary::try_new(
        &assurance_input,
        &error_input,
        &warning_input,
        &profile_input,
        &version_input,
        &fingerprint_input,
    )
    .map_err(lift_manifest)
}

fn reject_revalidation_unknown(
    entries: &[(InputKey, InputValue)],
) -> Result<(), ParseManifestError> {
    for (key, _) in entries {
        if string_allowed(key, &REVALIDATION_FIELDS) {
            continue;
        }
        let name = key_text(key);
        return Err(ParseManifestError::UnknownField(UnknownFieldError::new(
            format!("Unknown field in manifest revalidation: '{name}'"),
            Some(name),
        )));
    }
    Ok(())
}

fn require_revalidation_fields(
    entries: &[(InputKey, InputValue)],
) -> Result<(), ParseManifestError> {
    for name in REQUIRED_REVALIDATION_FIELDS {
        if mapped_ref(entries, name).is_none() {
            return Err(schema_manifest(format!(
                "Missing required field in manifest revalidation: '{name}'"
            )));
        }
    }
    Ok(())
}

fn revalidation_field<'a>(
    entries: &'a [(InputKey, InputValue)],
    name: &str,
) -> Result<&'a InputValue, ParseManifestError> {
    match mapped_ref(entries, name) {
        Some(value) => Ok(value),
        None => Err(schema_manifest(format!(
            "Missing required field in manifest revalidation: '{name}'"
        ))),
    }
}

fn revalidation_assurance(value: &InputValue) -> Result<String, ParseManifestError> {
    match value {
        InputValue::Str(text) if VALID_ASSURANCE_LEVELS.contains(&text.as_str()) => Ok(text.clone()),
        other => Err(ParseManifestError::Assurance(AssuranceError::new(format!(
            "Invalid revalidation assurance: {}. Must be one of {}",
            input_repr(other),
            sorted_assurance_repr()
        )))),
    }
}

fn revalidation_count(value: &InputValue, field: &str) -> Result<i64, ParseManifestError> {
    match value {
        InputValue::Int(number) if *number >= 0 => Ok(*number),
        other => Err(schema_manifest(format!(
            "revalidation.{field} must be a non-negative integer, got {}",
            input_repr(other)
        ))),
    }
}

fn revalidation_text(value: &InputValue, field: &str) -> Result<String, ParseManifestError> {
    match value {
        InputValue::Str(text) if !python_strip(text).is_empty() => Ok(python_strip(text).to_owned()),
        _ => Err(schema_manifest(format!(
            "revalidation.{field} must be a non-empty string"
        ))),
    }
}

fn revalidation_fingerprint(
    entries: &[(InputKey, InputValue)],
) -> Result<Option<String>, ParseManifestError> {
    match mapped_ref(entries, "report_fingerprint") {
        None | Some(InputValue::None) => Ok(None),
        Some(InputValue::Str(text)) if !python_strip(text).is_empty() => {
            Ok(Some(python_strip(text).to_owned()))
        }
        Some(_) => Err(schema_manifest(
            "revalidation.report_fingerprint must be a non-empty string or None".to_owned(),
        )),
    }
}

fn parse_ceiling(value: &InputValue) -> Result<String, ParseManifestError> {
    match value {
        InputValue::Str(text) if VALID_ASSURANCE_LEVELS.contains(&text.as_str()) => Ok(text.clone()),
        other => Err(ParseManifestError::Assurance(AssuranceError::new(format!(
            "Invalid assurance_ceiling: {}. Must be one of {}",
            input_repr(other),
            sorted_assurance_repr()
        )))),
    }
}

fn schema_manifest(message: String) -> ParseManifestError {
    ParseManifestError::Schema(schema(message))
}

fn lift_manifest(error: EnvelopeError) -> ParseManifestError {
    match error {
        EnvelopeError::Schema(error) => ParseManifestError::Schema(error),
        EnvelopeError::Version(error) => ParseManifestError::Version(error),
        EnvelopeError::Assurance(error) => ParseManifestError::Assurance(error),
        EnvelopeError::ContentLeak(error) => ParseManifestError::ContentLeak(error),
        EnvelopeError::TypeMismatch(message) => ParseManifestError::Type(message),
        EnvelopeError::Unavailable(name) => ParseManifestError::Unavailable(name),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        action_sort_key, build_manifest, build_report, compute_assurance,
        compute_manifest_idempotency_key, default_coverage, dump_report, skip_sort_key, ActionElem,
        ActionSeq, ActionSortFields, BuildCoverage, BuildManifestError, BuildManifestParts,
        BuildReportParts, BuildRevalidation, CountKey, CountValue, Counts, CountsInput, Coverage,
        CoverageInput, CoverageSkip, DumpReportError, DumpReportInput, EnvelopeError, FindingElem,
        FindingsInput, IdempotencyError, InputKey, InputValue, RepairAction, RepairManifest,
        RepairManifestParts, Report, ReportParts, RevalidationInput, RevalidationSummary, SkipElem,
        SkipSeq, SkipSortFields, ASSURANCE_LIMITATIONS, COMPUTE_ASSURANCE_CEILING,
        PROFILES_BUILTIN_ALL_RULES, REPORT_SCHEMA_VERSION, REQUIRED_SEVERITIES,
        VALID_ASSURANCE_LEVELS, VALID_COVERAGE_SKIP_REASONS,
    };
    use model::codes::{Repairability, Severity, SL001, SL002, SL003, SL101};
    use model::errors::SchemaError;
    use model::errors::{AssuranceError, ContentLeakError, VersionError};
    use model::finding::enforce_content_free_text;
    use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};

    fn finding(code: &str, severity: Severity) -> Finding {
        let source = match SourceRef::try_new("probe.jsonl", Some(SourceLine::Int(1)), None) {
            Ok(source) => source,
            Err(err) => panic!("synthetic source rejected: {err}"),
        };
        match Finding::try_new(FindingInput {
            code: PyValue::string(code),
            severity: PyValue::severity(severity),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence: PyValue::None,
        }) {
            Ok(finding) => finding,
            Err(err) => panic!("synthetic finding rejected: {err}"),
        }
    }

    fn level(
        events: Option<&[u8]>,
        findings: &[Finding],
        has_profile_replay: bool,
        reference_equivalent: bool,
    ) -> (&'static str, &'static str) {
        compute_assurance(events, findings, has_profile_replay, reference_equivalent)
    }

    fn sev(pairs: &[(&str, i64)]) -> CountValue {
        CountValue::dict(
            pairs
                .iter()
                .map(|(name, count)| (CountKey::str_key(*name), CountValue::int(*count)))
                .collect(),
        )
    }

    fn codes(pairs: &[(&str, i64)]) -> CountValue {
        sev(pairs)
    }

    fn zeros() -> CountValue {
        sev(&[("fatal", 0), ("error", 0), ("warning", 0), ("info", 0)])
    }

    fn built(by_severity: &CountValue, by_code: &CountValue, total: &CountValue) -> Counts {
        match Counts::try_new(by_severity, by_code, total) {
            Ok(counts) => counts,
            Err(err) => panic!("synthetic counts rejected: {err}"),
        }
    }

    fn rejected(by_severity: &CountValue, by_code: &CountValue, total: &CountValue) -> SchemaError {
        match Counts::try_new(by_severity, by_code, total) {
            Ok(_) => panic!("expected SchemaError"),
            Err(err) => err,
        }
    }

    #[test]
    fn limitations_and_severities_match_the_pin() {
        assert_eq!(
            ASSURANCE_LIMITATIONS,
            [
                ("A0", "No structural conclusion."),
                ("A1", "Relationships may still be invalid."),
                (
                    "A2",
                    "Provider/runtime replay has not been independently exercised.",
                ),
                (
                    "A3",
                    "Does not prove semantic equivalence or external side effects.",
                ),
                (
                    "A4",
                    "Still not proof of model behavior, business correctness, or exactly-once effects.",
                ),
            ]
        );
        assert_eq!(REQUIRED_SEVERITIES, ["fatal", "error", "warning", "info"]);
        assert_eq!(
            REQUIRED_SEVERITIES,
            [
                Severity::Fatal.as_str(),
                Severity::Error.as_str(),
                Severity::Warning.as_str(),
                Severity::Info.as_str(),
            ]
        );
    }

    #[test]
    fn empty_or_missing_events_are_a0() {
        let warning = finding(SL003, Severity::Warning);
        let error = finding(SL101, Severity::Error);
        let sl001 = finding(SL001, Severity::Error);
        let warning_findings = std::slice::from_ref(&warning);
        let error_findings = std::slice::from_ref(&error);
        let sl001_findings = std::slice::from_ref(&sl001);
        let cases = [
            (None, &[][..]),
            (Some(&[][..]), &[][..]),
            (None, warning_findings),
            (Some(&[][..]), warning_findings),
            (Some(&[][..]), error_findings),
            (Some(&[][..]), sl001_findings),
        ];
        for (events, findings) in cases {
            assert_eq!(
                level(events, findings, true, true),
                ASSURANCE_LIMITATIONS[0]
            );
        }
    }

    #[test]
    fn non_empty_events_follow_the_stage_order() {
        let events = &[1u8, 2u8][..];
        let warning = finding(SL003, Severity::Warning);
        let error = finding(SL101, Severity::Error);
        let fatal = finding(SL101, Severity::Fatal);
        let fatal_with_parse = finding(SL101, Severity::Fatal);
        let info = finding(SL003, Severity::Info);
        let sl001 = finding(SL001, Severity::Warning);
        let sl002 = finding(SL002, Severity::Info);

        assert_eq!(
            level(Some(events), &[], true, false),
            ASSURANCE_LIMITATIONS[3]
        );
        assert_eq!(
            level(Some(events), &[], false, false),
            ASSURANCE_LIMITATIONS[2]
        );
        assert_eq!(
            level(Some(events), std::slice::from_ref(&warning), true, false),
            ASSURANCE_LIMITATIONS[2]
        );
        assert_eq!(
            level(Some(events), std::slice::from_ref(&error), true, false),
            ASSURANCE_LIMITATIONS[1]
        );
        assert_eq!(
            level(Some(events), std::slice::from_ref(&info), true, false),
            ASSURANCE_LIMITATIONS[3]
        );
        assert_eq!(
            level(Some(events), std::slice::from_ref(&sl001), true, true),
            ASSURANCE_LIMITATIONS[0]
        );
        assert_eq!(
            level(Some(events), &[sl002, fatal_with_parse], true, true),
            ASSURANCE_LIMITATIONS[0]
        );
        assert_eq!(
            level(Some(events), std::slice::from_ref(&info), true, true),
            ASSURANCE_LIMITATIONS[4]
        );
        assert_eq!(
            level(Some(events), std::slice::from_ref(&info), false, true),
            ASSURANCE_LIMITATIONS[2]
        );
        assert_eq!(
            level(Some(events), &[fatal, warning], true, false),
            ASSURANCE_LIMITATIONS[1]
        );
        assert_eq!(
            level(Some(events), std::slice::from_ref(&error), true, true),
            ASSURANCE_LIMITATIONS[1]
        );
    }

    #[test]
    fn counts_to_dict_fills_gaps_and_sorts_codes() {
        let counts = built(
            &sev(&[("info", 2), ("error", 1), ("error", 4)]),
            &codes(&[
                ("SL101", 1),
                ("SL010", 3),
                ("SL002", 2),
                (" SL001", 5),
                ("", 6),
            ]),
            &CountValue::int(9),
        );
        assert_eq!(counts.total(), 9);
        assert_eq!(counts.severity_count("error"), Some(4));
        assert_eq!(counts.severity_count("warning"), None);
        assert_eq!(counts.severity_count("fatal"), None);
        assert_eq!(counts.code_count("SL002"), Some(2));
        assert_eq!(counts.code_count(""), Some(6));
        let dict = counts.to_dict();
        assert_eq!(
            dict.by_severity,
            [("fatal", 0), ("error", 4), ("warning", 0), ("info", 2)]
        );
        assert_eq!(
            dict.by_code,
            vec![
                (String::new(), 6),
                (" SL001".to_owned(), 5),
                ("SL002".to_owned(), 2),
                ("SL010".to_owned(), 3),
                ("SL101".to_owned(), 1),
            ]
        );
        assert_eq!(dict.total, 9);

        let explicit = built(&zeros(), &CountValue::dict(Vec::new()), &CountValue::int(0));
        let sparse = built(
            &sev(&[]),
            &CountValue::dict(Vec::new()),
            &CountValue::int(0),
        );
        assert_ne!(explicit, sparse);
        assert_eq!(explicit.to_dict(), sparse.to_dict());
        assert_eq!(
            explicit.to_dict().by_severity,
            [("fatal", 0), ("error", 0), ("warning", 0), ("info", 0)]
        );
        assert!(explicit.to_dict().by_code.is_empty());
    }

    #[test]
    fn counts_reject_in_post_init_order() {
        let bad_total = rejected(
            &CountValue::str_value("not-a-map"),
            &zeros(),
            &CountValue::int(-1),
        );
        assert_eq!(
            bad_total.to_string(),
            "Counts.total must be a non-negative integer, got -1"
        );
        assert_eq!(bad_total.code(), SchemaError::DEFAULT_CODE);

        let boolean_total = rejected(&zeros(), &codes(&[]), &CountValue::bool_value(true));
        assert_eq!(
            boolean_total.to_string(),
            "Counts.total must be a non-negative integer, got True"
        );
        let false_total = rejected(&zeros(), &codes(&[]), &CountValue::bool_value(false));
        assert_eq!(
            false_total.to_string(),
            "Counts.total must be a non-negative integer, got False"
        );
        let string_total = rejected(&zeros(), &codes(&[]), &CountValue::str_value("1"));
        assert_eq!(
            string_total.to_string(),
            "Counts.total must be a non-negative integer, got '1'"
        );
        let float_total = rejected(&zeros(), &codes(&[]), &CountValue::other("float", "1.5"));
        assert_eq!(
            float_total.to_string(),
            "Counts.total must be a non-negative integer, got 1.5"
        );
        let empty_dict_total = rejected(&zeros(), &codes(&[]), &CountValue::dict(Vec::new()));
        assert_eq!(
            empty_dict_total.to_string(),
            "Counts.total must be a non-negative integer, got {}"
        );

        let not_a_severity_map = rejected(
            &CountValue::str_value("not-a-map"),
            &codes(&[]),
            &CountValue::int(0),
        );
        assert_eq!(
            not_a_severity_map.to_string(),
            "Counts.by_severity must be a Mapping, got str"
        );
        let list_codes = rejected(&zeros(), &CountValue::list(Vec::new()), &CountValue::int(0));
        assert_eq!(
            list_codes.to_string(),
            "Counts.by_code must be a Mapping, got list"
        );

        let negative_error = rejected(
            &CountValue::dict(vec![
                (CountKey::str_key("fatal"), CountValue::int(0)),
                (CountKey::str_key("error"), CountValue::int(-1)),
                (CountKey::str_key("warning"), CountValue::str_value("x")),
                (CountKey::str_key("bogus"), CountValue::int(1)),
            ]),
            &codes(&[]),
            &CountValue::int(0),
        );
        assert_eq!(
            negative_error.to_string(),
            "Counts.by_severity['error'] must be non-negative int, got -1"
        );
        let true_fatal = rejected(
            &CountValue::dict(vec![
                (CountKey::str_key("fatal"), CountValue::bool_value(true)),
                (CountKey::str_key("error"), CountValue::int(-1)),
            ]),
            &codes(&[]),
            &CountValue::int(0),
        );
        assert_eq!(
            true_fatal.to_string(),
            "Counts.by_severity['fatal'] must be non-negative int, got True"
        );

        let unknown_later = rejected(
            &CountValue::dict(vec![
                (CountKey::str_key("zeta"), CountValue::int(1)),
                (CountKey::str_key("alpha"), CountValue::int(1)),
            ]),
            &codes(&[]),
            &CountValue::int(0),
        );
        assert_eq!(
            unknown_later.to_string(),
            "Counts.by_severity contains unknown severity: 'zeta'"
        );
        let capital = rejected(&sev(&[("Fatal", 1)]), &codes(&[]), &CountValue::int(0));
        assert_eq!(
            capital.to_string(),
            "Counts.by_severity contains unknown severity: 'Fatal'"
        );

        let int_code_key = rejected(
            &zeros(),
            &CountValue::dict(vec![
                (CountKey::int(123), CountValue::int(1)),
                (CountKey::str_key("SL001"), CountValue::int(-5)),
            ]),
            &CountValue::int(0),
        );
        assert_eq!(
            int_code_key.to_string(),
            "Counts.by_code key must be str, got 123"
        );
        let negative_code = rejected(&zeros(), &codes(&[("SL001", -5)]), &CountValue::int(0));
        assert_eq!(
            negative_code.to_string(),
            "Counts.by_code['SL001'] must be non-negative int, got -5"
        );
        let bool_code = rejected(
            &zeros(),
            &CountValue::dict(vec![(
                CountKey::str_key("SL001"),
                CountValue::bool_value(false),
            )]),
            &CountValue::int(0),
        );
        assert_eq!(
            bool_code.to_string(),
            "Counts.by_code['SL001'] must be non-negative int, got False"
        );
        let not_a_code_map = rejected(&zeros(), &CountValue::int(123), &CountValue::int(0));
        assert_eq!(
            not_a_code_map.to_string(),
            "Counts.by_code must be a Mapping, got int"
        );
    }

    #[test]
    fn counts_collapse_duplicate_keys_like_python_dict() {
        let recovered = built(
            &zeros(),
            &CountValue::dict(vec![
                (CountKey::str_key("SL001"), CountValue::int(-1)),
                (CountKey::str_key("SL001"), CountValue::int(3)),
            ]),
            &CountValue::int(3),
        );
        assert_eq!(recovered.code_count("SL001"), Some(3));

        let replaced = rejected(
            &zeros(),
            &CountValue::dict(vec![
                (CountKey::str_key("SL001"), CountValue::int(3)),
                (CountKey::str_key("SL001"), CountValue::int(-1)),
            ]),
            &CountValue::int(0),
        );
        assert_eq!(
            replaced.to_string(),
            "Counts.by_code['SL001'] must be non-negative int, got -1"
        );

        let int_then_bool = rejected(
            &zeros(),
            &CountValue::dict(vec![
                (CountKey::int(1), CountValue::int(-1)),
                (CountKey::bool_value(true), CountValue::int(5)),
            ]),
            &CountValue::int(0),
        );
        assert_eq!(
            int_then_bool.to_string(),
            "Counts.by_code key must be str, got 1"
        );
        let bool_then_int = rejected(
            &zeros(),
            &CountValue::dict(vec![
                (CountKey::bool_value(true), CountValue::int(-1)),
                (CountKey::int(1), CountValue::int(5)),
            ]),
            &CountValue::int(0),
        );
        assert_eq!(
            bool_then_int.to_string(),
            "Counts.by_code key must be str, got True"
        );
        assert_ne!(CountKey::bool_value(true), CountKey::int(1));

        let none_key = rejected(
            &CountValue::dict(vec![(CountKey::None, CountValue::int(1))]),
            &codes(&[]),
            &CountValue::int(0),
        );
        assert_eq!(
            none_key.to_string(),
            "Counts.by_severity contains unknown severity: None"
        );

        let tuple_value = rejected(
            &zeros(),
            &CountValue::tuple(vec![CountValue::int(1)]),
            &CountValue::int(0),
        );
        assert_eq!(
            tuple_value.to_string(),
            "Counts.by_code must be a Mapping, got tuple"
        );
        let nested = rejected(
            &zeros(),
            &codes(&[]),
            &CountValue::tuple(vec![CountValue::int(1)]),
        );
        assert_eq!(
            nested.to_string(),
            "Counts.total must be a non-negative integer, got (1,)"
        );
    }

    #[test]
    fn skip_sort_key_orders_check_then_reason_then_detail() {
        let fields = |check, reason, detail| SkipSortFields {
            check,
            reason,
            detail,
        };
        let first = fields("SL001", "profile-gated", "");
        let second = fields("SL002", "adapter-not-applicable", "");
        let third = fields("SL002", "profile-gated", "");
        let fourth = fields("SL002", "profile-gated", "extra");
        let mut keys = [
            skip_sort_key(fourth),
            skip_sort_key(second),
            skip_sort_key(first),
            skip_sort_key(third),
        ];
        keys.sort();
        assert_eq!(
            keys,
            [
                skip_sort_key(first),
                skip_sort_key(second),
                skip_sort_key(third),
                skip_sort_key(fourth),
            ]
        );
        let unvalidated = fields("SL201", "not-a-closed-reason", "detail");
        assert_eq!(
            skip_sort_key(unvalidated),
            ("SL201", "not-a-closed-reason", "detail")
        );
    }

    fn text(value: &str) -> InputValue {
        InputValue::str_value(value)
    }

    fn must_skip(check: &str, reason: &str, detail: &str) -> CoverageSkip {
        match CoverageSkip::try_new(&text(check), &text(reason), &text(detail)) {
            Ok(skip) => skip,
            Err(err) => panic!("synthetic skip rejected: {err}"),
        }
    }

    fn reject_skip(check: &InputValue, reason: &InputValue, detail: &InputValue) -> String {
        match CoverageSkip::try_new(check, reason, detail) {
            Ok(_) => panic!("expected CoverageSkip to fail"),
            Err(err) => err.to_string(),
        }
    }

    fn binding(pairs: &[(&str, &str)]) -> InputValue {
        InputValue::dict(
            pairs
                .iter()
                .map(|(key, value)| (InputKey::str_key(*key), text(value)))
                .collect(),
        )
    }

    fn must_coverage(
        performed: &InputValue,
        skipped: &SkipSeq,
        adapter: &InputValue,
        profile: &InputValue,
    ) -> Coverage {
        match Coverage::try_new(performed, skipped, adapter, profile) {
            Ok(coverage) => coverage,
            Err(err) => panic!("synthetic coverage rejected: {err}"),
        }
    }

    fn reject_coverage(
        performed: &InputValue,
        skipped: &SkipSeq,
        adapter: &InputValue,
        profile: &InputValue,
    ) -> String {
        match Coverage::try_new(performed, skipped, adapter, profile) {
            Ok(_) => panic!("expected Coverage to fail"),
            Err(err) => err.to_string(),
        }
    }

    fn empty_skips() -> SkipSeq {
        SkipSeq::Tuple(Vec::new())
    }

    fn neutral_profile() -> InputValue {
        binding(&[("id", "neutral"), ("version", "1.0.0")])
    }

    fn canonical_adapter() -> InputValue {
        binding(&[("id", "canonical"), ("version", "1.0.0")])
    }

    fn counts_for(findings: &[Finding]) -> Counts {
        let mut severity = [0_i64; 4];
        let mut code_pairs: Vec<(String, i64)> = Vec::new();
        for finding in findings {
            let slot = match finding.severity() {
                Severity::Fatal => 0,
                Severity::Error => 1,
                Severity::Warning => 2,
                Severity::Info => 3,
            };
            severity[slot] += 1;
            let mut found = false;
            for pair in &mut code_pairs {
                if pair.0 == finding.code() {
                    pair.1 += 1;
                    found = true;
                    break;
                }
            }
            if !found {
                code_pairs.push((finding.code().to_owned(), 1));
            }
        }
        let by_severity = CountValue::dict(
            REQUIRED_SEVERITIES
                .iter()
                .enumerate()
                .map(|(index, name)| (CountKey::str_key(*name), CountValue::int(severity[index])))
                .collect(),
        );
        let by_code = CountValue::dict(
            code_pairs
                .iter()
                .map(|(code, count)| (CountKey::str_key(code), CountValue::int(*count)))
                .collect(),
        );
        let total = match i64::try_from(findings.len()) {
            Ok(total) => total,
            Err(_) => panic!("synthetic finding list does not fit i64"),
        };
        built(&by_severity, &by_code, &CountValue::int(total))
    }

    fn must_report(
        session_id: &InputValue,
        findings: &[Finding],
        counts: &Counts,
        assurance: &InputValue,
        limitation: &InputValue,
        coverage: &Coverage,
    ) -> Report {
        let schema = text(REPORT_SCHEMA_VERSION);
        let fingerprint = text("fp");
        let tool = text("0.0.0");
        let findings_input =
            FindingsInput::Tuple(findings.iter().cloned().map(FindingElem::Finding).collect());
        let counts_input = CountsInput::Value(counts.clone());
        match Report::try_new(ReportParts {
            schema_version: &schema,
            session_id,
            source_fingerprint: &fingerprint,
            tool_version: &tool,
            findings: &findings_input,
            counts: &counts_input,
            assurance,
            limitation,
            coverage: CoverageInput::Value(coverage),
        }) {
            Ok(report) => report,
            Err(err) => panic!("synthetic report rejected: {err}"),
        }
    }

    fn reason_list() -> &'static str {
        "['adapter-not-applicable', 'cap-exceeded', 'deselected', 'empty-input', 'profile-gated', 'single-doc-fallback', 'version-gated']"
    }

    #[test]
    fn counts_keep_insertion_order_and_still_compare_as_maps() {
        let first = built(
            &zeros(),
            &codes(&[("SL101", 1), ("SL002", 4)]),
            &CountValue::int(5),
        );
        let second = built(
            &zeros(),
            &codes(&[("SL002", 4), ("SL101", 1)]),
            &CountValue::int(5),
        );
        assert_eq!(first, second);
        assert_eq!(first.to_dict().by_code, second.to_dict().by_code);
        assert_eq!(
            first.code_items(),
            [("SL101".to_owned(), 1), ("SL002".to_owned(), 4)]
        );
        assert_eq!(
            second.code_items(),
            [("SL002".to_owned(), 4), ("SL101".to_owned(), 1)]
        );
    }

    #[test]
    fn coverage_skip_strips_and_orders_by_skip_sort_key() {
        assert_eq!(
            VALID_COVERAGE_SKIP_REASONS,
            [
                "profile-gated",
                "adapter-not-applicable",
                "version-gated",
                "empty-input",
                "cap-exceeded",
                "single-doc-fallback",
                "deselected",
            ]
        );
        for reason in VALID_COVERAGE_SKIP_REASONS {
            let skip = must_skip(" SL001 ", reason, "  note  ");
            assert_eq!(skip.check(), "SL001");
            assert_eq!(skip.reason(), reason);
            assert_eq!(skip.detail(), "note");
        }
        let stripped = must_skip("\u{001c}SL002\u{001c}", "deselected", "   ");
        assert_eq!(stripped.check(), "SL002");
        assert_eq!(stripped.detail(), "");
        let dict = stripped.to_dict();
        assert_eq!(dict.check, "SL002");
        assert_eq!(dict.detail, "");
        assert_eq!(dict.reason, "deselected");

        let mut skips = [
            must_skip("SL002", "profile-gated", "extra"),
            must_skip("SL002", "adapter-not-applicable", ""),
            must_skip("SL001", "profile-gated", ""),
            must_skip("SL002", "profile-gated", ""),
        ];
        skips.sort();
        assert_eq!(skips[0].check(), "SL001");
        assert_eq!(skips[1].reason(), "adapter-not-applicable");
        assert_eq!(skips[2].detail(), "");
        assert_eq!(skips[3].detail(), "extra");
        assert!(skips[2] < skips[3]);
    }

    #[test]
    fn coverage_skip_rejects_in_post_init_order() {
        assert_eq!(
            reject_skip(&text("  "), &text("nope"), &InputValue::int(1)),
            "CoverageSkip.check must be a non-empty string, got '  '"
        );
        assert_eq!(
            reject_skip(
                &InputValue::bool_value(true),
                &text("profile-gated"),
                &text("")
            ),
            "CoverageSkip.check must be a non-empty string, got True"
        );
        assert_eq!(
            reject_skip(&text("SL001"), &text("nope"), &InputValue::int(1)),
            format!(
                "CoverageSkip.reason must be one of {}, got 'nope'",
                reason_list()
            )
        );
        assert_eq!(
            reject_skip(&text("SL001"), &InputValue::int(1), &text("")),
            format!(
                "CoverageSkip.reason must be one of {}, got 1",
                reason_list()
            )
        );
        let padded_check = must_skip(" profile-gated", "profile-gated", "");
        assert_eq!(padded_check.check(), "profile-gated");
        assert_eq!(
            reject_skip(&text("SL001"), &text(" profile-gated"), &text("")),
            format!(
                "CoverageSkip.reason must be one of {}, got ' profile-gated'",
                reason_list()
            )
        );
        assert_eq!(
            reject_skip(&text("SL001"), &text("profile-gated"), &InputValue::int(1)),
            "CoverageSkip.detail must be a string, got int"
        );
        assert_eq!(
            reject_skip(&text("SL001"), &text("profile-gated"), &InputValue::None),
            "CoverageSkip.detail must be a string, got NoneType"
        );

        let check_leak = match enforce_content_free_text("user@example.com", "CoverageSkip.check") {
            Ok(()) => panic!("expected content leak"),
            Err(err) => err,
        };
        assert_eq!(
            reject_skip(
                &text("user@example.com"),
                &text("profile-gated"),
                &text("a\nb")
            ),
            format!("Intrinsic content leak in CoverageSkip.check: {check_leak}")
        );
        let detail_leak = match enforce_content_free_text("a\nb", "CoverageSkip.detail") {
            Ok(()) => panic!("expected content leak"),
            Err(err) => err,
        };
        assert_eq!(
            reject_skip(&text("SL001"), &text("profile-gated"), &text("a\nb")),
            format!("Intrinsic content leak in CoverageSkip.detail: {detail_leak}")
        );
    }

    #[test]
    fn coverage_sorts_performed_and_skips_and_keeps_binding_order() {
        let skips = SkipSeq::List(vec![
            SkipElem::Skip(must_skip("SL002", "profile-gated", "")),
            SkipElem::Skip(must_skip("SL001", "deselected", "")),
            SkipElem::Skip(must_skip("SL002", "adapter-not-applicable", "z")),
            SkipElem::Skip(must_skip("SL001", "deselected", "")),
        ]);
        let coverage = must_coverage(
            &InputValue::list(vec![text("b"), text(" a "), text("b")]),
            &skips,
            &binding(&[
                ("version", "1"),
                ("id", "canonical"),
                ("name", "Canon"),
                ("extra", "no"),
            ]),
            &InputValue::dict(vec![
                (InputKey::str_key("name"), text("Neutral")),
                (InputKey::str_key("version"), text("1.0.0")),
            ]),
        );
        assert_eq!(
            coverage.performed(),
            [" a ".to_owned(), "b".to_owned(), "b".to_owned()]
        );
        assert_eq!(coverage.skipped().len(), 4);
        assert_eq!(coverage.skipped()[0].check(), "SL001");
        assert_eq!(coverage.skipped()[1].check(), "SL001");
        assert_eq!(coverage.skipped()[2].reason(), "adapter-not-applicable");
        assert_eq!(coverage.skipped()[3].reason(), "profile-gated");
        assert_eq!(
            coverage
                .adapter_items()
                .iter()
                .map(|(key, _)| match key {
                    InputKey::Str(name) => name.as_str(),
                    _ => panic!("expected string adapter key"),
                })
                .collect::<Vec<_>>(),
            ["version", "id", "name", "extra"]
        );
        assert_eq!(
            coverage
                .profile_items()
                .iter()
                .map(|(key, _)| match key {
                    InputKey::Str(name) => name.as_str(),
                    _ => panic!("expected string profile key"),
                })
                .collect::<Vec<_>>(),
            ["id", "name", "version"]
        );
        let dict = coverage.to_dict();
        assert_eq!(
            dict.adapter,
            vec![
                ("id".to_owned(), text("canonical")),
                ("name".to_owned(), text("Canon")),
                ("version".to_owned(), text("1")),
            ]
        );
        assert_eq!(
            dict.performed,
            vec![" a ".to_owned(), "b".to_owned(), "b".to_owned()]
        );
        assert_eq!(
            dict.profile,
            vec![
                ("id".to_owned(), text("Neutral")),
                ("name".to_owned(), text("Neutral")),
                ("version".to_owned(), text("1.0.0")),
            ]
        );
        assert_eq!(dict.skipped.len(), 4);
        assert_eq!(dict.skipped[2].detail, "z");

        let unique = must_coverage(
            &InputValue::set(vec![text("b"), text("a"), text("b")]),
            &SkipSeq::Set(vec![
                SkipElem::Skip(must_skip("SL001", "profile-gated", "a")),
                SkipElem::Skip(must_skip("SL001", "profile-gated", "a")),
            ]),
            &canonical_adapter(),
            &neutral_profile(),
        );
        assert_eq!(unique.performed(), ["a".to_owned(), "b".to_owned()]);
        assert_eq!(unique.skipped().len(), 1);

        let email = must_coverage(
            &InputValue::tuple(vec![text("user@example.com")]),
            &empty_skips(),
            &canonical_adapter(),
            &neutral_profile(),
        );
        assert_eq!(email.performed(), ["user@example.com".to_owned()]);
    }

    #[test]
    fn coverage_rejects_sequences_and_bindings_in_order() {
        let adapter = canonical_adapter();
        let profile = neutral_profile();
        assert_eq!(
            reject_coverage(&text("SL001"), &empty_skips(), &adapter, &profile),
            "Coverage.performed must be a sequence of strings, got str"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::FrozenSet(vec![text("a")]),
                &empty_skips(),
                &adapter,
                &profile
            ),
            "Coverage.performed must be a sequence of strings, got frozenset"
        );
        assert_eq!(
            reject_coverage(&InputValue::None, &empty_skips(), &adapter, &profile),
            "Coverage.performed must be a sequence of strings, got NoneType"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::list(vec![text("ok"), text("")]),
                &empty_skips(),
                &adapter,
                &profile
            ),
            "Coverage.performed[1] must be a non-empty string, got ''"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::list(vec![text("ok"), InputValue::int(1)]),
                &empty_skips(),
                &adapter,
                &profile
            ),
            "Coverage.performed[1] must be a non-empty string, got 1"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::tuple(Vec::new()),
                &SkipSeq::Tuple(vec![SkipElem::Wrong(text("nope"))]),
                &adapter,
                &profile
            ),
            "Coverage.skipped[0] must be a CoverageSkip instance, got str"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::tuple(Vec::new()),
                &SkipSeq::Other {
                    type_name: "dict".to_owned(),
                },
                &adapter,
                &profile
            ),
            "Coverage.skipped must be a sequence of CoverageSkip, got dict"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::tuple(Vec::new()),
                &empty_skips(),
                &InputValue::list(Vec::new()),
                &profile
            ),
            "Coverage.adapter must be a Mapping, got list"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::tuple(Vec::new()),
                &empty_skips(),
                &InputValue::dict(Vec::new()),
                &profile
            ),
            "Coverage.adapter must contain 'id'"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::tuple(Vec::new()),
                &empty_skips(),
                &binding(&[("id", "c")]),
                &profile
            ),
            "Coverage.adapter must contain 'version'"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::tuple(Vec::new()),
                &empty_skips(),
                &binding(&[("name", "canon")]),
                &profile
            ),
            "Coverage.adapter must contain 'version'"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::tuple(Vec::new()),
                &empty_skips(),
                &adapter,
                &InputValue::dict(vec![(InputKey::str_key("id"), text("p"))])
            ),
            "Coverage.profile must contain 'version'"
        );

        let kept = must_coverage(
            &InputValue::tuple(Vec::new()),
            &empty_skips(),
            &InputValue::dict(vec![
                (InputKey::str_key("name"), text("N")),
                (InputKey::str_key("id"), text("I")),
                (InputKey::str_key("version"), text("V")),
            ]),
            &profile,
        );
        assert_eq!(lookup_binding(kept.adapter_items(), "id"), Some(text("I")));
        assert_eq!(
            reject_coverage(
                &InputValue::tuple(Vec::new()),
                &empty_skips(),
                &InputValue::dict(vec![
                    (InputKey::int(1), text("x")),
                    (InputKey::str_key("name"), text("n")),
                    (InputKey::str_key("version"), text("1")),
                ]),
                &profile
            ),
            "'<' not supported between instances of 'str' and 'int'"
        );
        assert_eq!(
            reject_coverage(
                &InputValue::tuple(Vec::new()),
                &empty_skips(),
                &InputValue::dict(vec![
                    (InputKey::str_key("name"), text("n")),
                    (InputKey::int(1), text("x")),
                    (InputKey::str_key("version"), text("1")),
                ]),
                &profile
            ),
            "'<' not supported between instances of 'int' and 'str'"
        );

        let mixed = must_coverage(
            &InputValue::tuple(Vec::new()),
            &empty_skips(),
            &InputValue::dict(vec![
                (InputKey::int(1), text("x")),
                (InputKey::bool_value(true), text("y")),
                (InputKey::str_key("id"), text("a")),
                (InputKey::str_key("version"), text("1")),
            ]),
            &profile,
        );
        assert_eq!(mixed.adapter_items().len(), 3);
        assert_eq!(mixed.adapter_items()[0].0, InputKey::int(1));
        assert_eq!(mixed.adapter_items()[0].1, text("y"));
        let swapped = must_coverage(
            &InputValue::tuple(Vec::new()),
            &empty_skips(),
            &InputValue::dict(vec![
                (InputKey::str_key("version"), InputValue::int(1)),
                (InputKey::bool_value(true), text("y")),
                (InputKey::str_key("id"), InputValue::bool_value(true)),
            ]),
            &InputValue::dict(vec![
                (InputKey::str_key("version"), text("1.0.0")),
                (InputKey::str_key("id"), text("neutral")),
            ]),
        );
        let promoted = must_coverage(
            &InputValue::tuple(Vec::new()),
            &empty_skips(),
            &InputValue::dict(vec![
                (InputKey::str_key("version"), InputValue::int(1)),
                (InputKey::int(1), text("y")),
                (InputKey::str_key("id"), InputValue::int(1)),
            ]),
            &neutral_profile(),
        );
        assert_eq!(swapped, promoted);
        assert_eq!(
            swapped.to_dict().adapter,
            vec![
                ("id".to_owned(), InputValue::bool_value(true)),
                ("version".to_owned(), InputValue::int(1)),
            ]
        );
    }

    fn lookup_binding(entries: &[(InputKey, InputValue)], name: &str) -> Option<InputValue> {
        for (key, value) in entries {
            if let InputKey::Str(text) = key {
                if text == name {
                    return Some(value.clone());
                }
            }
        }
        None
    }

    #[test]
    fn default_coverage_names_the_missing_rules_import() {
        match default_coverage() {
            Err(err) => {
                assert_eq!(
                    err.to_string(),
                    format!("{PROFILES_BUILTIN_ALL_RULES} is not available")
                );
                assert!(std::error::Error::source(&err).is_none());
            }
            Ok(_) => panic!("default coverage must fail closed"),
        }
    }

    #[test]
    fn report_envelope_matches_findings_and_keeps_caller_text() {
        assert_eq!(VALID_ASSURANCE_LEVELS, ["A0", "A1", "A2", "A3", "A4"]);
        let coverage = must_coverage(
            &InputValue::tuple(vec![text("SL001")]),
            &empty_skips(),
            &canonical_adapter(),
            &neutral_profile(),
        );
        let info = finding(SL003, Severity::Info);
        let error = finding(SL101, Severity::Error);
        let findings = [info, error];
        let counts = counts_for(&findings);
        let session = text("  s  ");
        let limitation = text("  Relationships may still be invalid.  ");
        let report = must_report(
            &session,
            &findings,
            &counts,
            &text("A1"),
            &limitation,
            &coverage,
        );
        assert_eq!(report.schema_version(), REPORT_SCHEMA_VERSION);
        assert_eq!(report.session_id(), "  s  ");
        assert_eq!(report.source_fingerprint(), "fp");
        assert_eq!(report.tool_version(), "0.0.0");
        assert_eq!(report.assurance(), "A1");
        assert_eq!(
            report.limitation(),
            "  Relationships may still be invalid.  "
        );
        assert_eq!(report.findings().len(), 2);
        assert_eq!(report.findings()[0].code(), SL003);
        assert_eq!(report.findings()[1].code(), SL101);
        let dict = report.to_dict();
        assert_eq!(dict.assurance, "A1");
        assert_eq!(dict.schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(dict.session_id, "  s  ");
        assert_eq!(dict.findings.len(), 2);
        assert_eq!(dict.counts.total, 2);
        assert_eq!(
            dict.counts.by_code,
            vec![("SL003".to_owned(), 1), ("SL101".to_owned(), 1)]
        );
        assert_eq!(dict.coverage.performed, vec!["SL001".to_owned()]);
        assert!(dict.coverage.skipped.is_empty());

        let empty_counts = built(&zeros(), &CountValue::dict(Vec::new()), &CountValue::int(0));
        let sparse = built(
            &sev(&[]),
            &CountValue::dict(Vec::new()),
            &CountValue::int(0),
        );
        assert_ne!(empty_counts, sparse);
        let with_zeros = must_report(
            &text("s"),
            &[],
            &empty_counts,
            &text("A3"),
            &text("lim"),
            &coverage,
        );
        let with_gaps = must_report(
            &text("s"),
            &[],
            &sparse,
            &text("A3"),
            &text("lim"),
            &coverage,
        );
        assert_eq!(with_zeros.to_dict().counts, with_gaps.to_dict().counts);
        assert!(with_zeros.findings().is_empty());
    }

    #[test]
    fn report_rejects_in_post_init_order() {
        let coverage = must_coverage(
            &InputValue::tuple(Vec::new()),
            &empty_skips(),
            &canonical_adapter(),
            &neutral_profile(),
        );
        let error = finding(SL003, Severity::Error);
        let findings = [error];
        let counts = counts_for(&findings);
        let schema = text("nope");
        let session = text("s");
        let fingerprint = text("fp");
        let tool = text("0.0.0");
        let findings_input = FindingsInput::Tuple(vec![FindingElem::Finding(findings[0].clone())]);
        let counts_input = CountsInput::Value(counts.clone());
        let assurance = text("A1");
        let limitation = text("lim");

        match Report::try_new(ReportParts {
            schema_version: &schema,
            session_id: &text("   "),
            source_fingerprint: &fingerprint,
            tool_version: &tool,
            findings: &findings_input,
            counts: &counts_input,
            assurance: &text("A9"),
            limitation: &text("  "),
            coverage: CoverageInput::Default,
        }) {
            Err(err) => assert_eq!(
                err.to_string(),
                format!("{PROFILES_BUILTIN_ALL_RULES} is not available")
            ),
            Ok(_) => panic!("default coverage must win before schema checks"),
        }

        match Report::try_new(ReportParts {
            schema_version: &schema,
            session_id: &session,
            source_fingerprint: &fingerprint,
            tool_version: &tool,
            findings: &findings_input,
            counts: &counts_input,
            assurance: &assurance,
            limitation: &limitation,
            coverage: CoverageInput::WrongType { type_name: "dict" },
        }) {
            Err(EnvelopeError::Version(error)) => {
                assert_eq!(
                    error.to_string(),
                    "Report.schema_version must be 'sesslint.report/v1', got 'nope' (code: VERSION / SL301)"
                );
                assert_eq!(error.version(), Some("nope"));
                assert_eq!(error.code(), VersionError::CODE);
            }
            other => panic!("expected VersionError, got {other:?}"),
        }

        match Report::try_new(ReportParts {
            schema_version: &InputValue::int(1),
            session_id: &session,
            source_fingerprint: &fingerprint,
            tool_version: &tool,
            findings: &findings_input,
            counts: &counts_input,
            assurance: &assurance,
            limitation: &limitation,
            coverage: CoverageInput::Value(&coverage),
        }) {
            Err(EnvelopeError::Version(error)) => {
                assert_eq!(
                    error.to_string(),
                    "Report.schema_version must be 'sesslint.report/v1', got 1 (code: VERSION / SL301)"
                );
                assert_eq!(error.version(), None);
            }
            other => panic!("expected VersionError, got {other:?}"),
        }

        let good_schema = text(REPORT_SCHEMA_VERSION);
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &text("   "),
                source_fingerprint: &fingerprint,
                tool_version: &InputValue::None,
                findings: &findings_input,
                counts: &counts_input,
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.session_id must be a non-empty string, got '   '"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &InputValue::int(1),
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &counts_input,
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.session_id must be a non-empty string, got 1"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &text(""),
                tool_version: &tool,
                findings: &findings_input,
                counts: &counts_input,
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.source_fingerprint must be a non-empty string, got ''"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &InputValue::None,
                findings: &findings_input,
                counts: &counts_input,
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.tool_version must be a non-empty string, got None"
        );
        match Report::try_new(ReportParts {
            schema_version: &good_schema,
            session_id: &session,
            source_fingerprint: &fingerprint,
            tool_version: &tool,
            findings: &findings_input,
            counts: &counts_input,
            assurance: &text("A9"),
            limitation: &limitation,
            coverage: CoverageInput::Value(&coverage),
        }) {
            Err(EnvelopeError::Assurance(error)) => {
                assert_eq!(
                    error.to_string(),
                    "Report.assurance must be one of ['A0', 'A1', 'A2', 'A3', 'A4'], got 'A9'"
                );
                assert_eq!(error.code(), AssuranceError::DEFAULT_CODE);
            }
            other => panic!("expected AssuranceError, got {other:?}"),
        }
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &counts_input,
                assurance: &InputValue::int(1),
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.assurance must be one of ['A0', 'A1', 'A2', 'A3', 'A4'], got 1"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &counts_input,
                assurance: &text("A1 "),
                limitation: &text("  "),
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.assurance must be one of ['A0', 'A1', 'A2', 'A3', 'A4'], got 'A1 '"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &counts_input,
                assurance: &assurance,
                limitation: &InputValue::int(1),
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.limitation is required and must be non-empty for assurance level 'A1'"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &counts_input,
                assurance: &assurance,
                limitation: &text("  "),
                coverage: CoverageInput::WrongType { type_name: "dict" },
            }),
            "Report.limitation is required and must be non-empty for assurance level 'A1'"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &counts_input,
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::WrongType { type_name: "dict" },
            }),
            "Report.coverage must be a Coverage instance, got dict"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &FindingsInput::WrongType {
                    type_name: "list".to_owned(),
                },
                counts: &counts_input,
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.findings must be a tuple, got list"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &FindingsInput::Tuple(vec![
                    FindingElem::Finding(findings[0].clone()),
                    FindingElem::Wrong {
                        type_name: "str".to_owned(),
                    },
                ]),
                counts: &counts_input,
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.findings[1] must be a Finding instance, got str"
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &CountsInput::WrongType {
                    type_name: "dict".to_owned(),
                },
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Report.counts must be a Counts instance, got dict"
        );

        let doubled = built(
            &sev(&[("error", 1)]),
            &codes(&[("SL003", 1)]),
            &CountValue::int(2),
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &CountsInput::Value(doubled),
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Counts.total (2) does not match findings count (1)"
        );
        let severity_drift = built(
            &sev(&[("info", 1)]),
            &codes(&[("SL003", 1)]),
            &CountValue::int(1),
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &CountsInput::Value(severity_drift),
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Counts.by_severity ({'fatal': 0, 'error': 0, 'warning': 0, 'info': 1}) does not match findings severity distribution ({'fatal': 0, 'error': 1, 'warning': 0, 'info': 0})"
        );
        let code_drift = built(
            &sev(&[("error", 1)]),
            &CountValue::dict(vec![
                (CountKey::str_key("SL101"), CountValue::int(1)),
                (CountKey::str_key("SL002"), CountValue::int(1)),
            ]),
            &CountValue::int(1),
        );
        assert_eq!(
            code_drift.code_items(),
            [("SL101".to_owned(), 1), ("SL002".to_owned(), 1)]
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &CountsInput::Value(code_drift),
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Counts.by_code ({'SL101': 1, 'SL002': 1}) does not match findings code distribution ({'SL003': 1})"
        );
        let extra_zero = built(
            &sev(&[("error", 1)]),
            &CountValue::dict(vec![
                (CountKey::str_key("SL003"), CountValue::int(1)),
                (CountKey::str_key("SL101"), CountValue::int(0)),
            ]),
            &CountValue::int(1),
        );
        assert_eq!(
            report_error(ReportParts {
                schema_version: &good_schema,
                session_id: &session,
                source_fingerprint: &fingerprint,
                tool_version: &tool,
                findings: &findings_input,
                counts: &CountsInput::Value(extra_zero),
                assurance: &assurance,
                limitation: &limitation,
                coverage: CoverageInput::Value(&coverage),
            }),
            "Counts.by_code ({'SL003': 1, 'SL101': 0}) does not match findings code distribution ({'SL003': 1})"
        );
    }

    fn report_error(parts: ReportParts<'_>) -> String {
        match Report::try_new(parts) {
            Ok(_) => panic!("expected Report to fail"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn action_sort_key_splits_missing_record_id_from_empty() {
        let fields = |kind, record_id, detail| ActionSortFields {
            kind,
            record_id,
            detail,
        };
        assert_eq!(
            action_sort_key(fields("drop", None, "d")),
            ("drop", 0, "", "d")
        );
        assert_eq!(
            action_sort_key(fields("drop", Some(""), "d")),
            ("drop", 1, "", "d")
        );
        assert_eq!(
            action_sort_key(fields("drop", Some(" r "), " d ")),
            ("drop", 1, " r ", " d ")
        );
        let mut keys = [
            action_sort_key(fields("zeta", Some("b"), "a")),
            action_sort_key(fields("alpha", None, "z")),
            action_sort_key(fields("alpha", Some("a"), "a")),
            action_sort_key(fields("alpha", None, "a")),
            action_sort_key(fields("alpha", Some(""), "m")),
        ];
        keys.sort();
        assert_eq!(
            keys,
            [
                action_sort_key(fields("alpha", None, "a")),
                action_sort_key(fields("alpha", None, "z")),
                action_sort_key(fields("alpha", Some(""), "m")),
                action_sort_key(fields("alpha", Some("a"), "a")),
                action_sort_key(fields("zeta", Some("b"), "a")),
            ]
        );
    }

    fn must_action(kind: &str, record_id: Option<&str>, detail: &str) -> RepairAction {
        let record = match record_id {
            None => InputValue::None,
            Some(value) => text(value),
        };
        match RepairAction::try_new(&text(kind), &record, &text(detail)) {
            Ok(action) => action,
            Err(err) => panic!("synthetic action rejected: {err}"),
        }
    }

    fn action_error(
        kind: &InputValue,
        record_id: &InputValue,
        detail: &InputValue,
    ) -> EnvelopeError {
        match RepairAction::try_new(kind, record_id, detail) {
            Ok(_) => panic!("expected RepairAction to fail"),
            Err(err) => err,
        }
    }

    fn finding_leak(text: &str, context: &str) -> String {
        match enforce_content_free_text(text, context) {
            Ok(()) => panic!("expected content leak"),
            Err(err) => err.to_string(),
        }
    }

    fn assert_schema(err: EnvelopeError, message: &str) {
        assert_eq!(err.to_string(), message);
        match err {
            EnvelopeError::Schema(error) => {
                assert_eq!(error.code(), SchemaError::DEFAULT_CODE);
            }
            other => panic!("expected SchemaError, got {other:?}"),
        }
    }

    fn assert_leak(err: EnvelopeError, message: &str) {
        assert_eq!(err.to_string(), message);
        match err {
            EnvelopeError::ContentLeak(error) => {
                assert_eq!(error.code(), ContentLeakError::DEFAULT_CODE);
            }
            other => panic!("expected ContentLeakError, got {other:?}"),
        }
    }

    fn assert_assurance(err: EnvelopeError, message: &str) {
        assert_eq!(err.to_string(), message);
        match err {
            EnvelopeError::Assurance(error) => {
                assert_eq!(error.code(), AssuranceError::DEFAULT_CODE);
            }
            other => panic!("expected AssuranceError, got {other:?}"),
        }
    }

    #[test]
    fn repair_action_strips_and_orders_by_action_sort_key() {
        let missing = must_action("\u{001c}drop\u{001c}", None, "  \n  ");
        assert_eq!(missing.kind(), "drop");
        assert_eq!(missing.record_id(), None);
        assert_eq!(missing.detail(), "");
        assert_eq!(
            missing.to_dict(),
            super::RepairActionDict {
                kind: "drop".to_owned(),
                record_id: None,
                detail: String::new(),
            }
        );
        let same = must_action("drop", None, "");
        assert_eq!(missing, same);
        assert_eq!(missing.cmp(&same), std::cmp::Ordering::Equal);

        let present = must_action(" keep ", Some("  rec-1  "), " note ");
        assert_eq!(present.kind(), "keep");
        assert_eq!(present.record_id(), Some("rec-1"));
        assert_eq!(present.detail(), "note");
        assert_eq!(
            present.to_dict(),
            super::RepairActionDict {
                kind: "keep".to_owned(),
                record_id: Some("rec-1".to_owned()),
                detail: "note".to_owned(),
            }
        );
        let earlier = must_action("drop", Some(" b "), "a");
        let middle = must_action("drop", None, "z");
        let mut actions = [
            present.clone(),
            earlier.clone(),
            middle.clone(),
            missing.clone(),
        ];
        actions.sort();
        assert_eq!(
            actions,
            [
                missing.clone(),
                middle.clone(),
                earlier.clone(),
                present.clone()
            ]
        );
        assert!(missing < middle);
        assert!(middle < earlier);
        assert!(earlier < present);
        assert_ne!(missing, present);
        assert_eq!(
            missing.cmp(&earlier),
            action_sort_key(ActionSortFields {
                kind: missing.kind(),
                record_id: missing.record_id(),
                detail: missing.detail(),
            })
            .cmp(&action_sort_key(ActionSortFields {
                kind: earlier.kind(),
                record_id: earlier.record_id(),
                detail: earlier.detail(),
            }))
        );
    }

    #[test]
    fn repair_action_rejects_in_post_init_order() {
        let detail = text("");
        let record = InputValue::None;
        assert_schema(
            action_error(&InputValue::None, &record, &detail),
            "RepairAction.kind must be a non-empty string, got None",
        );
        assert_schema(
            action_error(&InputValue::int(1), &record, &detail),
            "RepairAction.kind must be a non-empty string, got 1",
        );
        assert_schema(
            action_error(&text(""), &InputValue::int(1), &detail),
            "RepairAction.kind must be a non-empty string, got ''",
        );
        assert_schema(
            action_error(&text("  "), &InputValue::int(1), &detail),
            "RepairAction.kind must be a non-empty string, got '  '",
        );
        assert_schema(
            action_error(&text("\n"), &InputValue::int(1), &detail),
            "RepairAction.kind must be a non-empty string, got '\\n'",
        );
        assert_schema(
            action_error(&text("\u{001c}"), &record, &detail),
            "RepairAction.kind must be a non-empty string, got '\\x1c'",
        );

        let kind_leak = finding_leak("user@example.com", "RepairAction.kind");
        assert_leak(
            action_error(
                &text("\nuser@example.com"),
                &InputValue::int(1),
                &InputValue::None,
            ),
            &format!("Intrinsic content leak in RepairAction.kind: {kind_leak}"),
        );

        assert_schema(
            action_error(&text("drop"), &InputValue::bool_value(true), &detail),
            "RepairAction.record_id must be non-empty string or None, got True",
        );
        assert_schema(
            action_error(&text("drop"), &text(""), &InputValue::int(1)),
            "RepairAction.record_id must be non-empty string or None, got ''",
        );
        assert_schema(
            action_error(&text("drop"), &text("  "), &InputValue::int(1)),
            "RepairAction.record_id must be non-empty string or None, got '  '",
        );
        assert_schema(
            action_error(&text("drop"), &text("\n"), &InputValue::int(1)),
            "RepairAction.record_id must be non-empty string or None, got '\\n'",
        );

        let record_leak = finding_leak("user@example.com", "RepairAction.record_id");
        assert_leak(
            action_error(
                &text("drop"),
                &text("\nuser@example.com\n"),
                &InputValue::int(7),
            ),
            &format!("Intrinsic content leak in RepairAction.record_id: {record_leak}"),
        );

        assert_schema(
            action_error(&text("drop"), &record, &InputValue::int(1)),
            "RepairAction.detail must be a string, got int",
        );
        assert_schema(
            action_error(&text("drop"), &record, &InputValue::None),
            "RepairAction.detail must be a string, got NoneType",
        );
        assert_schema(
            action_error(
                &text("drop"),
                &text("rec-1"),
                &InputValue::bool_value(false),
            ),
            "RepairAction.detail must be a string, got bool",
        );

        let detail_leak = finding_leak("keep\nnote", "RepairAction.detail");
        assert_leak(
            action_error(&text("drop"), &record, &text("  keep\nnote  ")),
            &format!("Intrinsic content leak in RepairAction.detail: {detail_leak}"),
        );
    }

    fn must_revalidation(
        assurance: &str,
        error_count: i64,
        warning_count: i64,
        profile_id: &str,
        profile_version: &str,
        report_fingerprint: Option<&str>,
    ) -> RevalidationSummary {
        let fingerprint = match report_fingerprint {
            None => InputValue::None,
            Some(value) => text(value),
        };
        match RevalidationSummary::try_new(
            &text(assurance),
            &InputValue::int(error_count),
            &InputValue::int(warning_count),
            &text(profile_id),
            &text(profile_version),
            &fingerprint,
        ) {
            Ok(summary) => summary,
            Err(err) => panic!("synthetic revalidation rejected: {err}"),
        }
    }

    fn revalidation_error(
        assurance: &InputValue,
        error_count: &InputValue,
        warning_count: &InputValue,
        profile_id: &InputValue,
        profile_version: &InputValue,
        report_fingerprint: &InputValue,
    ) -> EnvelopeError {
        match RevalidationSummary::try_new(
            assurance,
            error_count,
            warning_count,
            profile_id,
            profile_version,
            report_fingerprint,
        ) {
            Ok(_) => panic!("expected RevalidationSummary to fail"),
            Err(err) => err,
        }
    }

    fn assurance_message(rendered: &str) -> String {
        format!(
            "Invalid revalidation assurance {rendered}. Must be one of ['A0', 'A1', 'A2', 'A3', 'A4']"
        )
    }

    #[test]
    fn revalidation_summary_keeps_labels_and_omits_missing_fingerprint() {
        for level in VALID_ASSURANCE_LEVELS {
            let summary = must_revalidation(level, 0, 0, "profile-a", "1", None);
            assert_eq!(summary.assurance(), level);
            assert_eq!(summary.to_dict().report_fingerprint, None);
        }
        let summary = must_revalidation("A2", 0, 3, "\nprofile-a", "  1.2.3  ", Some("\nfp-1"));
        assert_eq!(summary.error_count(), 0);
        assert_eq!(summary.warning_count(), 3);
        assert_eq!(summary.profile_id(), "\nprofile-a");
        assert_eq!(summary.profile_version(), "  1.2.3  ");
        assert_eq!(summary.report_fingerprint(), Some("\nfp-1"));
        assert_eq!(
            summary.to_dict(),
            super::RevalidationSummaryDict {
                assurance: "A2".to_owned(),
                error_count: 0,
                profile_id: "\nprofile-a".to_owned(),
                profile_version: "  1.2.3  ".to_owned(),
                warning_count: 3,
                report_fingerprint: Some("\nfp-1".to_owned()),
            }
        );
        let omitted = must_revalidation("A0", 1, 0, "profile-a", "1", None);
        assert_eq!(omitted.report_fingerprint(), None);
        assert_eq!(
            omitted.to_dict(),
            super::RevalidationSummaryDict {
                assurance: "A0".to_owned(),
                error_count: 1,
                profile_id: "profile-a".to_owned(),
                profile_version: "1".to_owned(),
                warning_count: 0,
                report_fingerprint: None,
            }
        );
        let again = must_revalidation("A2", 0, 3, "\nprofile-a", "  1.2.3  ", Some("\nfp-1"));
        assert_eq!(summary, again);
        assert_ne!(summary, omitted);
        let wide = must_revalidation("A4", i64::MAX, 0, "profile-a", "1", None);
        assert_eq!(wide.error_count(), i64::MAX);
    }

    #[test]
    fn revalidation_summary_rejects_in_post_init_order() {
        let errors = InputValue::int(0);
        let warnings = InputValue::int(0);
        let profile = text("profile-a");
        let version = text("1");
        let fingerprint = InputValue::None;
        assert_assurance(
            revalidation_error(
                &text("A9"),
                &InputValue::int(-1),
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            &assurance_message("'A9'"),
        );
        assert_assurance(
            revalidation_error(
                &InputValue::int(1),
                &errors,
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            &assurance_message("1"),
        );
        assert_assurance(
            revalidation_error(
                &InputValue::bool_value(true),
                &errors,
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            &assurance_message("True"),
        );
        assert_assurance(
            revalidation_error(
                &text(" A0"),
                &errors,
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            &assurance_message("' A0'"),
        );
        assert_assurance(
            revalidation_error(
                &text("a4"),
                &errors,
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            &assurance_message("'a4'"),
        );

        assert_schema(
            revalidation_error(
                &text("A0"),
                &InputValue::bool_value(true),
                &InputValue::int(-1),
                &profile,
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.error_count must be non-negative integer, got True",
        );
        assert_schema(
            revalidation_error(
                &text("A0"),
                &InputValue::bool_value(false),
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.error_count must be non-negative integer, got False",
        );
        assert_schema(
            revalidation_error(
                &text("A0"),
                &InputValue::int(-1),
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.error_count must be non-negative integer, got -1",
        );
        assert_schema(
            revalidation_error(
                &text("A0"),
                &InputValue::int(i64::MIN),
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.error_count must be non-negative integer, got -9223372036854775808",
        );
        assert_schema(
            revalidation_error(
                &text("A0"),
                &InputValue::None,
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.error_count must be non-negative integer, got None",
        );
        assert_schema(
            revalidation_error(
                &text("A0"),
                &text("1"),
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.error_count must be non-negative integer, got '1'",
        );
        assert_schema(
            revalidation_error(
                &text("A0"),
                &InputValue::other("float", "1.5"),
                &warnings,
                &profile,
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.error_count must be non-negative integer, got 1.5",
        );

        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &InputValue::bool_value(false),
                &text("   "),
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.warning_count must be non-negative integer, got False",
        );
        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &InputValue::int(-1),
                &profile,
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.warning_count must be non-negative integer, got -1",
        );
        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &text("0"),
                &profile,
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.warning_count must be non-negative integer, got '0'",
        );

        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &warnings,
                &text("   "),
                &text(""),
                &fingerprint,
            ),
            "RevalidationSummary.profile_id must be a non-empty string, got '   '",
        );
        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &warnings,
                &InputValue::int(1),
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.profile_id must be a non-empty string, got 1",
        );
        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &warnings,
                &text("\n"),
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.profile_id must be a non-empty string, got '\\n'",
        );
        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &warnings,
                &text("\u{001c}"),
                &version,
                &fingerprint,
            ),
            "RevalidationSummary.profile_id must be a non-empty string, got '\\x1c'",
        );

        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &warnings,
                &profile,
                &text(""),
                &text("   "),
            ),
            "RevalidationSummary.profile_version must be a non-empty string, got ''",
        );
        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &warnings,
                &profile,
                &InputValue::None,
                &fingerprint,
            ),
            "RevalidationSummary.profile_version must be a non-empty string, got None",
        );
        assert_schema(
            revalidation_error(
                &text("A1"),
                &errors,
                &warnings,
                &profile,
                &text(" \n "),
                &fingerprint,
            ),
            "RevalidationSummary.profile_version must be a non-empty string, got ' \\n '",
        );

        let fingerprint_message =
            "RevalidationSummary.report_fingerprint must be a non-empty string or None";
        assert_schema(
            revalidation_error(
                &text("A3"),
                &errors,
                &warnings,
                &profile,
                &version,
                &text(""),
            ),
            fingerprint_message,
        );
        assert_schema(
            revalidation_error(
                &text("A3"),
                &errors,
                &warnings,
                &profile,
                &version,
                &text(" \n "),
            ),
            fingerprint_message,
        );
        assert_schema(
            revalidation_error(
                &text("A3"),
                &errors,
                &warnings,
                &profile,
                &version,
                &InputValue::int(1),
            ),
            fingerprint_message,
        );
        assert_schema(
            revalidation_error(
                &text("A3"),
                &errors,
                &warnings,
                &profile,
                &version,
                &InputValue::bool_value(false),
            ),
            fingerprint_message,
        );
    }

    fn hex_key() -> String {
        "0123456789abcdef".repeat(4)
    }

    fn sample_revalidation() -> RevalidationSummary {
        match RevalidationSummary::try_new(
            &text("A2"),
            &InputValue::int(1),
            &InputValue::int(0),
            &text("neutral"),
            &text("1.0.0"),
            &InputValue::None,
        ) {
            Ok(summary) => summary,
            Err(err) => panic!("synthetic revalidation rejected: {err}"),
        }
    }

    struct ManifestInputs {
        schema_version: InputValue,
        input_fingerprint: InputValue,
        output_fingerprint: InputValue,
        policy: InputValue,
        actions: ActionSeq,
        declared_loss: InputValue,
        revalidate_report: InputValue,
        idempotency_key: InputValue,
        revalidation: RevalidationInput,
        assurance_ceiling: InputValue,
        plan_fingerprint: InputValue,
        assurance: InputValue,
        recipe_versions: InputValue,
        profile_version: InputValue,
        adapter_id: InputValue,
        adapter_version: InputValue,
        byte_counts: InputValue,
        record_counts: InputValue,
    }

    fn empty_map() -> InputValue {
        InputValue::dict(Vec::new())
    }

    fn base_manifest() -> ManifestInputs {
        ManifestInputs {
            schema_version: text(model::version::MANIFEST_SCHEMA_VERSION),
            input_fingerprint: text(" in "),
            output_fingerprint: text(" out "),
            policy: text("conservative"),
            actions: ActionSeq::Tuple(vec![ActionElem::Action(must_action(
                "drop", None, "marker",
            ))]),
            declared_loss: InputValue::tuple(vec![text("loss")]),
            revalidate_report: InputValue::None,
            idempotency_key: text(&hex_key()),
            revalidation: RevalidationInput::Summary(sample_revalidation()),
            assurance_ceiling: text("A1"),
            plan_fingerprint: InputValue::None,
            assurance: InputValue::None,
            recipe_versions: empty_map(),
            profile_version: InputValue::None,
            adapter_id: InputValue::None,
            adapter_version: InputValue::None,
            byte_counts: empty_map(),
            record_counts: empty_map(),
        }
    }

    fn eval_manifest(inputs: &ManifestInputs) -> Result<RepairManifest, EnvelopeError> {
        RepairManifest::try_new(RepairManifestParts {
            schema_version: &inputs.schema_version,
            input_fingerprint: &inputs.input_fingerprint,
            output_fingerprint: &inputs.output_fingerprint,
            policy: &inputs.policy,
            actions: &inputs.actions,
            declared_loss: &inputs.declared_loss,
            revalidate_report: &inputs.revalidate_report,
            idempotency_key: &inputs.idempotency_key,
            revalidation: &inputs.revalidation,
            assurance_ceiling: &inputs.assurance_ceiling,
            plan_fingerprint: &inputs.plan_fingerprint,
            assurance: &inputs.assurance,
            recipe_versions: &inputs.recipe_versions,
            profile_version: &inputs.profile_version,
            adapter_id: &inputs.adapter_id,
            adapter_version: &inputs.adapter_version,
            byte_counts: &inputs.byte_counts,
            record_counts: &inputs.record_counts,
        })
    }

    fn manifest_err(inputs: &ManifestInputs) -> EnvelopeError {
        match eval_manifest(inputs) {
            Ok(_) => panic!("expected RepairManifest to fail"),
            Err(err) => err,
        }
    }

    fn build_result(
        session_id: &InputValue,
        source_fingerprint: &InputValue,
        tool_version: &InputValue,
        assurance: &InputValue,
        limitation: &InputValue,
        coverage: BuildCoverage<'_>,
    ) -> Result<Report, EnvelopeError> {
        build_report(BuildReportParts {
            session_id,
            source_fingerprint,
            tool_version,
            findings: &[],
            assurance,
            limitation,
            coverage,
        })
    }

    fn build_message(
        session_id: &InputValue,
        source_fingerprint: &InputValue,
        tool_version: &InputValue,
        assurance: &InputValue,
        limitation: &InputValue,
        coverage: BuildCoverage<'_>,
    ) -> String {
        match build_result(
            session_id,
            source_fingerprint,
            tool_version,
            assurance,
            limitation,
            coverage,
        ) {
            Ok(_) => panic!("expected build_report to fail"),
            Err(err) => err.to_string(),
        }
    }

    fn idempotency_err(
        input_fingerprint: &InputValue,
        policy: &InputValue,
        actions: &[RepairAction],
    ) -> IdempotencyError {
        match compute_manifest_idempotency_key(input_fingerprint, policy, actions) {
            Ok(digest) => panic!("idempotency invented a digest: {digest}"),
            Err(err) => err,
        }
    }

    #[test]
    fn repair_manifest_rejects_identity_before_actions() {
        let mut inputs = base_manifest();
        inputs.schema_version = text("nope");
        inputs.input_fingerprint = text("");
        match manifest_err(&inputs) {
            EnvelopeError::Version(error) => {
                assert_eq!(
                    error.to_string(),
                    "RepairManifest.schema_version must be 'sesslint.repair-manifest/v1', got 'nope' (code: VERSION / SL301)"
                );
                assert_eq!(error.version(), Some("nope"));
                assert_eq!(error.code(), VersionError::CODE);
            }
            other => panic!("expected VersionError, got {other:?}"),
        }

        inputs.schema_version = InputValue::int(1);
        match manifest_err(&inputs) {
            EnvelopeError::Version(error) => {
                assert_eq!(
                    error.to_string(),
                    "RepairManifest.schema_version must be 'sesslint.repair-manifest/v1', got 1 (code: VERSION / SL301)"
                );
                assert_eq!(error.version(), None);
            }
            other => panic!("expected VersionError, got {other:?}"),
        }

        inputs.schema_version = text(model::version::MANIFEST_SCHEMA_VERSION);
        inputs.input_fingerprint = text("");
        inputs.output_fingerprint = text("");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.input_fingerprint must be a non-empty string, got ''",
        );
        inputs.input_fingerprint = text("   ");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.input_fingerprint must be a non-empty string, got '   '",
        );
        inputs.input_fingerprint = InputValue::None;
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.input_fingerprint must be a non-empty string, got None",
        );

        inputs.input_fingerprint = text(" in ");
        inputs.output_fingerprint = text(" \n ");
        inputs.policy = text("nope");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.output_fingerprint must be a non-empty string, got ' \\n '",
        );
        inputs.output_fingerprint = text(" out ");
        inputs.actions = ActionSeq::Wrong {
            type_name: "list".to_owned(),
        };
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.policy must be one of ['conservative', 'salvage'], got 'nope'",
        );
        inputs.policy = text(" salvage");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.policy must be one of ['conservative', 'salvage'], got ' salvage'",
        );
        inputs.policy = InputValue::None;
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.policy must be one of ['conservative', 'salvage'], got None",
        );

        inputs.policy = text("conservative");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.actions must be a tuple, got list",
        );
        inputs.actions = ActionSeq::Tuple(vec![
            ActionElem::Action(must_action("drop", None, "marker")),
            ActionElem::Wrong {
                type_name: "dict".to_owned(),
            },
        ]);
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.actions[1] must be a RepairAction, got dict",
        );
    }

    #[test]
    fn repair_manifest_rejects_loss_key_and_ceiling_in_order() {
        let mut inputs = base_manifest();
        inputs.declared_loss = InputValue::list(vec![text("loss")]);
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.declared_loss must be a tuple, got list",
        );
        inputs.declared_loss = InputValue::tuple(vec![text("loss"), InputValue::None]);
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.declared_loss[1] must be a non-empty string, got None",
        );
        inputs.declared_loss = InputValue::tuple(vec![text("   ")]);
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.declared_loss[0] must be a non-empty string, got '   '",
        );
        inputs.declared_loss = InputValue::tuple(vec![InputValue::int(1)]);
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.declared_loss[0] must be a non-empty string, got 1",
        );

        inputs.declared_loss = InputValue::tuple(vec![text("loss")]);
        inputs.revalidate_report = text("");
        inputs.idempotency_key = text("abc");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.revalidate_report must be a non-empty string path or None, got ''",
        );
        inputs.revalidate_report = text("   ");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.revalidate_report must be a non-empty string path or None, got '   '",
        );
        inputs.revalidate_report = InputValue::None;
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.idempotency_key must be a 64-character lowercase hex string, got 'abc'",
        );
        inputs.idempotency_key = text(&"A".repeat(64));
        assert_schema(
            manifest_err(&inputs),
            &format!(
                "RepairManifest.idempotency_key must be a 64-character lowercase hex string, got '{}'",
                "A".repeat(64)
            ),
        );
        inputs.idempotency_key = InputValue::int(1);
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.idempotency_key must be a 64-character lowercase hex string, got 1",
        );

        inputs.idempotency_key = text(&hex_key());
        inputs.revalidation = RevalidationInput::Wrong {
            type_name: "dict".to_owned(),
        };
        inputs.assurance_ceiling = text("A9");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.revalidation must be a RevalidationSummary, got dict",
        );
        inputs.revalidation = RevalidationInput::Summary(sample_revalidation());
        inputs.plan_fingerprint = text("");
        assert_assurance(
            manifest_err(&inputs),
            "RepairManifest.assurance_ceiling must be one of ['A0', 'A1', 'A2', 'A3', 'A4'], got 'A9'",
        );
        inputs.assurance_ceiling = text("A1 ");
        assert_assurance(
            manifest_err(&inputs),
            "RepairManifest.assurance_ceiling must be one of ['A0', 'A1', 'A2', 'A3', 'A4'], got 'A1 '",
        );
        inputs.assurance_ceiling = InputValue::None;
        assert_assurance(
            manifest_err(&inputs),
            "RepairManifest.assurance_ceiling must be one of ['A0', 'A1', 'A2', 'A3', 'A4'], got None",
        );
    }

    #[test]
    fn repair_manifest_rejects_optional_fields_in_order() {
        let mut inputs = base_manifest();
        inputs.plan_fingerprint = text("   ");
        inputs.recipe_versions = InputValue::list(Vec::new());
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.plan_fingerprint must be a non-empty string",
        );
        inputs.plan_fingerprint = InputValue::int(1);
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.plan_fingerprint must be a non-empty string",
        );

        inputs.plan_fingerprint = InputValue::None;
        inputs.assurance = text("");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.assurance must be a non-empty string",
        );
        inputs.assurance = InputValue::None;
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.recipe_versions must be a Mapping",
        );
        inputs.recipe_versions = InputValue::None;
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.recipe_versions must be a Mapping",
        );

        inputs.recipe_versions = empty_map();
        inputs.profile_version = text(" \n ");
        inputs.byte_counts = InputValue::tuple(Vec::new());
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.profile_version must be a non-empty string",
        );
        inputs.profile_version = text("9");
        inputs.adapter_id = text("");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.adapter_id must be a non-empty string",
        );
        inputs.adapter_id = text("canon");
        inputs.adapter_version = InputValue::bool_value(true);
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.adapter_version must be a non-empty string",
        );
        inputs.adapter_version = text("1");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.byte_counts must be a Mapping",
        );
        inputs.byte_counts = empty_map();
        inputs.record_counts = text("nope");
        assert_schema(
            manifest_err(&inputs),
            "RepairManifest.record_counts must be a Mapping",
        );
    }

    #[test]
    fn repair_manifest_keeps_text_and_orders_optional_maps() {
        let mut inputs = base_manifest();
        inputs.actions = ActionSeq::Tuple(vec![
            ActionElem::Action(must_action("zeta", Some("b"), "z")),
            ActionElem::Action(must_action("alpha", None, "a")),
        ]);
        inputs.declared_loss = InputValue::tuple(vec![text(" zeta "), text("alpha")]);
        inputs.revalidate_report = text(" out.json ");
        inputs.plan_fingerprint = text(" plan ");
        inputs.assurance = text(" not-level ");
        inputs.recipe_versions = InputValue::dict(vec![
            (InputKey::str_key("m"), text("two")),
            (InputKey::str_key("a"), text("one")),
        ]);
        inputs.profile_version = text(" 9 ");
        inputs.adapter_id = text(" canon ");
        inputs.adapter_version = text(" 1 ");
        inputs.byte_counts = InputValue::dict(vec![
            (InputKey::str_key("b"), InputValue::int(2)),
            (InputKey::str_key("a"), InputValue::int(1)),
        ]);
        inputs.record_counts = InputValue::dict(vec![
            (InputKey::str_key("z"), text("kept")),
            (InputKey::str_key("a"), InputValue::int(3)),
        ]);
        let manifest = match eval_manifest(&inputs) {
            Ok(manifest) => manifest,
            Err(err) => panic!("synthetic manifest rejected: {err}"),
        };
        assert_eq!(
            manifest.schema_version(),
            model::version::MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(
            model::version::MANIFEST_SCHEMA_VERSION,
            "sesslint.repair-manifest/v1"
        );
        assert_eq!(manifest.input_fingerprint(), " in ");
        assert_eq!(manifest.output_fingerprint(), " out ");
        assert_eq!(manifest.plan_fingerprint(), Some(" plan "));
        assert_eq!(manifest.assurance(), Some(" not-level "));
        assert_eq!(manifest.revalidate_report(), Some(" out.json "));
        assert_eq!(manifest.policy(), "conservative");
        assert_eq!(manifest.assurance_ceiling(), "A1");
        assert_eq!(manifest.idempotency_key(), hex_key());
        assert_eq!(manifest.actions()[0].kind(), "zeta");
        assert_eq!(manifest.actions()[1].kind(), "alpha");
        let dict = match manifest.to_dict() {
            Ok(dict) => dict,
            Err(err) => panic!("synthetic manifest dict rejected: {err}"),
        };
        assert_eq!(dict.actions[0].kind, "zeta");
        assert_eq!(dict.actions[0].record_id.as_deref(), Some("b"));
        assert_eq!(dict.actions[1].kind, "alpha");
        assert_eq!(dict.actions[1].record_id, None);
        assert_eq!(dict.assurance_ceiling, "A1");
        assert_eq!(
            dict.declared_loss,
            vec![" zeta ".to_owned(), "alpha".to_owned()]
        );
        assert_eq!(dict.idempotency_key, hex_key());
        assert_eq!(dict.input_fingerprint, " in ");
        assert_eq!(dict.output_fingerprint, " out ");
        assert_eq!(dict.policy, "conservative");
        assert_eq!(dict.revalidate_report.as_deref(), Some(" out.json "));
        assert_eq!(dict.revalidation.assurance, "A2");
        assert_eq!(dict.revalidation.error_count, 1);
        assert_eq!(dict.schema_version, "sesslint.repair-manifest/v1");
        assert_eq!(dict.plan_fingerprint.as_deref(), Some(" plan "));
        assert_eq!(dict.assurance.as_deref(), Some(" not-level "));
        assert_eq!(
            dict.recipe_versions,
            Some(vec![
                (InputKey::str_key("a"), text("one")),
                (InputKey::str_key("m"), text("two")),
            ])
        );
        assert_eq!(dict.profile_version.as_deref(), Some(" 9 "));
        assert_eq!(dict.adapter_id.as_deref(), Some(" canon "));
        assert_eq!(dict.adapter_version.as_deref(), Some(" 1 "));
        assert_eq!(
            dict.byte_counts,
            Some(vec![
                (InputKey::str_key("a"), InputValue::int(1)),
                (InputKey::str_key("b"), InputValue::int(2)),
            ])
        );
        assert_eq!(
            dict.record_counts,
            Some(vec![
                (InputKey::str_key("a"), InputValue::int(3)),
                (InputKey::str_key("z"), text("kept")),
            ])
        );

        let mut minimal = base_manifest();
        minimal.actions = ActionSeq::Tuple(Vec::new());
        minimal.declared_loss = InputValue::tuple(Vec::new());
        minimal.policy = text("salvage");
        minimal.assurance_ceiling = text("A4");
        minimal.input_fingerprint = text("in");
        minimal.output_fingerprint = text("out");
        let minimal = match eval_manifest(&minimal) {
            Ok(manifest) => manifest,
            Err(err) => panic!("minimal manifest rejected: {err}"),
        };
        let dict = match minimal.to_dict() {
            Ok(dict) => dict,
            Err(err) => panic!("minimal manifest dict rejected: {err}"),
        };
        assert!(dict.actions.is_empty());
        assert!(dict.declared_loss.is_empty());
        assert_eq!(dict.policy, "salvage");
        assert_eq!(dict.assurance_ceiling, "A4");
        assert_eq!(dict.revalidate_report, None);
        assert_eq!(dict.plan_fingerprint, None);
        assert_eq!(dict.assurance, None);
        assert_eq!(dict.recipe_versions, None);
        assert_eq!(dict.profile_version, None);
        assert_eq!(dict.adapter_id, None);
        assert_eq!(dict.adapter_version, None);
        assert_eq!(dict.byte_counts, None);
        assert_eq!(dict.record_counts, None);
    }

    #[test]
    fn build_report_stops_at_omitted_coverage_after_checks() {
        let session = text("sess");
        let fingerprint = text("fp");
        let tool = text("0.0.0");
        let assurance = text("A1");
        let limitation = text("lim");
        assert_eq!(
            build_message(
                &text(""),
                &text(""),
                &text(""),
                &text("A9"),
                &text(""),
                BuildCoverage::Omitted
            ),
            "session_id must be a non-empty string, got ''"
        );
        assert_eq!(
            build_message(
                &text("   "),
                &fingerprint,
                &tool,
                &assurance,
                &limitation,
                BuildCoverage::Omitted
            ),
            "session_id must be a non-empty string, got '   '"
        );
        assert_eq!(
            build_message(
                &InputValue::int(1),
                &fingerprint,
                &tool,
                &assurance,
                &limitation,
                BuildCoverage::Omitted
            ),
            "session_id must be a non-empty string, got 1"
        );
        assert_eq!(
            build_message(
                &session,
                &text(""),
                &text(""),
                &assurance,
                &text(""),
                BuildCoverage::Omitted
            ),
            "source_fingerprint must be a non-empty string, got ''"
        );
        assert_eq!(
            build_message(
                &session,
                &fingerprint,
                &InputValue::None,
                &assurance,
                &limitation,
                BuildCoverage::Omitted
            ),
            "tool_version must be a non-empty string, got None"
        );
        assert_eq!(
            build_message(
                &session,
                &fingerprint,
                &tool,
                &text("A9"),
                &text(""),
                BuildCoverage::Omitted
            ),
            "Invalid assurance level 'A9'. Must be one of ['A0', 'A1', 'A2', 'A3', 'A4']"
        );
        assert_eq!(
            build_message(
                &session,
                &fingerprint,
                &tool,
                &InputValue::None,
                &limitation,
                BuildCoverage::Omitted
            ),
            "Invalid assurance level None. Must be one of ['A0', 'A1', 'A2', 'A3', 'A4']"
        );
        assert_eq!(
            build_message(
                &session,
                &fingerprint,
                &tool,
                &assurance,
                &text("   "),
                BuildCoverage::Omitted
            ),
            "limitation is required and must be non-empty for assurance level 'A1'"
        );
        match build_result(
            &session,
            &fingerprint,
            &tool,
            &assurance,
            &limitation,
            BuildCoverage::Omitted,
        ) {
            Err(err @ EnvelopeError::Unavailable(name)) => {
                assert_eq!(name, PROFILES_BUILTIN_ALL_RULES);
                assert_eq!(
                    err.to_string(),
                    "sesslint.profiles.builtin.ALL_RULES is not available"
                );
            }
            other => panic!("omitted coverage must stop at the rules import, got {other:?}"),
        }
        assert_eq!(
            build_message(
                &session,
                &fingerprint,
                &tool,
                &text("A3"),
                &text("lim"),
                BuildCoverage::Wrong { type_name: "dict" }
            ),
            "coverage must be a Coverage instance, got dict"
        );
    }

    #[test]
    fn build_report_sorts_findings_and_derives_counts() {
        let coverage = must_coverage(
            &InputValue::tuple(vec![text("SL001")]),
            &empty_skips(),
            &canonical_adapter(),
            &neutral_profile(),
        );
        let info = finding(SL003, Severity::Info);
        let error = finding(SL101, Severity::Error);
        let findings = [info, error];
        let report = match build_report(BuildReportParts {
            session_id: &text("  sess  "),
            source_fingerprint: &text("  fp  "),
            tool_version: &text("  0.0.0  "),
            findings: &findings,
            assurance: &text("A1"),
            limitation: &text("  kept  "),
            coverage: BuildCoverage::Value(&coverage),
        }) {
            Ok(report) => report,
            Err(err) => panic!("synthetic report rejected: {err}"),
        };
        assert_eq!(report.schema_version(), REPORT_SCHEMA_VERSION);
        assert_eq!(report.session_id(), "sess");
        assert_eq!(report.source_fingerprint(), "fp");
        assert_eq!(report.tool_version(), "0.0.0");
        assert_eq!(report.assurance(), "A1");
        assert_eq!(report.limitation(), "kept");
        assert_eq!(report.coverage(), &coverage);
        assert_eq!(report.findings()[0].code(), SL101);
        assert_eq!(report.findings()[0].severity(), Severity::Error);
        assert_eq!(report.findings()[1].code(), SL003);
        assert_eq!(report.findings()[1].severity(), Severity::Info);
        assert_eq!(report.counts().total(), 2);
        assert_eq!(report.counts().severity_count("fatal"), Some(0));
        assert_eq!(report.counts().severity_count("error"), Some(1));
        assert_eq!(report.counts().severity_count("warning"), Some(0));
        assert_eq!(report.counts().severity_count("info"), Some(1));
        assert_eq!(
            report.counts().code_items(),
            &[("SL003".to_owned(), 1), ("SL101".to_owned(), 1)][..]
        );

        let repeated = [
            finding(SL101, Severity::Error),
            finding(SL101, Severity::Error),
        ];
        let counted = match build_report(BuildReportParts {
            session_id: &text("s"),
            source_fingerprint: &text("fp"),
            tool_version: &text("0"),
            findings: &repeated,
            assurance: &text("A1"),
            limitation: &text("lim"),
            coverage: BuildCoverage::Value(&coverage),
        }) {
            Ok(report) => report,
            Err(err) => panic!("repeated findings rejected: {err}"),
        };
        assert_eq!(counted.counts().total(), 2);
        assert_eq!(counted.counts().severity_count("error"), Some(2));
        assert_eq!(
            counted.counts().code_items(),
            &[("SL101".to_owned(), 2)][..]
        );

        let empty = match build_report(BuildReportParts {
            session_id: &text("s"),
            source_fingerprint: &text("fp"),
            tool_version: &text("0"),
            findings: &[],
            assurance: &text("A0"),
            limitation: &text("none"),
            coverage: BuildCoverage::Value(&coverage),
        }) {
            Ok(report) => report,
            Err(err) => panic!("empty findings rejected: {err}"),
        };
        assert!(empty.findings().is_empty());
        assert_eq!(empty.counts().total(), 0);
        assert_eq!(empty.counts().severity_count("fatal"), Some(0));
        assert_eq!(empty.counts().severity_count("error"), Some(0));
        assert_eq!(empty.counts().severity_count("warning"), Some(0));
        assert_eq!(empty.counts().severity_count("info"), Some(0));
        assert_eq!(empty.counts().code_items(), &[][..]);
    }

    #[test]
    fn idempotency_key_reaches_canonical_codec_after_two_checks() {
        let actions = [
            must_action("zeta", Some("b"), "z"),
            must_action("alpha", None, "a"),
        ];
        match idempotency_err(&text("   "), &text("nope"), &actions) {
            IdempotencyError::Schema(error) => {
                assert_eq!(
                    error.to_string(),
                    "input_fingerprint must be a non-empty string, got '   '"
                );
                assert_eq!(error.code(), SchemaError::DEFAULT_CODE);
            }
            IdempotencyError::Canonical(error) => {
                panic!("fingerprint check must win before the codec, got {error}");
            }
        }
        match idempotency_err(&InputValue::int(7), &text("conservative"), &actions) {
            IdempotencyError::Schema(error) => {
                assert_eq!(
                    error.to_string(),
                    "input_fingerprint must be a non-empty string, got 7"
                );
            }
            IdempotencyError::Canonical(error) => {
                panic!("non-string fingerprint must not reach the codec, got {error}");
            }
        }
        match idempotency_err(&text(" fp "), &text(" conservative"), &actions) {
            IdempotencyError::Schema(error) => {
                assert_eq!(
                    error.to_string(),
                    "policy must be one of ['conservative', 'salvage'], got ' conservative'"
                );
            }
            IdempotencyError::Canonical(error) => {
                panic!("raw policy check must win before the codec, got {error}");
            }
        }
        match idempotency_err(&text("fp"), &InputValue::None, &actions) {
            IdempotencyError::Schema(error) => {
                assert_eq!(
                    error.to_string(),
                    "policy must be one of ['conservative', 'salvage'], got None"
                );
            }
            IdempotencyError::Canonical(error) => {
                panic!("non-string policy must not reach the codec, got {error}");
            }
        }
        for policy in ["conservative", "salvage"] {
            match idempotency_err(&text(" fp "), &text(policy), &actions) {
                IdempotencyError::Canonical(error) => {
                    assert_eq!(
                        error.to_string(),
                        "sesslint._canonical_codec.canonical_json_bytes is not available"
                    );
                    assert_eq!(
                        IdempotencyError::Canonical(error).to_string(),
                        "sesslint._canonical_codec.canonical_json_bytes is not available"
                    );
                }
                IdempotencyError::Schema(error) => {
                    panic!("valid inputs must reach the codec, got {error}");
                }
            }
        }
    }

    const CANONICAL_SEAM: &str = "sesslint._canonical_codec.canonical_json_bytes is not available";
    const CEILING_SEAM: &str =
        "sesslint.repair.assurance.compute_assurance_ceiling is not available";
    const LEAK_TEXT: &str = "user@example.com";

    struct BuildTail {
        plan_fingerprint: InputValue,
        assurance: InputValue,
        recipe_versions: InputValue,
        profile_version: InputValue,
        adapter_version: InputValue,
        byte_counts: InputValue,
        record_counts: InputValue,
    }

    struct BuildCase {
        input_fingerprint: InputValue,
        output_fingerprint: InputValue,
        policy: InputValue,
        actions: Vec<RepairAction>,
        declared_loss: Vec<InputValue>,
        revalidate_report: InputValue,
        assurance_ceiling: InputValue,
        adapter_id: InputValue,
        tail: BuildTail,
    }

    fn build_tail() -> BuildTail {
        BuildTail {
            plan_fingerprint: InputValue::None,
            assurance: InputValue::None,
            recipe_versions: InputValue::dict(Vec::new()),
            profile_version: InputValue::None,
            adapter_version: InputValue::None,
            byte_counts: InputValue::dict(Vec::new()),
            record_counts: InputValue::dict(Vec::new()),
        }
    }

    fn clean_build() -> BuildCase {
        BuildCase {
            input_fingerprint: text(" in "),
            output_fingerprint: text(" out "),
            policy: text("conservative"),
            actions: vec![
                must_action("zeta", Some("b"), "z"),
                must_action("alpha", None, "a"),
            ],
            declared_loss: vec![text(" z "), text(" a ")],
            revalidate_report: InputValue::None,
            assurance_ceiling: InputValue::None,
            adapter_id: InputValue::None,
            tail: build_tail(),
        }
    }

    fn run_case(
        case: &BuildCase,
        revalidation: BuildRevalidation<'_>,
    ) -> Result<RepairManifest, BuildManifestError> {
        build_manifest(BuildManifestParts {
            input_fingerprint: &case.input_fingerprint,
            output_fingerprint: &case.output_fingerprint,
            policy: &case.policy,
            actions: &case.actions,
            declared_loss: &case.declared_loss,
            revalidate_report: &case.revalidate_report,
            revalidation,
            assurance_ceiling: &case.assurance_ceiling,
            plan_fingerprint: &case.tail.plan_fingerprint,
            assurance: &case.tail.assurance,
            recipe_versions: &case.tail.recipe_versions,
            profile_version: &case.tail.profile_version,
            adapter_id: &case.adapter_id,
            adapter_version: &case.tail.adapter_version,
            byte_counts: &case.tail.byte_counts,
            record_counts: &case.tail.record_counts,
        })
    }

    fn case_err(case: &BuildCase, revalidation: BuildRevalidation<'_>) -> BuildManifestError {
        match run_case(case, revalidation) {
            Ok(manifest) => panic!(
                "build_manifest built a RepairManifest with key {}",
                manifest.idempotency_key()
            ),
            Err(error) => error,
        }
    }

    fn assert_build_schema(error: BuildManifestError, message: &str) {
        match error {
            BuildManifestError::Schema(error) => {
                assert_eq!(error.to_string(), message);
                assert_eq!(error.code(), SchemaError::DEFAULT_CODE);
            }
            other => panic!("expected SchemaError, got {other:?}"),
        }
    }

    fn assert_build_assurance(error: BuildManifestError, message: &str) {
        match error {
            BuildManifestError::Assurance(error) => {
                assert_eq!(error.to_string(), message);
                assert_eq!(error.code(), AssuranceError::DEFAULT_CODE);
            }
            other => panic!("expected AssuranceError, got {other:?}"),
        }
    }

    fn assert_build_leak(error: BuildManifestError, message: &str) {
        match error {
            BuildManifestError::ContentLeak(error) => {
                assert_eq!(error.to_string(), message);
                assert_eq!(error.code(), ContentLeakError::DEFAULT_CODE);
            }
            other => panic!("expected ContentLeakError, got {other:?}"),
        }
    }

    fn assert_ceiling(error: BuildManifestError) {
        assert_eq!(error.to_string(), CEILING_SEAM);
        assert!(std::error::Error::source(&error).is_none());
        match error {
            BuildManifestError::Unavailable(name) => assert_eq!(name, COMPUTE_ASSURANCE_CEILING),
            other => panic!("expected ceiling unavailable, got {other:?}"),
        }
    }

    fn assert_codec(error: BuildManifestError) {
        match error {
            BuildManifestError::Idempotency(error) => {
                assert_eq!(error.to_string(), CANONICAL_SEAM);
                match std::error::Error::source(&error) {
                    Some(source) => assert_eq!(source.to_string(), CANONICAL_SEAM),
                    None => panic!("canonical error must expose its source"),
                }
            }
            other => panic!("expected canonical codec, got {other:?}"),
        }
    }

    fn loss_leak(index: usize, value: &str) -> String {
        format!(
            "Content leak in declared_loss[{index}]: {}",
            finding_leak(value, "declared_loss")
        )
    }

    fn meta_leak(context: &str, value: &str) -> String {
        format!(
            "Content leak in manifest metadata: {}",
            finding_leak(value, context)
        )
    }

    fn field_map(pairs: &[(&str, InputValue)]) -> Vec<(InputKey, InputValue)> {
        pairs
            .iter()
            .map(|(key, value)| (InputKey::str_key(*key), value.clone()))
            .collect()
    }

    fn valid_map_pairs(
        assurance: InputValue,
        error_count: InputValue,
    ) -> Vec<(InputKey, InputValue)> {
        field_map(&[
            ("assurance", assurance),
            ("error_count", error_count),
            ("warning_count", InputValue::int(0)),
            ("profile_id", text("neutral")),
            ("profile_version", text("1.0.0")),
        ])
    }

    fn kept_summary(profile_id: &str, fingerprint: &InputValue) -> RevalidationSummary {
        match RevalidationSummary::try_new(
            &text("A2"),
            &InputValue::int(0),
            &InputValue::int(0),
            &text(profile_id),
            &text("1.0.0"),
            fingerprint,
        ) {
            Ok(summary) => summary,
            Err(err) => panic!("synthetic revalidation rejected: {err}"),
        }
    }

    #[test]
    fn default_revalidation_uses_the_pin_summary() {
        let summary = match super::default_revalidation() {
            Ok(summary) => summary,
            Err(err) => panic!("default revalidation rejected: {err}"),
        };
        assert_eq!(summary.assurance(), "A3");
        assert_eq!(summary.error_count(), 0);
        assert_eq!(summary.warning_count(), 0);
        assert_eq!(summary.profile_id(), "neutral");
        assert_eq!(summary.profile_version(), "1.0.0");
        assert_eq!(summary.report_fingerprint(), None);
    }

    #[test]
    fn build_manifest_checks_fingerprints_then_raw_policy() {
        let mut case = clean_build();
        case.input_fingerprint = text("");
        case.output_fingerprint = text("");
        case.declared_loss = vec![text(LEAK_TEXT)];
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "input_fingerprint must be a non-empty string, got ''",
        );
        case.input_fingerprint = text("   ");
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "input_fingerprint must be a non-empty string, got '   '",
        );
        case.input_fingerprint = text("\n");
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "input_fingerprint must be a non-empty string, got '\\n'",
        );
        case.input_fingerprint = InputValue::int(7);
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "input_fingerprint must be a non-empty string, got 7",
        );
        case.input_fingerprint = InputValue::None;
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "input_fingerprint must be a non-empty string, got None",
        );

        case.input_fingerprint = text(" fp ");
        case.output_fingerprint = text("");
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "output_fingerprint must be a non-empty string, got ''",
        );
        case.output_fingerprint = text(" \n ");
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "output_fingerprint must be a non-empty string, got ' \\n '",
        );
        case.output_fingerprint = InputValue::bool_value(true);
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "output_fingerprint must be a non-empty string, got True",
        );

        case.output_fingerprint = text(" out ");
        case.policy = text(" salvage");
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "policy must be one of ['conservative', 'salvage'], got ' salvage'",
        );
        case.policy = InputValue::None;
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "policy must be one of ['conservative', 'salvage'], got None",
        );
        case.policy = text("nope");
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "policy must be one of ['conservative', 'salvage'], got 'nope'",
        );
    }

    #[test]
    fn build_manifest_keeps_declared_loss_order_before_ceiling() {
        let mut case = clean_build();
        case.declared_loss = vec![InputValue::int(1)];
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "declared_loss[0] must be a non-empty string, got 1",
        );
        case.declared_loss = vec![text(""), text(LEAK_TEXT)];
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "declared_loss[0] must be a non-empty string, got ''",
        );
        case.declared_loss = vec![text("   ")];
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "declared_loss[0] must be a non-empty string, got '   '",
        );
        case.declared_loss = vec![text("z"), text(LEAK_TEXT)];
        assert_build_leak(
            case_err(&case, BuildRevalidation::Wrong { type_name: "dict" }),
            &loss_leak(1, LEAK_TEXT),
        );
        case.declared_loss = vec![text(LEAK_TEXT), text("z")];
        assert_build_leak(
            case_err(&case, BuildRevalidation::None),
            &loss_leak(0, LEAK_TEXT),
        );
        case.declared_loss = vec![text("  kept  ")];
        assert_ceiling(case_err(&case, BuildRevalidation::None));
    }

    #[test]
    fn build_manifest_normalizes_revalidate_path_before_ceiling() {
        let mut case = clean_build();
        case.revalidate_report = InputValue::int(1);
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "revalidate_report must be a non-empty string path or None, got 1",
        );
        case.revalidate_report = text("");
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "revalidate_report must be a non-empty string path or None, got ''",
        );
        case.revalidate_report = text("   ");
        assert_build_schema(
            case_err(&case, BuildRevalidation::None),
            "revalidate_report must be a non-empty string path or None, got '   '",
        );
        case.revalidate_report = text(" user@example.com\\x ");
        assert_build_leak(
            case_err(&case, BuildRevalidation::Wrong { type_name: "int" }),
            &format!(
                "Content leak in revalidate_report: {}",
                finding_leak("user@example.com/x", "revalidate_report")
            ),
        );
        case.revalidate_report = text(" reports\\out.json ");
        assert_ceiling(case_err(&case, BuildRevalidation::None));
    }

    #[test]
    fn build_manifest_revalidation_runs_before_ceiling() {
        let case = clean_build();
        assert_build_schema(
            case_err(&case, BuildRevalidation::Wrong { type_name: "list" }),
            "revalidation must be a RevalidationSummary or Mapping, got list",
        );
        let missing_assurance = field_map(&[("error_count", InputValue::int(0))]);
        assert_build_schema(
            case_err(&case, BuildRevalidation::Mapping(&missing_assurance)),
            "revalidation missing required field 'assurance'",
        );
        let missing_count = field_map(&[
            ("assurance", text("nope")),
            ("warning_count", InputValue::int(0)),
            ("profile_id", text("neutral")),
            ("profile_version", text("1.0.0")),
        ]);
        assert_build_schema(
            case_err(&case, BuildRevalidation::Mapping(&missing_count)),
            "revalidation missing required field 'error_count'",
        );

        let bad_assurance = valid_map_pairs(text("nope"), InputValue::int(1));
        assert_build_assurance(
            case_err(&case, BuildRevalidation::Mapping(&bad_assurance)),
            "Invalid revalidation assurance 'nope'. Must be one of ['A0', 'A1', 'A2', 'A3', 'A4']",
        );
        let bad_literal = valid_map_pairs(text("nope"), text("nope"));
        match case_err(&case, BuildRevalidation::Mapping(&bad_literal)) {
            BuildManifestError::Value(message) => {
                assert_eq!(message, "invalid literal for int() with base 10: 'nope'");
            }
            other => panic!("int() must fail before assurance, got {other:?}"),
        }
        let missing_number = valid_map_pairs(text("A1"), InputValue::None);
        match case_err(&case, BuildRevalidation::Mapping(&missing_number)) {
            BuildManifestError::Type(message) => {
                assert_eq!(
                    message,
                    "int() argument must be a string, a bytes-like object or a real number, not 'NoneType'"
                );
            }
            other => panic!("int(None) must be TypeError, got {other:?}"),
        }

        assert_ceiling(case_err(
            &case,
            BuildRevalidation::Mapping(&valid_map_pairs(text("A1"), InputValue::bool_value(true))),
        ));
        assert_ceiling(case_err(
            &case,
            BuildRevalidation::Mapping(&valid_map_pairs(text("A1"), text("  1_0 "))),
        ));
        let numeric_profile = field_map(&[
            ("assurance", text("A1")),
            ("error_count", InputValue::int(0)),
            ("warning_count", InputValue::int(0)),
            ("profile_id", InputValue::int(5)),
            ("profile_version", text("1.0.0")),
        ]);
        assert_ceiling(case_err(
            &case,
            BuildRevalidation::Mapping(&numeric_profile),
        ));
        let none_profile = field_map(&[
            ("assurance", text("A1")),
            ("error_count", InputValue::int(0)),
            ("warning_count", InputValue::int(0)),
            ("profile_id", InputValue::None),
            ("profile_version", text("1.0.0")),
        ]);
        assert_ceiling(case_err(&case, BuildRevalidation::Mapping(&none_profile)));
        let duplicate = field_map(&[
            ("assurance", text("nope")),
            ("error_count", InputValue::int(0)),
            ("warning_count", InputValue::int(0)),
            ("profile_id", text("neutral")),
            ("profile_version", text("1.0.0")),
            ("assurance", text("A3")),
        ]);
        assert_ceiling(case_err(&case, BuildRevalidation::Mapping(&duplicate)));

        let negative = valid_map_pairs(text("A1"), text("-1"));
        assert_build_schema(
            case_err(&case, BuildRevalidation::Mapping(&negative)),
            "RevalidationSummary.error_count must be non-negative integer, got -1",
        );
        let huge_digits = "9".repeat(40);
        let huge = valid_map_pairs(text("A1"), text(&huge_digits));
        assert_build_schema(
            case_err(&case, BuildRevalidation::Mapping(&huge)),
            "revalidation error_count does not fit in i64",
        );
        let mut warning = valid_map_pairs(text("A1"), InputValue::int(1));
        warning.push((InputKey::str_key("warning_count"), text(&huge_digits)));
        assert_build_schema(
            case_err(&case, BuildRevalidation::Mapping(&warning)),
            "revalidation warning_count does not fit in i64",
        );
        let mut blank_fingerprint = valid_map_pairs(text("A1"), InputValue::int(0));
        blank_fingerprint.push((InputKey::str_key("report_fingerprint"), text("")));
        assert_build_schema(
            case_err(&case, BuildRevalidation::Mapping(&blank_fingerprint)),
            "RevalidationSummary.report_fingerprint must be a non-empty string or None",
        );
        let mut bool_fingerprint = valid_map_pairs(text("A1"), InputValue::int(0));
        bool_fingerprint.push((
            InputKey::str_key("report_fingerprint"),
            InputValue::bool_value(true),
        ));
        assert_ceiling(case_err(
            &case,
            BuildRevalidation::Mapping(&bool_fingerprint),
        ));
    }

    #[test]
    fn build_manifest_ceiling_stops_before_metadata_and_codec() {
        let mut case = clean_build();
        let leaky = kept_summary(LEAK_TEXT, &InputValue::None);
        assert_ceiling(case_err(&case, BuildRevalidation::Summary(&leaky)));
        let clean = kept_summary("neutral", &InputValue::None);
        case.adapter_id = text(LEAK_TEXT);
        assert_ceiling(case_err(&case, BuildRevalidation::Summary(&clean)));

        case.adapter_id = InputValue::None;
        case.assurance_ceiling = text("A5");
        assert_build_assurance(
            case_err(&case, BuildRevalidation::Summary(&leaky)),
            "Invalid assurance_ceiling 'A5'. Must be one of ['A0', 'A1', 'A2', 'A3', 'A4']",
        );
        case.assurance_ceiling = text(" A3 ");
        assert_build_assurance(
            case_err(&case, BuildRevalidation::None),
            "Invalid assurance_ceiling ' A3 '. Must be one of ['A0', 'A1', 'A2', 'A3', 'A4']",
        );
        case.assurance_ceiling = InputValue::int(1);
        assert_build_assurance(
            case_err(&case, BuildRevalidation::None),
            "Invalid assurance_ceiling 1. Must be one of ['A0', 'A1', 'A2', 'A3', 'A4']",
        );

        case.assurance_ceiling = text("A1");
        assert_build_leak(
            case_err(&case, BuildRevalidation::Summary(&leaky)),
            &meta_leak("revalidation.profile_id", LEAK_TEXT),
        );
        let version_leak = match RevalidationSummary::try_new(
            &text("A2"),
            &InputValue::int(0),
            &InputValue::int(0),
            &text("neutral"),
            &text(LEAK_TEXT),
            &InputValue::None,
        ) {
            Ok(summary) => summary,
            Err(err) => panic!("synthetic revalidation rejected: {err}"),
        };
        assert_build_leak(
            case_err(&case, BuildRevalidation::Summary(&version_leak)),
            &meta_leak("revalidation.profile_version", LEAK_TEXT),
        );
        let fingerprint = text(LEAK_TEXT);
        let finger_leak = kept_summary("neutral", &fingerprint);
        assert_build_leak(
            case_err(&case, BuildRevalidation::Summary(&finger_leak)),
            &meta_leak("revalidation.report_fingerprint", LEAK_TEXT),
        );
        case.adapter_id = text(LEAK_TEXT);
        assert_build_leak(
            case_err(&case, BuildRevalidation::Summary(&clean)),
            &meta_leak("adapter_id", LEAK_TEXT),
        );
        case.adapter_id = InputValue::int(3);
        match case_err(&case, BuildRevalidation::Summary(&clean)) {
            BuildManifestError::Type(message) => {
                assert_eq!(message, "expected string or bytes-like object, got 'int'");
            }
            other => panic!("expected TypeError, got {other:?}"),
        }

        case.adapter_id = InputValue::None;
        case.actions = vec![
            must_action("alpha", None, "a"),
            must_action("zeta", Some("b"), "z"),
        ];
        case.declared_loss = Vec::new();
        for level in ["A0", "A1", "A2", "A3", "A4"] {
            case.assurance_ceiling = text(level);
            assert_codec(case_err(&case, BuildRevalidation::None));
        }
        case.policy = text("salvage");
        case.assurance_ceiling = text("A4");
        assert_codec(case_err(&case, BuildRevalidation::None));
        case.policy = text("conservative");
        assert_codec(case_err(&case, BuildRevalidation::Summary(&clean)));
    }

    #[test]
    fn dump_report_refuses_non_reports_and_does_not_emit_json() {
        match dump_report(DumpReportInput::Wrong { type_name: "list" }) {
            Err(DumpReportError::Type(message)) => {
                assert_eq!(message, "Expected Report instance, got list");
            }
            other => panic!("expected TypeError, got {other:?}"),
        }
        match dump_report(DumpReportInput::Wrong {
            type_name: "NoneType",
        }) {
            Err(DumpReportError::Type(message)) => {
                assert_eq!(message, "Expected Report instance, got NoneType");
            }
            other => panic!("expected TypeError, got {other:?}"),
        }
        let coverage = must_coverage(
            &InputValue::tuple(Vec::new()),
            &empty_skips(),
            &canonical_adapter(),
            &neutral_profile(),
        );
        let counts = counts_for(&[]);
        let report = must_report(
            &text("s"),
            &[],
            &counts,
            &text("A1"),
            &text("lim"),
            &coverage,
        );
        match dump_report(DumpReportInput::Report(&report)) {
            Ok(json) => panic!("dump_report emitted JSON: {json}"),
            Err(error) => {
                assert_eq!(error.to_string(), CANONICAL_SEAM);
                match std::error::Error::source(&error) {
                    Some(source) => assert_eq!(source.to_string(), CANONICAL_SEAM),
                    None => panic!("dump_report must expose the codec error"),
                }
            }
        }
    }
}

#[cfg(test)]
mod parse_report_port {
    use std::error::Error;

    use super::{
        dump_manifest, parse_report, ActionSeq, Coverage, DumpManifestError, DumpManifestInput,
        Finding, InputKey, InputValue, JsonLoadsUnavailable, ParseReportError, RepairManifest,
        RepairManifestParts, Report, RevalidationInput, RevalidationSummary,
        FINDING_EVIDENCE_OBJECT, REPORT_SCHEMA_VERSION, REQUIRED_REPORT_FIELD_ORDER_DEVIATION,
    };
    use model::finding::SCHEMA_VERSION as FINDING_SCHEMA_VERSION;

    const REASONS: &str = "['adapter-not-applicable', 'cap-exceeded', 'deselected', 'empty-input', 'profile-gated', 'single-doc-fallback', 'version-gated']";
    const LEVELS: &str = "['A0', 'A1', 'A2', 'A3', 'A4']";
    const CANONICAL_SEAM: &str = "sesslint._canonical_codec.canonical_json_bytes is not available";

    fn text(value: &str) -> InputValue {
        InputValue::str_value(value)
    }

    fn entry(name: &str, value: InputValue) -> (InputKey, InputValue) {
        (InputKey::str_key(name), value)
    }

    fn dict(entries: Vec<(InputKey, InputValue)>) -> InputValue {
        InputValue::dict(entries)
    }

    fn finding_dict(code: &str) -> InputValue {
        dict(vec![
            entry("schema_version", text(FINDING_SCHEMA_VERSION)),
            entry("code", text(code)),
            entry("severity", text("error")),
            entry("repairability", text("manual")),
            entry("message", text("synthetic marker")),
            entry(
                "source",
                dict(vec![
                    entry("path", text("probe.jsonl")),
                    entry("line", InputValue::int(1)),
                ]),
            ),
            entry("fingerprint", text("0123456789abcdef")),
        ])
    }

    fn severities(fatal: i64, error: i64, warning: i64, info: i64) -> InputValue {
        dict(vec![
            entry("fatal", InputValue::int(fatal)),
            entry("error", InputValue::int(error)),
            entry("warning", InputValue::int(warning)),
            entry("info", InputValue::int(info)),
        ])
    }

    fn counts(by_severity: InputValue, by_code: InputValue, total: InputValue) -> InputValue {
        dict(vec![
            entry("by_severity", by_severity),
            entry("by_code", by_code),
            entry("total", total),
        ])
    }

    fn binding(pairs: Vec<(&str, InputValue)>) -> InputValue {
        dict(
            pairs
                .into_iter()
                .map(|(name, value)| entry(name, value))
                .collect(),
        )
    }

    fn id_version(id: &str, version: &str) -> InputValue {
        binding(vec![("id", text(id)), ("version", text(version))])
    }

    fn coverage(
        performed: InputValue,
        skipped: InputValue,
        adapter: InputValue,
        profile: InputValue,
    ) -> InputValue {
        dict(vec![
            entry("performed", performed),
            entry("skipped", skipped),
            entry("adapter", adapter),
            entry("profile", profile),
        ])
    }

    fn bare_coverage() -> InputValue {
        coverage(
            InputValue::list(Vec::new()),
            InputValue::list(Vec::new()),
            id_version("canonical", "1.0.0"),
            id_version("neutral", "1.0.0"),
        )
    }

    fn report_with(
        findings: InputValue,
        counts_value: InputValue,
        coverage_value: InputValue,
    ) -> InputValue {
        dict(vec![
            entry("schema_version", text(REPORT_SCHEMA_VERSION)),
            entry("session_id", text("sess")),
            entry("source_fingerprint", text("fp")),
            entry("tool_version", text("0.1.0")),
            entry("findings", findings),
            entry("counts", counts_value),
            entry("assurance", text("A1")),
            entry("limitation", text("lim")),
            entry("coverage", coverage_value),
            entry("repro", InputValue::int(1)),
        ])
    }

    fn zero_report() -> InputValue {
        report_with(
            InputValue::list(Vec::new()),
            counts(severities(0, 0, 0, 0), dict(Vec::new()), InputValue::int(0)),
            bare_coverage(),
        )
    }

    fn replace(report: &InputValue, name: &str, value: InputValue) -> InputValue {
        let InputValue::Dict(entries) = report else {
            panic!("report mapping");
        };
        let mut entries = entries.clone();
        let mut found = false;
        for (key, slot) in &mut entries {
            if matches!(key, InputKey::Str(text) if text == name) {
                *slot = value.clone();
                found = true;
            }
        }
        if !found {
            entries.push(entry(name, value));
        }
        dict(entries)
    }

    fn remove(report: &InputValue, name: &str) -> InputValue {
        let InputValue::Dict(entries) = report else {
            panic!("report mapping");
        };
        dict(
            entries
                .iter()
                .filter(|(key, _)| !matches!(key, InputKey::Str(text) if text == name))
                .cloned()
                .collect(),
        )
    }

    fn parse_ok(value: &InputValue) -> Report {
        match parse_report(value) {
            Ok(report) => report,
            Err(error) => panic!("parse_report rejected a valid report: {error}"),
        }
    }

    fn parse_err(value: &InputValue) -> ParseReportError {
        match parse_report(value) {
            Err(error) => error,
            Ok(_) => panic!("parse_report accepted an invalid report"),
        }
    }

    fn message(value: &InputValue) -> String {
        parse_err(value).to_string()
    }

    fn binding_pairs(items: &[(InputKey, InputValue)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(key, value)| {
                let InputKey::Str(name) = key else {
                    panic!("binding key {key:?}");
                };
                let InputValue::Str(text) = value else {
                    panic!("binding value {value:?}");
                };
                (name.clone(), text.clone())
            })
            .collect()
    }

    #[test]
    fn string_input_stops_at_json_loads() {
        for sample in ["{}", "[]", "not valid json {", ""] {
            let error = parse_err(&text(sample));
            assert_eq!(error.to_string(), "json.loads is not available");
            assert_eq!(error.to_string(), JsonLoadsUnavailable::MESSAGE);
            match &error {
                ParseReportError::Json(inner) => {
                    assert_eq!(inner.to_string(), JsonLoadsUnavailable::MESSAGE);
                }
                other => panic!("expected json.loads, got {other:?}"),
            }
            let source = Error::source(&error).map(ToString::to_string);
            assert_eq!(source.as_deref(), Some(JsonLoadsUnavailable::MESSAGE));
        }
    }

    #[test]
    fn non_mapping_uses_the_pin_type_message() {
        assert_eq!(
            message(&InputValue::int(123)),
            "Report must be a Mapping or JSON string, got int"
        );
        assert_eq!(
            message(&InputValue::list(Vec::new())),
            "Report must be a Mapping or JSON string, got list"
        );
        assert_eq!(
            message(&InputValue::None),
            "Report must be a Mapping or JSON string, got NoneType"
        );
        assert!(!message(&InputValue::list(Vec::new())).contains("Report root must be a mapping"));
        assert!(!message(&text("{")).contains("Malformed JSON"));
    }

    #[test]
    fn top_level_checks_run_before_later_fields() {
        assert!(REQUIRED_REPORT_FIELD_ORDER_DEVIATION.contains("frozenset"));
        let base = zero_report();
        let rogue = replace(
            &remove(
                &replace(&base, "schema_version", text("sesslint.report/v99")),
                "session_id",
            ),
            "rogue",
            text("x"),
        );
        match parse_err(&rogue) {
            ParseReportError::UnknownField(error) => {
                assert_eq!(error.reason_code(), "SL302");
                assert_eq!(error.field_name(), Some("rogue"));
                assert_eq!(
                    error.to_string(),
                    "Unknown top-level field in report: 'rogue' (code: UNKNOWN_FIELD / SL302)"
                );
            }
            other => panic!("unknown field must win, got {other}"),
        }
        let missing_session = remove(
            &replace(&base, "schema_version", text("sesslint.report/v99")),
            "session_id",
        );
        assert_eq!(
            message(&missing_session),
            "Missing required field in report: 'session_id'"
        );
        assert!(!message(&missing_session).contains("SL302"));
        let missing_both = remove(&remove(&base, "schema_version"), "coverage");
        assert_eq!(
            message(&missing_both),
            "Missing required field in report: 'schema_version'"
        );
        match parse_err(&replace(
            &base,
            "schema_version",
            text("sesslint.report/v99"),
        )) {
            ParseReportError::Version(error) => {
                assert_eq!(error.reason_code(), "SL301");
                assert_eq!(error.version(), Some("sesslint.report/v99"));
                assert_eq!(
                    error.to_string(),
                    "Unsupported report schema version: 'sesslint.report/v99' (code: VERSION / SL301)"
                );
            }
            other => panic!("version error, got {other}"),
        }
        match parse_err(&replace(&base, "schema_version", InputValue::int(4))) {
            ParseReportError::Version(error) => {
                assert_eq!(error.version(), Some("4"));
                assert_eq!(
                    error.to_string(),
                    "Unsupported report schema version: 4 (code: VERSION / SL301)"
                );
            }
            other => panic!("non-string version, got {other}"),
        }
        let bad_session = replace(
            &replace(&base, "session_id", InputValue::int(12345)),
            "findings",
            text("no"),
        );
        assert_eq!(
            message(&bad_session),
            "Report.session_id must be a non-empty string, got 12345"
        );
        assert_eq!(
            message(&replace(
                &base,
                "source_fingerprint",
                InputValue::list(vec![text("invalid"), text("type")])
            )),
            "Report.source_fingerprint must be a non-empty string, got ['invalid', 'type']"
        );
        assert_eq!(
            message(&replace(
                &base,
                "tool_version",
                InputValue::other("float", "1.0")
            )),
            "Report.tool_version must be a non-empty string, got 1.0"
        );
        assert_eq!(
            message(&replace(
                &replace(&base, "findings", text("no")),
                "counts",
                text("no")
            )),
            "findings must be a list or tuple, got str"
        );
    }

    #[test]
    fn findings_use_parse_finding_dict_before_counts() {
        let base = zero_report();
        assert_eq!(
            message(&replace(
                &base,
                "findings",
                InputValue::list(vec![InputValue::int(1)])
            )),
            "Finding object must be a mapping, got int"
        );
        let mut coded = finding_dict("SL001");
        coded = replace(&coded, "code", InputValue::other("float", "1.5"));
        assert_eq!(
            message(&replace(&base, "findings", InputValue::list(vec![coded]))),
            "Invalid finding code in dictionary: 1.5"
        );
        let mut schema_bad = finding_dict("SL001");
        schema_bad = replace(&schema_bad, "schema_version", text("nope"));
        schema_bad = replace(&schema_bad, "code", InputValue::other("float", "1.5"));
        assert_eq!(
            message(&replace(
                &base,
                "findings",
                InputValue::list(vec![schema_bad])
            )),
            format!(
                "Unsupported finding schema_version 'nope', expected '{FINDING_SCHEMA_VERSION}'"
            )
        );
        let mut evidence = finding_dict("SL001");
        evidence = replace(
            &evidence,
            "evidence",
            dict(vec![entry("note", InputValue::other("object", "<object>"))]),
        );
        assert_eq!(
            message(&replace(
                &base,
                "findings",
                InputValue::list(vec![evidence])
            )),
            FINDING_EVIDENCE_OBJECT
        );
    }

    #[test]
    fn counts_checks_run_before_assurance_and_the_report_constructor() {
        let base = zero_report();
        let extra = dict(vec![
            entry("by_severity", severities(0, 0, 0, 0)),
            entry("by_code", dict(Vec::new())),
            entry("rogue_counts_field", InputValue::int(99)),
        ]);
        assert_eq!(
            message(&replace(
                &replace(&base, "counts", extra),
                "assurance",
                text("INVALID")
            )),
            "Unknown field in counts: 'rogue_counts_field' (code: UNKNOWN_FIELD / SL302)"
        );
        let critical = dict(vec![
            entry("critical", InputValue::int(5)),
            entry("error", InputValue::int(0)),
            entry("warning", InputValue::int(0)),
            entry("info", InputValue::int(0)),
        ]);
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(critical, dict(Vec::new()), InputValue::int(0))
            )),
            "Unknown severity in counts.by_severity: 'critical' (code: UNKNOWN_FIELD / SL302)"
        );
        let missing_fatal = dict(vec![
            entry("error", InputValue::int(-1)),
            entry("warning", InputValue::int(0)),
            entry("info", InputValue::int(0)),
        ]);
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(missing_fatal, dict(Vec::new()), InputValue::int(0))
            )),
            "Missing required severity in counts.by_severity: 'fatal'"
        );
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(
                    text("not-a-mapping"),
                    text("not-a-mapping"),
                    InputValue::int(0)
                )
            )),
            "counts.by_severity must be a mapping, got str"
        );
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(
                    severities(0, 0, 0, 0),
                    text("not-a-mapping"),
                    InputValue::int(0)
                )
            )),
            "counts.by_code must be a mapping, got str"
        );
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(
                    severities(0, 0, 0, 0),
                    dict(Vec::new()),
                    InputValue::bool_value(true)
                )
            )),
            "counts.total must be a non-negative integer, got True"
        );
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(
                    severities(0, 0, 0, 0),
                    dict(Vec::new()),
                    InputValue::int(-1)
                )
            )),
            "counts.total must be a non-negative integer, got -1"
        );
        assert_eq!(
            message(&replace(
                &replace(
                    &base,
                    "counts",
                    counts(
                        severities(-1, 0, 0, 0),
                        dict(Vec::new()),
                        InputValue::int(0)
                    )
                ),
                "assurance",
                text("INVALID")
            )),
            "Counts.by_severity['fatal'] must be non-negative int, got -1"
        );
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(
                    severities(0, 0, 0, 0),
                    dict(vec![(InputKey::int(1), InputValue::int(0))]),
                    InputValue::int(0)
                )
            )),
            "Counts.by_code key must be str, got 1"
        );
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(severities(0, 0, 0, 0), dict(Vec::new()), InputValue::int(2))
            )),
            "Counts.total (2) does not match findings count (0)"
        );
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(severities(1, 0, 0, 0), dict(Vec::new()), InputValue::int(0))
            )),
            "Counts.by_severity ({'fatal': 1, 'error': 0, 'warning': 0, 'info': 0}) does not match findings severity distribution ({'fatal': 0, 'error': 0, 'warning': 0, 'info': 0})"
        );
        assert_eq!(
            message(&replace(
                &base,
                "counts",
                counts(
                    severities(0, 0, 0, 0),
                    dict(vec![entry("SL001", InputValue::int(1))]),
                    InputValue::int(0)
                )
            )),
            "Counts.by_code ({'SL001': 1}) does not match findings code distribution ({})"
        );
    }

    #[test]
    fn assurance_and_limitation_use_parse_report_text() {
        let base = zero_report();
        assert_eq!(
            message(&replace(
                &replace(&base, "assurance", text("INVALID")),
                "limitation",
                text("")
            )),
            format!("Invalid assurance level 'INVALID'. Must be one of {LEVELS}")
        );
        assert_eq!(
            message(&replace(&base, "limitation", text(""))),
            "Report limitation must be a non-empty string, got ''"
        );
        assert_eq!(
            message(&replace(&base, "limitation", InputValue::int(123))),
            "Report limitation must be a non-empty string, got 123"
        );
        assert!(!message(&replace(&base, "limitation", text(""))).contains("assurance level"));
    }

    #[test]
    fn coverage_checks_run_before_the_coverage_constructor() {
        let base = zero_report();
        let unknown = dict(vec![
            entry("extra", InputValue::int(1)),
            entry("skipped", InputValue::int(1)),
            entry("adapter", InputValue::int(1)),
            entry("profile", InputValue::int(1)),
        ]);
        assert_eq!(
            message(&replace(&base, "coverage", unknown)),
            "Unknown field in coverage: 'extra' (code: UNKNOWN_FIELD / SL302)"
        );
        let missing_performed = dict(vec![
            entry("skipped", InputValue::int(1)),
            entry("adapter", id_version("canonical", "1")),
            entry("profile", id_version("neutral", "1")),
        ]);
        assert_eq!(
            message(&replace(&base, "coverage", missing_performed)),
            "Missing required field in coverage: 'performed'"
        );
        assert_eq!(
            message(&replace(
                &base,
                "coverage",
                coverage(
                    InputValue::set(Vec::new()),
                    InputValue::list(Vec::new()),
                    id_version("canonical", "1"),
                    id_version("neutral", "1")
                )
            )),
            "coverage.performed must be a list or tuple, got set"
        );
        assert_eq!(
            message(&replace(
                &base,
                "coverage",
                coverage(
                    InputValue::list(vec![InputValue::int(1)]),
                    InputValue::list(Vec::new()),
                    id_version("canonical", "1"),
                    id_version("neutral", "1")
                )
            )),
            "coverage.performed[0] must be a non-empty string, got 1"
        );
        assert_eq!(
            message(&replace(
                &base,
                "coverage",
                coverage(
                    InputValue::list(Vec::new()),
                    InputValue::int(1),
                    InputValue::int(1),
                    InputValue::int(1)
                )
            )),
            "coverage.skipped must be a list or tuple, got int"
        );
        let unknown_skip = dict(vec![
            entry("extra", InputValue::int(1)),
            entry("reason", text("profile-gated")),
        ]);
        assert_eq!(
            message(&replace(
                &base,
                "coverage",
                coverage(
                    InputValue::list(Vec::new()),
                    InputValue::list(vec![unknown_skip]),
                    id_version("canonical", "1"),
                    id_version("neutral", "1")
                )
            )),
            "Unknown field in coverage.skipped[0]: 'extra' (code: UNKNOWN_FIELD / SL302)"
        );
        assert_eq!(
            message(&skip_report(
                &base,
                dict(vec![entry("reason", text("profile-gated"))])
            )),
            "coverage.skipped[0] missing required field 'check'"
        );
        assert_eq!(
            message(&skip_report(
                &base,
                dict(vec![entry("check", text("SL201"))])
            )),
            "coverage.skipped[0] missing required field 'reason'"
        );
        assert_eq!(
            message(&skip_report(
                &base,
                dict(vec![
                    entry("check", text("  ")),
                    entry("reason", text("profile-gated")),
                ])
            )),
            "coverage.skipped[0].check must be a non-empty string, got '  '"
        );
        let reason = message(&skip_report(
            &base,
            dict(vec![
                entry("check", text("has\nnewline")),
                entry("reason", text("nope")),
                entry("detail", InputValue::int(1)),
            ]),
        ));
        assert_eq!(
            reason,
            format!("Invalid coverage skip reason 'nope' in skipped[0]. Must be one of {REASONS}")
        );
        assert_eq!(
            message(&skip_report(
                &base,
                dict(vec![
                    entry("check", text("has\nnewline")),
                    entry("reason", text("profile-gated")),
                    entry("detail", InputValue::int(1)),
                ])
            )),
            "coverage.skipped[0].detail must be a string, got int"
        );
        let leak = message(&skip_report(
            &base,
            dict(vec![
                entry("check", text("has\nnewline")),
                entry("reason", text("profile-gated")),
            ]),
        ));
        assert!(
            leak.contains("Intrinsic content leak in CoverageSkip.check"),
            "{leak}"
        );
        assert!(
            leak.contains("Forbidden control or newline characters"),
            "{leak}"
        );
        assert_eq!(
            message(&replace(
                &base,
                "coverage",
                coverage(
                    InputValue::list(Vec::new()),
                    InputValue::list(Vec::new()),
                    dict(vec![entry("extra", InputValue::int(1))]),
                    InputValue::int(1)
                )
            )),
            "Unknown field in coverage.adapter: 'extra' (code: UNKNOWN_FIELD / SL302)"
        );
        assert_eq!(
            message(&replace(
                &base,
                "coverage",
                coverage(
                    InputValue::list(Vec::new()),
                    InputValue::list(Vec::new()),
                    binding(vec![
                        ("id", text("  ")),
                        ("name", text("Nom")),
                        ("version", text("")),
                    ]),
                    id_version("neutral", "1")
                )
            )),
            "coverage.adapter must contain non-empty 'id'"
        );
        assert_eq!(
            message(&replace(
                &base,
                "coverage",
                coverage(
                    InputValue::list(Vec::new()),
                    InputValue::list(Vec::new()),
                    binding(vec![("id", text("canonical")), ("version", text("  "))]),
                    InputValue::int(1)
                )
            )),
            "coverage.adapter must contain non-empty 'version'"
        );
        assert_eq!(
            message(&replace(
                &base,
                "coverage",
                coverage(
                    InputValue::list(Vec::new()),
                    InputValue::list(Vec::new()),
                    InputValue::int(1),
                    InputValue::int(1)
                )
            )),
            "coverage.adapter must be a mapping, got int"
        );
        assert_eq!(
            message(&replace(
                &base,
                "coverage",
                coverage(
                    InputValue::list(Vec::new()),
                    InputValue::list(Vec::new()),
                    id_version("canonical", "1"),
                    dict(Vec::new())
                )
            )),
            "coverage.profile must contain non-empty 'id'"
        );
    }

    fn skip_report(base: &InputValue, skip: InputValue) -> InputValue {
        replace(
            base,
            "coverage",
            coverage(
                InputValue::list(Vec::new()),
                InputValue::list(vec![skip]),
                id_version("canonical", "1"),
                id_version("neutral", "1"),
            ),
        )
    }

    #[test]
    fn valid_mapping_uses_the_report_and_finding_constructors() {
        let spaced = replace(
            &replace(
                &replace(&zero_report(), "session_id", text("  sess  ")),
                "source_fingerprint",
                text(" fp "),
            ),
            "tool_version",
            text(" 0.1.0 "),
        );
        let spaced = replace(&spaced, "limitation", text("  lim  "));
        let report = parse_ok(&spaced);
        assert_eq!(report.schema_version(), REPORT_SCHEMA_VERSION);
        assert_eq!(report.session_id(), "sess");
        assert_eq!(report.source_fingerprint(), "fp");
        assert_eq!(report.tool_version(), "0.1.0");
        assert_eq!(report.assurance(), "A1");
        assert_eq!(report.limitation(), "lim");
        assert!(report.findings().is_empty());
        assert_eq!(report.counts().total(), 0);

        let findings = InputValue::tuple(vec![finding_dict("SL101"), finding_dict("SL001")]);
        let counts_value = counts(
            severities(0, 2, 0, 0),
            dict(vec![
                entry("SL101", InputValue::int(1)),
                entry("SL001", InputValue::int(1)),
            ]),
            InputValue::int(2),
        );
        let performed = InputValue::list(vec![text("b"), text(" a ")]);
        let skips = InputValue::list(vec![
            dict(vec![
                entry("check", text(" b ")),
                entry("reason", text("profile-gated")),
                entry("detail", text(" d ")),
            ]),
            dict(vec![
                entry("check", text(" SL201 ")),
                entry("reason", text("profile-gated")),
            ]),
        ]);
        let adapter = binding(vec![("name", text(" Widget ")), ("version", text(" 1 "))]);
        let profile = binding(vec![
            ("id", text("neutral")),
            ("name", InputValue::int(3)),
            ("version", text("1.0.0")),
        ]);
        let report = parse_ok(&report_with(
            findings,
            counts_value,
            coverage(performed, skips, adapter, profile),
        ));
        let codes: Vec<&str> = report.findings().iter().map(Finding::code).collect();
        assert_eq!(codes, ["SL001", "SL101"]);
        assert_eq!(
            report.coverage().performed(),
            &["a".to_owned(), "b".to_owned()]
        );
        assert_eq!(report.coverage().skipped().len(), 2);
        assert_eq!(report.coverage().skipped()[0].check(), "SL201");
        assert_eq!(report.coverage().skipped()[0].detail(), "");
        assert_eq!(report.coverage().skipped()[1].check(), "b");
        assert_eq!(report.coverage().skipped()[1].detail(), "d");
        assert_eq!(
            binding_pairs(report.coverage().adapter_items()),
            vec![
                ("id".to_owned(), "Widget".to_owned()),
                ("version".to_owned(), "1".to_owned()),
                ("name".to_owned(), "Widget".to_owned()),
            ]
        );
        assert_eq!(
            binding_pairs(report.coverage().profile_items()),
            vec![
                ("id".to_owned(), "neutral".to_owned()),
                ("version".to_owned(), "1.0.0".to_owned()),
            ]
        );

        let copied = parse_ok(&replace(
            &zero_report(),
            "coverage",
            coverage(
                InputValue::list(Vec::new()),
                InputValue::list(Vec::new()),
                binding(vec![
                    ("id", text("")),
                    ("name", text("Nom")),
                    ("version", text("1")),
                ]),
                id_version("neutral", "1"),
            ),
        ));
        assert_eq!(
            binding_pairs(copied.coverage().adapter_items()),
            vec![
                ("id".to_owned(), "Nom".to_owned()),
                ("version".to_owned(), "1".to_owned()),
                ("name".to_owned(), "Nom".to_owned()),
            ]
        );
        let _kept: &Coverage = copied.coverage();
    }

    #[test]
    fn dump_manifest_refuses_substitutes_and_non_manifests() {
        match dump_manifest(DumpManifestInput::Wrong { type_name: "dict" }) {
            Err(DumpManifestError::Type(text)) => {
                assert_eq!(text, "Expected RepairManifest instance, got dict");
            }
            other => panic!("expected TypeError, got {other:?}"),
        }
        match dump_manifest(DumpManifestInput::Wrong {
            type_name: "NoneType",
        }) {
            Err(DumpManifestError::Type(text)) => {
                assert_eq!(text, "Expected RepairManifest instance, got NoneType");
            }
            other => panic!("expected TypeError, got {other:?}"),
        }
        let manifest = sample_manifest(&dict(Vec::new()));
        match dump_manifest(DumpManifestInput::Manifest(&manifest)) {
            Ok(json) => panic!("dump_manifest emitted JSON: {json}"),
            Err(error) => {
                assert_eq!(error.to_string(), CANONICAL_SEAM);
                match Error::source(&error) {
                    Some(source) => assert_eq!(source.to_string(), CANONICAL_SEAM),
                    None => panic!("dump_manifest must expose the codec error"),
                }
            }
        }
        let mixed = sample_manifest(&dict(vec![
            (InputKey::str_key("a"), text("1")),
            (InputKey::int(1), InputValue::int(2)),
        ]));
        match dump_manifest(DumpManifestInput::Manifest(&mixed)) {
            Err(DumpManifestError::Type(text)) => {
                assert_eq!(
                    text,
                    "'<' not supported between instances of 'int' and 'str'"
                );
                assert_ne!(text, CANONICAL_SEAM);
            }
            other => panic!("to_dict TypeError must win, got {other:?}"),
        }
    }

    fn sample_manifest(recipe: &InputValue) -> RepairManifest {
        let schema = text(model::version::MANIFEST_SCHEMA_VERSION);
        let input_fingerprint = text("in");
        let output_fingerprint = text("out");
        let policy = text("conservative");
        let actions = ActionSeq::Tuple(Vec::new());
        let declared_loss = InputValue::tuple(Vec::new());
        let none = InputValue::None;
        let empty = dict(Vec::new());
        let idempotency_key = text(&"0".repeat(64));
        let ceiling = text("A1");
        let assurance = text("A1");
        let zero = InputValue::int(0);
        let profile = text("neutral");
        let profile_version = text("1.0.0");
        let summary = match RevalidationSummary::try_new(
            &assurance,
            &zero,
            &zero,
            &profile,
            &profile_version,
            &none,
        ) {
            Ok(summary) => summary,
            Err(error) => panic!("synthetic revalidation rejected: {error}"),
        };
        let revalidation = RevalidationInput::Summary(summary);
        match RepairManifest::try_new(RepairManifestParts {
            schema_version: &schema,
            input_fingerprint: &input_fingerprint,
            output_fingerprint: &output_fingerprint,
            policy: &policy,
            actions: &actions,
            declared_loss: &declared_loss,
            revalidate_report: &none,
            idempotency_key: &idempotency_key,
            revalidation: &revalidation,
            assurance_ceiling: &ceiling,
            plan_fingerprint: &none,
            assurance: &none,
            recipe_versions: recipe,
            profile_version: &none,
            adapter_id: &none,
            adapter_version: &none,
            byte_counts: &empty,
            record_counts: &empty,
        }) {
            Ok(manifest) => manifest,
            Err(error) => panic!("synthetic manifest rejected: {error}"),
        }
    }

    #[test]
    fn non_string_top_level_key_is_unknown() {
        let mut entries = match zero_report() {
            InputValue::Dict(entries) => entries,
            other => panic!("dict, got {other:?}"),
        };
        entries.insert(0, (InputKey::int(1), text("x")));
        match parse_err(&dict(entries)) {
            ParseReportError::UnknownField(error) => {
                assert_eq!(error.field_name(), Some("1"));
                assert_eq!(
                    error.to_string(),
                    "Unknown top-level field in report: '1' (code: UNKNOWN_FIELD / SL302)"
                );
            }
            other => panic!("non-string key, got {other}"),
        }
    }
}

#[cfg(test)]
mod parse_manifest_port {
    use std::error::Error;

    use super::{
        parse_manifest, InputKey, InputValue, JsonLoadsUnavailable, ParseManifestError,
        MANIFEST_FIELD_ORDER_DEVIATION,
    };
    use model::errors::{AssuranceError, SchemaError};
    use model::finding::enforce_content_free_text;
    use model::version::MANIFEST_SCHEMA_VERSION;

    const LEVELS: &str = "['A0', 'A1', 'A2', 'A3', 'A4']";
    const UNKNOWN_SUFFIX: &str = " (code: UNKNOWN_FIELD / SL302)";
    const VERSION_SUFFIX: &str = " (code: VERSION / SL301)";

    fn text(value: &str) -> InputValue {
        InputValue::str_value(value)
    }

    fn entry(name: &str, value: InputValue) -> (InputKey, InputValue) {
        (InputKey::str_key(name), value)
    }

    fn dict(entries: Vec<(InputKey, InputValue)>) -> InputValue {
        InputValue::dict(entries)
    }

    fn idem() -> String {
        "ab".repeat(32)
    }

    fn revalidation() -> InputValue {
        dict(vec![
            entry("assurance", text("A1")),
            entry("error_count", InputValue::int(0)),
            entry("warning_count", InputValue::int(1)),
            entry("profile_id", text("neutral")),
            entry("profile_version", text("1")),
        ])
    }

    fn action(kind: &str, record_id: Option<&str>, detail: Option<&str>) -> InputValue {
        let mut entries = vec![entry("kind", text(kind))];
        if let Some(record_id) = record_id {
            entries.push(entry("record_id", text(record_id)));
        }
        if let Some(detail) = detail {
            entries.push(entry("detail", text(detail)));
        }
        dict(entries)
    }

    fn manifest() -> InputValue {
        dict(vec![
            entry("schema_version", text(MANIFEST_SCHEMA_VERSION)),
            entry("input_fingerprint", text("in")),
            entry("output_fingerprint", text("out")),
            entry("policy", text("conservative")),
            entry("actions", InputValue::list(Vec::new())),
            entry("declared_loss", InputValue::list(Vec::new())),
            entry("revalidate_report", InputValue::None),
            entry("idempotency_key", text(&idem())),
            entry("revalidation", revalidation()),
            entry("assurance_ceiling", text("A2")),
        ])
    }

    fn replace(value: &InputValue, name: &str, next: InputValue) -> InputValue {
        let InputValue::Dict(entries) = value else {
            panic!("manifest mapping");
        };
        let mut entries = entries.clone();
        let mut found = false;
        for (key, slot) in &mut entries {
            if matches!(key, InputKey::Str(text) if text == name) {
                *slot = next.clone();
                found = true;
            }
        }
        if !found {
            entries.push(entry(name, next));
        }
        dict(entries)
    }

    fn remove(value: &InputValue, name: &str) -> InputValue {
        let InputValue::Dict(entries) = value else {
            panic!("manifest mapping");
        };
        dict(
            entries
                .iter()
                .filter(|(key, _)| !matches!(key, InputKey::Str(text) if text == name))
                .cloned()
                .collect(),
        )
    }

    fn parse_ok(value: &InputValue) -> super::RepairManifest {
        match parse_manifest(value) {
            Ok(manifest) => manifest,
            Err(error) => panic!("parse_manifest rejected a valid manifest: {error}"),
        }
    }

    fn parse_err(value: &InputValue) -> ParseManifestError {
        match parse_manifest(value) {
            Err(error) => error,
            Ok(_) => panic!("parse_manifest accepted an invalid manifest"),
        }
    }

    fn message(value: &InputValue) -> String {
        parse_err(value).to_string()
    }

    fn replace_revalidation(name: &str, next: InputValue) -> InputValue {
        let InputValue::Dict(entries) = revalidation() else {
            panic!("revalidation mapping");
        };
        let mut entries = entries.clone();
        let mut found = false;
        for (key, slot) in &mut entries {
            if matches!(key, InputKey::Str(text) if text == name) {
                *slot = next.clone();
                found = true;
            }
        }
        if !found {
            entries.push(entry(name, next));
        }
        replace(&manifest(), "revalidation", dict(entries))
    }

    #[test]
    fn string_input_stops_at_json_loads() {
        let looks_like = format!("{{\"schema_version\":\"{MANIFEST_SCHEMA_VERSION}\"}}");
        for sample in ["{}", "[]", "not valid json {", "", looks_like.as_str()] {
            let error = parse_err(&text(sample));
            assert_eq!(error.to_string(), "json.loads is not available");
            assert_eq!(error.to_string(), JsonLoadsUnavailable::MESSAGE);
            assert!(!error.to_string().contains("Malformed JSON"));
            match &error {
                ParseManifestError::Json(inner) => {
                    assert_eq!(inner.to_string(), JsonLoadsUnavailable::MESSAGE);
                }
                other => panic!("expected json.loads, got {other:?}"),
            }
            let source = Error::source(&error).map(ToString::to_string);
            assert_eq!(source.as_deref(), Some(JsonLoadsUnavailable::MESSAGE));
        }
    }

    #[test]
    fn non_mapping_uses_the_pin_type_message() {
        let cases = [
            (InputValue::int(123), "int"),
            (InputValue::list(Vec::new()), "list"),
            (InputValue::tuple(Vec::new()), "tuple"),
            (InputValue::set(Vec::new()), "set"),
            (InputValue::FrozenSet(Vec::new()), "frozenset"),
            (InputValue::None, "NoneType"),
            (InputValue::bool_value(true), "bool"),
            (InputValue::other("float", "1.5"), "float"),
        ];
        for (value, type_name) in cases {
            let error = parse_err(&value);
            assert_eq!(
                error.to_string(),
                format!("Manifest must be a Mapping or JSON string, got {type_name}")
            );
            match error {
                ParseManifestError::Schema(inner) => {
                    assert_eq!(inner.code(), SchemaError::DEFAULT_CODE);
                }
                other => panic!("expected SchemaError, got {other:?}"),
            }
            assert!(!message(&value).contains("Manifest root must be a mapping"));
            assert!(!message(&value).contains("Malformed JSON"));
        }
    }

    #[test]
    fn synthetic_success_wins_before_unknown_keys() {
        let base = manifest();
        let mut success_later = match remove(&base, "schema_version") {
            InputValue::Dict(entries) => entries,
            other => panic!("dict, got {other:?}"),
        };
        success_later.insert(0, entry("rogue", text("x")));
        success_later.push(entry("success", InputValue::None));
        assert_eq!(
            message(&dict(success_later)),
            "Manifest must not contain synthetic 'success' field (never-synthetic-success invariant)"
        );
        let mut passed_after_healthy = match base.clone() {
            InputValue::Dict(entries) => entries,
            other => panic!("dict, got {other:?}"),
        };
        passed_after_healthy.insert(0, entry("healthy", text("1")));
        passed_after_healthy.push(entry("passed", text("1")));
        assert_eq!(
            message(&dict(passed_after_healthy)),
            "Manifest must not contain synthetic 'passed' field (never-synthetic-success invariant)"
        );
        assert_eq!(
            message(&replace(&base, "ok", text("1"))),
            "Manifest must not contain synthetic 'ok' field (never-synthetic-success invariant)"
        );
        assert_eq!(
            message(&replace(&base, "healthy", text("1"))),
            "Manifest must not contain synthetic 'healthy' field (never-synthetic-success invariant)"
        );
        match parse_err(&replace(&base, "healthy", text("1"))) {
            ParseManifestError::Schema(error) => {
                assert_eq!(error.code(), SchemaError::DEFAULT_CODE);
                assert!(!error.to_string().contains("SL302"));
            }
            other => panic!("synthetic field is SchemaError, got {other:?}"),
        }

        let mut unknown = match base.clone() {
            InputValue::Dict(entries) => entries,
            other => panic!("dict, got {other:?}"),
        };
        unknown.insert(0, (InputKey::int(1), text("x")));
        unknown.push(entry("rogue", text("y")));
        match parse_err(&dict(unknown)) {
            ParseManifestError::UnknownField(error) => {
                assert_eq!(error.reason_code(), "SL302");
                assert_eq!(error.field_name(), Some("1"));
                assert_eq!(
                    error.to_string(),
                    format!("Unknown top-level field in manifest: '1'{UNKNOWN_SUFFIX}")
                );
            }
            other => panic!("first unknown key, got {other:?}"),
        }
        let mut named = match &base {
            InputValue::Dict(entries) => entries.clone(),
            other => panic!("dict, got {other:?}"),
        };
        named.insert(0, entry("rogue", text("x")));
        named.push(entry("aaa", text("y")));
        match parse_err(&dict(named)) {
            ParseManifestError::UnknownField(error) => {
                assert_eq!(error.field_name(), Some("rogue"));
                assert_eq!(
                    error.to_string(),
                    format!("Unknown top-level field in manifest: 'rogue'{UNKNOWN_SUFFIX}")
                );
            }
            other => panic!("insertion order, got {other:?}"),
        }
        let mut false_key = match base {
            InputValue::Dict(entries) => entries,
            other => panic!("dict, got {other:?}"),
        };
        false_key.insert(0, (InputKey::bool_value(false), text("x")));
        match parse_err(&dict(false_key)) {
            ParseManifestError::UnknownField(error) => {
                assert_eq!(error.field_name(), Some("False"));
                assert_eq!(
                    error.to_string(),
                    format!("Unknown top-level field in manifest: 'False'{UNKNOWN_SUFFIX}")
                );
            }
            other => panic!("bool key, got {other:?}"),
        }
    }

    #[test]
    fn missing_fields_follow_the_source_literal_order() {
        assert!(MANIFEST_FIELD_ORDER_DEVIATION.contains("frozenset"));
        assert!(MANIFEST_FIELD_ORDER_DEVIATION.contains("literal order"));
        assert!(MANIFEST_FIELD_ORDER_DEVIATION.contains("not reproduced"));
        let base = manifest();
        let missing_schema = remove(&remove(&base, "schema_version"), "output_fingerprint");
        assert_eq!(
            message(&missing_schema),
            "Missing required field in manifest: 'schema_version'"
        );
        assert!(!message(&missing_schema).contains("SL302"));
        let missing_revalidation = remove(&remove(&base, "revalidation"), "assurance_ceiling");
        assert_eq!(
            message(&missing_revalidation),
            "Missing required field in manifest: 'revalidation'"
        );
        let missing_input = remove(&remove(&base, "input_fingerprint"), "assurance_ceiling");
        assert_eq!(
            message(&missing_input),
            "Missing required field in manifest: 'input_fingerprint'"
        );
        let unknown_and_missing = replace(
            &remove(&base, "policy"),
            "schema_version",
            text("sesslint.repair-manifest/v9"),
        );
        let unknown_and_missing = replace(&unknown_and_missing, "rogue", text("x"));
        match parse_err(&unknown_and_missing) {
            ParseManifestError::UnknownField(error) => {
                assert_eq!(error.field_name(), Some("rogue"));
            }
            other => panic!("unknown field must win over missing and version, got {other:?}"),
        }
    }

    #[test]
    fn version_error_uses_the_pin_repr() {
        let base = manifest();
        match parse_err(&replace(
            &base,
            "schema_version",
            text("sesslint.repair-manifest/v9"),
        )) {
            ParseManifestError::Version(error) => {
                assert_eq!(error.reason_code(), "SL301");
                assert_eq!(error.version(), Some("sesslint.repair-manifest/v9"));
                assert_eq!(
                    error.to_string(),
                    format!(
                        "Unsupported manifest schema version: 'sesslint.repair-manifest/v9'{VERSION_SUFFIX}"
                    )
                );
                assert!(!error.to_string().contains("RepairManifest.schema_version must be"));
            }
            other => panic!("string version, got {other:?}"),
        }
        match parse_err(&replace(&base, "schema_version", InputValue::int(4))) {
            ParseManifestError::Version(error) => {
                assert_eq!(error.version(), Some("4"));
                assert_eq!(
                    error.to_string(),
                    format!("Unsupported manifest schema version: 4{VERSION_SUFFIX}")
                );
            }
            other => panic!("int version, got {other:?}"),
        }
        match parse_err(&replace(&base, "schema_version", InputValue::bool_value(true))) {
            ParseManifestError::Version(error) => {
                assert_eq!(error.version(), Some("True"));
                assert_eq!(
                    error.to_string(),
                    format!("Unsupported manifest schema version: True{VERSION_SUFFIX}")
                );
            }
            other => panic!("bool version, got {other:?}"),
        }
        let bad_fingerprint = replace(
            &replace(&base, "schema_version", text("sesslint.repair-manifest/v9")),
            "input_fingerprint",
            InputValue::int(1),
        );
        assert!(message(&bad_fingerprint).starts_with("Unsupported manifest schema version:"));
    }

    #[test]
    fn fingerprints_policy_actions_and_loss_use_pin_messages() {
        let base = manifest();
        assert_eq!(
            message(&replace(&base, "input_fingerprint", text("  "))),
            "RepairManifest.input_fingerprint must be a non-empty string, got '  '"
        );
        assert_eq!(
            message(&replace(
                &replace(&base, "input_fingerprint", InputValue::int(1)),
                "output_fingerprint",
                text("  ")
            )),
            "RepairManifest.input_fingerprint must be a non-empty string, got 1"
        );
        assert_eq!(
            message(&replace(&base, "output_fingerprint", text(""))),
            "RepairManifest.output_fingerprint must be a non-empty string, got ''"
        );
        assert_eq!(
            message(&replace(&base, "policy", text(" conservative"))),
            "Invalid manifest policy: ' conservative'"
        );
        assert_eq!(
            message(&replace(&base, "policy", text("Salvage"))),
            "Invalid manifest policy: 'Salvage'"
        );
        assert!(!message(&replace(&base, "policy", text("nope"))).contains("must be one of"));
        let bad_actions = replace(
            &replace(&base, "actions", text("no")),
            "declared_loss",
            InputValue::int(1),
        );
        assert_eq!(message(&bad_actions), "actions must be a list or tuple, got str");
        assert_eq!(
            message(&replace(
                &base,
                "actions",
                InputValue::list(vec![InputValue::int(1)])
            )),
            "actions[0] must be a mapping, got int"
        );
        assert_eq!(
            message(&replace(
                &base,
                "actions",
                InputValue::list(vec![dict(vec![entry("rogue", text("x"))])])
            )),
            "actions[0] missing required field 'kind'"
        );
        match parse_err(&replace(
            &base,
            "actions",
            InputValue::list(vec![dict(vec![
                entry("kind", text("")),
                entry("rogue", InputValue::int(7)),
            ])]),
        )) {
            ParseManifestError::UnknownField(error) => {
                assert_eq!(error.field_name(), Some("rogue"));
                assert_eq!(
                    error.to_string(),
                    format!("Unknown field in action[0]: 'rogue'{UNKNOWN_SUFFIX}")
                );
            }
            other => panic!("action unknown field, got {other:?}"),
        }
        assert_eq!(
            message(&replace(
                &base,
                "actions",
                InputValue::list(vec![
                    action("drop", None, None),
                    dict(vec![entry("kind", text("drop")), entry("rogue", text("x"))]),
                ])
            )),
            format!("Unknown field in action[1]: 'rogue'{UNKNOWN_SUFFIX}")
        );
        assert_eq!(
            message(&replace(
                &base,
                "actions",
                InputValue::list(vec![action("  ", None, None)])
            )),
            "actions[0].kind must be a non-empty string, got '  '"
        );
        assert_eq!(
            message(&replace(
                &base,
                "actions",
                InputValue::list(vec![dict(vec![
                    entry("kind", text("drop")),
                    entry("record_id", text("  ")),
                    entry("detail", InputValue::int(1)),
                ])])
            )),
            "actions[0].record_id must be non-empty string or None, got '  '"
        );
        assert_eq!(
            message(&replace(
                &base,
                "actions",
                InputValue::list(vec![dict(vec![
                    entry("kind", text("drop")),
                    entry("detail", InputValue::None),
                ])])
            )),
            "actions[0].detail must be a string, got NoneType"
        );
        assert_eq!(
            message(&replace(&base, "declared_loss", InputValue::int(1))),
            "declared_loss must be a list or tuple, got int"
        );
        assert_eq!(
            message(&replace(
                &base,
                "declared_loss",
                InputValue::list(vec![text("  ")])
            )),
            "declared_loss[0] must be a non-empty string, got '  '"
        );
        assert_eq!(
            message(&replace(
                &base,
                "declared_loss",
                InputValue::tuple(vec![InputValue::int(3)])
            )),
            "declared_loss[0] must be a non-empty string, got 3"
        );
    }

    #[test]
    fn path_idempotency_and_optional_fields_keep_pin_order() {
        let base = manifest();
        assert_eq!(
            message(&replace(&base, "revalidate_report", InputValue::int(4))),
            "RepairManifest.revalidate_report must be a non-empty string path or None, got 4"
        );
        assert_eq!(
            message(&replace(&base, "revalidate_report", text("  "))),
            "RepairManifest.revalidate_report must be a non-empty string path or None, got '  '"
        );
        let upper = "AB".repeat(32);
        assert_eq!(
            message(&replace(&base, "idempotency_key", text("AA"))),
            "RepairManifest.idempotency_key must be a 64-character lowercase hex string, got 'AA'"
        );
        assert_eq!(
            message(&replace(&base, "idempotency_key", text(&upper))),
            format!(
                "RepairManifest.idempotency_key must be a 64-character lowercase hex string, got '{upper}'"
            )
        );
        assert_eq!(
            message(&replace(&base, "idempotency_key", text(&"ab".repeat(31)))),
            format!(
                "RepairManifest.idempotency_key must be a 64-character lowercase hex string, got '{}'",
                "ab".repeat(31)
            )
        );
        let bad_key = replace(
            &replace(&base, "idempotency_key", text("AA")),
            "plan_fingerprint",
            text(""),
        );
        assert!(message(&bad_key).contains("idempotency_key"));
        assert_eq!(
            message(&replace(
                &replace(&base, "plan_fingerprint", text("  ")),
                "assurance",
                text("")
            )),
            "RepairManifest.plan_fingerprint must be a non-empty string"
        );
        assert_eq!(
            message(&replace(&base, "assurance", InputValue::int(1))),
            "RepairManifest.assurance must be a non-empty string"
        );
        assert_eq!(
            message(&replace(
                &replace(&base, "recipe_versions", InputValue::None),
                "profile_version",
                text("  ")
            )),
            "RepairManifest.recipe_versions must be a mapping"
        );
        assert_eq!(
            message(&replace(&base, "profile_version", text(""))),
            "RepairManifest.profile_version must be a non-empty string"
        );
        assert_eq!(
            message(&replace(
                &replace(&base, "adapter_id", text(" ")),
                "adapter_version",
                InputValue::int(1)
            )),
            "RepairManifest.adapter_id must be a non-empty string"
        );
        assert_eq!(
            message(&replace(&base, "adapter_version", text(" "))),
            "RepairManifest.adapter_version must be a non-empty string"
        );
        let absent_text = parse_ok(&replace(&base, "adapter_version", InputValue::None));
        assert_eq!(absent_text.adapter_version(), None);
        assert_eq!(
            message(&replace(
                &replace(&base, "byte_counts", InputValue::list(Vec::new())),
                "record_counts",
                InputValue::None
            )),
            "RepairManifest.byte_counts must be a mapping"
        );
        assert_eq!(
            message(&replace(&base, "record_counts", InputValue::None)),
            "RepairManifest.record_counts must be a mapping"
        );
        let bad_records = replace(
            &replace(&base, "record_counts", InputValue::int(1)),
            "revalidation",
            InputValue::int(1),
        );
        assert_eq!(
            message(&bad_records),
            "RepairManifest.record_counts must be a mapping"
        );
    }

    #[test]
    fn revalidation_checks_run_before_the_ceiling() {
        let base = manifest();
        assert_eq!(
            message(&replace(&base, "revalidation", InputValue::int(1))),
            "RepairManifest.revalidation must be a mapping, got int"
        );
        let unknown = dict(vec![
            entry("rogue", text("x")),
            entry("error_count", InputValue::int(0)),
        ]);
        match parse_err(&replace(&base, "revalidation", unknown)) {
            ParseManifestError::UnknownField(error) => {
                assert_eq!(error.field_name(), Some("rogue"));
                assert_eq!(
                    error.to_string(),
                    format!("Unknown field in manifest revalidation: 'rogue'{UNKNOWN_SUFFIX}")
                );
            }
            other => panic!("revalidation unknown field, got {other:?}"),
        }
        let missing = dict(vec![
            entry("error_count", InputValue::int(0)),
            entry("warning_count", InputValue::int(0)),
            entry("profile_id", text("neutral")),
            entry("profile_version", text("1")),
        ]);
        assert_eq!(
            message(&replace(&base, "revalidation", missing)),
            "Missing required field in manifest revalidation: 'assurance'"
        );
        let missing_version = dict(vec![
            entry("assurance", text("A1")),
            entry("error_count", InputValue::int(0)),
            entry("warning_count", InputValue::int(0)),
            entry("profile_id", text("neutral")),
        ]);
        assert_eq!(
            message(&replace(&base, "revalidation", missing_version)),
            "Missing required field in manifest revalidation: 'profile_version'"
        );
        assert_eq!(
            message(&replace_revalidation("assurance", text("A9"))),
            format!("Invalid revalidation assurance: 'A9'. Must be one of {LEVELS}")
        );
        assert!(!message(&replace_revalidation("assurance", text("A9")))
            .contains("Invalid revalidation assurance 'A9'"));
        assert_eq!(
            message(&replace_revalidation("error_count", InputValue::bool_value(true))),
            "revalidation.error_count must be a non-negative integer, got True"
        );
        assert_eq!(
            message(&replace_revalidation("error_count", InputValue::bool_value(false))),
            "revalidation.error_count must be a non-negative integer, got False"
        );
        assert_eq!(
            message(&replace_revalidation("error_count", InputValue::int(-1))),
            "revalidation.error_count must be a non-negative integer, got -1"
        );
        assert!(!message(&replace_revalidation("error_count", InputValue::bool_value(true)))
            .contains("RevalidationSummary.error_count"));
        let warning_bool = replace_revalidation("warning_count", InputValue::bool_value(true));
        let warning_bool = replace(
            &warning_bool,
            "assurance_ceiling",
            text("A9"),
        );
        assert_eq!(
            message(&warning_bool),
            "revalidation.warning_count must be a non-negative integer, got True"
        );
        assert_eq!(
            message(&replace_revalidation("profile_id", text("  "))),
            "revalidation.profile_id must be a non-empty string"
        );
        assert_eq!(
            message(&replace_revalidation("profile_version", InputValue::int(1))),
            "revalidation.profile_version must be a non-empty string"
        );
        assert_eq!(
            message(&replace_revalidation("report_fingerprint", text("  "))),
            "revalidation.report_fingerprint must be a non-empty string or None"
        );
        match parse_err(&replace(&base, "assurance_ceiling", text("A9"))) {
            ParseManifestError::Assurance(error) => {
                assert_eq!(error.code(), AssuranceError::DEFAULT_CODE);
                assert_eq!(
                    error.to_string(),
                    format!("Invalid assurance_ceiling: 'A9'. Must be one of {LEVELS}")
                );
                assert!(!error
                    .to_string()
                    .contains("RepairManifest.assurance_ceiling must be one of"));
            }
            other => panic!("ceiling, got {other:?}"),
        }
        assert_eq!(
            message(&replace(&base, "assurance_ceiling", InputValue::int(3))),
            format!("Invalid assurance_ceiling: 3. Must be one of {LEVELS}")
        );
    }

    #[test]
    fn parsed_manifest_keeps_order_and_calls_the_constructor() {
        let minimal = parse_ok(&manifest());
        assert_eq!(minimal.schema_version(), MANIFEST_SCHEMA_VERSION);
        assert_eq!(minimal.input_fingerprint(), "in");
        assert_eq!(minimal.output_fingerprint(), "out");
        assert_eq!(minimal.policy(), "conservative");
        assert!(minimal.actions().is_empty());
        assert!(minimal.declared_loss().is_empty());
        assert_eq!(minimal.revalidate_report(), None);
        assert_eq!(minimal.idempotency_key(), idem());
        assert_eq!(minimal.assurance_ceiling(), "A2");
        assert_eq!(minimal.plan_fingerprint(), None);
        assert_eq!(minimal.assurance(), None);
        assert!(minimal.recipe_versions().is_empty());
        assert_eq!(minimal.profile_version(), None);
        assert_eq!(minimal.adapter_id(), None);
        assert_eq!(minimal.adapter_version(), None);
        assert!(minimal.byte_counts().is_empty());
        assert!(minimal.record_counts().is_empty());
        assert_eq!(minimal.revalidation().assurance(), "A1");
        assert_eq!(minimal.revalidation().error_count(), 0);
        assert_eq!(minimal.revalidation().warning_count(), 1);
        assert_eq!(minimal.revalidation().profile_id(), "neutral");
        assert_eq!(minimal.revalidation().profile_version(), "1");
        assert_eq!(minimal.revalidation().report_fingerprint(), None);

        let explicit_none = parse_ok(&replace(&manifest(), "plan_fingerprint", InputValue::None));
        assert_eq!(explicit_none.plan_fingerprint(), None);

        let actions = InputValue::list(vec![
            action("  zeta  ", None, Some(" later ")),
            action(" alpha ", Some(" b "), Some(" d ")),
            action("alpha", None, None),
        ]);
        let loss = InputValue::list(vec![text("  zeta  "), text(" alpha ")]);
        let recipes = dict(vec![
            entry("a", text("1")),
            entry("b", text("2")),
            entry("a", text("9")),
        ]);
        let bytes = dict(vec![
            entry("rows", InputValue::int(2)),
            entry("kept", InputValue::int(1)),
        ]);
        let records = dict(vec![
            entry("kept", InputValue::int(4)),
            entry("dropped", InputValue::int(1)),
        ]);
        let mut rich = replace(&manifest(), "input_fingerprint", text("  in  "));
        rich = replace(&rich, "output_fingerprint", text("  out  "));
        rich = replace(&rich, "policy", text("salvage"));
        rich = replace(&rich, "actions", actions);
        rich = replace(&rich, "declared_loss", loss);
        rich = replace(&rich, "revalidate_report", text("  C:\\tmp\\x  "));
        rich = replace(&rich, "plan_fingerprint", text("  plan  "));
        rich = replace(&rich, "assurance", text("  note  "));
        rich = replace(&rich, "recipe_versions", recipes);
        rich = replace(&rich, "profile_version", text("  9  "));
        rich = replace(&rich, "adapter_id", text("  canon  "));
        rich = replace(&rich, "adapter_version", text("  2  "));
        rich = replace(&rich, "byte_counts", bytes);
        rich = replace(&rich, "record_counts", records);
        rich = replace(
            &rich,
            "revalidation",
            replace_nested_fingerprint("  cd  "),
        );
        let parsed = parse_ok(&rich);
        assert_eq!(parsed.input_fingerprint(), "in");
        assert_eq!(parsed.output_fingerprint(), "out");
        assert_eq!(parsed.policy(), "salvage");
        assert_eq!(parsed.revalidate_report(), Some("C:/tmp/x"));
        assert_eq!(parsed.plan_fingerprint(), Some("plan"));
        assert_eq!(parsed.assurance(), Some("note"));
        assert_eq!(parsed.profile_version(), Some("9"));
        assert_eq!(parsed.adapter_id(), Some("canon"));
        assert_eq!(parsed.adapter_version(), Some("2"));
        assert_eq!(parsed.assurance_ceiling(), "A2");
        assert_eq!(parsed.idempotency_key(), idem());
        let kinds: Vec<(&str, Option<&str>, &str)> = parsed
            .actions()
            .iter()
            .map(|action| (action.kind(), action.record_id(), action.detail()))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("alpha", None, ""),
                ("alpha", Some("b"), "d"),
                ("zeta", None, "later"),
            ]
        );
        assert_eq!(
            parsed.declared_loss(),
            &["zeta".to_owned(), "alpha".to_owned()]
        );
        assert_eq!(
            parsed.recipe_versions(),
            &[
                (InputKey::str_key("a"), text("9")),
                (InputKey::str_key("b"), text("2")),
            ]
        );
        assert_eq!(
            parsed.byte_counts(),
            &[
                (InputKey::str_key("rows"), InputValue::int(2)),
                (InputKey::str_key("kept"), InputValue::int(1)),
            ]
        );
        assert_eq!(
            parsed.record_counts(),
            &[
                (InputKey::str_key("kept"), InputValue::int(4)),
                (InputKey::str_key("dropped"), InputValue::int(1)),
            ]
        );
        assert_eq!(parsed.revalidation().report_fingerprint(), Some("cd"));
        assert_eq!(parsed.revalidation().profile_id(), "neutral");

        let tuple_actions = InputValue::tuple(vec![
            action("  zeta  ", None, Some(" later ")),
            action(" alpha ", Some(" b "), Some(" d ")),
            action("alpha", None, None),
        ]);
        let from_tuple = parse_ok(&replace(&rich, "actions", tuple_actions));
        assert_eq!(from_tuple.actions(), parsed.actions());
        let tuple_loss = InputValue::tuple(vec![text("  zeta  "), text(" alpha ")]);
        let from_loss = parse_ok(&replace(&rich, "declared_loss", tuple_loss));
        assert_eq!(from_loss.declared_loss(), parsed.declared_loss());

        let collapsed = dict(vec![
            (InputKey::bool_value(true), text("first")),
            (InputKey::int(1), text("second")),
            entry("z", text("tail")),
        ]);
        let collapsed = parse_ok(&replace(&manifest(), "recipe_versions", collapsed));
        assert_eq!(
            collapsed.recipe_versions(),
            &[
                (InputKey::bool_value(true), text("second")),
                (InputKey::str_key("z"), text("tail")),
            ]
        );
    }

    fn replace_nested_fingerprint(value: &str) -> InputValue {
        replace_revalidation_value("report_fingerprint", text(value))
    }

    fn replace_revalidation_value(name: &str, next: InputValue) -> InputValue {
        let InputValue::Dict(entries) = revalidation() else {
            panic!("revalidation mapping");
        };
        let mut entries = entries.clone();
        entries.push(entry(name, next));
        dict(entries)
    }

    #[test]
    fn action_constructor_error_is_propagated() {
        let leaked = "keep\nnote";
        let finding = match enforce_content_free_text(leaked, "RepairAction.detail") {
            Ok(()) => panic!("expected content leak"),
            Err(error) => error.to_string(),
        };
        let bad = replace(
            &replace(
                &manifest(),
                "actions",
                InputValue::list(vec![action("drop", None, Some("  keep\nnote  "))]),
            ),
            "declared_loss",
            InputValue::int(1),
        );
        match parse_err(&bad) {
            ParseManifestError::ContentLeak(error) => {
                assert_eq!(
                    error.to_string(),
                    format!("Intrinsic content leak in RepairAction.detail: {finding}")
                );
                assert!(!error.to_string().contains("declared_loss"));
                assert!(!error.to_string().contains("SL302"));
            }
            other => panic!("constructor content leak, got {other:?}"),
        }
    }
}

// Lines 1610–1921: content-free enforcement, schema loading, plan assurance,
// path rendering, identifier minimization, and reproduction metadata.
//
// `get_report_schema_path` and `get_manifest_schema_path` call
// `sesslint._resources.schema_path`. That module is not in this crate.
// `load_report_schema` and `load_manifest_schema` call those functions
// first and do not read a schema file. `apply_plan_assurance` calls
// `sesslint.repair.assurance.cap_assurance`. `minimize_path` reaches
// `hashlib.sha1` only after the home-relative checks fail. `hint_path`
// does not hash. `build_repro_metadata` imports `sesslint.__version__`
// before it builds a value. Lexical `.` and `..` collapsing does not join
// the working directory and does not resolve symlinks.

/// `sesslint._resources.schema_path` is not linked into this crate.
pub const RESOURCES_SCHEMA_PATH: &str = "sesslint._resources.schema_path";

/// `sesslint.repair.assurance.cap_assurance` is not linked into this crate.
pub const CAP_ASSURANCE: &str = "sesslint.repair.assurance.cap_assurance";

/// `hashlib.sha1` is not a dependency of this crate.
pub const HASHLIB_SHA1: &str = "hashlib.sha1";

/// `sesslint.__version__` is not linked into this crate.
pub const SESSLINT_VERSION: &str = "sesslint.__version__";

/// Python default for [`short_hash`] when the caller omits `length`.
pub const SHORT_HASH_DEFAULT_LENGTH: usize = 8;

/// Failure from [`get_report_schema_path`], [`get_manifest_schema_path`],
/// [`load_report_schema`], and [`load_manifest_schema`].
///
/// [`Display`](fmt::Display) is `sesslint._resources.schema_path is not available`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaPathUnavailable;

impl fmt::Display for SchemaPathUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{RESOURCES_SCHEMA_PATH} is not available")
    }
}

impl Error for SchemaPathUnavailable {}

/// Failure from [`apply_plan_assurance`].
///
/// [`Display`](fmt::Display) is
/// `sesslint.repair.assurance.cap_assurance is not available`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapAssuranceUnavailable;

impl fmt::Display for CapAssuranceUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{CAP_ASSURANCE} is not available")
    }
}

impl Error for CapAssuranceUnavailable {}

/// `Path.home()` could not read the process home.
///
/// [`Display`](fmt::Display) is `Could not determine home directory.`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HomeDirectoryError;

impl fmt::Display for HomeDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Could not determine home directory.")
    }
}

impl Error for HomeDirectoryError {}

/// Failure from [`minimize_path`].
///
/// [`Self::Sha1`] is `hashlib.sha1 is not available`. [`Self::Home`] is
/// [`HomeDirectoryError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinimizePathError {
    Sha1,
    Home(HomeDirectoryError),
}

impl fmt::Display for MinimizePathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => write!(formatter, "{HASHLIB_SHA1} is not available"),
            Self::Home(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for MinimizePathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Home(error) => Some(error),
            Self::Sha1 => None,
        }
    }
}

/// Failure from [`build_repro_metadata`].
///
/// [`Display`](fmt::Display) is `sesslint.__version__ is not available`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SesslintVersionUnavailable;

impl fmt::Display for SesslintVersionUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{SESSLINT_VERSION} is not available")
    }
}

impl Error for SesslintVersionUnavailable {}

/// Python `Report`, `RepairManifest`, or another object.
///
/// [`ContentFreeInput::Other`] carries `type(obj).__name__`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentFreeInput<'a> {
    Report(&'a Report),
    Manifest(&'a RepairManifest),
    Other { type_name: &'a str },
}

/// Failure from [`enforce_content_free`].
///
/// [`Self::Leak`] is [`ContentLeakError`]. [`Self::Type`] is Python
/// `TypeError` text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentFreeError {
    Leak(ContentLeakError),
    Type(String),
}

impl fmt::Display for ContentFreeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Leak(error) => write!(formatter, "{error}"),
            Self::Type(message) => formatter.write_str(message),
        }
    }
}

impl Error for ContentFreeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Leak(error) => Some(error),
            Self::Type(_) => None,
        }
    }
}

/// Python `str` or `pathlib.Path` passed to [`minimize_path`] and [`hint_path`].
///
/// The `~/`, `~`, and `.._` shortcut in [`minimize_path`] applies only to
/// [`Self::Text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathInput<'a> {
    Text(&'a str),
    Path(&'a std::path::Path),
}

/// One value in a [`MinimizedId::Map`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinimizedField {
    Text(String),
    Int(i64),
}

/// Dict mode of [`minimize_id`].
///
/// Key order is `short`, then `ordinal` when it is present, then `full`
/// when content is included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimizedIdMap {
    pub short: String,
    pub ordinal: Option<i64>,
    pub full: Option<String>,
}

impl MinimizedIdMap {
    /// Entries in Python dict insertion order.
    #[must_use]
    pub fn entries(&self) -> Vec<(&'static str, MinimizedField)> {
        let mut entries = vec![("short", MinimizedField::Text(self.short.clone()))];
        if let Some(ordinal) = self.ordinal {
            entries.push(("ordinal", MinimizedField::Int(ordinal)));
        }
        if let Some(full) = &self.full {
            entries.push(("full", MinimizedField::Text(full.clone())));
        }
        entries
    }
}

/// Python return of [`minimize_id`]: a string or an ordered dict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinimizedId {
    Text(String),
    Map(MinimizedIdMap),
}

/// Scalar stored in a reproduction-metadata map.
///
/// `confidence` is [`Self::Null`] or [`Self::Float`]. Names and versions are
/// [`Self::Text`].
#[derive(Debug, Clone, PartialEq)]
pub enum ReproValue {
    Null,
    Float(f64),
    Text(String),
}

/// Python: `ReproMetadata`.
///
/// Field order matches the dataclass. [`Self::to_dict`] uses a different key
/// order. Nested maps keep the `Vec` insertion order.
#[derive(Debug, Clone, PartialEq)]
pub struct ReproMetadata {
    pub cli_version: String,
    pub schema_versions: Vec<(String, String)>,
    pub adapter: Vec<(String, String)>,
    pub profile: Vec<(String, String)>,
    pub detection: Vec<(String, ReproValue)>,
    pub platform: Vec<(String, String)>,
}

/// One value in [`ReproDict::entries`].
#[derive(Debug, Clone, PartialEq)]
pub enum ReproEntry {
    Text(String),
    Map(Vec<(String, String)>),
    Any(Vec<(String, ReproValue)>),
}

/// Python: `ReproMetadata.to_dict`.
///
/// Key order is `adapter`, `cli_version`, `detection`, `platform`, `profile`,
/// `schema_versions`.
#[derive(Debug, Clone, PartialEq)]
pub struct ReproDict {
    pub adapter: Vec<(String, String)>,
    pub cli_version: String,
    pub detection: Vec<(String, ReproValue)>,
    pub platform: Vec<(String, String)>,
    pub profile: Vec<(String, String)>,
    pub schema_versions: Vec<(String, String)>,
}

impl ReproDict {
    /// Entries in the pinned `to_dict` order.
    #[must_use]
    pub fn entries(&self) -> Vec<(&'static str, ReproEntry)> {
        vec![
            ("adapter", ReproEntry::Map(self.adapter.clone())),
            ("cli_version", ReproEntry::Text(self.cli_version.clone())),
            ("detection", ReproEntry::Any(self.detection.clone())),
            ("platform", ReproEntry::Map(self.platform.clone())),
            ("profile", ReproEntry::Map(self.profile.clone())),
            (
                "schema_versions",
                ReproEntry::Map(self.schema_versions.clone()),
            ),
        ]
    }
}

impl ReproMetadata {
    /// Python: `ReproMetadata.to_dict`.
    ///
    /// Each nested map is copied. Insertion order is preserved.
    #[must_use]
    pub fn to_dict(&self) -> ReproDict {
        ReproDict {
            adapter: self.adapter.clone(),
            cli_version: self.cli_version.clone(),
            detection: self.detection.clone(),
            platform: self.platform.clone(),
            profile: self.profile.clone(),
            schema_versions: self.schema_versions.clone(),
        }
    }
}

/// Keyword arguments of [`build_repro_metadata`].
///
/// Python defaults, which Rust does not infer: omitted names and versions are
/// `"unknown"`, and omitted `detection_confidence` is `None`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReproRequest<'a> {
    pub adapter_name: &'a str,
    pub adapter_version: &'a str,
    pub profile_name: &'a str,
    pub profile_version: &'a str,
    pub detection_method: &'a str,
    pub detection_confidence: Option<f64>,
}

/// Python: `enforce_content_free`.
///
/// `forbidden_substrings` of `None` leaves the extra list empty. Otherwise
/// each item that is non-empty after `strip` is kept, in input order.
/// [`enforce_content_free_text`] runs before the substring scan. A
/// [`FindingError`] becomes [`ContentLeakError`] with
/// `Intrinsic content leak in {context}: {err}`. The substring message is
/// `Forbidden payload text {sub!r} detected in {context}: {text!r}`.
/// Anything other than a [`Report`] or [`RepairManifest`] is
/// `Expected Report or RepairManifest, got {type}`.
pub fn enforce_content_free(
    artifact: ContentFreeInput<'_>,
    forbidden_substrings: Option<&[&str]>,
) -> Result<(), ContentFreeError> {
    let cleaned = clean_substrings(forbidden_substrings);
    match artifact {
        ContentFreeInput::Report(report) => enforce_report(report, &cleaned),
        ContentFreeInput::Manifest(manifest) => enforce_manifest(manifest, &cleaned),
        ContentFreeInput::Other { type_name } => Err(ContentFreeError::Type(format!(
            "Expected Report or RepairManifest, got {type_name}"
        ))),
    }
}

/// Python: `get_report_schema_path`.
///
/// Calls `sesslint._resources.schema_path` and does not invent a filesystem path.
pub fn get_report_schema_path() -> Result<std::path::PathBuf, SchemaPathUnavailable> {
    resources_schema_path()
}

/// Python: `load_report_schema`.
///
/// Calls [`get_report_schema_path`] first. This crate does not read a schema
/// file and does not call `json.loads`.
pub fn load_report_schema() -> Result<Vec<(String, String)>, SchemaPathUnavailable> {
    let _path = get_report_schema_path()?;
    Err(SchemaPathUnavailable)
}

/// Python: `get_manifest_schema_path`.
///
/// Calls `sesslint._resources.schema_path` and does not invent a filesystem path.
pub fn get_manifest_schema_path() -> Result<std::path::PathBuf, SchemaPathUnavailable> {
    resources_schema_path()
}

/// Python: `load_manifest_schema`.
///
/// Calls [`get_manifest_schema_path`] first. This crate does not read a schema
/// file and does not call `json.loads`.
pub fn load_manifest_schema() -> Result<Vec<(String, String)>, SchemaPathUnavailable> {
    let _path = get_manifest_schema_path()?;
    Err(SchemaPathUnavailable)
}

/// Python: `apply_plan_assurance`.
///
/// The body is `return cap_assurance(base, plan)`. This crate does not link
/// `sesslint.repair` and does not return `base` unchanged.
pub fn apply_plan_assurance<Plan>(
    base: &str,
    plan: &Plan,
) -> Result<String, CapAssuranceUnavailable> {
    let _ = (base, plan);
    Err(CapAssuranceUnavailable)
}

/// Python: `minimize_path`.
///
/// A provided `home` is the only directory used. An omitted `home` reads the
/// process home (`USERPROFILE` on Windows, `HOME` on Unix) on each call.
/// A string that is `~`, starts with `~/`, or starts with `.._` is returned
/// unchanged. Home-relative absolute paths render `~` or `~/...` with forward
/// slashes. A relative path with no parent returns the file name. The hashed
/// `.._<8hex>/name` branch returns [`MinimizePathError::Sha1`] and does not
/// invent hex digits.
pub fn minimize_path(path: PathInput<'_>, home: Option<&str>) -> Result<String, MinimizePathError> {
    if let PathInput::Text(text) = path {
        if is_minimized_prefix(text) {
            return Ok(text.to_owned());
        }
    }
    let shown = shown_text(path);
    let parsed = parse_input(path);
    let home_path = parse_py_path(&require_home(home).map_err(MinimizePathError::Home)?);
    if is_abs_text(&parsed, &shown) {
        if let Some(relative) = parsed.relative_to(&home_path) {
            return Ok(render_tilde(&relative, false));
        }
        if is_native_abs(&parsed, &shown) {
            let resolved = parsed.resolve_lexical();
            let resolved_home = home_path.resolve_lexical();
            if let Some(relative) = resolved.relative_to(&resolved_home) {
                return Ok(render_tilde(&relative, false));
            }
        }
        return Err(MinimizePathError::Sha1);
    }
    if parsed.parent_is_dot() {
        return Ok(parsed.name());
    }
    Err(MinimizePathError::Sha1)
}

/// Python: `_human_bytes`.
///
/// Values below 1024, including negatives, render `{n} B`. Larger values use
/// one decimal place in the same way as Python `f"{n:.1f}"`.
#[must_use]
pub fn human_bytes(n: i64) -> String {
    if n < 1024 {
        return format!("{n} B");
    }
    let (scaled, suffix) = if n < 1024 * 1024 {
        ((n as f64) / 1024.0, "KiB")
    } else if n < 1024 * 1024 * 1024 {
        ((n as f64) / (1024.0 * 1024.0), "MiB")
    } else {
        ((n as f64) / (1024.0 * 1024.0 * 1024.0), "GiB")
    };
    format!("{} {suffix}", one_decimal(scaled))
}

/// Python: `hint_path`.
///
/// A provided `home` is the only directory used. An omitted `home` reads the
/// process home only when the path is absolute. Home-relative absolute paths
/// render `~/...` with forward slashes, including `~/.` for the home directory
/// itself. An absolute path outside home returns the slash-normalized path.
/// This function does not hash.
pub fn hint_path(path: PathInput<'_>, home: Option<&str>) -> Result<String, HomeDirectoryError> {
    let shown = shown_text(path);
    if is_minimized_prefix(&shown) {
        return Ok(shown);
    }
    let parsed = parse_input(path);
    if !is_abs_text(&parsed, &shown) {
        return Ok(shown);
    }
    let home_path = parse_py_path(&require_home(home)?);
    if let Some(relative) = parsed.relative_to(&home_path) {
        return Ok(render_tilde(&relative, true));
    }
    if is_native_abs(&parsed, &shown) {
        let resolved = parsed.resolve_lexical();
        let resolved_home = home_path.resolve_lexical();
        if let Some(relative) = resolved.relative_to(&resolved_home) {
            return Ok(render_tilde(&relative, true));
        }
    }
    Ok(shown)
}

/// Python: `short_hash`.
///
/// SHA-256 of the UTF-8 identifier, then the first `length` hex characters.
/// `length` of 0 is empty. `length` above 64 is the whole digest.
#[must_use]
pub fn short_hash(identifier: &str, length: usize) -> String {
    let digest = sha256_hex(identifier.as_bytes());
    let take = length.min(digest.len());
    digest[..take].to_owned()
}

/// Python: `minimize_id`.
///
/// Dict key order is `short`, then `ordinal` when it is an int, then `full`
/// when `include_content` is set. A bool is not an ordinal. String mode with
/// `include_content` returns the identifier. String mode with an int ordinal
/// returns `#{ordinal}`. Otherwise the result is [`short_hash`] of length 8.
#[must_use]
pub fn minimize_id(
    identifier: &str,
    ordinal: Option<&InputValue>,
    include_content: bool,
    as_dict: bool,
) -> MinimizedId {
    let short = short_hash(identifier, SHORT_HASH_DEFAULT_LENGTH);
    let ordinal = ordinal.and_then(ordinal_int);
    if as_dict {
        let full = if include_content {
            Some(identifier.to_owned())
        } else {
            None
        };
        return MinimizedId::Map(MinimizedIdMap {
            short,
            ordinal,
            full,
        });
    }
    if include_content {
        return MinimizedId::Text(identifier.to_owned());
    }
    if let Some(number) = ordinal {
        return MinimizedId::Text(format!("#{number}"));
    }
    MinimizedId::Text(short)
}

/// Python: `build_repro_metadata`.
///
/// Imports `sesslint.__version__` before building a [`ReproMetadata`]. That
/// attribute is not in this crate, so this does not invent a version, an
/// architecture, an operating-system name, or a Python version. Tests can
/// still construct [`ReproMetadata`] directly.
pub fn build_repro_metadata(
    request: ReproRequest<'_>,
) -> Result<ReproMetadata, SesslintVersionUnavailable> {
    let _bound = (
        request.adapter_name,
        request.adapter_version,
        request.profile_name,
        request.profile_version,
        request.detection_method,
        request.detection_confidence.is_some(),
    );
    Err(SesslintVersionUnavailable)
}

fn resources_schema_path() -> Result<std::path::PathBuf, SchemaPathUnavailable> {
    Err(SchemaPathUnavailable)
}

fn clean_substrings(forbidden: Option<&[&str]>) -> Vec<String> {
    let Some(items) = forbidden else {
        return Vec::new();
    };
    let mut cleaned = Vec::new();
    for item in items {
        if item.is_empty() {
            continue;
        }
        let stripped = python_strip(item);
        if !stripped.is_empty() {
            cleaned.push(stripped.to_owned());
        }
    }
    cleaned
}

fn enforce_report(report: &Report, subs: &[String]) -> Result<(), ContentFreeError> {
    check_text(report.session_id(), "Report.session_id", subs)?;
    check_text(
        report.source_fingerprint(),
        "Report.source_fingerprint",
        subs,
    )?;
    check_text(report.tool_version(), "Report.tool_version", subs)?;
    check_text(report.limitation(), "Report.limitation", subs)?;
    for (index, skip) in report.coverage().skipped().iter().enumerate() {
        check_text(
            skip.check(),
            &format!("Report.coverage.skipped[{index}].check"),
            subs,
        )?;
        check_text(
            skip.detail(),
            &format!("Report.coverage.skipped[{index}].detail"),
            subs,
        )?;
    }
    for (index, finding) in report.findings().iter().enumerate() {
        check_text(
            finding.message(),
            &format!("Report.findings[{index}].message"),
            subs,
        )?;
        if let Some(template) = finding.message_template() {
            check_text(
                template,
                &format!("Report.findings[{index}].message_template"),
                subs,
            )?;
        }
        check_text(
            finding.source().path(),
            &format!("Report.findings[{index}].source.path"),
            subs,
        )?;
        if let Some(record_id) = finding.source().record_id() {
            check_text(
                record_id,
                &format!("Report.findings[{index}].source.record_id"),
                subs,
            )?;
        }
        for (rel_index, rel_id) in finding.related_ids().iter().enumerate() {
            check_text(
                rel_id,
                &format!("Report.findings[{index}].related_ids[{rel_index}]"),
                subs,
            )?;
        }
    }
    Ok(())
}

fn enforce_manifest(manifest: &RepairManifest, subs: &[String]) -> Result<(), ContentFreeError> {
    check_text(
        manifest.input_fingerprint(),
        "RepairManifest.input_fingerprint",
        subs,
    )?;
    check_text(
        manifest.output_fingerprint(),
        "RepairManifest.output_fingerprint",
        subs,
    )?;
    if let Some(path) = manifest.revalidate_report() {
        check_text(path, "RepairManifest.revalidate_report", subs)?;
    }
    for (index, loss) in manifest.declared_loss().iter().enumerate() {
        check_text(
            loss,
            &format!("RepairManifest.declared_loss[{index}]"),
            subs,
        )?;
    }
    for (index, action) in manifest.actions().iter().enumerate() {
        check_text(
            action.kind(),
            &format!("RepairManifest.actions[{index}].kind"),
            subs,
        )?;
        if let Some(record_id) = action.record_id() {
            check_text(
                record_id,
                &format!("RepairManifest.actions[{index}].record_id"),
                subs,
            )?;
        }
        check_text(
            action.detail(),
            &format!("RepairManifest.actions[{index}].detail"),
            subs,
        )?;
    }
    let revalidation = manifest.revalidation();
    check_text(
        revalidation.profile_id(),
        "RepairManifest.revalidation.profile_id",
        subs,
    )?;
    check_text(
        revalidation.profile_version(),
        "RepairManifest.revalidation.profile_version",
        subs,
    )?;
    if let Some(fingerprint) = revalidation.report_fingerprint() {
        check_text(
            fingerprint,
            "RepairManifest.revalidation.report_fingerprint",
            subs,
        )?;
    }
    if let Some(adapter_id) = manifest.adapter_id() {
        check_text(adapter_id, "RepairManifest.adapter_id", subs)?;
    }
    Ok(())
}

fn check_text(text: &str, context: &str, subs: &[String]) -> Result<(), ContentFreeError> {
    if let Err(error) = enforce_content_free_text(text, context) {
        return Err(ContentFreeError::Leak(ContentLeakError::new(format!(
            "Intrinsic content leak in {context}: {error}"
        ))));
    }
    for sub in subs {
        if text.contains(sub.as_str()) || contains_lower(text, sub) {
            return Err(ContentFreeError::Leak(ContentLeakError::new(format!(
                "Forbidden payload text {} detected in {context}: {}",
                python_str_repr(sub),
                python_str_repr(text)
            ))));
        }
    }
    Ok(())
}

fn contains_lower(text: &str, sub: &str) -> bool {
    text.to_lowercase().contains(&sub.to_lowercase())
}

fn ordinal_int(value: &InputValue) -> Option<i64> {
    match value {
        InputValue::Int(number) => Some(*number),
        InputValue::Bool(_)
        | InputValue::None
        | InputValue::Str(_)
        | InputValue::List(_)
        | InputValue::Tuple(_)
        | InputValue::Set(_)
        | InputValue::FrozenSet(_)
        | InputValue::Dict(_)
        | InputValue::Other { .. } => None,
    }
}

fn one_decimal(value: f64) -> String {
    let negative = value.is_sign_negative() && value != 0.0;
    let tenths = round_half_even(value.abs() * 10.0);
    let whole = tenths.div_euclid(10);
    let frac = tenths.rem_euclid(10);
    if negative {
        format!("-{whole}.{frac}")
    } else {
        format!("{whole}.{frac}")
    }
}

fn round_half_even(scaled: f64) -> i64 {
    if !scaled.is_finite() || scaled >= (i64::MAX as f64) {
        return i64::MAX;
    }
    let floor = scaled.floor();
    let mut base = floor as i64;
    let diff = scaled - floor;
    if diff > 0.5 || (diff == 0.5 && base % 2 != 0) {
        base = base.saturating_add(1);
    }
    base
}

fn home_env_key() -> &'static str {
    if cfg!(windows) {
        "USERPROFILE"
    } else {
        "HOME"
    }
}

fn process_home() -> Result<String, HomeDirectoryError> {
    match std::env::var(home_env_key()) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(HomeDirectoryError),
    }
}

fn require_home(home: Option<&str>) -> Result<String, HomeDirectoryError> {
    match home {
        Some(text) => Ok(text.to_owned()),
        None => process_home(),
    }
}

fn is_minimized_prefix(text: &str) -> bool {
    text.starts_with("~/") || text == "~" || text.starts_with(".._")
}

fn shown_text(path: PathInput<'_>) -> String {
    match path {
        PathInput::Text(text) => text.replace('\\', "/"),
        PathInput::Path(path) => parse_py_path(&path.to_string_lossy())
            .to_py_str()
            .replace('\\', "/"),
    }
}

fn parse_input(path: PathInput<'_>) -> PyPath {
    match path {
        PathInput::Text(text) => parse_py_path(text),
        PathInput::Path(path) => parse_py_path(&path.to_string_lossy()),
    }
}

fn is_abs_text(parsed: &PyPath, shown: &str) -> bool {
    parsed.is_absolute() || shown.starts_with('/') || second_is_colon(shown)
}

fn is_native_abs(parsed: &PyPath, shown: &str) -> bool {
    parsed.is_absolute() || shown.starts_with('/')
}

fn second_is_colon(text: &str) -> bool {
    let mut chars = text.chars();
    chars.next();
    chars.next() == Some(':')
}

fn render_tilde(relative: &PyPath, hint: bool) -> String {
    let bare_dot = relative.drv.is_empty() && relative.root.is_empty() && relative.parts.is_empty();
    if !hint && bare_dot {
        return "~".to_owned();
    }
    format!("~/{}", relative.as_posix())
}

fn os_sep() -> &'static str {
    if cfg!(windows) {
        "\\"
    } else {
        "/"
    }
}

#[derive(Clone, Debug)]
struct PyPath {
    drv: String,
    root: String,
    parts: Vec<String>,
}

impl PyPath {
    fn from_tail(drv: String, root: String, tail: Vec<String>) -> Self {
        let mut parts = Vec::new();
        if !drv.is_empty() || !root.is_empty() {
            parts.push(format!("{drv}{root}"));
        }
        parts.extend(tail);
        Self { drv, root, parts }
    }

    fn is_absolute(&self) -> bool {
        if self.root.is_empty() {
            return false;
        }
        if cfg!(windows) {
            !self.drv.is_empty()
        } else {
            true
        }
    }

    fn name(&self) -> String {
        let anchor = usize::from(!self.drv.is_empty() || !self.root.is_empty());
        if self.parts.len() == anchor {
            String::new()
        } else {
            self.parts.last().cloned().unwrap_or_default()
        }
    }

    fn parent_is_dot(&self) -> bool {
        self.drv.is_empty() && self.root.is_empty() && self.parts.len() <= 1
    }

    fn tail(&self) -> impl Iterator<Item = &str> {
        let skip = usize::from(!self.drv.is_empty() || !self.root.is_empty());
        self.parts.iter().skip(skip).map(String::as_str)
    }

    fn abs_parts(&self) -> Vec<String> {
        if self.root.is_empty() {
            self.parts.clone()
        } else {
            let mut out = vec![self.drv.clone(), self.root.clone()];
            out.extend(self.parts.iter().skip(1).cloned());
            out
        }
    }

    fn relative_to(&self, other: &Self) -> Option<Self> {
        let abs = self.abs_parts();
        let to = other.abs_parts();
        let count = to.len();
        let anchored = !self.drv.is_empty() || !self.root.is_empty();
        let mismatch = if count == 0 {
            anchored
        } else {
            !prefix_equal(&abs, &to)
        };
        if mismatch {
            return None;
        }
        let root = if count == 1 {
            self.root.clone()
        } else {
            String::new()
        };
        Some(Self {
            drv: String::new(),
            root,
            parts: abs.into_iter().skip(count).collect(),
        })
    }

    fn resolve_lexical(&self) -> Self {
        let mut tail = Vec::new();
        let has_root = !self.root.is_empty();
        for component in self.tail() {
            if component == ".." {
                if tail.last().is_some_and(|previous| previous != "..") {
                    tail.pop();
                } else if !has_root {
                    tail.push("..".to_owned());
                }
            } else {
                tail.push(component.to_owned());
            }
        }
        Self::from_tail(self.drv.clone(), self.root.clone(), tail)
    }

    fn to_py_str(&self) -> String {
        let sep = os_sep();
        if !self.drv.is_empty() || !self.root.is_empty() {
            let mut out = String::new();
            out.push_str(&self.drv);
            out.push_str(&self.root);
            let mut tail = self.parts.iter().skip(1);
            if let Some(first) = tail.next() {
                out.push_str(first);
                for part in tail {
                    out.push_str(sep);
                    out.push_str(part);
                }
            }
            return out;
        }
        if self.parts.is_empty() {
            ".".to_owned()
        } else {
            self.parts.join(sep)
        }
    }

    fn as_posix(&self) -> String {
        let text = self.to_py_str();
        if cfg!(windows) {
            text.replace('\\', "/")
        } else {
            text
        }
    }
}

fn parse_py_path(text: &str) -> PyPath {
    if cfg!(windows) {
        parse_windows(text)
    } else {
        parse_posix(text)
    }
}

fn parse_windows(text: &str) -> PyPath {
    let normalized = text.replace('/', "\\");
    let (drv, root, rel) = splitroot_windows(&normalized);
    PyPath::from_tail(drv, root, split_tail(&rel, '\\'))
}

fn parse_posix(text: &str) -> PyPath {
    let leading = text.chars().take_while(|ch| *ch == '/').count();
    let (root, rel) = if leading == 0 {
        (String::new(), text.to_owned())
    } else if leading == 2 {
        (
            "//".to_owned(),
            text[2..].trim_start_matches('/').to_owned(),
        )
    } else {
        ("/".to_owned(), text[leading..].to_owned())
    };
    PyPath::from_tail(String::new(), root, split_tail(&rel, '/'))
}

fn split_tail(rel: &str, sep: char) -> Vec<String> {
    if rel.is_empty() {
        return Vec::new();
    }
    rel.split(sep)
        .filter(|piece| !piece.is_empty() && *piece != ".")
        .map(str::to_owned)
        .collect()
}

fn splitroot_windows(part: &str) -> (String, String, String) {
    let chars: Vec<char> = part.chars().collect();
    let mut index = 0usize;
    let mut prefix = String::new();
    if char_at(&chars, 0) == Some('\\') && char_at(&chars, 1) == Some('\\') {
        let (extended, next) = split_extended(&chars);
        prefix = extended;
        index = next;
    }
    let first = char_at(&chars, index);
    let second = char_at(&chars, index + 1);
    let third = char_at(&chars, index + 2);
    if first == Some('\\') && second == Some('\\') && third != Some('\\') {
        if let Some(unc) = split_unc(&chars, index, &prefix) {
            return unc;
        }
    }
    let mut cursor = index;
    let mut drive = String::new();
    if first.is_some_and(|ch| ch.is_ascii_alphabetic()) && second == Some(':') {
        drive = chars[cursor..cursor + 2].iter().collect();
        cursor += 2;
    }
    let mut root = String::new();
    if char_at(&chars, cursor) == Some('\\') {
        root = "\\".to_owned();
        cursor += 1;
        while char_at(&chars, cursor) == Some('\\') {
            cursor += 1;
        }
    }
    let rel: String = chars.get(cursor..).unwrap_or_default().iter().collect();
    (format!("{prefix}{drive}"), root, rel)
}

fn split_extended(chars: &[char]) -> (String, usize) {
    if chars.len() >= 4
        && chars[0] == '\\'
        && chars[1] == '\\'
        && chars[2] == '?'
        && chars[3] == '\\'
    {
        let prefix: String = chars[..4].iter().collect();
        return (prefix, 4);
    }
    (String::new(), 0)
}

fn split_unc(chars: &[char], start: usize, prefix: &str) -> Option<(String, String, String)> {
    let index = find_char(chars, '\\', start + 2)?;
    let index2 = find_char(chars, '\\', index + 1).unwrap_or(chars.len());
    if index2 == index + 1 {
        return None;
    }
    let drive = if prefix.is_empty() {
        chars.get(start..index2)?.iter().collect()
    } else {
        let mut combined = prefix.to_owned();
        let from = start + 1;
        if from < index2 {
            combined.extend(chars.get(from..index2)?.iter().copied());
        }
        combined
    };
    let rel = if index2 >= chars.len() {
        String::new()
    } else {
        chars.get(index2 + 1..).unwrap_or_default().iter().collect()
    };
    Some((drive, "\\".to_owned(), rel))
}

fn char_at(chars: &[char], index: usize) -> Option<char> {
    chars.get(index).copied()
}

fn find_char(chars: &[char], needle: char, from: usize) -> Option<usize> {
    chars
        .iter()
        .skip(from)
        .position(|ch| *ch == needle)
        .map(|offset| from + offset)
}

fn prefix_equal(left: &[String], right: &[String]) -> bool {
    if right.len() > left.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .all(|(item, expected)| casefold(item) == casefold(expected))
}

fn casefold(text: &str) -> String {
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text.to_owned()
    }
}

#[cfg(test)]
mod port_1610 {
    use super::{
        apply_plan_assurance, build_repro_metadata, enforce_content_free, get_manifest_schema_path,
        get_report_schema_path, hint_path, human_bytes, load_manifest_schema, load_report_schema,
        minimize_id, minimize_path, python_str_repr, short_hash, ActionElem, ActionSeq,
        CapAssuranceUnavailable, ContentFreeError, ContentFreeInput, CountKey, CountValue, Counts,
        CountsInput, Coverage, CoverageInput, CoverageSkip, FindingElem, FindingsInput,
        HomeDirectoryError, InputKey, InputValue, MinimizePathError, MinimizedField, MinimizedId,
        PathInput, RepairAction, RepairManifest, RepairManifestParts, Report, ReportParts,
        ReproEntry, ReproMetadata, ReproRequest, ReproValue, RevalidationInput,
        RevalidationSummary, SchemaPathUnavailable, SesslintVersionUnavailable, SkipElem, SkipSeq,
        CAP_ASSURANCE, HASHLIB_SHA1, REPORT_SCHEMA_VERSION, RESOURCES_SCHEMA_PATH,
        SESSLINT_VERSION, SHORT_HASH_DEFAULT_LENGTH,
    };
    use model::codes::{Repairability, Severity, SL001};
    use model::finding::{
        enforce_content_free_text, Finding, FindingInput, PyValue, SourceLine, SourceRef,
        SCHEMA_VERSION,
    };
    use std::path::Path;

    const HOME: &str = "C:/SyntheticHome";
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn text(value: &str) -> InputValue {
        InputValue::str_value(value)
    }

    fn minimized(path: &str) -> Result<String, MinimizePathError> {
        minimize_path(PathInput::Text(path), Some(HOME))
    }

    fn hinted(path: &str) -> String {
        match hint_path(PathInput::Text(path), Some(HOME)) {
            Ok(value) => value,
            Err(error) => panic!("hint {path:?} failed: {error}"),
        }
    }

    fn binding(id: &str, version: &str) -> InputValue {
        InputValue::dict(vec![
            (InputKey::str_key("id"), text(id)),
            (InputKey::str_key("version"), text(version)),
        ])
    }

    fn counts_for(code: &str, total: i64) -> Counts {
        let by_severity = CountValue::dict(vec![
            (CountKey::str_key("fatal"), CountValue::int(0)),
            (CountKey::str_key("error"), CountValue::int(total)),
            (CountKey::str_key("warning"), CountValue::int(0)),
            (CountKey::str_key("info"), CountValue::int(0)),
        ]);
        let by_code = if total == 0 {
            CountValue::dict(Vec::new())
        } else {
            CountValue::dict(vec![(CountKey::str_key(code), CountValue::int(total))])
        };
        match Counts::try_new(&by_severity, &by_code, &CountValue::int(total)) {
            Ok(counts) => counts,
            Err(error) => panic!("counts rejected: {error}"),
        }
    }

    fn make_finding(
        message: &str,
        template: Option<&str>,
        path: &str,
        record_id: Option<&str>,
        related: &[&str],
    ) -> Finding {
        let source = match SourceRef::try_new(path, Some(SourceLine::Int(1)), record_id) {
            Ok(source) => source,
            Err(error) => panic!("source rejected: {error}"),
        };
        let template = match template {
            Some(value) => PyValue::string(value),
            None => PyValue::None,
        };
        match Finding::try_new(FindingInput {
            code: PyValue::string(SL001),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string(message),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(related.iter().copied().map(PyValue::string).collect()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: template,
            evidence: PyValue::None,
        }) {
            Ok(finding) => finding,
            Err(error) => panic!("finding rejected: {error}"),
        }
    }

    fn make_report(
        session_id: &str,
        fingerprint: &str,
        tool_version: &str,
        limitation: &str,
        findings: &[Finding],
        skips: &[CoverageSkip],
    ) -> Report {
        let coverage = match Coverage::try_new(
            &InputValue::tuple(Vec::new()),
            &SkipSeq::Tuple(skips.iter().cloned().map(SkipElem::Skip).collect()),
            &binding("canonical", "1"),
            &binding("neutral", "1"),
        ) {
            Ok(coverage) => coverage,
            Err(error) => panic!("coverage rejected: {error}"),
        };
        let schema = text(REPORT_SCHEMA_VERSION);
        let session = text(session_id);
        let source = text(fingerprint);
        let tool = text(tool_version);
        let assurance = text("A1");
        let limit = text(limitation);
        let findings_input =
            FindingsInput::Tuple(findings.iter().cloned().map(FindingElem::Finding).collect());
        let counts = counts_for(SL001, i64::try_from(findings.len()).unwrap_or(0));
        let counts_input = CountsInput::Value(counts);
        match Report::try_new(ReportParts {
            schema_version: &schema,
            session_id: &session,
            source_fingerprint: &source,
            tool_version: &tool,
            findings: &findings_input,
            counts: &counts_input,
            assurance: &assurance,
            limitation: &limit,
            coverage: CoverageInput::Value(&coverage),
        }) {
            Ok(report) => report,
            Err(error) => panic!("report rejected: {error}"),
        }
    }

    fn rich_report() -> Report {
        let skip = match CoverageSkip::try_new(
            &text("check-marker-eee"),
            &text("deselected"),
            &text("detail-marker-fff"),
        ) {
            Ok(skip) => skip,
            Err(error) => panic!("skip rejected: {error}"),
        };
        let finding = make_finding(
            "message-marker-ggg",
            Some("template-marker-hhh"),
            "path-marker-iii.jsonl",
            Some("record-marker-jjj"),
            &["rel-clean", "rel-marker-kkk"],
        );
        make_report(
            "sess-marker-aaa",
            "fp-marker-bbb",
            "tool-marker-ccc",
            "lim-marker-ddd",
            &[finding],
            &[skip],
        )
    }

    fn forbid(report: &Report, subs: &[&str]) -> ContentFreeError {
        match enforce_content_free(ContentFreeInput::Report(report), Some(subs)) {
            Ok(()) => panic!("expected a content-free failure"),
            Err(error) => error,
        }
    }

    fn forbidden_message(sub: &str, context: &str, text: &str) -> String {
        format!(
            "Forbidden payload text {} detected in {context}: {}",
            python_str_repr(sub),
            python_str_repr(text)
        )
    }

    fn rich_manifest() -> RepairManifest {
        let action = match RepairAction::try_new(
            &text("kind-marker-eee"),
            &text("record-marker-fff"),
            &text("detail-marker-ggg"),
        ) {
            Ok(action) => action,
            Err(error) => panic!("action rejected: {error}"),
        };
        let actions = ActionSeq::Tuple(vec![ActionElem::Action(action)]);
        let loss = InputValue::tuple(vec![text("loss-marker-ddd")]);
        let revalidation = match RevalidationSummary::try_new(
            &text("A1"),
            &InputValue::int(0),
            &InputValue::int(1),
            &text("profile-marker-hhh"),
            &text("ver-marker-iii"),
            &text("report-marker-jjj"),
        ) {
            Ok(summary) => summary,
            Err(error) => panic!("revalidation rejected: {error}"),
        };
        let revalidation = RevalidationInput::Summary(revalidation);
        let schema = text(model::version::MANIFEST_SCHEMA_VERSION);
        let input = text("in-marker-aaa");
        let output = text("out-marker-bbb");
        let policy = text("conservative");
        let revalidate = text("reports/reval-marker-ccc.json");
        let key_text = "a".repeat(64);
        let key = text(&key_text);
        let ceiling = text("A2");
        let none = InputValue::None;
        let empty = InputValue::dict(Vec::new());
        let adapter = text("adapter-marker-kkk");
        let adapter_version = text("version-marker-lll");
        match RepairManifest::try_new(RepairManifestParts {
            schema_version: &schema,
            input_fingerprint: &input,
            output_fingerprint: &output,
            policy: &policy,
            actions: &actions,
            declared_loss: &loss,
            revalidate_report: &revalidate,
            idempotency_key: &key,
            revalidation: &revalidation,
            assurance_ceiling: &ceiling,
            plan_fingerprint: &none,
            assurance: &none,
            recipe_versions: &empty,
            profile_version: &none,
            adapter_id: &adapter,
            adapter_version: &adapter_version,
            byte_counts: &empty,
            record_counts: &empty,
        }) {
            Ok(manifest) => manifest,
            Err(error) => panic!("manifest rejected: {error}"),
        }
    }

    #[test]
    fn report_fields_are_checked_in_pin_order() {
        let report = rich_report();
        let cases = [
            ("marker-aaa", "Report.session_id", "sess-marker-aaa"),
            ("marker-bbb", "Report.source_fingerprint", "fp-marker-bbb"),
            ("marker-ccc", "Report.tool_version", "tool-marker-ccc"),
            ("marker-ddd", "Report.limitation", "lim-marker-ddd"),
            (
                "marker-eee",
                "Report.coverage.skipped[0].check",
                "check-marker-eee",
            ),
            (
                "marker-fff",
                "Report.coverage.skipped[0].detail",
                "detail-marker-fff",
            ),
            (
                "marker-ggg",
                "Report.findings[0].message",
                "message-marker-ggg",
            ),
            (
                "marker-hhh",
                "Report.findings[0].message_template",
                "template-marker-hhh",
            ),
            (
                "marker-iii",
                "Report.findings[0].source.path",
                "path-marker-iii.jsonl",
            ),
            (
                "marker-jjj",
                "Report.findings[0].source.record_id",
                "record-marker-jjj",
            ),
            (
                "marker-kkk",
                "Report.findings[0].related_ids[1]",
                "rel-marker-kkk",
            ),
        ];
        for (sub, context, stored) in cases {
            match forbid(&report, &[sub]) {
                ContentFreeError::Leak(error) => {
                    assert_eq!(error.to_string(), forbidden_message(sub, context, stored));
                }
                ContentFreeError::Type(message) => panic!("type error for {context}: {message}"),
            }
        }
        let shared = make_report(
            "sess-shared-marker",
            "fp",
            "0.0.0",
            "lim-shared-marker",
            &[make_finding(
                "synthetic marker",
                None,
                "probe.jsonl",
                None,
                &[],
            )],
            &[],
        );
        match forbid(&shared, &["shared-marker"]) {
            ContentFreeError::Leak(error) => {
                assert_eq!(
                    error.to_string(),
                    forbidden_message("shared-marker", "Report.session_id", "sess-shared-marker")
                );
            }
            ContentFreeError::Type(message) => panic!("shared type error: {message}"),
        }
    }

    #[test]
    fn forbidden_substrings_strip_and_none_skips_only_the_extra_list() {
        let report = rich_report();
        match enforce_content_free(ContentFreeInput::Report(&report), None) {
            Ok(()) => {}
            Err(error) => panic!("none must not fail a clean report: {error}"),
        }
        match enforce_content_free(ContentFreeInput::Report(&report), Some(&[])) {
            Ok(()) => {}
            Err(error) => panic!("empty list must not fail: {error}"),
        }
        match enforce_content_free(ContentFreeInput::Report(&report), Some(&["", "   "])) {
            Ok(()) => {}
            Err(error) => panic!("blank substrings must be dropped: {error}"),
        }
        match forbid(&report, &["  marker-aaa  ", "", "marker-bbb"]) {
            ContentFreeError::Leak(error) => {
                assert_eq!(
                    error.to_string(),
                    forbidden_message("marker-aaa", "Report.session_id", "sess-marker-aaa")
                );
            }
            ContentFreeError::Type(message) => panic!("strip type error: {message}"),
        }
        let cased = make_report(
            "sess",
            "fp",
            "0.0.0",
            "Hello Marker",
            &[make_finding(
                "synthetic marker",
                None,
                "probe.jsonl",
                None,
                &[],
            )],
            &[],
        );
        match forbid(&cased, &["hello marker"]) {
            ContentFreeError::Leak(error) => {
                assert_eq!(
                    error.to_string(),
                    forbidden_message("hello marker", "Report.limitation", "Hello Marker")
                );
            }
            ContentFreeError::Type(message) => panic!("case type error: {message}"),
        }
    }

    #[test]
    fn intrinsic_leak_is_reported_before_the_substring_scan() {
        let report = make_report(
            "sess",
            "fp",
            "0.0.0",
            "line\nbreak",
            &[make_finding(
                "synthetic marker",
                None,
                "probe.jsonl",
                None,
                &[],
            )],
            &[],
        );
        let inner = match enforce_content_free_text("line\nbreak", "Report.limitation") {
            Ok(()) => panic!("newline must be an intrinsic leak"),
            Err(error) => error.to_string(),
        };
        match forbid(&report, &["line"]) {
            ContentFreeError::Leak(error) => {
                assert_eq!(
                    error.to_string(),
                    format!("Intrinsic content leak in Report.limitation: {inner}")
                );
                assert!(!error.to_string().contains("Forbidden payload"));
            }
            ContentFreeError::Type(message) => panic!("intrinsic type error: {message}"),
        }
    }

    #[test]
    fn other_artifacts_are_type_errors() {
        match enforce_content_free(
            ContentFreeInput::Other { type_name: "str" },
            Some(&["marker"]),
        ) {
            Err(ContentFreeError::Type(message)) => {
                assert_eq!(message, "Expected Report or RepairManifest, got str");
            }
            other => panic!("expected TypeError, got {other:?}"),
        }
        match enforce_content_free(
            ContentFreeInput::Other {
                type_name: "NoneType",
            },
            None,
        ) {
            Err(ContentFreeError::Type(message)) => {
                assert_eq!(message, "Expected Report or RepairManifest, got NoneType");
            }
            other => panic!("expected TypeError, got {other:?}"),
        }
    }

    #[test]
    fn manifest_fields_are_checked_in_pin_order() {
        let manifest = rich_manifest();
        let cases = [
            (
                "marker-aaa",
                "RepairManifest.input_fingerprint",
                "in-marker-aaa",
            ),
            (
                "marker-bbb",
                "RepairManifest.output_fingerprint",
                "out-marker-bbb",
            ),
            (
                "marker-ccc",
                "RepairManifest.revalidate_report",
                "reports/reval-marker-ccc.json",
            ),
            (
                "marker-ddd",
                "RepairManifest.declared_loss[0]",
                "loss-marker-ddd",
            ),
            (
                "marker-eee",
                "RepairManifest.actions[0].kind",
                "kind-marker-eee",
            ),
            (
                "marker-fff",
                "RepairManifest.actions[0].record_id",
                "record-marker-fff",
            ),
            (
                "marker-ggg",
                "RepairManifest.actions[0].detail",
                "detail-marker-ggg",
            ),
            (
                "marker-hhh",
                "RepairManifest.revalidation.profile_id",
                "profile-marker-hhh",
            ),
            (
                "marker-iii",
                "RepairManifest.revalidation.profile_version",
                "ver-marker-iii",
            ),
            (
                "marker-jjj",
                "RepairManifest.revalidation.report_fingerprint",
                "report-marker-jjj",
            ),
            (
                "marker-kkk",
                "RepairManifest.adapter_id",
                "adapter-marker-kkk",
            ),
        ];
        for (sub, context, stored) in cases {
            match enforce_content_free(ContentFreeInput::Manifest(&manifest), Some(&[sub])) {
                Err(ContentFreeError::Leak(error)) => {
                    assert_eq!(error.to_string(), forbidden_message(sub, context, stored));
                }
                other => panic!("manifest {context}: {other:?}"),
            }
        }
        match enforce_content_free(
            ContentFreeInput::Manifest(&manifest),
            Some(&["version-marker-lll"]),
        ) {
            Ok(()) => {}
            Err(error) => panic!("adapter_version is not a checked field: {error}"),
        }
    }

    #[test]
    fn schema_loaders_stop_at_the_missing_resource_helper() {
        let display = format!("{RESOURCES_SCHEMA_PATH} is not available");
        assert_eq!(SchemaPathUnavailable.to_string(), display);
        match get_report_schema_path() {
            Ok(path) => panic!("invented report schema path {}", path.display()),
            Err(error) => assert_eq!(error.to_string(), display),
        }
        match load_report_schema() {
            Ok(schema) => panic!("loaded a report schema: {schema:?}"),
            Err(error) => assert_eq!(error.to_string(), display),
        }
        match get_manifest_schema_path() {
            Ok(path) => panic!("invented manifest schema path {}", path.display()),
            Err(error) => assert_eq!(error.to_string(), display),
        }
        match load_manifest_schema() {
            Ok(schema) => panic!("loaded a manifest schema: {schema:?}"),
            Err(error) => assert_eq!(error.to_string(), display),
        }
    }

    #[test]
    fn plan_assurance_does_not_return_the_base_level() {
        let display = format!("{CAP_ASSURANCE} is not available");
        assert_eq!(CapAssuranceUnavailable.to_string(), display);
        match apply_plan_assurance("clean", &()) {
            Ok(level) => panic!("returned {level} unchanged"),
            Err(error) => {
                assert_eq!(error.to_string(), display);
                assert_ne!(error.to_string(), "clean");
            }
        }
    }

    #[test]
    fn minimize_path_renders_home_and_stops_before_sha1() {
        assert_eq!(minimized(HOME).expect("home"), "~");
        assert_eq!(hinted(HOME), "~/.");
        assert_eq!(
            minimized("C:/SyntheticHome/work/a.jsonl").expect("under"),
            "~/work/a.jsonl"
        );
        assert_eq!(hinted("C:/SyntheticHome/work/a.jsonl"), "~/work/a.jsonl");
        assert_eq!(
            minimized("C:\\SyntheticHome\\work\\a.jsonl").expect("slashes"),
            "~/work/a.jsonl"
        );
        if cfg!(windows) {
            assert_eq!(
                minimized("c:/synthetichome/Work/A.JSONL").expect("case"),
                "~/Work/A.JSONL"
            );
        } else {
            assert!(matches!(
                minimized("c:/synthetichome/Work/A.JSONL"),
                Err(MinimizePathError::Sha1)
            ));
        }
        assert_eq!(
            minimized("C:/SyntheticHome/work/../a.jsonl").expect("lexical dotdot"),
            "~/work/../a.jsonl"
        );
        assert_eq!(
            minimized("C:/Other/../SyntheticHome/a.jsonl").expect("resolved"),
            "~/a.jsonl"
        );
        assert_eq!(hinted("C:/Other/../SyntheticHome/a.jsonl"), "~/a.jsonl");
        assert_eq!(
            minimized("C:/Other/../SyntheticHome").expect("resolved home"),
            "~"
        );
        assert_eq!(hinted("C:/Other/../SyntheticHome"), "~/.");
        assert_eq!(
            minimized("C:/SyntheticHome/foo/../../SyntheticHome/a.jsonl").expect("prefix wins"),
            "~/foo/../../SyntheticHome/a.jsonl"
        );
        assert_eq!(
            minimized("C:/SyntheticHome/thư mục/a.jsonl").expect("unicode"),
            "~/thư mục/a.jsonl"
        );
        assert_eq!(minimized("C:/SyntheticHome/").expect("trailing"), "~");
        assert_eq!(hinted("C:/SyntheticHome/"), "~/.");
        assert_eq!(minimized("file.jsonl").expect("name"), "file.jsonl");
        assert_eq!(hinted("file.jsonl"), "file.jsonl");
        assert_eq!(minimized(".").expect("dot"), "");
        assert_eq!(hinted("."), ".");
        assert_eq!(minimized("..").expect("dotdot"), "..");
        assert_eq!(minimized("").expect("empty"), "");
        assert_eq!(hinted(""), "");
        assert_eq!(minimized("foo/.").expect("trailing dot"), "foo");
        assert_eq!(hinted("foo/."), "foo/.");
        assert_eq!(minimized("~").expect("tilde"), "~");
        assert_eq!(
            minimized("~/already/x").expect("tilde slash"),
            "~/already/x"
        );
        assert_eq!(
            minimized(".._abcd1234/x").expect("already hashed form"),
            ".._abcd1234/x"
        );
        assert_eq!(minimized(".._ab\\x").expect("raw prefix"), ".._ab\\x");
        assert_eq!(hinted(".._ab\\x"), ".._ab/x");
        let outside = minimized("C:/Other/dir/file.jsonl").expect_err("outside");
        assert_eq!(
            outside.to_string(),
            format!("{HASHLIB_SHA1} is not available")
        );
        assert!(!outside.to_string().contains(".._"));
        assert_eq!(hinted("C:/Other/dir/file.jsonl"), "C:/Other/dir/file.jsonl");
        assert!(matches!(
            minimized("dir/file.jsonl"),
            Err(MinimizePathError::Sha1)
        ));
        assert_eq!(hinted("dir/file.jsonl"), "dir/file.jsonl");
        assert!(matches!(minimized("foo/.."), Err(MinimizePathError::Sha1)));
        assert_eq!(hinted("foo/.."), "foo/..");
        assert!(matches!(
            minimized("C:relative/file"),
            Err(MinimizePathError::Sha1)
        ));
        assert_eq!(hinted("C:relative/file"), "C:relative/file");
        assert!(matches!(
            minimized("//server/share/file"),
            Err(MinimizePathError::Sha1)
        ));
        assert_eq!(hinted("//server/share/file"), "//server/share/file");
        assert_eq!(
            hinted("C:/nope/../nope2/a.jsonl"),
            "C:/nope/../nope2/a.jsonl"
        );
        let path_form = Path::new("~/already/x");
        assert!(matches!(
            minimize_path(PathInput::Path(path_form), Some(HOME)),
            Err(MinimizePathError::Sha1)
        ));
        assert_eq!(
            hint_path(PathInput::Path(path_form), Some(HOME)).expect("path hint"),
            "~/already/x"
        );
        let absolute = Path::new("C:/SyntheticHome/work/a.jsonl");
        assert_eq!(
            minimize_path(PathInput::Path(absolute), Some(HOME)).expect("path under"),
            "~/work/a.jsonl"
        );
    }

    #[test]
    fn provided_home_is_not_replaced_by_the_process_home() {
        assert_eq!(
            minimize_path(PathInput::Text("~/kept"), None).expect("prefix skips home"),
            "~/kept"
        );
        let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
        let Ok(real_home) = std::env::var(key) else {
            return;
        };
        if real_home.is_empty() {
            return;
        }
        let under_real = format!("{real_home}/sesslint-explicit-home.jsonl");
        let error = minimize_path(PathInput::Text(&under_real), Some(HOME))
            .expect_err("explicit home must win");
        assert_eq!(
            error.to_string(),
            format!("{HASHLIB_SHA1} is not available")
        );
        let hint = hint_path(PathInput::Text(&under_real), Some(HOME)).expect("hint outside");
        assert!(!hint.starts_with('~'), "{hint}");
        let under_explicit = format!("{real_home}/sesslint-process-home.jsonl");
        let rendered = minimize_path(PathInput::Text(&under_explicit), None).expect("process home");
        assert_eq!(rendered, "~/sesslint-process-home.jsonl");
        let again = minimize_path(PathInput::Text(&under_explicit), None).expect("second read");
        assert_eq!(again, rendered);
    }

    #[test]
    fn human_bytes_matches_python_boundaries() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(human_bytes(-1), "-1 B");
        assert_eq!(human_bytes(-1024), "-1024 B");
        assert_eq!(human_bytes(410), "410 B");
        assert_eq!(human_bytes(1280), "1.2 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(2048), "2.0 KiB");
        assert_eq!(human_bytes(11 * 1024 * 1024), "11.0 MiB");
        assert_eq!(human_bytes(1024 * 1024 - 1), "1024.0 KiB");
        assert_eq!(human_bytes(1024 * 1024 * 1024 - 1), "1024.0 MiB");
    }

    #[test]
    fn short_hash_and_minimize_id_keep_dict_order() {
        assert_eq!(SHORT_HASH_DEFAULT_LENGTH, 8);
        assert_eq!(short_hash("abc", 0), "");
        assert_eq!(short_hash("abc", 8), "ba7816bf");
        assert_eq!(short_hash("abc", 64), ABC_SHA256);
        assert_eq!(short_hash("abc", 65), ABC_SHA256);
        let identifier = "550e8400-e29b-41d4-a716-446655440000";
        let short = short_hash(identifier, 8);
        assert_eq!(
            minimize_id(identifier, None, false, false),
            MinimizedId::Text(short.clone())
        );
        let ordinal = InputValue::int(3);
        assert_eq!(
            minimize_id(identifier, Some(&ordinal), false, false),
            MinimizedId::Text("#3".to_owned())
        );
        let zero = InputValue::int(0);
        assert_eq!(
            minimize_id(identifier, Some(&zero), false, false),
            MinimizedId::Text("#0".to_owned())
        );
        assert_eq!(
            minimize_id(identifier, Some(&ordinal), true, false),
            MinimizedId::Text(identifier.to_owned())
        );
        let flag = InputValue::bool_value(true);
        assert_eq!(
            minimize_id(identifier, Some(&flag), false, false),
            MinimizedId::Text(short.clone())
        );
        let false_flag = InputValue::bool_value(false);
        assert_eq!(
            minimize_id(identifier, Some(&false_flag), false, false),
            MinimizedId::Text(short.clone())
        );
        match minimize_id(identifier, Some(&ordinal), true, true) {
            MinimizedId::Map(map) => {
                assert_eq!(
                    map.entries(),
                    vec![
                        ("short", MinimizedField::Text(short.clone())),
                        ("ordinal", MinimizedField::Int(3)),
                        ("full", MinimizedField::Text(identifier.to_owned())),
                    ]
                );
            }
            MinimizedId::Text(text) => panic!("dict mode returned {text}"),
        }
        match minimize_id(identifier, Some(&flag), true, true) {
            MinimizedId::Map(map) => {
                let keys: Vec<&str> = map.entries().iter().map(|(key, _)| *key).collect();
                assert_eq!(keys, vec!["short", "full"]);
            }
            MinimizedId::Text(text) => panic!("bool ordinal returned {text}"),
        }
    }

    #[test]
    fn repro_metadata_keeps_insertion_order_and_build_stops_at_version() {
        let metadata = ReproMetadata {
            cli_version: "test-cli".to_owned(),
            schema_versions: vec![
                ("z".to_owned(), "later".to_owned()),
                ("a".to_owned(), "earlier".to_owned()),
            ],
            adapter: vec![
                ("name".to_owned(), "canonical".to_owned()),
                ("version".to_owned(), "1.0.0".to_owned()),
            ],
            profile: vec![
                ("name".to_owned(), "neutral".to_owned()),
                ("version".to_owned(), "unknown".to_owned()),
            ],
            detection: vec![
                ("confidence".to_owned(), ReproValue::Null),
                ("method".to_owned(), ReproValue::Text("unknown".to_owned())),
            ],
            platform: vec![
                ("architecture".to_owned(), "synthetic".to_owned()),
                ("os".to_owned(), "synthetic".to_owned()),
                ("python".to_owned(), "synthetic".to_owned()),
            ],
        };
        let dict = metadata.to_dict();
        let keys: Vec<&str> = dict.entries().iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            vec![
                "adapter",
                "cli_version",
                "detection",
                "platform",
                "profile",
                "schema_versions",
            ]
        );
        assert_eq!(
            dict.schema_versions,
            vec![
                ("z".to_owned(), "later".to_owned()),
                ("a".to_owned(), "earlier".to_owned()),
            ]
        );
        match dict.entries().iter().find(|(key, _)| *key == "detection") {
            Some((_, ReproEntry::Any(entries))) => {
                assert_eq!(entries[0].0, "confidence");
                assert_eq!(entries[0].1, ReproValue::Null);
                assert_eq!(entries[1].0, "method");
            }
            other => panic!("detection order lost: {other:?}"),
        }
        let explicit = ReproMetadata {
            detection: vec![
                ("confidence".to_owned(), ReproValue::Float(0.87)),
                ("method".to_owned(), ReproValue::Text("auto".to_owned())),
            ],
            ..metadata
        };
        assert_eq!(explicit.to_dict().detection[0].1, ReproValue::Float(0.87));
        let request = ReproRequest {
            adapter_name: "canonical",
            adapter_version: "1.0.0",
            profile_name: "neutral",
            profile_version: "1.0.0",
            detection_method: "auto",
            detection_confidence: Some(0.87),
        };
        match build_repro_metadata(request) {
            Ok(built) => panic!("invented repro metadata {built:?}"),
            Err(error) => {
                assert_eq!(
                    error.to_string(),
                    format!("{SESSLINT_VERSION} is not available")
                );
                assert_eq!(SesslintVersionUnavailable.to_string(), error.to_string());
                let rendered = error.to_string();
                assert!(!rendered.contains("0.0.0"));
                assert!(!rendered.contains("windows"));
                assert!(!rendered.contains("x86_64"));
            }
        }
    }

    #[test]
    fn home_directory_error_names_the_python_message() {
        assert_eq!(
            HomeDirectoryError.to_string(),
            "Could not determine home directory."
        );
    }
}
