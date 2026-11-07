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
//! The late import `sesslint.codes` (`SL001`, `SL002`, `Severity`) is the
//! ported codes registry. `enforce_content_free_text` is the ported finding
//! helper. No wall clock, randomness, or `HashMap` is used.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use model::canonical::CanonicalUnavailable;
use model::codes::{Severity, SL001, SL002};
use model::errors::{AssuranceError, ContentLeakError, SchemaError, VersionError};
use model::finding::{enforce_content_free_text, DictValue, Finding};
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

#[cfg(test)]
mod tests {
    use super::{
        action_sort_key, build_report, compute_assurance, compute_manifest_idempotency_key,
        default_coverage, skip_sort_key, ActionElem, ActionSeq, ActionSortFields, BuildCoverage,
        BuildReportParts, CountKey, CountValue, Counts, CountsInput, Coverage, CoverageInput,
        CoverageSkip, EnvelopeError, FindingElem, FindingsInput, IdempotencyError, InputKey,
        InputValue, RepairAction, RepairManifest, RepairManifestParts, Report, ReportParts,
        RevalidationInput, RevalidationSummary, SkipElem, SkipSeq, SkipSortFields,
        ASSURANCE_LIMITATIONS, PROFILES_BUILTIN_ALL_RULES, REPORT_SCHEMA_VERSION,
        REQUIRED_SEVERITIES, VALID_ASSURANCE_LEVELS, VALID_COVERAGE_SKIP_REASONS,
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
}
