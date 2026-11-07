//! Assurance level, finding counts, coverage, and the report envelope.
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
//! The late import `sesslint.codes` (`SL001`, `SL002`, `Severity`) is the
//! ported codes registry. `enforce_content_free_text` is the ported finding
//! helper. No wall clock, randomness, or `HashMap` is used.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use model::codes::{Severity, SL001, SL002};
use model::errors::{AssuranceError, ContentLeakError, SchemaError, VersionError};
use model::finding::{enforce_content_free_text, DictValue, Finding};

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
/// or [`default_coverage`].
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
/// This is not a `RepairAction`. The constructor that strips and checks those
/// fields is past line 542 of the pin. `None` and `Some("")` stay distinct:
/// only `None` uses the `(0, "")` record key.
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

#[cfg(test)]
mod tests {
    use super::{
        action_sort_key, compute_assurance, default_coverage, skip_sort_key, ActionSortFields,
        CountKey, CountValue, Counts, CountsInput, Coverage, CoverageInput, CoverageSkip,
        EnvelopeError, FindingElem, FindingsInput, InputKey, InputValue, Report, ReportParts,
        SkipElem, SkipSeq, SkipSortFields, ASSURANCE_LIMITATIONS, PROFILES_BUILTIN_ALL_RULES,
        REPORT_SCHEMA_VERSION, REQUIRED_SEVERITIES, VALID_ASSURANCE_LEVELS,
        VALID_COVERAGE_SKIP_REASONS,
    };
    use model::codes::{Repairability, Severity, SL001, SL002, SL003, SL101};
    use model::errors::SchemaError;
    use model::errors::{AssuranceError, VersionError};
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
}
