//! Assurance level, finding counts, and coverage-skip sort key.
//!
//! Port of `src/sesslint/report.py` lines 1–270
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`, limited to
//! [`compute_assurance`], [`Counts`], and `_skip_sort_key`, plus the constants
//! those symbols read (`ASSURANCE_LIMITATIONS`, `REQUIRED_SEVERITIES`).
//!
//! `CoverageSkip` validation starts at line 274 of that pin and is not
//! constructed here. [`skip_sort_key`] only reads `check`, `reason`, and
//! `detail`. Schema versions, policy sets, field-name sets, and the SHA-256
//! pattern in the same span are not read by these three symbols.
//!
//! The late import `sesslint.codes` (`SL001`, `SL002`, `Severity`) is the
//! ported codes registry. No wall clock, randomness, or `HashMap` is used.

use std::collections::BTreeMap;

use model::codes::{Severity, SL001, SL002};
use model::errors::SchemaError;
use model::finding::Finding;

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
/// zero. `by_code` equality matches Python `dict` equality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
    by_severity: BTreeMap<String, i64>,
    by_code: BTreeMap<String, i64>,
    total: i64,
}

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
        let by_code = require_code_map(by_code)?;
        Ok(Self {
            by_severity,
            by_code,
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

fn require_code_map(value: &CountValue) -> Result<BTreeMap<String, i64>, SchemaError> {
    let Some(entries) = mapping_entries(value) else {
        return Err(schema(format!(
            "Counts.by_code must be a Mapping, got {}",
            type_name(value)
        )));
    };
    let collapsed = collapse(entries);
    let mut by_code = BTreeMap::new();
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
    }
    Ok(by_code)
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
/// This is not a `CoverageSkip`. The constructor that checks the reason
/// vocabulary and content-free text is past line 270 of the pin.
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

#[cfg(test)]
mod tests {
    use super::{
        compute_assurance, skip_sort_key, CountKey, CountValue, Counts, SkipSortFields,
        ASSURANCE_LIMITATIONS, REQUIRED_SEVERITIES,
    };
    use model::codes::{Repairability, Severity, SL001, SL002, SL003, SL101};
    use model::errors::SchemaError;
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
}
