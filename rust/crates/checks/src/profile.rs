//! Profile data, configuration resolution, and the canonical guard.
//!
//! Port of `src/sesslint/profiles/profile.py` lines 1–318
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`get_profile`] and [`list_profiles`] do not read a registry.
//! `sesslint.profiles.builtin` is not ported. Any path that would import it
//! returns [`BUILTIN_UNAVAILABLE`] and does not invent `REGISTRY` or
//! `ALL_RULES`. [`builtin`](crate::builtin) is a later card.
//!
//! # Recorded gaps
//!
//! * [`str::trim`] does not drop U+001C through U+001F. Python `str.strip`
//!   does. A format override that is valid only after those characters are
//!   removed stays invalid here. No Unicode crate is added.
//! * There is no `bytes` input. Python rejects `bytes` before the sequence
//!   check (`got bytes`). That value cannot be represented, and a byte
//!   string is not walked as events.
//! * A float or a list schema has no honest Python `repr`. The guard returns
//!   [`EventError::PythonFloatStr`] or [`EventError::PythonStr`] and does
//!   not invent one. A mapping schema uses the same list/mapping error.
//! * [`EventValue::Other`] has no Python type name. The guard returns
//!   [`PYTHON_TYPE_NAME_UNREPRESENTABLE`] and does not invent `got int`.
//! * A `bool` is not an `f64`. `true` is not coerced to `1.0`.
//! * The `KeyError` suggestion inside [`get_profile`] stays unreachable.
//!   No fuzzy-match crate is added.
//! * Bound and margin messages format finite floats with Rust debug text,
//!   appending `.0` when that text has no decimal mark. `0.0`, `1.0`, `0.2`,
//!   and `0.3` match CPython. Other magnitudes can differ from Python `str`.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use model::canonical::SCHEMA_VERSION;
use model::codes::Severity;
use model::events::{EventError, EventField, EventMapping, EventValue};

/// Python `sesslint.profiles.builtin` is not ported.
pub const BUILTIN_UNAVAILABLE: &str = "sesslint.profiles.builtin is not available";

/// [`EventValue::Other`] has no Python type name.
pub const PYTHON_TYPE_NAME_UNREPRESENTABLE: &str =
    "A sequence element that is neither SessionEvent nor a mapping has no Python type name";

/// Python: `VALID_FORMATS`, source literal order.
///
/// Membership is a linear scan. The invalid-format error sorts a copy.
pub const VALID_FORMATS: [&str; 8] = [
    "auto",
    "canonical",
    "claude",
    "openai",
    "codex",
    "claude-code-jsonl",
    "openai-agents",
    "codex-rollout",
];

/// Python `__all__`, in that order. [`deselected_rules`] is public and omitted.
pub const ALL: [&str; 9] = [
    "EffectiveConfig",
    "Profile",
    "VALID_FORMATS",
    "apply_rule_selection",
    "get_profile",
    "list_profiles",
    "require_canonical",
    "resolve_effective_config",
    "stamp_source_profile",
];

/// Vec-backed map. Insertion order is the vec order.
///
/// Inserting an existing key replaces the value and keeps that position.
/// Keys are not sorted. This is not a [`std::collections::BTreeMap`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedMap<T> {
    entries: Vec<(String, T)>,
}

impl<T> Default for OrderedMap<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T> OrderedMap<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[(String, T)] {
        &self.entries
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        self.entries
            .iter()
            .find(|(existing, _)| existing == key)
            .map(|(_, value)| value)
    }

    /// Replace `key` in place, or append it.
    pub fn insert(&mut self, key: impl Into<String>, value: T) {
        let key = key.into();
        if let Some((_, slot)) = self
            .entries
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            *slot = value;
        } else {
            self.entries.push((key, value));
        }
    }
}

/// One JSON-like value in a profile or source dictionary.
#[derive(Clone, Debug, PartialEq)]
pub enum DictValue {
    Null,
    Str(String),
    Int(i64),
    Float(f64),
    List(Vec<DictValue>),
    Map(Vec<(String, DictValue)>),
}

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    BuiltinUnavailable,
    MutualExclusion,
    NonFiniteConfidence,
    NonFiniteMargin,
    Message(String),
    Event(EventError),
    PythonTypeName,
}

impl ProfileError {
    pub fn message(&self) -> &str {
        match self {
            Self::BuiltinUnavailable => BUILTIN_UNAVAILABLE,
            Self::MutualExclusion => "select and ignore are mutually exclusive",
            Self::NonFiniteConfidence => "confidence_min must be a finite float",
            Self::NonFiniteMargin => "margin_min must be a finite float",
            Self::Message(text) => text,
            Self::Event(error) => error.message(),
            Self::PythonTypeName => PYTHON_TYPE_NAME_UNREPRESENTABLE,
        }
    }
}

impl fmt::Display for ProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ProfileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Event(error) => Some(error),
            Self::BuiltinUnavailable
            | Self::MutualExclusion
            | Self::NonFiniteConfidence
            | Self::NonFiniteMargin
            | Self::Message(_)
            | Self::PythonTypeName => None,
        }
    }
}

/// Immutable specification of a replay validation profile.
///
/// [`Profile::new`] sets `version` to `"1.0.0"`, `rule_severities` empty, and
/// `timestamp_skew_ms` to `2000`.
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub allowed_adapters: Vec<String>,
    pub enabled_rules: Vec<String>,
    pub thresholds: OrderedMap<f64>,
    pub checkpoint_sensitivity: String,
    pub version: String,
    pub rule_severities: OrderedMap<Severity>,
    pub timestamp_skew_ms: i64,
}

impl Profile {
    pub fn new<A, E>(
        name: impl Into<String>,
        description: impl Into<String>,
        allowed_adapters: A,
        enabled_rules: E,
        thresholds: OrderedMap<f64>,
        checkpoint_sensitivity: impl Into<String>,
    ) -> Self
    where
        A: IntoIterator,
        A::Item: Into<String>,
        E: IntoIterator,
        E::Item: Into<String>,
    {
        Self {
            name: name.into(),
            description: description.into(),
            allowed_adapters: allowed_adapters.into_iter().map(Into::into).collect(),
            enabled_rules: enabled_rules.into_iter().map(Into::into).collect(),
            thresholds,
            checkpoint_sensitivity: checkpoint_sensitivity.into(),
            version: "1.0.0".to_owned(),
            rule_severities: OrderedMap::new(),
            timestamp_skew_ms: 2000,
        }
    }

    /// Python: `Profile.to_dict`.
    ///
    /// Key order is `allowed_adapters`, `checkpoint_sensitivity`,
    /// `description`, `enabled_rules`, `name`, `thresholds`,
    /// `timestamp_skew_ms`, `version`. `rule_severities` is appended only
    /// when non-empty, and those keys are sorted. Severity values are
    /// [`Severity::as_str`]. `allowed_adapters`, `enabled_rules`, and
    /// `thresholds` keep their existing order.
    pub fn to_dict(&self) -> Vec<(String, DictValue)> {
        let mut dict = vec![
            (
                "allowed_adapters".to_owned(),
                DictValue::List(string_list(&self.allowed_adapters)),
            ),
            (
                "checkpoint_sensitivity".to_owned(),
                DictValue::Str(self.checkpoint_sensitivity.clone()),
            ),
            (
                "description".to_owned(),
                DictValue::Str(self.description.clone()),
            ),
            (
                "enabled_rules".to_owned(),
                DictValue::List(string_list(&self.enabled_rules)),
            ),
            ("name".to_owned(), DictValue::Str(self.name.clone())),
            (
                "thresholds".to_owned(),
                DictValue::Map(
                    self.thresholds
                        .entries()
                        .iter()
                        .map(|(key, value)| (key.clone(), DictValue::Float(*value)))
                        .collect(),
                ),
            ),
            (
                "timestamp_skew_ms".to_owned(),
                DictValue::Int(self.timestamp_skew_ms),
            ),
            ("version".to_owned(), DictValue::Str(self.version.clone())),
        ];
        if !self.rule_severities.is_empty() {
            dict.push((
                "rule_severities".to_owned(),
                DictValue::Map(sorted_severities(&self.rule_severities)),
            ));
        }
        dict
    }
}

/// Resolved runtime configuration.
///
/// `to_dict` does not include `version`.
#[derive(Clone, Debug, PartialEq)]
pub struct EffectiveConfig {
    pub profile: String,
    pub description: String,
    pub allowed_adapters: Vec<String>,
    pub enabled_rules: Vec<String>,
    pub confidence_min: f64,
    pub margin_min: f64,
    pub checkpoint_sensitivity: String,
    pub format_override: Option<String>,
    pub thresholds_source: String,
    pub version: String,
}

impl EffectiveConfig {
    /// Python: `EffectiveConfig.to_dict`.
    ///
    /// `confidence_min` and `margin_min` are Python `round(value, 4)`.
    pub fn to_dict(&self) -> Vec<(String, DictValue)> {
        vec![
            (
                "allowed_adapters".to_owned(),
                DictValue::List(string_list(&self.allowed_adapters)),
            ),
            (
                "checkpoint_sensitivity".to_owned(),
                DictValue::Str(self.checkpoint_sensitivity.clone()),
            ),
            (
                "confidence_min".to_owned(),
                DictValue::Float(python_round4(self.confidence_min)),
            ),
            (
                "description".to_owned(),
                DictValue::Str(self.description.clone()),
            ),
            (
                "enabled_rules".to_owned(),
                DictValue::List(string_list(&self.enabled_rules)),
            ),
            (
                "format_override".to_owned(),
                optional_string(&self.format_override),
            ),
            (
                "margin_min".to_owned(),
                DictValue::Float(python_round4(self.margin_min)),
            ),
            ("profile".to_owned(), DictValue::Str(self.profile.clone())),
            (
                "thresholds_source".to_owned(),
                DictValue::Str(self.thresholds_source.clone()),
            ),
        ]
    }

    /// Python: `EffectiveConfig.to_source_resolution`.
    pub fn to_source_resolution(&self) -> Vec<(String, DictValue)> {
        vec![
            (
                "confidence_min".to_owned(),
                DictValue::Float(python_round4(self.confidence_min)),
            ),
            (
                "format_override".to_owned(),
                optional_string(&self.format_override),
            ),
            (
                "margin_min".to_owned(),
                DictValue::Float(python_round4(self.margin_min)),
            ),
            ("profile".to_owned(), DictValue::Str(self.profile.clone())),
            (
                "thresholds_source".to_owned(),
                DictValue::Str(self.thresholds_source.clone()),
            ),
        ]
    }
}

/// Python `Profile | str`.
///
/// [`ProfileInput::Name`] resolves through [`get_profile`] before any other
/// check. That returns [`BUILTIN_UNAVAILABLE`].
#[derive(Clone, Copy, Debug)]
pub enum ProfileInput<'a> {
    Name(&'a str),
    Profile(&'a Profile),
}

/// Input for [`require_canonical`].
///
/// [`CanonicalInput::Str`] is Python `str` and is not a sequence of events.
/// There is no `bytes` variant.
#[derive(Clone, Copy, Debug)]
pub enum CanonicalInput<'a> {
    None,
    Mapping(&'a EventMapping),
    Sequence(&'a [EventValue]),
    Str(&'a str),
}

/// Python: `get_profile`.
///
/// Always returns [`BUILTIN_UNAVAILABLE`]. The name is not looked up, and the
/// close-match suggestion does not run.
pub fn get_profile(name: &str) -> Result<Profile, ProfileError> {
    let _ = name;
    Err(ProfileError::BuiltinUnavailable)
}

/// Python: `list_profiles`.
///
/// Always returns [`BUILTIN_UNAVAILABLE`].
pub fn list_profiles() -> Result<Vec<String>, ProfileError> {
    Err(ProfileError::BuiltinUnavailable)
}

/// Python: `resolve_effective_config`.
///
/// A [`ProfileInput::Name`] returns [`BUILTIN_UNAVAILABLE`] before the format
/// and threshold checks. `format_override` of `None` stays `None`. Any other
/// text is trimmed and lowercased. Rust trim leaves U+001C through U+001F in
/// place. An empty cleaned value, or one outside [`VALID_FORMATS`], is
/// invalid. The stored override is the cleaned string.
///
/// Missing `confidence_min` uses the profile key or `0.55`. Missing
/// `margin_min` uses the profile key or `0.15`. An explicit value wins and
/// sets `thresholds_source` to `"cli"`; otherwise the source is `"profile"`.
/// The numeric arguments are `f64`. A bool cannot be passed.
///
/// # Errors
///
/// A name, an invalid format, a non-finite threshold, a threshold outside
/// `(0.0, 1.0)`, or `margin_min` greater than `confidence_min`.
pub fn resolve_effective_config(
    profile: ProfileInput<'_>,
    format_override: Option<&str>,
    confidence_min: Option<f64>,
    margin_min: Option<f64>,
) -> Result<EffectiveConfig, ProfileError> {
    let prof = match profile {
        ProfileInput::Name(name) => get_profile(name)?,
        ProfileInput::Profile(prof) => prof.clone(),
    };

    let format_override = match format_override {
        None => None,
        Some(raw) => {
            let cleaned = raw.trim().to_lowercase();
            if cleaned.is_empty() || !VALID_FORMATS.contains(&cleaned.as_str()) {
                return Err(ProfileError::Message(invalid_format_message(raw)));
            }
            Some(cleaned)
        }
    };

    let thresholds_source = if confidence_min.is_some() || margin_min.is_some() {
        "cli"
    } else {
        "profile"
    };
    let conf = match confidence_min {
        Some(value) => value,
        None => prof
            .thresholds
            .get("confidence_min")
            .copied()
            .unwrap_or(0.55),
    };
    let marg = match margin_min {
        Some(value) => value,
        None => prof.thresholds.get("margin_min").copied().unwrap_or(0.15),
    };

    if !conf.is_finite() {
        return Err(ProfileError::NonFiniteConfidence);
    }
    if !marg.is_finite() {
        return Err(ProfileError::NonFiniteMargin);
    }
    if !(conf > 0.0 && conf < 1.0) {
        return Err(ProfileError::Message(bounds_message(
            "confidence_min",
            conf,
        )));
    }
    if !(marg > 0.0 && marg < 1.0) {
        return Err(ProfileError::Message(bounds_message("margin_min", marg)));
    }
    if marg > conf {
        return Err(ProfileError::Message(format!(
            "margin_min ({}) cannot exceed confidence_min ({})",
            python_float_text(marg),
            python_float_text(conf)
        )));
    }

    Ok(EffectiveConfig {
        profile: prof.name.clone(),
        description: prof.description.clone(),
        allowed_adapters: prof.allowed_adapters.clone(),
        enabled_rules: prof.enabled_rules.clone(),
        confidence_min: conf,
        margin_min: marg,
        checkpoint_sensitivity: prof.checkpoint_sensitivity.clone(),
        format_override,
        thresholds_source: thresholds_source.to_owned(),
        version: prof.version.clone(),
    })
}

/// Python: `apply_rule_selection`.
///
/// A name returns [`BUILTIN_UNAVAILABLE`] before the mutual-exclusion check.
/// On a [`Profile`], both sides non-empty returns the mutual-exclusion error
/// and does not ask for builtin. Both sides empty or `None` return that same
/// profile. One side non-empty returns [`BUILTIN_UNAVAILABLE`]. An empty list
/// is not a selection. Rules are not filtered.
pub fn apply_rule_selection<S, I>(
    profile: ProfileInput<'_>,
    select: Option<&[S]>,
    ignore: Option<&[I]>,
) -> Result<Profile, ProfileError>
where
    S: AsRef<str>,
    I: AsRef<str>,
{
    let prof = match profile {
        ProfileInput::Name(name) => get_profile(name)?,
        ProfileInput::Profile(prof) => prof.clone(),
    };
    let has_select = is_selection(select);
    let has_ignore = is_selection(ignore);
    if has_select && has_ignore {
        return Err(ProfileError::MutualExclusion);
    }
    if !has_select && !has_ignore {
        return Ok(prof);
    }
    // `sesslint.profiles.builtin.ALL_RULES` is not available. Do not filter.
    let _ = (select, ignore);
    Err(ProfileError::BuiltinUnavailable)
}

/// Python: `deselected_rules`.
///
/// A name returns [`BUILTIN_UNAVAILABLE`] even when no selection is set. A
/// profile with no selection returns an empty set. Both sides non-empty
/// returns the mutual-exclusion error. One side returns
/// [`BUILTIN_UNAVAILABLE`].
pub fn deselected_rules<S, I>(
    profile: ProfileInput<'_>,
    select: Option<&[S]>,
    ignore: Option<&[I]>,
) -> Result<BTreeSet<String>, ProfileError>
where
    S: AsRef<str>,
    I: AsRef<str>,
{
    let prof = match profile {
        ProfileInput::Name(name) => get_profile(name)?,
        ProfileInput::Profile(prof) => prof.clone(),
    };
    if !is_selection(select) && !is_selection(ignore) {
        return Ok(BTreeSet::new());
    }
    let selected = apply_rule_selection(ProfileInput::Profile(&prof), select, ignore)?;
    let kept: BTreeSet<&str> = selected.enabled_rules.iter().map(String::as_str).collect();
    Ok(prof
        .enabled_rules
        .iter()
        .filter(|rule| !kept.contains(rule.as_str()))
        .cloned()
        .collect())
}

/// Python: `require_canonical`.
///
/// A mapping reads `schema` when that value is truthy, otherwise
/// `schema_version`. Missing, null, false, `0`, and `""` fall through.
/// Bool `true`, a non-zero int, and a non-empty string are used. The value
/// must equal [`SCHEMA_VERSION`]. A float or a list has no honest Python
/// `repr` and returns the existing typed error.
///
/// Either `events` or `session_id` must then be present. The value may be
/// null. An empty sequence is accepted. The first [`model::canonical::SessionEvent`] is
/// accepted. A mapping needs a `kind` key, and a null kind still counts.
/// Text is rejected and is not treated as events.
pub fn require_canonical(session_or_events: CanonicalInput<'_>) -> Result<(), ProfileError> {
    match session_or_events {
        CanonicalInput::None => Err(ProfileError::Message(
            "Input cannot be None; expected canonical session or events".to_owned(),
        )),
        CanonicalInput::Mapping(mapping) => require_mapping(mapping),
        CanonicalInput::Sequence(events) => require_sequence(events),
        CanonicalInput::Str(_) => Err(ProfileError::Message(
            "Expected canonical session Mapping or Sequence of events, got str".to_owned(),
        )),
    }
}

/// Python: `stamp_source_profile`.
///
/// Copies `source_block` in its existing order. `profile` and `resolution`
/// replace an existing key in place, or append. `None` or an empty map
/// starts with `profile`, then `resolution`. Caller keys are not sorted.
/// `resolution` is [`EffectiveConfig::to_source_resolution`].
pub fn stamp_source_profile(
    source_block: Option<&OrderedMap<DictValue>>,
    effective_config: &EffectiveConfig,
) -> OrderedMap<DictValue> {
    let mut block = match source_block {
        Some(block) => block.clone(),
        None => OrderedMap::new(),
    };
    block.insert("profile", DictValue::Str(effective_config.profile.clone()));
    block.insert(
        "resolution",
        DictValue::Map(effective_config.to_source_resolution()),
    );
    block
}

/// Python `round(value, 4)`.
///
/// CPython 3.11 formats a finite float with correctly rounded four digits
/// after the decimal point (`dtoa` mode 3) and parses that decimal back.
/// `{value:.4}` followed by `f64` parse matches those results, including the
/// half-even value `0.03125` (exact `1/32`), which Python prints as `0.0312`.
/// This is not [`f64::round`]. Non-finite values are unchanged, matching
/// `round`.
fn python_round4(value: f64) -> f64 {
    if !value.is_finite() {
        return value;
    }
    let text = format!("{value:.4}");
    text.parse::<f64>().unwrap_or(value)
}

fn python_float_text(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        };
    }
    let text = format!("{value:?}");
    if text.contains(['.', 'e', 'E']) {
        text
    } else {
        format!("{text}.0")
    }
}

fn python_str_repr(text: &str) -> String {
    let use_double = text.contains('\'') && !text.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::new();
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\'' if !use_double => out.push_str("\\'"),
            '"' if use_double => out.push_str("\\\""),
            ch if (u32::from(ch)) < 32 || ch == '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", u32::from(ch)));
            }
            ch => out.push(ch),
        }
    }
    out.push(quote);
    out
}

fn valid_formats_repr() -> String {
    let mut names = VALID_FORMATS;
    names.sort_unstable();
    let mut out = String::from("[");
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(name));
    }
    out.push(']');
    out
}

fn invalid_format_message(original: &str) -> String {
    format!(
        "Invalid format override {}. Must be one of {}",
        python_str_repr(original),
        valid_formats_repr()
    )
}

fn bounds_message(name: &str, value: f64) -> String {
    format!(
        "{name} must be strictly between 0.0 and 1.0 exclusive, got {}",
        python_float_text(value)
    )
}

fn string_list(items: &[String]) -> Vec<DictValue> {
    items
        .iter()
        .map(|item| DictValue::Str(item.clone()))
        .collect()
}

fn optional_string(value: &Option<String>) -> DictValue {
    match value {
        Some(text) => DictValue::Str(text.clone()),
        None => DictValue::Null,
    }
}

fn sorted_severities(severities: &OrderedMap<Severity>) -> Vec<(String, DictValue)> {
    let mut pairs: Vec<(String, DictValue)> = severities
        .entries()
        .iter()
        .map(|(code, severity)| (code.clone(), DictValue::Str(severity.as_str().to_owned())))
        .collect();
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    pairs
}

fn is_selection<T>(items: Option<&[T]>) -> bool {
    items.is_some_and(|items| !items.is_empty())
}

fn is_truthy(value: &EventField) -> bool {
    match value {
        EventField::Null => false,
        EventField::Bool(flag) => *flag,
        EventField::Int(number) => *number != 0,
        EventField::Float(number) => float_is_truthy(*number),
        EventField::Str(text) => !text.is_empty(),
        EventField::List(items) => !items.is_empty(),
        EventField::Mapping(mapping) => !mapping.entries().is_empty(),
    }
}

fn float_is_truthy(number: f64) -> bool {
    let magnitude = number.to_bits() & !(1_u64 << 63);
    magnitude != 0
}

fn selected_schema(mapping: &EventMapping) -> Option<&EventField> {
    if let Some(value) = mapping.get("schema") {
        if is_truthy(value) {
            return Some(value);
        }
    }
    mapping.get("schema_version")
}

fn require_mapping(mapping: &EventMapping) -> Result<(), ProfileError> {
    let schema = selected_schema(mapping);
    if let Some(EventField::Str(text)) = schema {
        if text == SCHEMA_VERSION {
            if mapping.get("events").is_none() && mapping.get("session_id").is_none() {
                return Err(ProfileError::Message(
                    "Canonical session dictionary must contain 'events' array or 'session_id'"
                        .to_owned(),
                ));
            }
            return Ok(());
        }
    }
    schema_mismatch(schema)
}

fn schema_mismatch(schema: Option<&EventField>) -> Result<(), ProfileError> {
    let rendered = match schema {
        None | Some(EventField::Null) => "None".to_owned(),
        Some(EventField::Bool(true)) => "True".to_owned(),
        Some(EventField::Bool(false)) => "False".to_owned(),
        Some(EventField::Int(number)) => number.to_string(),
        Some(EventField::Str(text)) => python_str_repr(text),
        Some(EventField::Float(_)) => {
            return Err(ProfileError::Event(EventError::PythonFloatStr));
        }
        Some(EventField::List(_) | EventField::Mapping(_)) => {
            return Err(ProfileError::Event(EventError::PythonStr));
        }
    };
    let schema_repr = python_str_repr(SCHEMA_VERSION);
    Err(ProfileError::Message(format!(
        "Expected canonical session schema {schema_repr}, got {rendered}"
    )))
}

fn require_sequence(events: &[EventValue]) -> Result<(), ProfileError> {
    let Some(first) = events.first() else {
        return Ok(());
    };
    match first {
        EventValue::Session(_) => Ok(()),
        EventValue::Mapping(mapping) if mapping.get("kind").is_none() => {
            Err(ProfileError::Message(
                "Non-canonical event dictionary missing required 'kind' field".to_owned(),
            ))
        }
        EventValue::Mapping(_) => Ok(()),
        EventValue::Other => Err(ProfileError::PythonTypeName),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_rule_selection, deselected_rules, get_profile, list_profiles, require_canonical,
        resolve_effective_config, stamp_source_profile, CanonicalInput, DictValue, EffectiveConfig,
        OrderedMap, Profile, ProfileInput, ALL, BUILTIN_UNAVAILABLE,
        PYTHON_TYPE_NAME_UNREPRESENTABLE, VALID_FORMATS,
    };
    use model::canonical::{SessionEvent, SCHEMA_VERSION};
    use model::codes::Severity;
    use model::events::{
        EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };

    const PROFILE_KEYS: [&str; 8] = [
        "allowed_adapters",
        "checkpoint_sensitivity",
        "description",
        "enabled_rules",
        "name",
        "thresholds",
        "timestamp_skew_ms",
        "version",
    ];
    const EFFECTIVE_KEYS: [&str; 9] = [
        "allowed_adapters",
        "checkpoint_sensitivity",
        "confidence_min",
        "description",
        "enabled_rules",
        "format_override",
        "margin_min",
        "profile",
        "thresholds_source",
    ];
    const RESOLUTION_KEYS: [&str; 5] = [
        "confidence_min",
        "format_override",
        "margin_min",
        "profile",
        "thresholds_source",
    ];
    const SORTED_FORMATS: &str = "['auto', 'canonical', 'claude', 'claude-code-jsonl', 'codex', 'codex-rollout', 'openai', 'openai-agents']";

    fn sample(thresholds: OrderedMap<f64>) -> Profile {
        Profile::new(
            "replay",
            "synthetic profile",
            ["codex", "claude"],
            ["SL002", "SL001"],
            thresholds,
            "strict",
        )
    }

    fn keys_of(dict: &[(String, DictValue)]) -> Vec<&str> {
        dict.iter().map(|(key, _)| key.as_str()).collect()
    }

    fn map_keys(map: &OrderedMap<DictValue>) -> Vec<&str> {
        map.entries().iter().map(|(key, _)| key.as_str()).collect()
    }

    fn float_at<'a>(dict: &'a [(String, DictValue)], key: &str) -> &'a DictValue {
        dict.iter()
            .find(|(entry, _)| entry == key)
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("missing {key}"))
    }

    fn assert_rounded(dict: &[(String, DictValue)], key: &str, printed: &str, bits: u64) {
        match float_at(dict, key) {
            DictValue::Float(number) => {
                assert_eq!(number.to_bits(), bits, "{key}");
                assert_eq!(format!("{number:?}"), printed, "{key}");
            }
            other => panic!("expected float for {key}, got {other:?}"),
        }
    }

    fn field_map(entries: Vec<(&str, EventField)>) -> EventMapping {
        EventMapping::new(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    #[test]
    fn defaults_and_to_dict_order() {
        let mut thresholds = OrderedMap::new();
        thresholds.insert("margin_min", 0.2);
        thresholds.insert("confidence_min", 0.5);
        let profile = sample(thresholds);
        assert_eq!(profile.version, "1.0.0");
        assert!(profile.rule_severities.is_empty());
        assert_eq!(profile.timestamp_skew_ms, 2000);

        let dict = profile.to_dict();
        assert_eq!(keys_of(&dict).as_slice(), PROFILE_KEYS.as_slice());
        assert_eq!(
            float_at(&dict, "allowed_adapters"),
            &DictValue::List(vec![
                DictValue::Str("codex".to_owned()),
                DictValue::Str("claude".to_owned()),
            ])
        );
        assert_eq!(
            float_at(&dict, "enabled_rules"),
            &DictValue::List(vec![
                DictValue::Str("SL002".to_owned()),
                DictValue::Str("SL001".to_owned()),
            ])
        );
        match float_at(&dict, "thresholds") {
            DictValue::Map(entries) => {
                assert_eq!(
                    keys_of(entries),
                    ["margin_min".to_owned(), "confidence_min".to_owned()]
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(float_at(&dict, "timestamp_skew_ms"), &DictValue::Int(2000));
        assert_eq!(
            float_at(&dict, "version"),
            &DictValue::Str("1.0.0".to_owned())
        );
        assert!(!keys_of(&dict).contains(&"rule_severities"));
    }

    #[test]
    fn empty_rule_severities_omitted() {
        let dict = sample(OrderedMap::new()).to_dict();
        assert!(!keys_of(&dict).contains(&"rule_severities"));
    }

    #[test]
    fn severities_sorted_with_python_values() {
        let mut profile = sample(OrderedMap::new());
        profile.rule_severities.insert("SL010", Severity::Info);
        profile.rule_severities.insert("SL001", Severity::Fatal);
        profile.rule_severities.insert("SL002", Severity::Warning);
        profile.rule_severities.insert("SL003", Severity::Error);
        let dict = profile.to_dict();
        let mut expected = PROFILE_KEYS.to_vec();
        expected.push("rule_severities");
        assert_eq!(keys_of(&dict).as_slice(), expected.as_slice());
        match float_at(&dict, "rule_severities") {
            DictValue::Map(entries) => {
                assert_eq!(
                    entries,
                    &vec![
                        ("SL001".to_owned(), DictValue::Str("fatal".to_owned())),
                        ("SL002".to_owned(), DictValue::Str("warning".to_owned())),
                        ("SL003".to_owned(), DictValue::Str("error".to_owned())),
                        ("SL010".to_owned(), DictValue::Str("info".to_owned())),
                    ]
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn threshold_update_keeps_position() {
        let mut thresholds = OrderedMap::<f64>::new();
        thresholds.insert("margin_min", 0.2);
        thresholds.insert("confidence_min", 0.5);
        thresholds.insert("other", 0.3);
        thresholds.insert("margin_min", 0.11);
        assert_eq!(
            thresholds
                .entries()
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            ["margin_min", "confidence_min", "other"]
        );
        assert_eq!(
            thresholds.get("margin_min").copied().unwrap().to_bits(),
            0.11_f64.to_bits()
        );
        let dict = sample(thresholds).to_dict();
        match float_at(&dict, "thresholds") {
            DictValue::Map(entries) => {
                assert_eq!(
                    keys_of(entries).as_slice(),
                    ["margin_min", "confidence_min", "other"].as_slice()
                );
                assert_eq!(entries[0].1, DictValue::Float(0.11));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn effective_config_rounds_locked_python_values() {
        // CPython 3.11.9 `repr(round(x, 4))` and `float.hex` of that result.
        // `0.03125` is exact `1/32`, halfway between `0.0312` and `0.0313`.
        // Python prints `0.0312`.
        const ROUND_055_BITS: u64 = 0x3fe1_9999_9999_999a;
        const ROUND_015_BITS: u64 = 0x3fc3_3333_3333_3333;
        const ROUND_0312_BITS: u64 = 0x3f9f_f2e4_8e8a_71de;

        let mut profile = sample(OrderedMap::new());
        profile.version = "9.9.9".to_owned();
        let defaults =
            resolve_effective_config(ProfileInput::Profile(&profile), None, None, None).unwrap();
        assert_eq!(defaults.thresholds_source, "profile");
        assert_eq!(defaults.version, "9.9.9");
        assert_eq!(defaults.confidence_min.to_bits(), 0.55_f64.to_bits());
        assert_eq!(defaults.margin_min.to_bits(), 0.15_f64.to_bits());
        assert!(defaults.format_override.is_none());
        let dict = defaults.to_dict();
        let resolution = defaults.to_source_resolution();
        assert_eq!(keys_of(&dict).as_slice(), EFFECTIVE_KEYS.as_slice());
        assert_eq!(keys_of(&resolution).as_slice(), RESOLUTION_KEYS.as_slice());
        assert!(!keys_of(&dict).contains(&"version"));
        for rendered in [&dict, &resolution] {
            assert_rounded(rendered, "confidence_min", "0.55", ROUND_055_BITS);
            assert_rounded(rendered, "margin_min", "0.15", ROUND_015_BITS);
        }
        assert_eq!(float_at(&dict, "format_override"), &DictValue::Null);
        assert_eq!(
            float_at(&dict, "allowed_adapters"),
            &DictValue::List(vec![
                DictValue::Str("codex".to_owned()),
                DictValue::Str("claude".to_owned()),
            ])
        );

        let halfway =
            resolve_effective_config(ProfileInput::Profile(&profile), None, None, Some(0.03125))
                .unwrap();
        assert_eq!(halfway.thresholds_source, "cli");
        assert_eq!(halfway.margin_min.to_bits(), 0.03125_f64.to_bits());
        assert_ne!(halfway.margin_min.to_bits(), ROUND_0312_BITS);
        for rendered in [halfway.to_dict(), halfway.to_source_resolution()] {
            assert_rounded(&rendered, "confidence_min", "0.55", ROUND_055_BITS);
            assert_rounded(&rendered, "margin_min", "0.0312", ROUND_0312_BITS);
        }
    }

    #[test]
    fn explicit_threshold_overrides_profile_and_sets_cli() {
        let mut thresholds = OrderedMap::new();
        thresholds.insert("confidence_min", 0.4);
        thresholds.insert("margin_min", 0.1);
        let profile = sample(thresholds);
        let overridden =
            resolve_effective_config(ProfileInput::Profile(&profile), None, Some(0.7), None)
                .unwrap();
        assert_eq!(overridden.confidence_min.to_bits(), 0.7_f64.to_bits());
        assert_eq!(overridden.margin_min.to_bits(), 0.1_f64.to_bits());
        assert_eq!(overridden.thresholds_source, "cli");

        let from_profile =
            resolve_effective_config(ProfileInput::Profile(&profile), None, None, None).unwrap();
        assert_eq!(from_profile.confidence_min.to_bits(), 0.4_f64.to_bits());
        assert_eq!(from_profile.margin_min.to_bits(), 0.1_f64.to_bits());
        assert_eq!(from_profile.thresholds_source, "profile");
    }

    #[test]
    fn threshold_bounds_match_python_messages() {
        let profile = sample(OrderedMap::new());
        let resolve = |conf, marg| {
            resolve_effective_config(ProfileInput::Profile(&profile), None, conf, marg)
                .unwrap_err()
                .to_string()
        };
        assert_eq!(
            resolve(Some(f64::NAN), Some(0.0)),
            "confidence_min must be a finite float"
        );
        assert_eq!(
            resolve(Some(0.0), Some(f64::NAN)),
            "margin_min must be a finite float"
        );
        assert_eq!(
            resolve(Some(f64::INFINITY), None),
            "confidence_min must be a finite float"
        );
        assert_eq!(
            resolve(None, Some(f64::NEG_INFINITY)),
            "margin_min must be a finite float"
        );
        assert_eq!(
            resolve(Some(0.0), None),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 0.0"
        );
        assert_eq!(
            resolve(Some(1.0), None),
            "confidence_min must be strictly between 0.0 and 1.0 exclusive, got 1.0"
        );
        assert_eq!(
            resolve(None, Some(0.0)),
            "margin_min must be strictly between 0.0 and 1.0 exclusive, got 0.0"
        );
        assert_eq!(
            resolve(Some(0.2), Some(0.3)),
            "margin_min (0.3) cannot exceed confidence_min (0.2)"
        );
    }

    #[test]
    fn format_strip_and_invalid_format() {
        let profile = sample(OrderedMap::new());
        assert_eq!(
            VALID_FORMATS,
            [
                "auto",
                "canonical",
                "claude",
                "openai",
                "codex",
                "claude-code-jsonl",
                "openai-agents",
                "codex-rollout",
            ]
        );
        for name in VALID_FORMATS {
            let config = resolve_effective_config(
                ProfileInput::Profile(&profile),
                Some(&format!("  {name} ")),
                None,
                None,
            )
            .unwrap();
            assert_eq!(config.format_override.as_deref(), Some(name));
        }
        let mixed = resolve_effective_config(
            ProfileInput::Profile(&profile),
            Some("  Claude-Code-JSONL\n"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(mixed.format_override.as_deref(), Some("claude-code-jsonl"));
        let absent =
            resolve_effective_config(ProfileInput::Profile(&profile), None, None, None).unwrap();
        assert!(absent.format_override.is_none());

        let invalid = resolve_effective_config(
            ProfileInput::Profile(&profile),
            Some("  NOPE "),
            Some(f64::NAN),
            None,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            invalid,
            format!("Invalid format override '  NOPE '. Must be one of {SORTED_FORMATS}")
        );
        let blank =
            resolve_effective_config(ProfileInput::Profile(&profile), Some(" \n\t "), None, None)
                .unwrap_err()
                .to_string();
        assert_eq!(
            blank,
            format!("Invalid format override ' \\n\\t '. Must be one of {SORTED_FORMATS}")
        );
        // Python strip would drop U+001C and accept `auto`. Rust trim does not.
        let file_separator = resolve_effective_config(
            ProfileInput::Profile(&profile),
            Some("\u{1c}auto"),
            None,
            None,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            file_separator,
            format!("Invalid format override '\\x1cauto'. Must be one of {SORTED_FORMATS}")
        );
    }

    #[test]
    fn name_lookup_unavailable() {
        assert_eq!(
            BUILTIN_UNAVAILABLE,
            "sesslint.profiles.builtin is not available"
        );
        assert_eq!(
            get_profile("replay").unwrap_err().to_string(),
            "sesslint.profiles.builtin is not available"
        );
        assert_eq!(
            list_profiles().unwrap_err().to_string(),
            "sesslint.profiles.builtin is not available"
        );
        let named = resolve_effective_config(
            ProfileInput::Name("replay"),
            Some("not-a-format"),
            Some(f64::NAN),
            Some(2.0),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(named, "sesslint.profiles.builtin is not available");
        let deselected = deselected_rules::<&str, &str>(ProfileInput::Name("replay"), None, None)
            .unwrap_err()
            .to_string();
        assert_eq!(deselected, "sesslint.profiles.builtin is not available");
    }

    #[test]
    fn mutual_exclusion_before_builtin() {
        let profile = sample(OrderedMap::new());
        let err = apply_rule_selection(
            ProfileInput::Profile(&profile),
            Some(&["SL001"][..]),
            Some(&["SL002"][..]),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(err, "select and ignore are mutually exclusive");
        let deselected = deselected_rules(
            ProfileInput::Profile(&profile),
            Some(&["SL001"][..]),
            Some(&["SL002"][..]),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(deselected, "select and ignore are mutually exclusive");

        let named = apply_rule_selection(
            ProfileInput::Name("replay"),
            Some(&["SL001"][..]),
            Some(&["SL002"][..]),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(named, "sesslint.profiles.builtin is not available");
    }

    #[test]
    fn empty_selection_does_not_call_builtin() {
        let profile = sample(OrderedMap::new());
        let empty: &[&str] = &[];
        let same = apply_rule_selection::<&str, &str>(ProfileInput::Profile(&profile), None, None)
            .unwrap();
        assert_eq!(same, profile);
        let same = apply_rule_selection(ProfileInput::Profile(&profile), Some(empty), Some(empty))
            .unwrap();
        assert_eq!(same.enabled_rules, profile.enabled_rules);
        assert!(
            deselected_rules::<&str, &str>(ProfileInput::Profile(&profile), None, None)
                .unwrap()
                .is_empty()
        );
        assert!(
            deselected_rules(ProfileInput::Profile(&profile), Some(empty), Some(empty))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn one_sided_selection_is_unavailable() {
        let profile = sample(OrderedMap::new());
        let empty: &[&str] = &[];
        let assert_side = |select: Option<&[&str]>, ignore: Option<&[&str]>| {
            let err = apply_rule_selection(ProfileInput::Profile(&profile), select, ignore)
                .unwrap_err()
                .to_string();
            assert_eq!(err, "sesslint.profiles.builtin is not available");
            let deselected = deselected_rules(ProfileInput::Profile(&profile), select, ignore)
                .unwrap_err()
                .to_string();
            assert_eq!(deselected, "sesslint.profiles.builtin is not available");
        };
        assert_side(Some(&["SL001"][..]), None);
        assert_side(None, Some(&["SL002"][..]));
        assert_side(Some(empty), Some(&["SL002"][..]));
        assert_eq!(
            profile.enabled_rules,
            ["SL002".to_owned(), "SL001".to_owned()]
        );
    }

    #[test]
    fn require_canonical_none() {
        let err = require_canonical(CanonicalInput::None)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Input cannot be None; expected canonical session or events"
        );
    }

    #[test]
    fn require_canonical_bad_schema() {
        let nope = field_map(vec![
            ("schema", EventField::Str("nope".to_owned())),
            ("events", EventField::Null),
        ]);
        assert_eq!(
            require_canonical(CanonicalInput::Mapping(&nope))
                .unwrap_err()
                .to_string(),
            "Expected canonical session schema 'sesslint.session/v1', got 'nope'"
        );
        let truth = field_map(vec![
            ("schema", EventField::Bool(true)),
            ("events", EventField::List(Vec::new())),
        ]);
        assert_eq!(
            require_canonical(CanonicalInput::Mapping(&truth))
                .unwrap_err()
                .to_string(),
            "Expected canonical session schema 'sesslint.session/v1', got True"
        );
        let number = field_map(vec![
            ("schema", EventField::Int(2)),
            ("events", EventField::Null),
        ]);
        assert_eq!(
            require_canonical(CanonicalInput::Mapping(&number))
                .unwrap_err()
                .to_string(),
            "Expected canonical session schema 'sesslint.session/v1', got 2"
        );
        let float_schema = field_map(vec![
            ("schema", EventField::Float(1.5)),
            ("events", EventField::Null),
        ]);
        let err = require_canonical(CanonicalInput::Mapping(&float_schema))
            .unwrap_err()
            .to_string();
        assert_eq!(err, PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(!err.contains("1.5"));
        let list_schema = field_map(vec![("schema", EventField::List(vec![EventField::Int(1)]))]);
        assert_eq!(
            require_canonical(CanonicalInput::Mapping(&list_schema))
                .unwrap_err()
                .to_string(),
            PYTHON_STR_UNREPRESENTABLE
        );

        let fallthrough = field_map(vec![
            ("schema", EventField::Str(String::new())),
            ("schema_version", EventField::Str(SCHEMA_VERSION.to_owned())),
            ("session_id", EventField::Null),
        ]);
        assert!(require_canonical(CanonicalInput::Mapping(&fallthrough)).is_ok());
        let false_schema = field_map(vec![("schema", EventField::Bool(false))]);
        assert_eq!(
            require_canonical(CanonicalInput::Mapping(&false_schema))
                .unwrap_err()
                .to_string(),
            "Expected canonical session schema 'sesslint.session/v1', got None"
        );
        let false_version = field_map(vec![
            ("schema_version", EventField::Bool(false)),
            ("events", EventField::List(Vec::new())),
        ]);
        assert_eq!(
            require_canonical(CanonicalInput::Mapping(&false_version))
                .unwrap_err()
                .to_string(),
            "Expected canonical session schema 'sesslint.session/v1', got False"
        );
        let zeros = field_map(vec![
            ("schema", EventField::Int(0)),
            ("schema_version", EventField::Int(0)),
        ]);
        assert_eq!(
            require_canonical(CanonicalInput::Mapping(&zeros))
                .unwrap_err()
                .to_string(),
            "Expected canonical session schema 'sesslint.session/v1', got 0"
        );
        let empty_strings = field_map(vec![
            ("schema", EventField::Str(String::new())),
            ("schema_version", EventField::Str(String::new())),
        ]);
        assert_eq!(
            require_canonical(CanonicalInput::Mapping(&empty_strings))
                .unwrap_err()
                .to_string(),
            "Expected canonical session schema 'sesslint.session/v1', got ''"
        );
    }

    #[test]
    fn require_canonical_missing_events_and_session_id() {
        let mapping = field_map(vec![("schema", EventField::Str(SCHEMA_VERSION.to_owned()))]);
        assert_eq!(
            require_canonical(CanonicalInput::Mapping(&mapping))
                .unwrap_err()
                .to_string(),
            "Canonical session dictionary must contain 'events' array or 'session_id'"
        );
        let null_id = field_map(vec![
            ("schema_version", EventField::Str(SCHEMA_VERSION.to_owned())),
            ("session_id", EventField::Null),
        ]);
        assert!(require_canonical(CanonicalInput::Mapping(&null_id)).is_ok());
    }

    #[test]
    fn require_canonical_empty_event_list() {
        assert!(require_canonical(CanonicalInput::Sequence(&[])).is_ok());
    }

    #[test]
    fn require_canonical_session_event() {
        let event = SessionEvent::new(
            "evt-synthetic",
            None,
            0,
            "2020-01-01T00:00:00Z",
            "user",
            "message",
        );
        let events = [EventValue::from_session(event)];
        assert!(require_canonical(CanonicalInput::Sequence(&events)).is_ok());
    }

    #[test]
    fn require_canonical_mapping_without_kind() {
        let missing = EventMapping::new(Vec::new());
        let events = [EventValue::Mapping(missing)];
        assert_eq!(
            require_canonical(CanonicalInput::Sequence(&events))
                .unwrap_err()
                .to_string(),
            "Non-canonical event dictionary missing required 'kind' field"
        );
        let null_kind = EventMapping::new(vec![("kind".to_owned(), EventField::Null)]);
        let events = [EventValue::Mapping(null_kind)];
        assert!(require_canonical(CanonicalInput::Sequence(&events)).is_ok());
    }

    #[test]
    fn require_canonical_text_rejected() {
        let err = require_canonical(CanonicalInput::Str("sesslint.session/v1"))
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Expected canonical session Mapping or Sequence of events, got str"
        );
        let events = [EventValue::Other];
        let other = require_canonical(CanonicalInput::Sequence(&events))
            .unwrap_err()
            .to_string();
        assert_eq!(other, PYTHON_TYPE_NAME_UNREPRESENTABLE);
        assert!(!other.contains("got "));
    }

    #[test]
    fn stamp_updates_existing_profile_key_in_place() {
        let profile = sample(OrderedMap::new());
        let config =
            resolve_effective_config(ProfileInput::Profile(&profile), Some(" auto "), None, None)
                .unwrap();
        assert_eq!(config.format_override.as_deref(), Some("auto"));

        let mut block = OrderedMap::new();
        block.insert("adapter", DictValue::Str("codex".to_owned()));
        block.insert("profile", DictValue::Str("old-name".to_owned()));
        block.insert("tail", DictValue::Int(1));
        let stamped = stamp_source_profile(Some(&block), &config);
        assert_eq!(
            map_keys(&stamped).as_slice(),
            ["adapter", "profile", "tail", "resolution"].as_slice()
        );
        assert_eq!(
            stamped.get("profile"),
            Some(&DictValue::Str("replay".to_owned()))
        );
        assert_eq!(
            stamped.get("adapter"),
            Some(&DictValue::Str("codex".to_owned()))
        );
        assert_eq!(stamped.get("tail"), Some(&DictValue::Int(1)));
        assert_eq!(
            stamped.get("resolution"),
            Some(&DictValue::Map(config.to_source_resolution()))
        );

        let mut existing = OrderedMap::new();
        existing.insert("resolution", DictValue::Null);
        existing.insert("profile", DictValue::Str("old-name".to_owned()));
        let updated = stamp_source_profile(Some(&existing), &config);
        assert_eq!(
            map_keys(&updated).as_slice(),
            ["resolution", "profile"].as_slice()
        );
        assert_eq!(
            updated.get("resolution"),
            Some(&DictValue::Map(config.to_source_resolution()))
        );

        let fresh = stamp_source_profile(None, &config);
        assert_eq!(
            map_keys(&fresh).as_slice(),
            ["profile", "resolution"].as_slice()
        );
        let empty = stamp_source_profile(Some(&OrderedMap::new()), &config);
        assert_eq!(
            map_keys(&empty).as_slice(),
            ["profile", "resolution"].as_slice()
        );
    }

    #[test]
    fn all_is_python_order_and_omits_deselected_rules() {
        assert_eq!(ALL.len(), 9);
        assert_eq!(
            ALL,
            [
                "EffectiveConfig",
                "Profile",
                "VALID_FORMATS",
                "apply_rule_selection",
                "get_profile",
                "list_profiles",
                "require_canonical",
                "resolve_effective_config",
                "stamp_source_profile",
            ]
        );
        assert!(!ALL.contains(&"deselected_rules"));
        let profile = sample(OrderedMap::new());
        assert!(
            deselected_rules::<&str, &str>(ProfileInput::Profile(&profile), None, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn direct_effective_config_rounds_halfway_confidence() {
        let config = EffectiveConfig {
            profile: "replay".to_owned(),
            description: "synthetic profile".to_owned(),
            allowed_adapters: vec!["codex".to_owned()],
            enabled_rules: Vec::new(),
            confidence_min: 0.03125,
            margin_min: 0.15,
            checkpoint_sensitivity: "strict".to_owned(),
            format_override: None,
            thresholds_source: "profile".to_owned(),
            version: "1.0.0".to_owned(),
        };
        for rendered in [config.to_dict(), config.to_source_resolution()] {
            assert_rounded(&rendered, "confidence_min", "0.0312", 0x3f9f_f2e4_8e8a_71de);
            assert_rounded(&rendered, "margin_min", "0.15", 0x3fc3_3333_3333_3333);
        }
    }
}
