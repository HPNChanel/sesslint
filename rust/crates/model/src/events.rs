//! Shared canonical-event field accessors and converters (DW-T-10).
//!
//! Port of `src/sesslint/_events.py` lines 1–113
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Private Python module: not part of the public API surface.
//!
//! The four getters check the attribute first. Only when that value is `None`
//! and the object is a mapping do they use the mapping key. A [`SessionEvent`]
//! is not a mapping. `None` stays `None`; it is not the string `"None"`.
//! `str(True)` is `True`, `str(False)` is `False`, an int is its decimal text,
//! and a string stays the string.
//!
//! Hashing and canonical JSON stay on their seams. This module does not call
//! the codec crate, does not call `sesslint.determinism.canonical_json_bytes`,
//! and does not hash.
//!
//! # Recorded gaps
//!
//! * [`event_content_fingerprint`] on a [`SessionEvent`] with a missing or
//!   empty `content_hash` does not call [`SessionEvent::payload_hash`]. That
//!   Rust method returns a stored empty string and would hide
//!   [`CanonicalUnavailable::payload_content_hash`].
//! * A mapping payload, or a whole mapping, needs
//!   `sesslint.determinism.canonical_json_bytes`. The typed error Display is
//!   [`DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE`]. Nothing is hashed.
//! * [`SessionEvent::to_canonical_bytes`] is the codec canonical-bytes seam.
//!   The error is propagated; no digest is produced.
//! * The final `sha256(str(ev))` branch is not representable for the values
//!   this crate can hold ([`PYTHON_STR_HASH_UNREPRESENTABLE`]). `sha2` is not
//!   added to cover it.
//! * A float's Python `str` is not matched here
//!   ([`PYTHON_FLOAT_STR_UNREPRESENTABLE`]). The getter returns that error and
//!   does not panic.
//! * [`to_event_dict`] on a [`SessionEvent`] calls
//!   [`SessionEvent::to_canonical_dict`] and propagates
//!   [`CanonicalUnavailable::normalize_canonical`]. The `hasattr` path does
//!   not catch the error and does not fall back to `dict(ev)`.
//! * The module `to_canonical_dict` is the same unavailable normalize seam.
//!   The tolerant `dict(ev)` fallback is not simulated
//!   ([`DICT_FALLBACK_NOT_SIMULATED`]).

use std::error::Error;
use std::fmt;

use crate::canonical::{to_canonical_dict, CanonicalUnavailable, Payload, SessionEvent};

/// Late import. `model` cannot depend on the codec crate, and this module
/// does not reimplement canonical JSON.
pub const DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE: &str =
    "sesslint.determinism.canonical_json_bytes is not available";

/// Final `hashlib.sha256(str(ev).encode("utf-8")).hexdigest()` branch.
pub const PYTHON_STR_HASH_UNREPRESENTABLE: &str =
    "sha256(str(ev)) is not representable for the values this crate can hold";

/// Python `str(float)` is not matched in this crate.
pub const PYTHON_FLOAT_STR_UNREPRESENTABLE: &str = "Python str(float) is not representable";

/// Python `_to_event_dict` `except Exception: dict(ev)` is not simulated.
pub const DICT_FALLBACK_NOT_SIMULATED: &str =
    "The tolerant dict(ev) fallback in _to_event_dict is not simulated";

/// Python `str()` of a non-scalar field value is not matched here.
pub const PYTHON_STR_UNREPRESENTABLE: &str =
    "Python str() of this event field is not representable";

/// Failure from a seam this slice does not implement.
///
/// [`Display`] is the message only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    Canonical(CanonicalUnavailable),
    DeterminismCanonicalJsonBytes,
    PythonFloatStr,
    PythonStrHash,
    PythonStr,
}

impl EventError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::Canonical(error) => error.message(),
            Self::DeterminismCanonicalJsonBytes => DETERMINISM_CANONICAL_JSON_BYTES_UNAVAILABLE,
            Self::PythonFloatStr => PYTHON_FLOAT_STR_UNREPRESENTABLE,
            Self::PythonStrHash => PYTHON_STR_HASH_UNREPRESENTABLE,
            Self::PythonStr => PYTHON_STR_UNREPRESENTABLE,
        }
    }
}

impl fmt::Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for EventError {}

impl From<CanonicalUnavailable> for EventError {
    fn from(error: CanonicalUnavailable) -> Self {
        Self::Canonical(error)
    }
}

/// Ordered mapping. Insertion order is the vec order. Keys are not sorted.
/// Last matching string key wins, matching [`Payload`] field lookup.
#[derive(Clone, Debug, PartialEq)]
pub struct EventMapping {
    entries: Vec<(String, EventField)>,
}

impl EventMapping {
    pub fn new(entries: Vec<(String, EventField)>) -> Self {
        Self { entries }
    }

    pub fn entries(&self) -> &[(String, EventField)] {
        &self.entries
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(key, _)| key.as_str())
    }

    pub fn get(&self, key: &str) -> Option<&EventField> {
        self.entries
            .iter()
            .rev()
            .find(|(entry_key, _)| entry_key == key)
            .map(|(_, value)| value)
    }

    pub fn push(&mut self, key: impl Into<String>, value: EventField) {
        self.entries.push((key.into(), value));
    }

    /// Python `copy.deepcopy(dict(ev))` as a new [`Payload`] map.
    ///
    /// Entry order is insertion order. Keys are not sorted. Nested values
    /// are new [`Payload`] nodes.
    pub fn to_payload(&self) -> Payload {
        Payload::map(
            self.entries
                .iter()
                .map(|(key, value)| (Payload::string(key.clone()), field_to_payload(value)))
                .collect(),
        )
    }
}

/// JSON-like field stored on an [`EventMapping`].
#[derive(Clone, Debug, PartialEq)]
pub enum EventField {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<EventField>),
    Mapping(EventMapping),
}

/// Python `Any` values this crate can hold for the `_event_*` helpers.
#[derive(Clone, Debug)]
pub enum EventValue {
    Session(Box<SessionEvent>),
    Mapping(EventMapping),
    Other,
}

impl EventValue {
    pub fn from_session(event: SessionEvent) -> Self {
        Self::Session(Box::new(event))
    }
}

/// Python: `_event_kind`.
pub fn event_kind(ev: &EventValue) -> Result<Option<String>, EventError> {
    let k = match ev {
        EventValue::Session(event) => Some(EventField::Str(event.kind.clone())),
        EventValue::Mapping(_) | EventValue::Other => None,
    };
    field_to_optional_str(attribute_or_mapping(ev, k, "kind"))
}

/// Python: `_event_id`.
pub fn event_id(ev: &EventValue) -> Result<Option<String>, EventError> {
    let i = match ev {
        EventValue::Session(event) => Some(EventField::Str(event.id.clone())),
        EventValue::Mapping(_) | EventValue::Other => None,
    };
    field_to_optional_str(attribute_or_mapping(ev, i, "id"))
}

/// Python: `_event_parent_id`.
pub fn event_parent_id(ev: &EventValue) -> Result<Option<String>, EventError> {
    let p = match ev {
        EventValue::Session(event) => event
            .parent_id
            .as_deref()
            .map(|text| EventField::Str(text.to_owned())),
        EventValue::Mapping(_) | EventValue::Other => None,
    };
    field_to_optional_str(attribute_or_mapping(ev, p, "parent_id"))
}

/// Python: `_event_corr_id`.
pub fn event_corr_id(ev: &EventValue) -> Result<Option<String>, EventError> {
    let c = match ev {
        EventValue::Session(event) => event
            .correlation_id
            .as_deref()
            .map(|text| EventField::Str(text.to_owned())),
        EventValue::Mapping(_) | EventValue::Other => None,
    };
    field_to_optional_str(attribute_or_mapping(ev, c, "correlation_id"))
}

/// Python: `_event_content_fingerprint`.
///
/// Order follows the pin. A non-empty string `content_hash` is returned as
/// itself. An empty string is false in Python and falls through.
pub fn event_content_fingerprint(ev: &EventValue) -> Result<String, EventError> {
    let ch = match ev {
        EventValue::Session(event) => event.content_hash.clone().map(EventField::Str),
        EventValue::Mapping(_) | EventValue::Other => None,
    };
    let ch = attribute_or_mapping(ev, ch, "content_hash");
    if let Some(EventField::Str(text)) = &ch {
        if !text.is_empty() {
            return Ok(text.clone());
        }
    }
    match ev {
        EventValue::Session(_) => Err(EventError::from(
            CanonicalUnavailable::payload_content_hash(),
        )),
        EventValue::Mapping(mapping) => {
            if matches!(mapping.get("payload"), Some(EventField::Mapping(_))) {
                return Err(EventError::DeterminismCanonicalJsonBytes);
            }
            Err(EventError::DeterminismCanonicalJsonBytes)
        }
        EventValue::Other => Err(EventError::PythonStrHash),
    }
}

/// Python: `_event_canonical_hash`.
pub fn event_canonical_hash(ev: &EventValue) -> Result<String, EventError> {
    match ev {
        EventValue::Session(event) => match event.canonical_hash() {
            Ok(_digest) => Err(EventError::from(
                CanonicalUnavailable::canonical_json_bytes(),
            )),
            Err(error) => Err(EventError::from(error)),
        },
        EventValue::Mapping(_) => Err(EventError::DeterminismCanonicalJsonBytes),
        EventValue::Other => Err(EventError::PythonStrHash),
    }
}

/// Python: `_to_event_dict`.
///
/// A mapping is a deep copy in insertion order. Keys are not sorted.
pub fn to_event_dict(ev: &EventValue) -> Result<EventMapping, EventError> {
    match ev {
        EventValue::Session(event) => match event.to_canonical_dict() {
            Ok(()) => Err(EventError::from(CanonicalUnavailable::normalize_canonical())),
            Err(error) => Err(EventError::from(error)),
        },
        EventValue::Mapping(mapping) => {
            let copied = mapping.clone();
            let _payload = copied.to_payload();
            Ok(copied)
        }
        EventValue::Other => match to_canonical_dict(ev) {
            Ok(()) => Err(EventError::from(CanonicalUnavailable::normalize_canonical())),
            Err(error) => Err(EventError::from(error)),
        },
    }
}

/// Python: `_copy_events_as_dicts`.
///
/// Calls [`to_event_dict`] on each event, in order. One unavailable event
/// fails the call. The Python `dict(ev)` fallback is not simulated.
pub fn copy_events_as_dicts(events: &[EventValue]) -> Result<Vec<EventMapping>, EventError> {
    events.iter().map(to_event_dict).collect()
}

/// Python: `_copy_events_as_dicts_strict`.
///
/// Executor semantics: deep-copy events with no `dict(ev)` fallback.
/// A mapping is copied. A [`SessionEvent`] and any other value return the
/// unavailable normalize error.
pub fn copy_events_as_dicts_strict(events: &[EventValue]) -> Result<Vec<EventMapping>, EventError> {
    let mut result = Vec::new();
    for ev in events {
        match ev {
            EventValue::Session(event) => match event.to_canonical_dict() {
                Ok(()) => {
                    return Err(EventError::from(CanonicalUnavailable::normalize_canonical()));
                }
                Err(error) => return Err(EventError::from(error)),
            },
            EventValue::Mapping(mapping) => {
                let copied = mapping.clone();
                let _payload = copied.to_payload();
                result.push(copied);
            }
            EventValue::Other => match to_canonical_dict(ev) {
                Ok(()) => {
                    return Err(EventError::from(CanonicalUnavailable::normalize_canonical()));
                }
                Err(error) => return Err(EventError::from(error)),
            },
        }
    }
    Ok(result)
}

fn attribute_or_mapping(
    ev: &EventValue,
    attribute: Option<EventField>,
    key: &str,
) -> Option<EventField> {
    if let Some(value) = attribute {
        return Some(value);
    }
    match ev {
        EventValue::Mapping(mapping) => mapping.get(key).cloned(),
        EventValue::Session(_) | EventValue::Other => None,
    }
}

fn field_to_optional_str(value: Option<EventField>) -> Result<Option<String>, EventError> {
    match value {
        None | Some(EventField::Null) => Ok(None),
        Some(EventField::Bool(true)) => Ok(Some("True".to_owned())),
        Some(EventField::Bool(false)) => Ok(Some("False".to_owned())),
        Some(EventField::Int(number)) => Ok(Some(number.to_string())),
        Some(EventField::Str(text)) => Ok(Some(text)),
        Some(EventField::Float(_)) => Err(EventError::PythonFloatStr),
        Some(EventField::List(_) | EventField::Mapping(_)) => Err(EventError::PythonStr),
    }
}

fn field_to_payload(value: &EventField) -> Payload {
    match value {
        EventField::Null => Payload::null(),
        EventField::Bool(flag) => Payload::bool_value(*flag),
        EventField::Int(number) => Payload::int(*number),
        EventField::Float(number) => Payload::float(*number),
        EventField::Str(text) => Payload::string(text.clone()),
        EventField::List(items) => Payload::list(items.iter().map(field_to_payload).collect()),
        EventField::Mapping(mapping) => mapping.to_payload(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        copy_events_as_dicts, copy_events_as_dicts_strict, event_canonical_hash,
        event_content_fingerprint, event_corr_id, event_id, event_kind, event_parent_id,
        to_event_dict, EventError, EventField, EventMapping, EventValue,
        DICT_FALLBACK_NOT_SIMULATED, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_HASH_UNREPRESENTABLE,
    };
    use crate::canonical::{CanonicalUnavailable, Payload, SessionEvent};
    use std::error::Error;

    #[test]
    fn mapping_returns_kind_id_parent_id_and_correlation_id() {
        let mapping = EventMapping::new(vec![
            ("kind".to_owned(), EventField::Str("message".to_owned())),
            ("id".to_owned(), EventField::Str("evt-synthetic".to_owned())),
            (
                "parent_id".to_owned(),
                EventField::Str("parent-synthetic".to_owned()),
            ),
            (
                "correlation_id".to_owned(),
                EventField::Str("corr-synthetic".to_owned()),
            ),
        ]);
        let ev = EventValue::Mapping(mapping);
        assert_eq!(event_kind(&ev).unwrap().as_deref(), Some("message"));
        assert_eq!(event_id(&ev).unwrap().as_deref(), Some("evt-synthetic"));
        assert_eq!(
            event_parent_id(&ev).unwrap().as_deref(),
            Some("parent-synthetic")
        );
        assert_eq!(
            event_corr_id(&ev).unwrap().as_deref(),
            Some("corr-synthetic")
        );
    }

    #[test]
    fn session_event_field_wins_and_none_kind_stays_none() {
        let mut event = SessionEvent::new(
            "evt-synthetic",
            None,
            1,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        );
        event.payload = Payload::map(vec![(Payload::string("kind"), Payload::string("opaque"))]);
        event.correlation_id = Some("corr-synthetic".to_owned());
        let ev = EventValue::from_session(event);
        assert_eq!(event_kind(&ev).unwrap().as_deref(), Some("message"));
        assert_eq!(event_parent_id(&ev).unwrap(), None);
        assert_eq!(
            event_corr_id(&ev).unwrap().as_deref(),
            Some("corr-synthetic")
        );

        let none_kind = EventMapping::new(vec![("kind".to_owned(), EventField::Null)]);
        assert_eq!(event_kind(&EventValue::Mapping(none_kind)).unwrap(), None);
        let missing = EventMapping::new(Vec::new());
        assert_eq!(event_kind(&EventValue::Mapping(missing)).unwrap(), None);
    }

    #[test]
    fn integer_kind_is_decimal_text_and_true_is_true() {
        let int_kind = EventMapping::new(vec![("kind".to_owned(), EventField::Int(7))]);
        assert_eq!(
            event_kind(&EventValue::Mapping(int_kind))
                .unwrap()
                .as_deref(),
            Some("7")
        );
        let true_kind = EventMapping::new(vec![("kind".to_owned(), EventField::Bool(true))]);
        assert_eq!(
            event_kind(&EventValue::Mapping(true_kind))
                .unwrap()
                .as_deref(),
            Some("True")
        );
        let false_kind = EventMapping::new(vec![("kind".to_owned(), EventField::Bool(false))]);
        assert_eq!(
            event_kind(&EventValue::Mapping(false_kind))
                .unwrap()
                .as_deref(),
            Some("False")
        );
        let float_kind = EventMapping::new(vec![("kind".to_owned(), EventField::Float(1.0))]);
        let err = event_kind(&EventValue::Mapping(float_kind)).unwrap_err();
        assert_eq!(err, EventError::PythonFloatStr);
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(!is_sha256_hex(&err.to_string()));
    }

    #[test]
    fn content_hash_abc_is_returned_unchanged() {
        let mut event = SessionEvent::new(
            "evt-synthetic",
            None,
            1,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        );
        event.content_hash = Some("abc".to_owned());
        assert_eq!(
            event_content_fingerprint(&EventValue::from_session(event)).unwrap(),
            "abc"
        );

        let mapping = EventMapping::new(vec![(
            "content_hash".to_owned(),
            EventField::Str("abc".to_owned()),
        )]);
        assert_eq!(
            event_content_fingerprint(&EventValue::Mapping(mapping)).unwrap(),
            "abc"
        );
    }

    #[test]
    fn empty_content_hash_is_not_an_empty_digest_or_empty_string() {
        let mut event = SessionEvent::new(
            "evt-synthetic",
            None,
            1,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        );
        event.content_hash = Some(String::new());
        let err = event_content_fingerprint(&EventValue::from_session(event)).unwrap_err();
        assert_eq!(
            err,
            EventError::from(CanonicalUnavailable::payload_content_hash())
        );
        assert_eq!(
            err.to_string(),
            "sesslint._canonical_codec.payload_content_hash is not available"
        );
        assert_ne!(err.to_string(), "");
        assert!(!is_sha256_hex(&err.to_string()));

        let mapping = EventMapping::new(vec![(
            "content_hash".to_owned(),
            EventField::Str(String::new()),
        )]);
        let mapping_err = event_content_fingerprint(&EventValue::Mapping(mapping)).unwrap_err();
        assert_eq!(mapping_err, EventError::DeterminismCanonicalJsonBytes);
        assert_eq!(
            mapping_err.to_string(),
            "sesslint.determinism.canonical_json_bytes is not available"
        );
        assert_ne!(mapping_err.to_string(), "");
        assert!(!is_sha256_hex(&mapping_err.to_string()));
    }

    #[test]
    fn canonical_hash_of_session_event_is_canonical_bytes_unavailable() {
        let event = SessionEvent::new(
            "evt-synthetic",
            None,
            1,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        );
        let err = event_canonical_hash(&EventValue::from_session(event)).unwrap_err();
        assert_eq!(
            err,
            EventError::from(CanonicalUnavailable::canonical_json_bytes())
        );
        assert_eq!(
            err.to_string(),
            "sesslint._canonical_codec.canonical_json_bytes is not available"
        );
        assert!(!is_sha256_hex(&err.to_string()));
        assert!(Error::source(&err).is_none());

        let mapping = EventMapping::new(vec![(
            "kind".to_owned(),
            EventField::Str("message".to_owned()),
        )]);
        let mapping_err = event_canonical_hash(&EventValue::Mapping(mapping)).unwrap_err();
        assert_eq!(mapping_err, EventError::DeterminismCanonicalJsonBytes);
        assert!(!is_sha256_hex(&mapping_err.to_string()));

        let other_err = event_canonical_hash(&EventValue::Other).unwrap_err();
        assert_eq!(other_err, EventError::PythonStrHash);
        assert_eq!(other_err.to_string(), PYTHON_STR_HASH_UNREPRESENTABLE);
        assert!(!is_sha256_hex(&other_err.to_string()));
    }

    #[test]
    fn mapping_copy_keeps_insertion_order_and_does_not_share_storage() {
        let original = EventMapping::new(vec![
            ("key-z".to_owned(), EventField::Str("last".to_owned())),
            ("key-a".to_owned(), EventField::Str("first".to_owned())),
            ("key-m".to_owned(), EventField::Int(1)),
        ]);
        let ev = EventValue::Mapping(original.clone());
        let mut copy = to_event_dict(&ev).unwrap();
        assert_eq!(
            copy.keys().collect::<Vec<_>>(),
            vec!["key-z", "key-a", "key-m"]
        );
        let payload = copy.to_payload();
        let debug = format!("{payload:?}");
        let pos_z = debug.find("key-z").expect("key-z");
        let pos_a = debug.find("key-a").expect("key-a");
        let pos_m = debug.find("key-m").expect("key-m");
        assert!(pos_z < pos_a);
        assert!(pos_a < pos_m);

        copy.push("key-extra", EventField::Null);
        assert_eq!(
            original.keys().collect::<Vec<_>>(),
            vec!["key-z", "key-a", "key-m"]
        );
        assert_eq!(copy.keys().collect::<Vec<_>>().len(), 4);
        let payload_copy = original.to_payload();
        assert!(payload_copy.push_map_entry(Payload::string("key-extra"), Payload::null()));
        assert_eq!(original.entries().len(), 3);

        let mixed = copy_events_as_dicts(&[
            EventValue::Mapping(original.clone()),
            EventValue::from_session(SessionEvent::new(
                "evt-synthetic",
                None,
                1,
                "2024-02-29T00:00:00Z",
                "assistant",
                "message",
            )),
        ])
        .unwrap_err();
        assert_eq!(
            mixed,
            EventError::from(CanonicalUnavailable::normalize_canonical())
        );
        assert!(DICT_FALLBACK_NOT_SIMULATED.contains("dict(ev)"));
    }

    #[test]
    fn strict_converter_copies_a_mapping_and_rejects_a_session_event() {
        let mapping = EventMapping::new(vec![
            ("key-z".to_owned(), EventField::Str("last".to_owned())),
            ("key-a".to_owned(), EventField::Str("first".to_owned())),
        ]);
        let copied = copy_events_as_dicts_strict(&[EventValue::Mapping(mapping.clone())]).unwrap();
        assert_eq!(copied.len(), 1);
        assert_eq!(copied[0].keys().collect::<Vec<_>>(), vec!["key-z", "key-a"]);
        assert_eq!(copied[0], mapping);

        let event = SessionEvent::new(
            "evt-synthetic",
            None,
            1,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        );
        let err = copy_events_as_dicts_strict(&[EventValue::from_session(event)]).unwrap_err();
        assert_eq!(
            err,
            EventError::from(CanonicalUnavailable::normalize_canonical())
        );
        assert_eq!(
            err.to_string(),
            "sesslint._canonical_codec.normalize_canonical is not available"
        );
        assert!(!is_sha256_hex(&err.to_string()));
    }

    fn is_sha256_hex(text: &str) -> bool {
        let bytes = text.as_bytes();
        bytes.len() == 64
            && bytes
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }
}
