//! SL305 provider-incompatible record shape detector (detector-depth T-05).
//!
//! Port of `src/sesslint/checks/foreign_shape.py` lines 1–123
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. The pin has no `__all__`.
//! [`check_foreign_shape`] calls [`make_finding`] with the fingerprint
//! omitted. That returns the codec error and does not produce a digest.
//! This module does not call [`crate::graph::cap_graph_findings`].
//!
//! Codex-rollout-scoped check (evidence-assurance T-02 memo — GO verdict):
//! session records written against a third-party Responses-compatible
//! provider can carry shapes the official replay path rejects — the file
//! parses cleanly but the resume target refuses it (openai/codex#36551:
//! `reasoning` items persisted with a non-null `content` array;
//! official shape is `content: null` or absent — "Expected maximum
//! length 0").
//!
//! This is a *shape-vocabulary* check, not provenance inference: it can
//! only prove "shape outside the cited official vocabulary", never "the
//! file came from a foreign provider". Provider identity on disk is
//! self-reported (`session_meta.model_provider`/`originator`) and is
//! surfaced as a bounded hash, never a claim. Known-shapes list only —
//! absent or novel shapes stay silent; unknown is never foreign.
//!
//! Fires at most once per file, anchored at the first offending record.
//! Evidence is structural only: shape class labels, counts, ordinals,
//! and hashed config metadata — never payload content.
//!
//! [`foreign_shape_record`] reports the single first-offender record.
//! It does not hash. [`check_foreign_shape`] calls [`make_finding`] only
//! when that function returns a record, and propagates the codec error.
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. [`ForeignShapeRecord::item_count`] uses
//!   `i64` checked addition. Overflow is [`PYTHON_INT_UNBOUNDED`], not a
//!   wrap and not a panic.
//! * [`MapLookup::Borrowed`] is a failed borrow, not a missing key
//!   ([`BORROWED_LOOKUP`]). [`MapLookup::NotAMap`] and
//!   [`MapLookup::Absent`] skip that level and the event is not a marker.
//! * [`crate::graph::event_get`] does not return `extra_fields` for a
//!   [`model::canonical::SessionEvent`]. This module reads
//!   [`model::canonical::SessionEvent::extra_fields`] directly. For
//!   [`EventValue::Mapping`], it reads the `extra_fields` field and uses
//!   [`model::events::EventMapping::to_payload`] when that field is a mapping.
//! * A bool is not an int. A missing or non-int ordinal is stored as
//!   absent. [`ForeignShapeRecord::first_ordinal`] is included only when
//!   the first offender's ordinal is ≥ 0.
//! * This check never infers a provider. Declared provider context is
//!   read from [`CheckContext::source_metadata`] and hashed; it is
//!   evidence, not the finding fingerprint.
//! * `source_metadata` is a JSON object, not a Python `Mapping`. A JSON
//!   `null` originator is Python `None` and does not set the flag.

use std::error::Error;
use std::fmt;

use model::canonical::{MapLookup, Payload};
use model::codes::{Repairability, Severity, SL305};
use model::errors::FindingError;
use model::events::{EventField, EventValue};
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::context::CheckContext;
use crate::graph::{event_get, resolve_source_coords, safe_id, GraphError};

/// Python: `_MSG_FOREIGN`.
pub const MSG_FOREIGN: &str =
    "Record shape outside the replay vocabulary on line {line} for record {record_id}";

/// Python evidence `shape_violation` for the only cited family.
pub const SHAPE_VIOLATION: &str = "reasoning-content-non-null";

/// Python evidence `item_family`. The only vocabulary family is `reasoning`.
pub const ITEM_FAMILY: &str = "reasoning";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// [`MapLookup::Borrowed`] is not a missing key.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignShapeError {
    BorrowedLookup,
    PythonIntUnbounded,
    Finding(FindingError),
    Graph(GraphError),
}

impl ForeignShapeError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::Finding(error) => error.message(),
            Self::Graph(error) => error.message(),
        }
    }
}

impl fmt::Display for ForeignShapeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ForeignShapeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::Graph(error) => Some(error),
            Self::BorrowedLookup | Self::PythonIntUnbounded => None,
        }
    }
}

impl From<FindingError> for ForeignShapeError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

impl From<GraphError> for ForeignShapeError {
    fn from(error: GraphError) -> Self {
        match error {
            GraphError::Finding(error) => Self::Finding(error),
            other => Self::Graph(other),
        }
    }
}

/// First offending record plus file-level counts. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignShapeRecord {
    pub event_index: usize,
    pub item_count: i64,
    pub shape_violation: &'static str,
    pub item_family: &'static str,
    pub first_ordinal: Option<i64>,
    pub declared_provider_hash: Option<String>,
    pub declared_originator_present: bool,
}

/// Extra-fields payload for one event. [`event_get`] is not used here.
fn extra_fields_payload(ev: &EventValue) -> Option<Payload> {
    match ev {
        EventValue::Session(event) => Some(event.extra_fields.clone()),
        EventValue::Mapping(mapping) => match mapping.get("extra_fields") {
            Some(EventField::Mapping(inner)) => Some(inner.to_payload()),
            Some(_) | None => None,
        },
        EventValue::Other => None,
    }
}

/// [`MapLookup::Borrowed`] is an error. [`MapLookup::NotAMap`] and
/// [`MapLookup::Absent`] skip that level.
fn map_field(payload: &Payload, key: &str) -> Result<Option<Payload>, ForeignShapeError> {
    match payload.map_string(key) {
        MapLookup::Borrowed => Err(ForeignShapeError::BorrowedLookup),
        MapLookup::NotAMap | MapLookup::Absent => Ok(None),
        MapLookup::Present(value) => Ok(Some(value)),
    }
}

/// Official replay vocabulary per item family. Additive only: a shape must
/// be cited as provider-rejected before it can fire. The only family is
/// `reasoning`; its foreign shapes are exactly `array` and `other`.
fn is_foreign_shape(item_type: &str, shape: &str) -> bool {
    match item_type {
        "reasoning" => matches!(shape, "array" | "other"),
        _ => false,
    }
}

/// Ordinal stored for one offender. A bool is not an int. Missing and
/// non-int values are absent (`-1` in the Python tuple, omitted from
/// evidence when the first offender's value is < 0).
fn marker_ordinal(codex: &Payload) -> Result<i64, ForeignShapeError> {
    match map_field(codex, "ordinal")? {
        Some(value) => Ok(value.as_int().unwrap_or(-1)),
        None => Ok(-1),
    }
}

/// Whether one event is a cited foreign shape, and its stored ordinal.
fn offending_ordinal(ev: &EventValue) -> Result<Option<i64>, ForeignShapeError> {
    let Some(extra) = extra_fields_payload(ev) else {
        return Ok(None);
    };
    let Some(codex) = map_field(&extra, "codex")? else {
        return Ok(None);
    };
    if !codex.is_map() {
        return Ok(None);
    }
    let Some(item_type_raw) = map_field(&codex, "item_type")? else {
        return Ok(None);
    };
    let Some(item_type) = item_type_raw.as_str() else {
        return Ok(None);
    };
    let Some(shape_raw) = map_field(&codex, "reasoning_content_shape")? else {
        return Ok(None);
    };
    let Some(shape) = shape_raw.as_str() else {
        return Ok(None);
    };
    if !is_foreign_shape(item_type, shape) {
        return Ok(None);
    }
    Ok(Some(marker_ordinal(&codex)?))
}

/// Python: `_marker_hash`. sha256-8 of a config marker string.
fn marker_hash(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(8);
    for byte in digest.iter().take(4) {
        out.push(char::from(HEX[usize::from(*byte >> 4)]));
        out.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    out
}

/// Declared provider context from [`CheckContext::source_metadata`].
///
/// `model_provider` is hashed only when it is a non-empty stripped string.
/// `originator` sets the present flag when the key is present and not JSON
/// `null` (Python `is not None`, including `false` / `0` / `""`).
fn declared_meta(context: Option<&CheckContext>) -> (Option<String>, bool) {
    let Some(sm) = context.and_then(CheckContext::source_metadata) else {
        return (None, false);
    };
    let Some(meta) = sm.get("session_meta").and_then(Value::as_object) else {
        return (None, false);
    };
    let provider_hash = match meta.get("model_provider") {
        Some(Value::String(text)) => {
            let stripped = text.trim();
            if stripped.is_empty() {
                None
            } else {
                Some(marker_hash(stripped))
            }
        }
        _ => None,
    };
    let originator_present = match meta.get("originator") {
        None | Some(Value::Null) => false,
        Some(_) => true,
    };
    (provider_hash, originator_present)
}

fn record_id(ev: &EventValue) -> Option<String> {
    match event_get(ev, "id") {
        Some(EventField::Str(text)) => {
            let stripped = text.trim();
            if stripped.is_empty() {
                None
            } else {
                Some(safe_id(stripped))
            }
        }
        _ => None,
    }
}

fn shape_evidence(record: &ForeignShapeRecord) -> PyValue {
    let mut entries = vec![
        (
            PyValue::string("shape_violation"),
            PyValue::string(record.shape_violation),
        ),
        (
            PyValue::string("item_family"),
            PyValue::string(record.item_family),
        ),
        (
            PyValue::string("item_count"),
            PyValue::int(record.item_count),
        ),
    ];
    if let Some(ordinal) = record.first_ordinal {
        entries.push((PyValue::string("first_ordinal"), PyValue::int(ordinal)));
    }
    if let Some(hash) = record.declared_provider_hash.as_deref() {
        entries.push((
            PyValue::string("declared_provider_hash"),
            PyValue::string(hash),
        ));
    }
    if record.declared_originator_present {
        entries.push((
            PyValue::string("declared_originator_present"),
            PyValue::bool_value(true),
        ));
    }
    PyValue::map(entries)
}

/// The single first-offender record, or `None` when the file is silent.
/// Does not call [`make_finding`].
pub fn foreign_shape_record(
    events: &[EventValue],
    context: Option<&CheckContext>,
) -> Result<Option<ForeignShapeRecord>, ForeignShapeError> {
    let mut first: Option<(usize, i64)> = None;
    let mut item_count: i64 = 0;
    for (event_index, ev) in events.iter().enumerate() {
        if let Some(ordinal) = offending_ordinal(ev)? {
            item_count = item_count
                .checked_add(1)
                .ok_or(ForeignShapeError::PythonIntUnbounded)?;
            if first.is_none() {
                first = Some((event_index, ordinal));
            }
        }
    }
    let Some((event_index, first_ord)) = first else {
        return Ok(None);
    };
    let (declared_provider_hash, declared_originator_present) = declared_meta(context);
    Ok(Some(ForeignShapeRecord {
        event_index,
        item_count,
        shape_violation: SHAPE_VIOLATION,
        item_family: ITEM_FAMILY,
        first_ordinal: (first_ord >= 0).then_some(first_ord),
        declared_provider_hash,
        declared_originator_present,
    }))
}

/// Python: `check_foreign_shape`.
///
/// No offender returns an empty list and does not call [`make_finding`].
/// An offender calls [`make_finding`] with the fingerprint omitted; that
/// codec error is propagated.
pub fn check_foreign_shape(
    events: &[EventValue],
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, ForeignShapeError> {
    let Some(record) = foreign_shape_record(events, context)? else {
        return Ok(Vec::new());
    };
    let Some(ev) = events.get(record.event_index) else {
        return Ok(Vec::new());
    };

    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };

    let (resolved_path, line_num) = resolve_source_coords(ev, source_path)?;
    let rec_id = record_id(ev);
    let source = SourceRef::try_new(
        &resolved_path,
        line_num.map(SourceLine::Int),
        rec_id.as_deref(),
    )?;
    Ok(vec![make_finding(&MakeFindingInput {
        code: PyValue::string(SL305),
        severity: PyValue::severity(Severity::Warning),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_FOREIGN),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence: shape_evidence(&record),
        fingerprint: PyValue::None,
        adapter_id: Some(ctx.adapter_id().to_owned()),
        adapter_version: Some(ctx.adapter_version().to_owned()),
        profile_id: Some(ctx.profile_id().to_owned()),
        profile_version: Some(ctx.profile_version().to_owned()),
        ordinal: None,
        context: None,
    })?])
}

#[cfg(test)]
mod tests {
    use super::{
        check_foreign_shape, foreign_shape_record, ForeignShapeError, MSG_FOREIGN, SHAPE_VIOLATION,
    };
    use crate::context::CheckContext;
    use model::canonical::{Payload, SessionEvent};
    use model::events::EventValue;
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;
    use std::collections::BTreeMap;

    fn session_event(id: &str, extra: Payload) -> EventValue {
        let mut event =
            SessionEvent::new(id, None, 0, "2024-02-29T00:00:00Z", "assistant", "message");
        event.extra_fields = extra;
        EventValue::from_session(event)
    }

    fn unmarked(id: &str) -> EventValue {
        session_event(id, Payload::map(Vec::new()))
    }

    fn codex_event(id: &str, entries: Vec<(Payload, Payload)>) -> EventValue {
        session_event(
            id,
            Payload::map(vec![(Payload::string("codex"), Payload::map(entries))]),
        )
    }

    fn reasoning_shape(id: &str, shape: &str, ordinal: Option<Payload>) -> EventValue {
        let mut entries = vec![
            (Payload::string("item_type"), Payload::string("reasoning")),
            (
                Payload::string("reasoning_content_shape"),
                Payload::string(shape),
            ),
        ];
        if let Some(value) = ordinal {
            entries.push((Payload::string("ordinal"), value));
        }
        codex_event(id, entries)
    }

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn assert_codec_unavailable(err: ForeignShapeError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn no_marker_is_silent() {
        let events = vec![unmarked("evt-a-synthetic"), unmarked("evt-b-synthetic")];
        let record = foreign_shape_record(&events, None).unwrap();
        assert!(record.is_none());
        let findings = check_foreign_shape(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn reasoning_shape_null_is_silent() {
        let events = vec![reasoning_shape("evt-null-synthetic", "null", None)];
        let record = foreign_shape_record(&events, None).unwrap();
        assert!(record.is_none());
        let findings = check_foreign_shape(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn unknown_item_type_with_shape_array_is_silent() {
        let events = vec![codex_event(
            "evt-message-synthetic",
            vec![
                (Payload::string("item_type"), Payload::string("message")),
                (
                    Payload::string("reasoning_content_shape"),
                    Payload::string("array"),
                ),
            ],
        )];
        let record = foreign_shape_record(&events, None).unwrap();
        assert!(record.is_none());
        let findings = check_foreign_shape(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn one_reasoning_array_records_count_and_codec_error() {
        let events = vec![reasoning_shape("evt-array-synthetic", "array", None)];
        let record = foreign_shape_record(&events, None).unwrap().expect("fires");
        assert_eq!(record.item_count, 1);
        assert_eq!(record.shape_violation, SHAPE_VIOLATION);
        assert_eq!(record.event_index, 0);
        let err = check_foreign_shape(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
        assert_eq!(
            MSG_FOREIGN,
            "Record shape outside the replay vocabulary on line {line} for record {record_id}"
        );
    }

    #[test]
    fn later_second_offender_keeps_first_anchor_and_count_two() {
        let events = vec![
            reasoning_shape("evt-first-synthetic", "array", Some(Payload::int(2))),
            unmarked("evt-middle-synthetic"),
            reasoning_shape("evt-second-synthetic", "other", Some(Payload::int(5))),
        ];
        let record = foreign_shape_record(&events, None).unwrap().expect("fires");
        assert_eq!(record.event_index, 0);
        assert_eq!(record.item_count, 2);
        assert_eq!(record.first_ordinal, Some(2));
        let err = check_foreign_shape(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn bool_ordinal_omits_first_ordinal() {
        let events = vec![reasoning_shape(
            "evt-bool-ordinal-synthetic",
            "array",
            Some(Payload::bool_value(true)),
        )];
        let record = foreign_shape_record(&events, None).unwrap().expect("fires");
        assert_eq!(record.first_ordinal, None);
        let err = check_foreign_shape(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn stripped_model_provider_hashes_and_false_originator_is_present() {
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "session_meta".to_owned(),
            serde_json::json!({
                "model_provider": " openai ",
                "originator": false,
            }),
        );
        let ctx = CheckContext::create(None, None, None, None, Some(metadata));
        let events = vec![reasoning_shape("evt-provider-synthetic", "array", None)];
        let record = foreign_shape_record(&events, Some(&ctx))
            .unwrap()
            .expect("fires");
        assert_eq!(record.declared_provider_hash.as_deref(), Some("7d3194f7"));
        assert!(record.declared_originator_present);
        let err = check_foreign_shape(&events, None, Some(&ctx)).unwrap_err();
        assert_codec_unavailable(err);
    }
}
