//! SL208 compaction-snapshot divergence detector (detector-depth T-04).
//!
//! Port of `src/sesslint/checks/compaction_snapshot.py` lines 1–235
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`check_compaction_snapshot`] calls [`make_finding`] with the fingerprint
//! omitted. That returns the codec error and does not produce a digest.
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Occurrence counts and indexes use `i64`
//!   checked conversion. Overflow is [`PYTHON_INT_UNBOUNDED`], not a wrap
//!   and not a panic.
//! * [`MapWalk::Borrowed`] and [`ListWalk::Borrowed`] are failed borrows, not
//!   an empty marker or an empty guardian list ([`BORROWED_WALK`]).
//! * [`crate::graph::event_get`] does not return `extra_fields` for a
//!   [`model::canonical::SessionEvent`]. This module reads
//!   [`model::canonical::SessionEvent::extra_fields`] directly. For
//!   [`EventValue::Mapping`], it reads the `extra_fields` field and uses
//!   [`model::events::EventMapping::to_payload`] when that field is a mapping.
//! * A float or other non-string `kind` is not a boundary. Python `str()` is
//!   not invented.
//! * A tuple is [`ListWalk::NotAList`]. It is not a guardian list.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use model::canonical::{ListWalk, MapWalk, Payload};
use model::codes::{Repairability, Severity, SL208};
use model::errors::FindingError;
use model::events::{EventField, EventValue};
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef};

use crate::context::CheckContext;
use crate::graph::{event_get, resolve_source_coords, safe_id, GraphError};

/// Python: `_KIND_COMPACTION`.
pub const KIND_COMPACTION: &str = "compaction_boundary";

/// Python: `_MSG_TYPE`.
pub const MSG_TYPE: &str =
    "Compaction snapshot item type disagrees with the durable stream on line {line} for record {record_id}";

/// Python: `_MSG_CORR`.
pub const MSG_CORR: &str =
    "Compaction snapshot correlator disagrees with the durable stream on line {line} for record {record_id}";

/// Python: `_MSG_FUTURE`.
pub const MSG_FUTURE: &str =
    "Compaction snapshot cites an item not yet written to the stream on line {line} for record {record_id}";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// A borrowed map or list walk is not an empty container.
pub const BORROWED_WALK: &str = "A borrowed walk is not an empty map or list";

const TYPE_PREFIX_CHARS: usize = 64;
const ID_PREFIX_CHARS: usize = 256;

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactionSnapshotError {
    BorrowedWalk,
    PythonIntUnbounded,
    Finding(FindingError),
    Graph(GraphError),
}

impl CompactionSnapshotError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedWalk => BORROWED_WALK,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::Finding(error) => error.message(),
            Self::Graph(error) => error.message(),
        }
    }
}

impl fmt::Display for CompactionSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for CompactionSnapshotError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::Graph(error) => Some(error),
            Self::BorrowedWalk | Self::PythonIntUnbounded => None,
        }
    }
}

impl From<FindingError> for CompactionSnapshotError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

impl From<GraphError> for CompactionSnapshotError {
    fn from(error: GraphError) -> Self {
        match error {
            GraphError::Finding(error) => Self::Finding(error),
            other => Self::Graph(other),
        }
    }
}

/// One divergence kind with its first-item anchor. Does not call
/// [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotDivergence {
    pub divergence: &'static str,
    pub item_id: String,
    pub occurrences: i64,
    pub boundary_index: i64,
    pub item_index: i64,
    pub snapshot_item_type: Option<String>,
    pub stream_item_type: Option<String>,
    pub snapshot_correlator: Option<String>,
    pub stream_correlator: Option<String>,
}

struct StreamItem {
    index: usize,
    item_type: String,
    correlator: Option<String>,
}

struct CodexMarker {
    item_type: Option<String>,
    correlator: Option<String>,
    guardian_items: Option<Payload>,
}

struct KindState {
    item_id: String,
    boundary_index: usize,
    item_index: usize,
    snapshot_item_type: Option<String>,
    stream_item_type: Option<String>,
    snapshot_correlator: Option<String>,
    stream_correlator: Option<String>,
    occurrences: i64,
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

fn event_id_string(ev: &EventValue) -> Option<String> {
    match event_get(ev, "id") {
        Some(EventField::Str(text)) => Some(text),
        _ => None,
    }
}

fn kind_is_compaction_boundary(ev: &EventValue) -> bool {
    matches!(
        event_get(ev, "kind"),
        Some(EventField::Str(ref kind)) if kind == KIND_COMPACTION
    )
}

fn rec_id(ev: &EventValue) -> Option<String> {
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

fn truncate_prefix(text: &str, max_chars: usize) -> &str {
    match text.char_indices().nth(max_chars) {
        Some((index, _)) => &text[..index],
        None => text,
    }
}

fn bounded_id(text: &str) -> String {
    safe_id(truncate_prefix(text, ID_PREFIX_CHARS))
}

fn bounded_type(text: &str) -> String {
    safe_id(truncate_prefix(text, TYPE_PREFIX_CHARS))
}

fn bounded_correlator(text: Option<&str>) -> Option<String> {
    text.map(bounded_id)
}

fn add_i64(left: i64, right: i64) -> Result<i64, CompactionSnapshotError> {
    left.checked_add(right)
        .ok_or(CompactionSnapshotError::PythonIntUnbounded)
}

fn usize_to_i64(value: usize) -> Result<i64, CompactionSnapshotError> {
    i64::try_from(value).map_err(|_| CompactionSnapshotError::PythonIntUnbounded)
}

fn optional_text(value: Option<&str>) -> PyValue {
    match value {
        Some(text) => PyValue::string(text),
        None => PyValue::None,
    }
}

/// Python: `_codex_marker`.
fn read_codex_marker(extra: &Payload) -> Result<Option<CodexMarker>, CompactionSnapshotError> {
    let mut codex = None;
    match extra.walk_string_entries(|key, value| {
        if key == "codex" {
            codex = Some(value.clone());
        }
    }) {
        MapWalk::NotAMap => return Ok(None),
        MapWalk::Borrowed => return Err(CompactionSnapshotError::BorrowedWalk),
        MapWalk::Done => {}
    }
    let Some(codex) = codex else {
        return Ok(None);
    };

    let mut item_type = None;
    let mut correlator = None;
    let mut guardian_items = None;
    match codex.walk_string_entries(|key, value| match key {
        "item_type" => item_type = value.as_str().map(str::to_owned),
        "call_id" => correlator = value.as_str().map(str::to_owned),
        "guardian_items" => guardian_items = Some(value.clone()),
        _ => {}
    }) {
        MapWalk::NotAMap => return Ok(None),
        MapWalk::Borrowed => return Err(CompactionSnapshotError::BorrowedWalk),
        MapWalk::Done => {}
    }
    Ok(Some(CodexMarker {
        item_type,
        correlator,
        guardian_items,
    }))
}

fn marker_for_event(ev: &EventValue) -> Result<Option<CodexMarker>, CompactionSnapshotError> {
    let Some(extra) = extra_fields_payload(ev) else {
        return Ok(None);
    };
    read_codex_marker(&extra)
}

fn read_guardian_list(items: &Payload) -> Result<Option<Vec<Payload>>, CompactionSnapshotError> {
    let mut collected = Vec::new();
    match items.walk_list_items(|_, item| {
        collected.push(item.clone());
    }) {
        ListWalk::NotAList => Ok(None),
        ListWalk::Borrowed => Err(CompactionSnapshotError::BorrowedWalk),
        ListWalk::Done => Ok(Some(collected)),
    }
}

struct GuardianFields {
    id: Option<String>,
    item_type: Option<String>,
    correlator: Option<String>,
}

fn read_guardian_item(item: &Payload) -> Result<Option<GuardianFields>, CompactionSnapshotError> {
    let mut id = None;
    let mut item_type = None;
    let mut correlator = None;
    match item.walk_string_entries(|key, value| match key {
        "id" => id = value.as_str().map(str::to_owned),
        "type" => item_type = value.as_str().map(str::to_owned),
        "call_id" => correlator = value.as_str().map(str::to_owned),
        _ => {}
    }) {
        MapWalk::NotAMap => Ok(None),
        MapWalk::Borrowed => Err(CompactionSnapshotError::BorrowedWalk),
        MapWalk::Done => Ok(Some(GuardianFields {
            id,
            item_type,
            correlator,
        })),
    }
}

struct KindNote<'a> {
    item_id: &'a str,
    boundary_index: usize,
    item_index: usize,
    snapshot_item_type: Option<String>,
    stream_item_type: Option<String>,
    snapshot_correlator: Option<String>,
    stream_correlator: Option<String>,
}

fn note_kind(
    slot: &mut Option<KindState>,
    hit: KindNote<'_>,
) -> Result<(), CompactionSnapshotError> {
    match slot {
        Some(state) => {
            state.occurrences = add_i64(state.occurrences, 1)?;
            Ok(())
        }
        None => {
            *slot = Some(KindState {
                item_id: hit.item_id.to_owned(),
                boundary_index: hit.boundary_index,
                item_index: hit.item_index,
                snapshot_item_type: hit.snapshot_item_type,
                stream_item_type: hit.stream_item_type,
                snapshot_correlator: hit.snapshot_correlator,
                stream_correlator: hit.stream_correlator,
                occurrences: 1,
            });
            Ok(())
        }
    }
}

fn into_record(
    divergence: &'static str,
    state: KindState,
) -> Result<SnapshotDivergence, CompactionSnapshotError> {
    Ok(SnapshotDivergence {
        divergence,
        item_id: bounded_id(&state.item_id),
        occurrences: state.occurrences,
        boundary_index: usize_to_i64(state.boundary_index)?,
        item_index: usize_to_i64(state.item_index)?,
        snapshot_item_type: state.snapshot_item_type,
        stream_item_type: state.stream_item_type,
        snapshot_correlator: state.snapshot_correlator,
        stream_correlator: state.stream_correlator,
    })
}

/// At most one record per divergence kind, in emission order. Does not call
/// [`make_finding`].
pub fn compaction_snapshot_divergences(
    events: &[EventValue],
) -> Result<Vec<SnapshotDivergence>, CompactionSnapshotError> {
    let mut stream: HashMap<String, StreamItem> = HashMap::new();
    let mut boundaries: Vec<(usize, Vec<Payload>)> = Vec::new();

    for (idx, ev) in events.iter().enumerate() {
        let Some(marker) = marker_for_event(ev)? else {
            continue;
        };
        if let (Some(eid), Some(item_type)) = (event_id_string(ev), marker.item_type) {
            if let Entry::Vacant(slot) = stream.entry(eid) {
                slot.insert(StreamItem {
                    index: idx,
                    item_type,
                    correlator: marker.correlator,
                });
            }
        }
        if kind_is_compaction_boundary(ev) {
            if let Some(raw_items) = marker.guardian_items {
                if let Some(items) = read_guardian_list(&raw_items)? {
                    boundaries.push((idx, items));
                }
            }
        }
    }

    if boundaries.is_empty() {
        return Ok(Vec::new());
    }

    let mut type_mismatch = None;
    let mut correlation_mismatch = None;
    let mut future_item = None;

    for (b_idx, gh_items) in boundaries {
        for gh in gh_items {
            let Some(fields) = read_guardian_item(&gh)? else {
                continue;
            };
            let Some(gid) = fields.id else {
                continue;
            };
            let Some(durable) = stream.get(&gid) else {
                continue;
            };
            if durable.index > b_idx {
                note_kind(
                    &mut future_item,
                    KindNote {
                        item_id: &gid,
                        boundary_index: b_idx,
                        item_index: durable.index,
                        snapshot_item_type: None,
                        stream_item_type: None,
                        snapshot_correlator: None,
                        stream_correlator: None,
                    },
                )?;
            }
            if let Some(ref gh_type) = fields.item_type {
                if gh_type != &durable.item_type {
                    note_kind(
                        &mut type_mismatch,
                        KindNote {
                            item_id: &gid,
                            boundary_index: b_idx,
                            item_index: durable.index,
                            snapshot_item_type: Some(bounded_type(gh_type)),
                            stream_item_type: Some(bounded_type(&durable.item_type)),
                            snapshot_correlator: None,
                            stream_correlator: None,
                        },
                    )?;
                }
            }
            if fields.correlator.as_deref() != durable.correlator.as_deref() {
                note_kind(
                    &mut correlation_mismatch,
                    KindNote {
                        item_id: &gid,
                        boundary_index: b_idx,
                        item_index: durable.index,
                        snapshot_item_type: None,
                        stream_item_type: None,
                        snapshot_correlator: bounded_correlator(fields.correlator.as_deref()),
                        stream_correlator: bounded_correlator(durable.correlator.as_deref()),
                    },
                )?;
            }
        }
    }

    let mut records = Vec::new();
    if let Some(state) = type_mismatch {
        records.push(into_record("type-mismatch", state)?);
    }
    if let Some(state) = correlation_mismatch {
        records.push(into_record("correlation-mismatch", state)?);
    }
    if let Some(state) = future_item {
        records.push(into_record("future-item", state)?);
    }
    Ok(records)
}

fn message_template(divergence: &str) -> &'static str {
    if divergence == "type-mismatch" {
        MSG_TYPE
    } else if divergence == "correlation-mismatch" {
        MSG_CORR
    } else {
        MSG_FUTURE
    }
}

fn divergence_evidence(record: &SnapshotDivergence) -> PyValue {
    let mut entries = vec![
        (
            PyValue::string("divergence"),
            PyValue::string(record.divergence),
        ),
        (
            PyValue::string("item_id"),
            PyValue::string(record.item_id.clone()),
        ),
        (
            PyValue::string("occurrences"),
            PyValue::int(record.occurrences),
        ),
        (
            PyValue::string("boundary_index"),
            PyValue::int(record.boundary_index),
        ),
        (
            PyValue::string("item_index"),
            PyValue::int(record.item_index),
        ),
    ];
    if record.divergence == "type-mismatch" {
        entries.push((
            PyValue::string("snapshot_item_type"),
            optional_text(record.snapshot_item_type.as_deref()),
        ));
        entries.push((
            PyValue::string("stream_item_type"),
            optional_text(record.stream_item_type.as_deref()),
        ));
    } else if record.divergence == "correlation-mismatch" {
        entries.push((
            PyValue::string("snapshot_correlator"),
            optional_text(record.snapshot_correlator.as_deref()),
        ));
        entries.push((
            PyValue::string("stream_correlator"),
            optional_text(record.stream_correlator.as_deref()),
        ));
    }
    PyValue::map(entries)
}

/// Python: `check_compaction_snapshot`.
///
/// No divergence returns an empty list and does not call [`make_finding`].
/// A divergence calls [`make_finding`] with the fingerprint omitted; that
/// codec error is propagated. The list is not capped a second time.
pub fn check_compaction_snapshot(
    events: &[EventValue],
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, CompactionSnapshotError> {
    let records = compaction_snapshot_divergences(events)?;
    if records.is_empty() {
        return Ok(Vec::new());
    }

    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };

    let mut findings = Vec::new();
    for record in records {
        let Ok(ordinal) = usize::try_from(record.boundary_index) else {
            continue;
        };
        let Some(ev) = events.get(ordinal) else {
            continue;
        };
        let (resolved_path, line_num) = resolve_source_coords(ev, source_path)?;
        let clean_rec_id = rec_id(ev);
        let source = SourceRef::try_new(
            &resolved_path,
            line_num.map(SourceLine::Int),
            clean_rec_id.as_deref(),
        )?;
        findings.push(make_finding(&MakeFindingInput {
            code: PyValue::string(SL208),
            severity: PyValue::severity(Severity::Warning),
            repairability: PyValue::repairability(Repairability::Manual),
            message_template: PyValue::string(message_template(record.divergence)),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            evidence: divergence_evidence(&record),
            fingerprint: PyValue::None,
            adapter_id: Some(ctx.adapter_id().to_owned()),
            adapter_version: Some(ctx.adapter_version().to_owned()),
            profile_id: Some(ctx.profile_id().to_owned()),
            profile_version: Some(ctx.profile_version().to_owned()),
            ordinal: None,
            context: None,
        })?);
    }
    Ok(findings)
}

/// Python `__all__`, in that order.
pub const ALL: [&str; 1] = ["check_compaction_snapshot"];

#[cfg(test)]
mod tests {
    use super::{
        check_compaction_snapshot, compaction_snapshot_divergences, CompactionSnapshotError, ALL,
        MSG_CORR, MSG_FUTURE, MSG_TYPE,
    };
    use model::canonical::{Payload, SessionEvent};
    use model::events::{EventField, EventMapping, EventValue};
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    fn session_event(id: &str, seq: i64, kind: &str, extra: Payload) -> EventValue {
        let mut event = SessionEvent::new(id, None, seq, "2024-02-29T00:00:00Z", "assistant", kind);
        event.extra_fields = extra;
        EventValue::from_session(event)
    }

    fn codex_extra(entries: Vec<(Payload, Payload)>) -> Payload {
        Payload::map(vec![(Payload::string("codex"), Payload::map(entries))])
    }

    fn durable(id: &str, seq: i64, item_type: &str, call_id: Option<&str>) -> EventValue {
        let mut entries = vec![(Payload::string("item_type"), Payload::string(item_type))];
        if let Some(corr) = call_id {
            entries.push((Payload::string("call_id"), Payload::string(corr)));
        }
        session_event(id, seq, "message", codex_extra(entries))
    }

    fn guardian_item(id: &str, item_type: &str, call_id: Option<&str>) -> Payload {
        let mut entries = vec![
            (Payload::string("id"), Payload::string(id)),
            (Payload::string("type"), Payload::string(item_type)),
        ];
        match call_id {
            Some(corr) => entries.push((Payload::string("call_id"), Payload::string(corr))),
            None => entries.push((Payload::string("call_id"), Payload::null())),
        }
        Payload::map(entries)
    }

    fn boundary(id: &str, seq: i64, items: Vec<Payload>) -> EventValue {
        session_event(
            id,
            seq,
            "compaction_boundary",
            codex_extra(vec![(
                Payload::string("guardian_items"),
                Payload::list(items),
            )]),
        )
    }

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn assert_codec_unavailable(err: CompactionSnapshotError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn all_is_check_compaction_snapshot() {
        assert_eq!(ALL, ["check_compaction_snapshot"]);
        assert_eq!(
            MSG_TYPE,
            "Compaction snapshot item type disagrees with the durable stream on line {line} for record {record_id}"
        );
        assert_eq!(
            MSG_CORR,
            "Compaction snapshot correlator disagrees with the durable stream on line {line} for record {record_id}"
        );
        assert_eq!(
            MSG_FUTURE,
            "Compaction snapshot cites an item not yet written to the stream on line {line} for record {record_id}"
        );
    }

    #[test]
    fn no_codex_marker_returns_no_divergences_and_check_is_empty() {
        let events = vec![
            session_event("evt-a-synthetic", 0, "message", Payload::map(Vec::new())),
            session_event(
                "evt-bound-synthetic",
                1,
                "compaction_boundary",
                Payload::map(Vec::new()),
            ),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_compaction_snapshot(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn shared_item_same_type_same_call_id_returns_no_divergences() {
        let events = vec![
            durable("evt-call-synthetic", 0, "function_call", Some("corr-a")),
            boundary(
                "evt-bound-synthetic",
                1,
                vec![guardian_item(
                    "evt-call-synthetic",
                    "function_call",
                    Some("corr-a"),
                )],
            ),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_compaction_snapshot(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn snapshot_only_id_returns_no_divergences() {
        let events = vec![
            durable("evt-a-synthetic", 0, "message", None),
            boundary(
                "evt-bound-synthetic",
                1,
                vec![
                    guardian_item("evt-a-synthetic", "message", None),
                    guardian_item("evt-inherited-synthetic", "reasoning", None),
                ],
            ),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_compaction_snapshot(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn item_absent_from_snapshot_returns_no_divergences() {
        let events = vec![
            durable("evt-a-synthetic", 0, "message", None),
            durable("evt-b-synthetic", 1, "message", None),
            boundary(
                "evt-bound-synthetic",
                2,
                vec![guardian_item("evt-a-synthetic", "message", None)],
            ),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_compaction_snapshot(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn type_mismatch_records_first_item_id_and_check_returns_codec_error() {
        let events = vec![
            durable("evt-a-synthetic", 0, "message", None),
            boundary(
                "evt-bound-synthetic",
                1,
                vec![guardian_item("evt-a-synthetic", "reasoning", None)],
            ),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].divergence, "type-mismatch");
        assert_eq!(records[0].item_id, "evt-a-synthetic");
        assert_eq!(records[0].occurrences, 1);
        assert_eq!(records[0].snapshot_item_type.as_deref(), Some("reasoning"));
        assert_eq!(records[0].stream_item_type.as_deref(), Some("message"));
        let err = check_compaction_snapshot(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn correlator_present_on_only_one_side_is_correlation_mismatch() {
        let events = vec![
            durable("evt-a-synthetic", 0, "message", None),
            boundary(
                "evt-bound-synthetic",
                1,
                vec![guardian_item(
                    "evt-a-synthetic",
                    "message",
                    Some("corr-only"),
                )],
            ),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].divergence, "correlation-mismatch");
        assert_eq!(records[0].item_id, "evt-a-synthetic");
        assert_eq!(records[0].snapshot_correlator.as_deref(), Some("corr-only"));
        assert_eq!(records[0].stream_correlator, None);
        let err = check_compaction_snapshot(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn durable_item_after_boundary_is_future_item() {
        let events = vec![
            boundary(
                "evt-bound-synthetic",
                0,
                vec![guardian_item("evt-late-synthetic", "message", None)],
            ),
            durable("evt-late-synthetic", 1, "message", None),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].divergence, "future-item");
        assert_eq!(records[0].item_id, "evt-late-synthetic");
        assert_eq!(records[0].boundary_index, 0);
        assert_eq!(records[0].item_index, 1);
        let err = check_compaction_snapshot(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn two_type_mismatches_keep_the_first_anchor_and_occurrence_count_2() {
        let events = vec![
            durable("evt-a-synthetic", 0, "message", None),
            durable("evt-b-synthetic", 1, "message", None),
            boundary(
                "evt-bound-synthetic",
                2,
                vec![
                    guardian_item("evt-a-synthetic", "reasoning", None),
                    guardian_item("evt-b-synthetic", "reasoning", None),
                ],
            ),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].divergence, "type-mismatch");
        assert_eq!(records[0].item_id, "evt-a-synthetic");
        assert_eq!(records[0].occurrences, 2);
        let err = check_compaction_snapshot(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn tuple_guardian_items_produces_no_divergences() {
        let events = vec![
            durable("evt-a-synthetic", 0, "message", None),
            session_event(
                "evt-bound-synthetic",
                1,
                "compaction_boundary",
                codex_extra(vec![(
                    Payload::string("guardian_items"),
                    Payload::tuple(vec![guardian_item("evt-a-synthetic", "reasoning", None)]),
                )]),
            ),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_compaction_snapshot(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn mapping_extra_fields_uses_to_payload() {
        let durable_extra = EventField::Mapping(EventMapping::new(vec![(
            "codex".to_owned(),
            EventField::Mapping(EventMapping::new(vec![(
                "item_type".to_owned(),
                EventField::Str("message".to_owned()),
            )])),
        )]));
        let snapshot_item = EventField::Mapping(EventMapping::new(vec![
            (
                "id".to_owned(),
                EventField::Str("evt-map-synthetic".to_owned()),
            ),
            ("type".to_owned(), EventField::Str("message".to_owned())),
        ]));
        let boundary_extra = EventField::Mapping(EventMapping::new(vec![(
            "codex".to_owned(),
            EventField::Mapping(EventMapping::new(vec![(
                "guardian_items".to_owned(),
                EventField::List(vec![snapshot_item]),
            )])),
        )]));
        let events = vec![
            EventValue::Mapping(EventMapping::new(vec![
                (
                    "id".to_owned(),
                    EventField::Str("evt-map-synthetic".to_owned()),
                ),
                ("kind".to_owned(), EventField::Str("message".to_owned())),
                ("extra_fields".to_owned(), durable_extra),
            ])),
            EventValue::Mapping(EventMapping::new(vec![
                (
                    "id".to_owned(),
                    EventField::Str("evt-bound-synthetic".to_owned()),
                ),
                (
                    "kind".to_owned(),
                    EventField::Str("compaction_boundary".to_owned()),
                ),
                ("extra_fields".to_owned(), boundary_extra),
            ])),
        ];
        let records = compaction_snapshot_divergences(&events).unwrap();
        assert!(records.is_empty());
        let findings = check_compaction_snapshot(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }
}
