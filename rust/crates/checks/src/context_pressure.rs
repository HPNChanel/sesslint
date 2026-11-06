//! SL207 context-pressure projection detector (detector-depth T-04).
//!
//! Port of `src/sesslint/checks/context_pressure.py` lines 1–119
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`check_context_pressure`] calls [`make_finding`] with the fingerprint
//! omitted. That returns the codec error and does not produce a digest.
//! This module does not call [`crate::graph::cap_graph_findings`].
//!
//! Codex-rollout-scoped check: `event_msg/token_count` records carry the
//! vendor's own per-request context footprint
//! (`info.last_token_usage.input_tokens` — the input side is what
//! occupies the window; `cached_input_tokens` is a subset of it) and the
//! declared model window (`info.model_context_window`). The adapter
//! normalizes both into `extra_fields["codex"]["context_pressure"]` as
//! `{occupancy, window}` integers.
//!
//! Two counters are deliberately *not* used: `total_token_usage` and
//! `thread_token_usage` are cumulative lifetime billing totals (corpus
//! observation: they routinely exceed the window by orders of magnitude)
//! — mapping them to window occupancy would be the wrong counter and
//! produce false confidence.
//!
//! [`last_pressure_marker`] reports whether the last qualifying marker
//! fires. It does not hash. [`check_context_pressure`] calls
//! [`make_finding`] only when that function says it fires, and
//! propagates the codec error.
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Headroom and the 15% comparison use `i64`
//!   checked arithmetic. Overflow is [`PYTHON_INT_UNBOUNDED`], not a wrap
//!   and not a panic.
//! * [`MapLookup::Borrowed`] is a failed borrow, not a missing key
//!   ([`BORROWED_LOOKUP`]). [`MapLookup::NotAMap`] and
//!   [`MapLookup::Absent`] skip that level and the event is not a marker.
//! * [`crate::graph::event_get`] does not return `extra_fields` for a
//!   [`model::canonical::SessionEvent`]. This module reads
//!   [`model::canonical::SessionEvent::extra_fields`] directly. For
//!   [`EventValue::Mapping`], it reads the `extra_fields` field and uses
//!   [`model::events::EventMapping::to_payload`] when that field is a mapping.
//! * A bool is not an int. A float, a string, and a missing value do not
//!   qualify. `window <= 0` does not qualify.

use std::error::Error;
use std::fmt;

use model::canonical::{MapLookup, Payload};
use model::codes::{Repairability, Severity, SL207};
use model::errors::FindingError;
use model::events::{EventField, EventValue};
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef};

use crate::context::CheckContext;
use crate::graph::{event_get, resolve_source_coords, safe_id, GraphError};

/// Python: `_MSG_PRESSURE`.
pub const MSG_PRESSURE: &str =
    "Context headroom below 15% of the declared window on line {line} for record {record_id}";

/// Python: `_HEADROOM_NUM`.
pub const HEADROOM_NUM: i64 = 3;

/// Python: `_HEADROOM_DEN`.
pub const HEADROOM_DEN: i64 = 20;

/// Python: `_THRESHOLD_SOURCE`.
pub const THRESHOLD_SOURCE: &str = "declared-window:15pct-headroom";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// [`MapLookup::Borrowed`] is not a missing key.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextPressureError {
    BorrowedLookup,
    PythonIntUnbounded,
    Finding(FindingError),
    Graph(GraphError),
}

impl ContextPressureError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::Finding(error) => error.message(),
            Self::Graph(error) => error.message(),
        }
    }
}

impl fmt::Display for ContextPressureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ContextPressureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::Graph(error) => Some(error),
            Self::BorrowedLookup | Self::PythonIntUnbounded => None,
        }
    }
}

impl From<FindingError> for ContextPressureError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

impl From<GraphError> for ContextPressureError {
    fn from(error: GraphError) -> Self {
        match error {
            GraphError::Finding(error) => Self::Finding(error),
            other => Self::Graph(other),
        }
    }
}

/// Last qualifying marker that fires. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastPressureMarker {
    pub occupancy: i64,
    pub window: i64,
    pub headroom: i64,
    pub event_index: usize,
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
fn map_field(payload: &Payload, key: &str) -> Result<Option<Payload>, ContextPressureError> {
    match payload.map_string(key) {
        MapLookup::Borrowed => Err(ContextPressureError::BorrowedLookup),
        MapLookup::NotAMap | MapLookup::Absent => Ok(None),
        MapLookup::Present(value) => Ok(Some(value)),
    }
}

/// Occupancy and window from one event, or `None` when it is not a marker.
/// Does not read `total_token_usage` or `thread_token_usage`.
fn marker_occupancy_window(ev: &EventValue) -> Result<Option<(i64, i64)>, ContextPressureError> {
    let Some(extra) = extra_fields_payload(ev) else {
        return Ok(None);
    };
    let Some(codex) = map_field(&extra, "codex")? else {
        return Ok(None);
    };
    let Some(pressure) = map_field(&codex, "context_pressure")? else {
        return Ok(None);
    };
    let Some(occupancy_raw) = map_field(&pressure, "occupancy")? else {
        return Ok(None);
    };
    let Some(window_raw) = map_field(&pressure, "window")? else {
        return Ok(None);
    };
    let Some(occupancy) = occupancy_raw.as_int() else {
        return Ok(None);
    };
    let Some(window) = window_raw.as_int() else {
        return Ok(None);
    };
    if window <= 0 {
        return Ok(None);
    }
    Ok(Some((occupancy, window)))
}

fn checked_sub(left: i64, right: i64) -> Result<i64, ContextPressureError> {
    left.checked_sub(right)
        .ok_or(ContextPressureError::PythonIntUnbounded)
}

fn checked_mul(left: i64, right: i64) -> Result<i64, ContextPressureError> {
    left.checked_mul(right)
        .ok_or(ContextPressureError::PythonIntUnbounded)
}

/// Whether the last qualifying marker fires. Does not hash.
///
/// Walks events in stored order. An earlier qualifying marker is replaced
/// by a later one. No qualifying marker, or a last marker whose headroom
/// stays at or above 15% of the declared window, is silent.
pub fn last_pressure_marker(
    events: &[EventValue],
) -> Result<Option<LastPressureMarker>, ContextPressureError> {
    let mut last = None;
    for (event_index, ev) in events.iter().enumerate() {
        if let Some((occupancy, window)) = marker_occupancy_window(ev)? {
            last = Some((event_index, occupancy, window));
        }
    }
    let Some((event_index, occupancy, window)) = last else {
        return Ok(None);
    };
    let headroom = checked_sub(window, occupancy)?;
    let left = checked_mul(headroom, HEADROOM_DEN)?;
    let right = checked_mul(window, HEADROOM_NUM)?;
    if left >= right {
        return Ok(None);
    }
    Ok(Some(LastPressureMarker {
        occupancy,
        window,
        headroom,
        event_index,
    }))
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

fn pressure_evidence(marker: &LastPressureMarker, line_num: Option<i64>) -> PyValue {
    let mut entries = vec![
        (
            PyValue::string("context_tokens"),
            PyValue::int(marker.occupancy),
        ),
        (PyValue::string("window_limit"), PyValue::int(marker.window)),
        (PyValue::string("headroom"), PyValue::int(marker.headroom)),
        (
            PyValue::string("threshold_source"),
            PyValue::string(THRESHOLD_SOURCE),
        ),
    ];
    if let Some(line) = line_num {
        entries.push((PyValue::string("last_marker_line"), PyValue::int(line)));
    }
    PyValue::map(entries)
}

/// Python: `check_context_pressure`.
///
/// No qualifying marker, or a last marker at or above the 15% boundary,
/// returns an empty list and does not call [`make_finding`]. A firing
/// marker calls [`make_finding`] with the fingerprint omitted; that codec
/// error is propagated.
pub fn check_context_pressure(
    events: &[EventValue],
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, ContextPressureError> {
    let Some(marker) = last_pressure_marker(events)? else {
        return Ok(Vec::new());
    };
    let Some(ev) = events.get(marker.event_index) else {
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
        code: PyValue::string(SL207),
        severity: PyValue::severity(Severity::Warning),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_PRESSURE),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence: pressure_evidence(&marker, line_num),
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
        check_context_pressure, last_pressure_marker, ContextPressureError, HEADROOM_DEN,
        HEADROOM_NUM, MSG_PRESSURE, THRESHOLD_SOURCE,
    };
    use model::canonical::{Payload, SessionEvent};
    use model::events::EventValue;
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    fn session_event(id: &str, extra: Payload) -> EventValue {
        let mut event =
            SessionEvent::new(id, None, 0, "2024-02-29T00:00:00Z", "assistant", "message");
        event.extra_fields = extra;
        EventValue::from_session(event)
    }

    fn pressure_extra(occupancy: Payload, window: Payload) -> Payload {
        Payload::map(vec![(
            Payload::string("codex"),
            Payload::map(vec![(
                Payload::string("context_pressure"),
                Payload::map(vec![
                    (Payload::string("occupancy"), occupancy),
                    (Payload::string("window"), window),
                ]),
            )]),
        )])
    }

    fn marker_event(id: &str, occupancy: i64, window: i64) -> EventValue {
        session_event(
            id,
            pressure_extra(Payload::int(occupancy), Payload::int(window)),
        )
    }

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn assert_codec_unavailable(err: ContextPressureError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn constants_match_python() {
        assert_eq!(HEADROOM_NUM, 3);
        assert_eq!(HEADROOM_DEN, 20);
        assert_eq!(THRESHOLD_SOURCE, "declared-window:15pct-headroom");
        assert_eq!(
            MSG_PRESSURE,
            "Context headroom below 15% of the declared window on line {line} for record {record_id}"
        );
    }

    #[test]
    fn no_marker_is_silent() {
        let events = vec![
            session_event("evt-a-synthetic", Payload::map(Vec::new())),
            session_event("evt-b-synthetic", Payload::map(Vec::new())),
        ];
        let marker = last_pressure_marker(&events).unwrap();
        assert!(marker.is_none());
        let findings = check_context_pressure(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn headroom_exactly_on_15pct_boundary_stays_silent() {
        let events = vec![marker_event("evt-boundary-synthetic", 8500, 10000)];
        let marker = last_pressure_marker(&events).unwrap();
        assert!(marker.is_none());
        let findings = check_context_pressure(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn one_step_under_boundary_records_marker_and_codec_error() {
        let events = vec![marker_event("evt-under-synthetic", 8501, 10000)];
        let marker = last_pressure_marker(&events).unwrap().expect("fires");
        assert_eq!(marker.occupancy, 8501);
        assert_eq!(marker.window, 10000);
        assert_eq!(marker.headroom, 1499);
        assert_eq!(marker.event_index, 0);
        let err = check_context_pressure(&events, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn earlier_tight_then_later_comfortable_stays_silent() {
        let events = vec![
            marker_event("evt-tight-synthetic", 8501, 10000),
            marker_event("evt-comfortable-synthetic", 8500, 10000),
        ];
        let marker = last_pressure_marker(&events).unwrap();
        assert!(marker.is_none());
        let findings = check_context_pressure(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn bool_occupancy_is_ignored() {
        let events = vec![session_event(
            "evt-bool-synthetic",
            pressure_extra(Payload::bool_value(true), Payload::int(10000)),
        )];
        let marker = last_pressure_marker(&events).unwrap();
        assert!(marker.is_none());
        let findings = check_context_pressure(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn window_zero_is_ignored() {
        let events = vec![marker_event("evt-zero-window-synthetic", 1, 0)];
        let marker = last_pressure_marker(&events).unwrap();
        assert!(marker.is_none());
        let findings = check_context_pressure(&events, None, None).unwrap();
        assert!(findings.is_empty());
    }
}
