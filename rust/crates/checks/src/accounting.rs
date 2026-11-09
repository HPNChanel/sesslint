//! SL204 token-usage arithmetic inconsistency detector.
//!
//! Port of `src/sesslint/checks/accounting.py` lines 1–178
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`check_accounting`] calls [`make_finding`] with the fingerprint omitted.
//! That returns the codec error and does not produce a digest. This module
//! does not substitute [`crate::graph::compute_graph_fingerprint`].
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Counter sums use `i64` checked addition.
//!   Overflow is [`PYTHON_INT_UNBOUNDED`], not a wrap and not a panic.
//! * [`MapWalk::Borrowed`] is a failed borrow, not an empty map
//!   ([`BORROWED_WALK`]). [`MapWalk::NotAMap`] is an empty counter dict.
//! * [`MapLookup::Borrowed`] is a failed borrow, not a missing slot
//!   ([`BORROWED_LOOKUP`]).
//! * [`crate::graph::event_get`] does not return `extra_fields` for a
//!   [`model::canonical::SessionEvent`]. This module reads
//!   [`model::canonical::SessionEvent::extra_fields`] directly. For
//!   [`EventValue::Mapping`], it reads the `extra_fields` field and uses
//!   [`model::events::EventMapping::to_payload`] when that field is a mapping.
//! * A bool is not an int. A float, a string, and a negative int are
//!   dropped per key. A Python repr is not invented.

use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use model::canonical::{MapLookup, MapWalk, Payload};
use model::codes::{Repairability, Severity, SL204};
use model::errors::FindingError;
use model::events::{EventField, EventValue};
use model::finding::{make_finding, MakeFindingInput, PyValue, SourceLine, SourceRef};

use crate::context::CheckContext;
use crate::graph::{
    cap_graph_findings, event_get, event_id_safe, resolve_source_coords, safe_id, GraphError,
    MAX_GRAPH_FINDINGS,
};

/// Python: `_MSG_SL204`.
pub const MSG_SL204: &str = "Token usage arithmetic inconsistency for record {record_id}";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// [`MapWalk::Borrowed`] is not an empty counter dict.
pub const BORROWED_WALK: &str = "A borrowed map walk is not an empty map";

/// [`MapLookup::Borrowed`] is not a missing usage slot.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountingError {
    BorrowedWalk,
    BorrowedLookup,
    PythonIntUnbounded,
    Finding(FindingError),
    Graph(GraphError),
}

impl AccountingError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedWalk => BORROWED_WALK,
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::Finding(error) => error.message(),
            Self::Graph(error) => error.message(),
        }
    }
}

impl fmt::Display for AccountingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for AccountingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::Graph(error) => Some(error),
            Self::BorrowedWalk | Self::BorrowedLookup | Self::PythonIntUnbounded => None,
        }
    }
}

impl From<FindingError> for AccountingError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

impl From<GraphError> for AccountingError {
    fn from(error: GraphError) -> Self {
        match error {
            GraphError::Finding(error) => Self::Finding(error),
            other => Self::Graph(other),
        }
    }
}

/// One cumulative marker whose window sum disagrees. Does not call
/// [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountingMismatch {
    pub record_ordinal: usize,
    pub expected_total: i64,
    pub observed_total: i64,
    pub mismatched_key_count: i64,
    pub window_start_index: usize,
    pub window_end_index: usize,
}

type CounterMap = HashMap<String, i64>;
type UsageSlot = (CounterMap, CounterMap);

fn empty_slot() -> UsageSlot {
    (CounterMap::new(), CounterMap::new())
}

/// Python: `_clean_counters`.
///
/// A non-map is empty. [`MapWalk::Borrowed`] is an error. Each string key
/// is visited once; the last value wins. A bool is not an int.
fn clean_counters(raw: &Payload) -> Result<CounterMap, AccountingError> {
    let mut counters = CounterMap::new();
    match raw.walk_string_entries(|key, value| {
        if let Some(number) = value.as_int() {
            if number >= 0 {
                counters.insert(key.to_owned(), number);
            }
        }
    }) {
        MapWalk::NotAMap => Ok(CounterMap::new()),
        MapWalk::Borrowed => Err(AccountingError::BorrowedWalk),
        MapWalk::Done => Ok(counters),
    }
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

fn slot_counters(usage: &Payload, slot: &str) -> Result<CounterMap, AccountingError> {
    match usage.map_string(slot) {
        MapLookup::Borrowed => Err(AccountingError::BorrowedLookup),
        MapLookup::NotAMap | MapLookup::Absent => Ok(CounterMap::new()),
        MapLookup::Present(raw) => clean_counters(&raw),
    }
}

/// Python: `_usage_slot`.
fn usage_slot(ev: &EventValue) -> Result<UsageSlot, AccountingError> {
    let Some(extra) = extra_fields_payload(ev) else {
        return Ok(empty_slot());
    };
    match extra.map_string("usage") {
        MapLookup::Borrowed => Err(AccountingError::BorrowedLookup),
        MapLookup::NotAMap | MapLookup::Absent => Ok(empty_slot()),
        MapLookup::Present(usage) => {
            if !usage.is_map() {
                return Ok(empty_slot());
            }
            Ok((
                slot_counters(&usage, "contribution")?,
                slot_counters(&usage, "cumulative")?,
            ))
        }
    }
}

fn add_i64(left: i64, right: i64) -> Result<i64, AccountingError> {
    left.checked_add(right)
        .ok_or(AccountingError::PythonIntUnbounded)
}

fn next_index(idx: usize) -> Result<usize, AccountingError> {
    idx.checked_add(1)
        .ok_or(AccountingError::PythonIntUnbounded)
}

fn usize_to_i64(value: usize) -> Result<i64, AccountingError> {
    i64::try_from(value).map_err(|_| AccountingError::PythonIntUnbounded)
}

fn kind_is_compaction_boundary(ev: &EventValue) -> bool {
    matches!(
        event_get(ev, "kind"),
        Some(EventField::Str(ref kind)) if kind == "compaction_boundary"
    )
}

/// Every window/marker disagreement in `events`. Does not call [`make_finding`].
pub fn accounting_mismatches(
    events: &[EventValue],
) -> Result<Vec<AccountingMismatch>, AccountingError> {
    let mut baseline: Option<CounterMap> = None;
    let mut window: CounterMap = CounterMap::new();
    let mut window_start_idx = 0usize;
    let mut unchecked_next_marker = false;
    let mut mismatches = Vec::new();

    for (idx, ev) in events.iter().enumerate() {
        if kind_is_compaction_boundary(ev) {
            baseline = None;
            window = CounterMap::new();
            window_start_idx = next_index(idx)?;
            unchecked_next_marker = true;
            continue;
        }

        let (contribution, cumulative) = usage_slot(ev)?;
        for (key, val) in contribution {
            let current = window.get(&key).copied().unwrap_or(0);
            window.insert(key, add_i64(current, val)?);
        }

        if cumulative.is_empty() {
            continue;
        }
        if unchecked_next_marker {
            baseline = Some(cumulative);
            window = CounterMap::new();
            window_start_idx = next_index(idx)?;
            unchecked_next_marker = false;
            continue;
        }

        let mut mismatched = 0i64;
        let mut expected_total = 0i64;
        let mut observed_total = 0i64;
        for (key, observed) in &cumulative {
            let base = baseline
                .as_ref()
                .and_then(|counters| counters.get(key))
                .copied()
                .unwrap_or(0);
            let window_val = window.get(key).copied().unwrap_or(0);
            let expected = add_i64(base, window_val)?;
            expected_total = add_i64(expected_total, expected)?;
            observed_total = add_i64(observed_total, *observed)?;
            if expected != *observed {
                mismatched = add_i64(mismatched, 1)?;
            }
        }

        if mismatched != 0 {
            mismatches.push(AccountingMismatch {
                record_ordinal: idx,
                expected_total,
                observed_total,
                mismatched_key_count: mismatched,
                window_start_index: window_start_idx,
                window_end_index: idx,
            });
        }

        baseline = Some(cumulative);
        window = CounterMap::new();
        window_start_idx = next_index(idx)?;
    }

    Ok(mismatches)
}

/// Python: `check_accounting`.
///
/// No mismatch returns an empty list and does not call [`make_finding`].
/// A mismatch calls [`make_finding`] with the fingerprint omitted; that
/// codec error is propagated. After a successful [`make_finding`],
/// [`cap_graph_findings`] is called.
pub fn check_accounting(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<usize>,
    context: Option<&CheckContext>,
) -> Result<Vec<model::finding::Finding>, AccountingError> {
    let mismatches = accounting_mismatches(events)?;
    if mismatches.is_empty() {
        return Ok(Vec::new());
    }

    let source_path = source_path.unwrap_or("<canonical>");
    let max_findings = max_findings.unwrap_or(MAX_GRAPH_FINDINGS);
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };

    let mut findings = Vec::new();
    for mismatch in mismatches {
        let Some(ev) = events.get(mismatch.record_ordinal) else {
            continue;
        };
        let (resolved_path, line_num) = resolve_source_coords(ev, source_path)?;
        let clean_rec_id = safe_id(&event_id_safe(ev).unwrap_or_default());
        let source = SourceRef::try_new(
            &resolved_path,
            line_num.map(SourceLine::Int),
            Some(clean_rec_id.as_str()),
        )?;
        let evidence = PyValue::map(vec![
            (
                PyValue::string("record_id"),
                PyValue::string(clean_rec_id.clone()),
            ),
            (
                PyValue::string("expected_total"),
                PyValue::int(mismatch.expected_total),
            ),
            (
                PyValue::string("observed_total"),
                PyValue::int(mismatch.observed_total),
            ),
            (
                PyValue::string("mismatched_key_count"),
                PyValue::int(mismatch.mismatched_key_count),
            ),
            (
                PyValue::string("window_start_index"),
                PyValue::int(usize_to_i64(mismatch.window_start_index)?),
            ),
            (
                PyValue::string("window_end_index"),
                PyValue::int(usize_to_i64(mismatch.window_end_index)?),
            ),
            (
                PyValue::string("record_ordinal"),
                PyValue::int(usize_to_i64(mismatch.record_ordinal)?),
            ),
        ]);
        findings.push(make_finding(&MakeFindingInput {
            code: PyValue::string(SL204),
            severity: PyValue::severity(Severity::Warning),
            repairability: PyValue::repairability(Repairability::Manual),
            message_template: PyValue::string(MSG_SL204),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::tuple(vec![PyValue::string(clean_rec_id)]),
            evidence,
            fingerprint: PyValue::None,
            adapter_id: Some(ctx.adapter_id().to_owned()),
            adapter_version: Some(ctx.adapter_version().to_owned()),
            profile_id: Some(ctx.profile_id().to_owned()),
            profile_version: Some(ctx.profile_version().to_owned()),
            ordinal: None,
            context: None,
        })?);
    }

    Ok(cap_graph_findings(
        findings,
        SL204,
        Some(max_findings),
        Some(source_path),
        Some(ctx),
    )?)
}

/// Python `__all__`, in that order.
pub const ALL: [&str; 1] = ["check_accounting"];

#[cfg(test)]
mod tests {
    use super::{
        accounting_mismatches, check_accounting, AccountingError, ALL, MSG_SL204,
        PYTHON_INT_UNBOUNDED,
    };
    use model::canonical::{Payload, SessionEvent};
    use model::events::{EventField, EventMapping, EventValue};
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    fn session_event(id: &str, seq: i64, kind: &str, extra: Payload) -> EventValue {
        let mut event = SessionEvent::new(id, None, seq, "2024-02-29T00:00:00Z", "system", kind);
        event.extra_fields = extra;
        EventValue::from_session(event)
    }

    fn usage_extra(contribution: Option<Payload>, cumulative: Option<Payload>) -> Payload {
        let mut slots = Vec::new();
        if let Some(value) = contribution {
            slots.push((Payload::string("contribution"), value));
        }
        if let Some(value) = cumulative {
            slots.push((Payload::string("cumulative"), value));
        }
        Payload::map(vec![(Payload::string("usage"), Payload::map(slots))])
    }

    fn usage_event(
        id: &str,
        seq: i64,
        contribution: Option<Payload>,
        cumulative: Option<Payload>,
    ) -> EventValue {
        session_event(id, seq, "message", usage_extra(contribution, cumulative))
    }

    fn boundary(id: &str, seq: i64) -> EventValue {
        session_event(id, seq, "compaction_boundary", Payload::map(Vec::new()))
    }

    fn one(value: i64) -> Payload {
        Payload::map(vec![(Payload::string("n"), Payload::int(value))])
    }

    fn two_keys(primary: i64, extra: i64) -> Payload {
        Payload::map(vec![
            (Payload::string("n"), Payload::int(primary)),
            (Payload::string("w"), Payload::int(extra)),
        ])
    }

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn assert_codec_unavailable(err: AccountingError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn all_is_check_accounting() {
        assert_eq!(ALL, ["check_accounting"]);
        assert_eq!(
            MSG_SL204,
            "Token usage arithmetic inconsistency for record {record_id}"
        );
        assert_eq!(
            PYTHON_INT_UNBOUNDED,
            "Python ints are unbounded; an i64 overflow is not a wrap and not a panic"
        );
    }

    #[test]
    fn no_usage_returns_no_mismatches_and_check_accounting_is_empty() {
        let events = vec![
            session_event("evt-a-synthetic", 0, "message", Payload::map(Vec::new())),
            session_event("evt-b-synthetic", 1, "message", Payload::map(Vec::new())),
        ];
        let mismatches = accounting_mismatches(&events).unwrap();
        assert!(mismatches.is_empty());
        let findings = check_accounting(&events, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn contribution_two_then_cumulative_two_has_no_mismatches() {
        let events = vec![
            usage_event("evt-a-synthetic", 0, Some(one(2)), None),
            usage_event("evt-b-synthetic", 1, None, Some(one(2))),
        ];
        let mismatches = accounting_mismatches(&events).unwrap();
        assert!(mismatches.is_empty());
        let findings = check_accounting(&events, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn contribution_two_then_cumulative_three_reports_two_and_three() {
        let events = vec![
            usage_event("evt-a-synthetic", 0, Some(one(2)), None),
            usage_event("evt-b-synthetic", 1, None, Some(one(3))),
        ];
        let mismatches = accounting_mismatches(&events).unwrap();
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].expected_total, 2);
        assert_eq!(mismatches[0].observed_total, 3);
        assert_eq!(mismatches[0].mismatched_key_count, 1);
        assert_eq!(mismatches[0].window_start_index, 0);
        assert_eq!(mismatches[0].window_end_index, 1);
        assert_eq!(mismatches[0].record_ordinal, 1);
        let err = check_accounting(&events, None, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn marker_own_contribution_is_inside_the_expected_sum() {
        let events = vec![
            usage_event("evt-a-synthetic", 0, Some(one(5)), None),
            usage_event("evt-b-synthetic", 1, Some(one(2)), Some(one(7))),
        ];
        let mismatches = accounting_mismatches(&events).unwrap();
        assert!(mismatches.is_empty());
        let findings = check_accounting(&events, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn a_key_only_in_the_window_does_not_mismatch() {
        let events = vec![usage_event(
            "evt-a-synthetic",
            0,
            Some(two_keys(2, 9)),
            Some(one(2)),
        )];
        let mismatches = accounting_mismatches(&events).unwrap();
        assert!(mismatches.is_empty());
        let findings = check_accounting(&events, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn bool_float_and_negative_int_are_ignored() {
        let mixed = Payload::map(vec![
            (Payload::string("n"), Payload::int(2)),
            (Payload::string("a"), Payload::bool_value(true)),
            (Payload::string("b"), Payload::float(1.5)),
            (Payload::string("c"), Payload::int(-1)),
            (Payload::string("e"), Payload::string("x")),
        ]);
        let events = vec![usage_event("evt-a-synthetic", 0, Some(one(2)), Some(mixed))];
        let mismatches = accounting_mismatches(&events).unwrap();
        assert!(mismatches.is_empty());
        let findings = check_accounting(&events, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn compaction_boundary_makes_the_next_marker_a_baseline() {
        let events = vec![
            boundary("evt-bound-synthetic", 0),
            usage_event("evt-a-synthetic", 1, None, Some(one(99))),
            usage_event("evt-b-synthetic", 2, Some(one(1)), Some(one(50))),
        ];
        let mismatches = accounting_mismatches(&events).unwrap();
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].expected_total, 100);
        assert_eq!(mismatches[0].observed_total, 50);
        assert_eq!(mismatches[0].record_ordinal, 2);
        let err = check_accounting(&events, None, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn two_mismatches_are_both_present_in_the_pure_result() {
        let events = vec![
            usage_event("evt-a-synthetic", 0, Some(one(2)), Some(one(3))),
            usage_event("evt-b-synthetic", 1, Some(one(1)), Some(one(9))),
        ];
        let mismatches = accounting_mismatches(&events).unwrap();
        assert_eq!(mismatches.len(), 2);
        assert_eq!(mismatches[0].expected_total, 2);
        assert_eq!(mismatches[0].observed_total, 3);
        assert_eq!(mismatches[1].expected_total, 4);
        assert_eq!(mismatches[1].observed_total, 9);
        let err = check_accounting(&events, None, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn mapping_extra_fields_uses_to_payload() {
        let usage = EventField::Mapping(EventMapping::new(vec![
            (
                "contribution".to_owned(),
                EventField::Mapping(EventMapping::new(vec![(
                    "n".to_owned(),
                    EventField::Int(2),
                )])),
            ),
            (
                "cumulative".to_owned(),
                EventField::Mapping(EventMapping::new(vec![(
                    "n".to_owned(),
                    EventField::Int(2),
                )])),
            ),
        ]));
        let events = vec![EventValue::Mapping(EventMapping::new(vec![
            (
                "id".to_owned(),
                EventField::Str("evt-map-synthetic".to_owned()),
            ),
            ("kind".to_owned(), EventField::Str("message".to_owned())),
            (
                "extra_fields".to_owned(),
                EventField::Mapping(EventMapping::new(vec![("usage".to_owned(), usage)])),
            ),
        ]))];
        let mismatches = accounting_mismatches(&events).unwrap();
        assert!(mismatches.is_empty());
        let findings = check_accounting(&events, None, None, None).unwrap();
        assert!(findings.is_empty());
    }
}
