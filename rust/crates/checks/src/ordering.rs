//! SL008 non-monotonic timestamp detector (checks-rules T-01).
//!
//! Port of `src/sesslint/checks/ordering.py` lines 1–188
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`check_ordering`] calls [`make_finding`] with the fingerprint omitted.
//! That returns the codec error and does not produce a digest. This module
//! does not call [`crate::graph::cap_graph_findings`].
//!
//! Compares `ts` along a uniquely resolved parent edge. It does not compare
//! neighbours in file order. A child whose timestamp precedes its parent's
//! beyond the configured skew contributes to one aggregate warning per file.
//!
//! [`ordering_record`] reports that aggregate. It does not hash.
//! [`check_ordering`] calls [`make_finding`] only when that function returns
//! a record, and propagates the codec error.
//!
//! Evidence is structural only: ids, stream indices, and the integer
//! millisecond delta — never payload or raw timestamps.
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Deltas, counts, and indexes use `i64`
//!   checked arithmetic. Overflow is [`PYTHON_INT_UNBOUNDED`], not a wrap
//!   and not a panic.
//! * [`crate::graph::event_get`] does not return `ts` for a
//!   [`model::canonical::SessionEvent`]. This module reads
//!   [`model::canonical::SessionEvent::ts`] when that lookup is absent.
//! * A bool is not an int. `timestamp_skew_ms` is [`Option<i64>`]. Python
//!   `type(True) is bool` so `True` is rejected; that case is not
//!   representable here.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use model::codes::{Repairability, Severity, SL008};
use model::errors::FindingError;
use model::events::{EventField, EventValue};
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef};

use crate::context::CheckContext;
use crate::graph::{
    event_get, event_id_safe, event_parent_id_safe, resolve_source_coords, safe_id, GraphError,
};

/// Python: `_MSG_SL008`.
pub const MSG_SL008: &str = "Non-monotonic timestamp for record {record_id}";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// Python `ValueError` text from a negative `timestamp_skew_ms`.
pub const TIMESTAMP_SKEW_MS_MUST_BE_NONNEGATIVE: &str =
    "timestamp_skew_ms must be a nonnegative integer";

const TS_EPOCH_SENTINEL: &str = "1970-01-01T00:00:00Z";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderingError {
    NegativeSkew,
    PythonIntUnbounded,
    Finding(FindingError),
    Graph(GraphError),
}

impl OrderingError {
    pub fn message(&self) -> &str {
        match self {
            Self::NegativeSkew => TIMESTAMP_SKEW_MS_MUST_BE_NONNEGATIVE,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::Finding(error) => error.message(),
            Self::Graph(error) => error.message(),
        }
    }
}

impl fmt::Display for OrderingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for OrderingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::Graph(error) => Some(error),
            Self::NegativeSkew | Self::PythonIntUnbounded => None,
        }
    }
}

impl From<FindingError> for OrderingError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

impl From<GraphError> for OrderingError {
    fn from(error: GraphError) -> Self {
        match error {
            GraphError::Finding(error) => Self::Finding(error),
            other => Self::Graph(other),
        }
    }
}

/// One aggregate non-monotonic edge plus file-level counts. Does not call
/// [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderingRecord {
    pub record_id: String,
    pub parent_id: String,
    pub ts_delta_ms: i64,
    pub child_index: usize,
    pub parent_index: usize,
    pub record_ordinal: usize,
    pub count: i64,
    pub max_delta_ms: i64,
    pub timestamp_skew_ms: i64,
}

struct ParsedTs {
    micros: i64,
    aware: bool,
}

/// Timestamp field. [`event_get`] does not return `ts` for a [`SessionEvent`].
fn event_ts(ev: &EventValue) -> Option<EventField> {
    match event_get(ev, "ts") {
        Some(field) => Some(field),
        None => match ev {
            EventValue::Session(event) => Some(EventField::Str(event.ts.clone())),
            EventValue::Mapping(_) | EventValue::Other => None,
        },
    }
}

fn ts_is_python_none(value: Option<&EventField>) -> bool {
    matches!(value, None | Some(EventField::Null))
}

/// Python: `_parse_ts`.
fn parse_ts(raw: &EventField) -> Option<ParsedTs> {
    let EventField::Str(text) = raw else {
        return None;
    };
    if text.trim().is_empty() || text == TS_EPOCH_SENTINEL {
        return None;
    }
    parse_isoformat(&text.replace('Z', "+00:00"))
}

fn parse_isoformat(text: &str) -> Option<ParsedTs> {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let year = eat_n_digits(bytes, &mut index, 4)?;
    eat_byte(bytes, &mut index, b'-')?;
    let month = eat_n_digits(bytes, &mut index, 2)?;
    eat_byte(bytes, &mut index, b'-')?;
    let day = eat_n_digits(bytes, &mut index, 2)?;
    if !(1..=9999).contains(&year) || !calendar_date_ok(year, month, day) {
        return None;
    }
    let year = i32::try_from(year).ok()?;

    let (hour, minute, second, micros, aware, offset_secs) = if index == bytes.len() {
        (0u32, 0u32, 0u32, 0u32, false, 0i32)
    } else {
        let sep = *bytes.get(index)?;
        if sep != b'T' && sep != b' ' {
            return None;
        }
        index = index.checked_add(1)?;
        let hour = eat_n_digits(bytes, &mut index, 2)?;
        eat_byte(bytes, &mut index, b':')?;
        let minute = eat_n_digits(bytes, &mut index, 2)?;
        eat_byte(bytes, &mut index, b':')?;
        let second = eat_n_digits(bytes, &mut index, 2)?;
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        let micros = if bytes.get(index).copied() == Some(b'.') {
            index = index.checked_add(1)?;
            eat_fraction(bytes, &mut index)?
        } else {
            0
        };
        let (aware, offset_secs) = match bytes.get(index).copied() {
            None => (false, 0i32),
            Some(sign) if sign == b'+' || sign == b'-' => {
                index = index.checked_add(1)?;
                (true, parse_offset(bytes, &mut index, sign)?)
            }
            Some(_) => return None,
        };
        (hour, minute, second, micros, aware, offset_secs)
    };
    if index != bytes.len() {
        return None;
    }
    let local = civil_micros(year, month, day, hour, minute, second, micros)?;
    let offset_micros = i64::from(offset_secs).checked_mul(1_000_000)?;
    let micros = if aware {
        local.checked_sub(offset_micros)?
    } else {
        local
    };
    Some(ParsedTs { micros, aware })
}

fn calendar_date_ok(year: u32, month: u32, day: u32) -> bool {
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_gregorian_leap(year) => 29,
        2 => 28,
        _ => return false,
    };
    day >= 1 && day <= last
}

fn is_gregorian_leap(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

fn eat_byte(bytes: &[u8], index: &mut usize, expected: u8) -> Option<()> {
    if bytes.get(*index).copied() == Some(expected) {
        *index = index.checked_add(1)?;
        Some(())
    } else {
        None
    }
}

fn eat_n_digits(bytes: &[u8], index: &mut usize, count: usize) -> Option<u32> {
    let start = *index;
    let end = start.checked_add(count)?;
    let slice = bytes.get(start..end)?;
    let mut value = 0u32;
    for byte in slice {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
    }
    *index = end;
    Some(value)
}

fn eat_fraction(bytes: &[u8], index: &mut usize) -> Option<u32> {
    if !bytes
        .get(*index)
        .copied()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut micros = 0u32;
    let mut seen = 0u32;
    while bytes
        .get(*index)
        .copied()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        let digit = u32::from(bytes.get(*index).copied()? - b'0');
        if seen < 6 {
            micros = micros.checked_mul(10)?.checked_add(digit)?;
        }
        seen = seen.checked_add(1)?;
        *index = index.checked_add(1)?;
    }
    while seen < 6 {
        micros = micros.checked_mul(10)?;
        seen = seen.checked_add(1)?;
    }
    Some(micros)
}

fn parse_offset(bytes: &[u8], index: &mut usize, sign: u8) -> Option<i32> {
    let hour = eat_n_digits(bytes, index, 2)?;
    if hour > 23 {
        return None;
    }
    let (minute, second) = if bytes.get(*index).copied() == Some(b':') {
        *index = index.checked_add(1)?;
        let minute = eat_n_digits(bytes, index, 2)?;
        let second = if bytes.get(*index).copied() == Some(b':') {
            *index = index.checked_add(1)?;
            eat_n_digits(bytes, index, 2)?
        } else {
            0
        };
        (minute, second)
    } else if bytes
        .get(*index)
        .copied()
        .is_some_and(|byte| byte.is_ascii_digit())
    {
        let minute = eat_n_digits(bytes, index, 2)?;
        let second = if bytes
            .get(*index)
            .copied()
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            eat_n_digits(bytes, index, 2)?
        } else {
            0
        };
        (minute, second)
    } else {
        (0, 0)
    };
    if minute > 59 || second > 59 {
        return None;
    }
    let total = i32::try_from(hour.checked_mul(3600)?.checked_add(minute * 60 + second)?).ok()?;
    Some(if sign == b'-' { -total } else { total })
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    let mut y = i64::from(year);
    if month <= 2 {
        y = y.checked_sub(1)?;
    }
    let era = y.div_euclid(400);
    let yoe = u64::try_from(y.checked_sub(era.checked_mul(400)?)?).ok()?;
    let mp = if month > 2 {
        u64::from(month.checked_sub(3)?)
    } else {
        u64::from(month).checked_add(9)?
    };
    let doy = (153u64.checked_mul(mp)?.checked_add(2)?)
        .checked_div(5)?
        .checked_add(u64::from(day))?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe / 4)?
        .checked_sub(yoe / 100)?
        .checked_add(doy)?;
    era.checked_mul(146097)?
        .checked_add(i64::try_from(doe).ok()?)?
        .checked_sub(719468)
}

fn civil_micros(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    micros: u32,
) -> Option<i64> {
    let days = days_from_civil(year, month, day)?;
    let day_secs = days.checked_mul(86_400)?;
    let time_secs = i64::from(hour)
        .checked_mul(3600)?
        .checked_add(i64::from(minute).checked_mul(60)?)?
        .checked_add(i64::from(second))?;
    day_secs
        .checked_add(time_secs)?
        .checked_mul(1_000_000)?
        .checked_add(i64::from(micros))
}

fn ts_delta_ms(child: &ParsedTs, parent: &ParsedTs) -> Result<i64, OrderingError> {
    let delta_us = child
        .micros
        .checked_sub(parent.micros)
        .ok_or(OrderingError::PythonIntUnbounded)?;
    Ok(delta_us.div_euclid(1000))
}

fn usize_to_i64(value: usize) -> Result<i64, OrderingError> {
    i64::try_from(value).map_err(|_| OrderingError::PythonIntUnbounded)
}

fn resolved_skew(
    context: Option<&CheckContext>,
    timestamp_skew_ms: Option<i64>,
) -> Result<i64, OrderingError> {
    let skew = match (timestamp_skew_ms, context) {
        (Some(value), _) => value,
        (None, Some(ctx)) => ctx.timestamp_skew_ms(),
        (None, None) => CheckContext::default().timestamp_skew_ms(),
    };
    if skew < 0 {
        return Err(OrderingError::NegativeSkew);
    }
    Ok(skew)
}

fn edge_datetimes(
    child_ts_raw: &EventField,
    parent_ts_raw: &EventField,
) -> Option<(ParsedTs, ParsedTs)> {
    if let (EventField::Str(child_s), EventField::Str(parent_s)) = (child_ts_raw, parent_ts_raw) {
        if child_s.len() == parent_s.len() && child_s.ends_with('Z') && parent_s.ends_with('Z') {
            if child_s == TS_EPOCH_SENTINEL || parent_s == TS_EPOCH_SENTINEL {
                return None;
            }
            if child_s.as_str() >= parent_s.as_str() {
                return None;
            }
            let child_ts = parse_ts(child_ts_raw)?;
            let parent_ts = parse_ts(parent_ts_raw)?;
            return Some((child_ts, parent_ts));
        }
    }
    let child_ts = parse_ts(child_ts_raw)?;
    let parent_ts = parse_ts(parent_ts_raw)?;
    if child_ts.aware != parent_ts.aware {
        return None;
    }
    if child_ts.micros >= parent_ts.micros {
        return None;
    }
    Some((child_ts, parent_ts))
}

/// One aggregate record for the file. Does not call [`make_finding`].
pub fn ordering_record(
    events: &[EventValue],
    context: Option<&CheckContext>,
    timestamp_skew_ms: Option<i64>,
) -> Result<Option<OrderingRecord>, OrderingError> {
    let skew = resolved_skew(context, timestamp_skew_ms)?;
    let mut id_to_index: HashMap<String, i64> = HashMap::new();
    for (idx, ev) in events.iter().enumerate() {
        let Some(eid) = event_id_safe(ev) else {
            continue;
        };
        if eid.is_empty() {
            continue;
        }
        let stored = usize_to_i64(idx)?;
        match id_to_index.entry(eid) {
            Entry::Occupied(mut occupied) => {
                *occupied.get_mut() = -1;
            }
            Entry::Vacant(vacant) => {
                vacant.insert(stored);
            }
        }
    }

    let mut count = 0i64;
    let mut max_delta = 0i64;
    let mut anchor: Option<OrderingRecord> = None;
    for (child_idx, child) in events.iter().enumerate() {
        let Some(parent_id) = event_parent_id_safe(child) else {
            continue;
        };
        if parent_id.is_empty() {
            continue;
        }
        let Some(&parent_idx) = id_to_index.get(&parent_id) else {
            continue;
        };
        if parent_idx < 0 {
            continue;
        }
        let parent_idx =
            usize::try_from(parent_idx).map_err(|_| OrderingError::PythonIntUnbounded)?;
        let Some(parent) = events.get(parent_idx) else {
            continue;
        };

        let child_ts_raw = event_ts(child);
        let parent_ts_raw = event_ts(parent);
        if ts_is_python_none(child_ts_raw.as_ref()) && ts_is_python_none(parent_ts_raw.as_ref()) {
            continue;
        }
        let (Some(child_field), Some(parent_field)) = (child_ts_raw, parent_ts_raw) else {
            continue;
        };
        let Some((child_ts, parent_ts)) = edge_datetimes(&child_field, &parent_field) else {
            continue;
        };
        let delta_ms = ts_delta_ms(&child_ts, &parent_ts)?;
        let Some(magnitude) = delta_ms.checked_neg() else {
            return Err(OrderingError::PythonIntUnbounded);
        };
        if magnitude <= skew {
            continue;
        }
        count = count
            .checked_add(1)
            .ok_or(OrderingError::PythonIntUnbounded)?;
        max_delta = max_delta.max(magnitude);
        if anchor.is_some() {
            continue;
        }
        let clean_rec_id = safe_id(&event_id_safe(child).unwrap_or_default());
        let clean_parent_id = safe_id(&parent_id);
        anchor = Some(OrderingRecord {
            record_id: clean_rec_id,
            parent_id: clean_parent_id,
            ts_delta_ms: delta_ms,
            child_index: child_idx,
            parent_index: parent_idx,
            record_ordinal: child_idx,
            count: 0,
            max_delta_ms: 0,
            timestamp_skew_ms: skew,
        });
    }

    Ok(anchor.map(|mut record| {
        record.count = count;
        record.max_delta_ms = max_delta;
        record
    }))
}

fn record_evidence(record: &OrderingRecord) -> Result<PyValue, OrderingError> {
    Ok(PyValue::map(vec![
        (
            PyValue::string("record_id"),
            PyValue::string(record.record_id.clone()),
        ),
        (
            PyValue::string("parent_id"),
            PyValue::string(record.parent_id.clone()),
        ),
        (
            PyValue::string("ts_delta_ms"),
            PyValue::int(record.ts_delta_ms),
        ),
        (
            PyValue::string("child_index"),
            PyValue::int(usize_to_i64(record.child_index)?),
        ),
        (
            PyValue::string("parent_index"),
            PyValue::int(usize_to_i64(record.parent_index)?),
        ),
        (
            PyValue::string("record_ordinal"),
            PyValue::int(usize_to_i64(record.record_ordinal)?),
        ),
        (PyValue::string("count"), PyValue::int(record.count)),
        (
            PyValue::string("max_delta_ms"),
            PyValue::int(record.max_delta_ms),
        ),
        (
            PyValue::string("timestamp_skew_ms"),
            PyValue::int(record.timestamp_skew_ms),
        ),
    ]))
}

/// Python: `check_ordering`.
///
/// No violation returns an empty list and does not call [`make_finding`].
/// A violation calls [`make_finding`] with the fingerprint omitted; that
/// codec error is propagated. `max_findings` is ignored.
pub fn check_ordering(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<usize>,
    context: Option<&CheckContext>,
    timestamp_skew_ms: Option<i64>,
) -> Result<Vec<Finding>, OrderingError> {
    let _ = max_findings;
    let Some(record) = ordering_record(events, context, timestamp_skew_ms)? else {
        return Ok(Vec::new());
    };
    let Some(ev) = events.get(record.child_index) else {
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
    let source = SourceRef::try_new(
        &resolved_path,
        line_num.map(SourceLine::Int),
        Some(record.record_id.as_str()),
    )?;
    Ok(vec![make_finding(&MakeFindingInput {
        code: PyValue::string(SL008),
        severity: PyValue::severity(Severity::Warning),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_SL008),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(vec![
            PyValue::string(record.record_id.clone()),
            PyValue::string(record.parent_id.clone()),
        ]),
        evidence: record_evidence(&record)?,
        fingerprint: PyValue::None,
        adapter_id: Some(ctx.adapter_id().to_owned()),
        adapter_version: Some(ctx.adapter_version().to_owned()),
        profile_id: Some(ctx.profile_id().to_owned()),
        profile_version: Some(ctx.profile_version().to_owned()),
        ordinal: None,
        context: None,
    })?])
}

/// Python `__all__`, in that order.
pub const ALL: [&str; 1] = ["check_ordering"];

#[cfg(test)]
mod tests {
    use super::{
        check_ordering, ordering_record, OrderingError, ALL, MSG_SL008,
        TIMESTAMP_SKEW_MS_MUST_BE_NONNEGATIVE,
    };
    use model::canonical::SessionEvent;
    use model::events::EventValue;
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    fn session_event(id: &str, parent_id: Option<&str>, ts: &str) -> EventValue {
        EventValue::from_session(SessionEvent::new(
            id,
            parent_id.map(str::to_owned),
            0,
            ts,
            "user",
            "message",
        ))
    }

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn assert_codec_unavailable(err: OrderingError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    fn parent_child(child_ts: &str, parent_ts: &str) -> Vec<EventValue> {
        vec![
            session_event("evt-parent-synthetic", None, parent_ts),
            session_event(
                "evt-child-synthetic",
                Some("evt-parent-synthetic"),
                child_ts,
            ),
        ]
    }

    #[test]
    fn constants_match_python() {
        assert_eq!(ALL, ["check_ordering"]);
        assert_eq!(MSG_SL008, "Non-monotonic timestamp for record {record_id}");
        assert_eq!(
            TIMESTAMP_SKEW_MS_MUST_BE_NONNEGATIVE,
            "timestamp_skew_ms must be a nonnegative integer"
        );
    }

    #[test]
    fn no_parent_id_is_silent() {
        let events = vec![
            session_event("evt-root-synthetic", None, "2024-01-01T00:00:02Z"),
            session_event("evt-child-synthetic", None, "2024-01-01T00:00:00Z"),
        ];
        let record = ordering_record(&events, None, None).unwrap();
        assert!(record.is_none());
        let findings = check_ordering(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn missing_parent_id_is_silent() {
        let events = vec![
            session_event("evt-root-synthetic", None, "2024-01-01T00:00:02Z"),
            session_event(
                "evt-child-synthetic",
                Some("evt-ghost-synthetic"),
                "2024-01-01T00:00:00Z",
            ),
        ];
        let record = ordering_record(&events, None, None).unwrap();
        assert!(record.is_none());
        let findings = check_ordering(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn duplicate_parent_id_is_silent() {
        let events = vec![
            session_event("evt-dup-synthetic", None, "2024-01-01T00:00:02Z"),
            session_event("evt-dup-synthetic", None, "2024-01-01T00:00:03Z"),
            session_event(
                "evt-child-synthetic",
                Some("evt-dup-synthetic"),
                "2024-01-01T00:00:00Z",
            ),
        ];
        let record = ordering_record(&events, None, None).unwrap();
        assert!(record.is_none());
        let findings = check_ordering(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn epoch_sentinel_on_either_side_is_silent() {
        let sentinel = "1970-01-01T00:00:00Z";
        let child_sentinel = parent_child(sentinel, "2024-01-01T00:00:02Z");
        assert!(ordering_record(&child_sentinel, None, Some(0))
            .unwrap()
            .is_none());
        assert!(check_ordering(&child_sentinel, None, None, None, Some(0))
            .unwrap()
            .is_empty());

        let parent_sentinel = parent_child("2024-01-01T00:00:00Z", sentinel);
        assert!(ordering_record(&parent_sentinel, None, Some(0))
            .unwrap()
            .is_none());
        assert!(check_ordering(&parent_sentinel, None, None, None, Some(0))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn default_skew_covers_two_second_regression() {
        let events = parent_child("2024-01-01T00:00:00Z", "2024-01-01T00:00:02Z");
        let record = ordering_record(&events, None, None).unwrap();
        assert!(record.is_none());
        let findings = check_ordering(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn skew_zero_records_two_second_regression_and_codec_error() {
        let events = parent_child("2024-01-01T00:00:00Z", "2024-01-01T00:00:02Z");
        let record = ordering_record(&events, None, Some(0))
            .unwrap()
            .expect("violation");
        assert_eq!(record.count, 1);
        assert_eq!(record.ts_delta_ms, -2000);
        assert_eq!(record.max_delta_ms, 2000);
        assert_eq!(record.record_id, "evt-child-synthetic");
        assert_eq!(record.parent_id, "evt-parent-synthetic");
        assert_eq!(record.child_index, 1);
        assert_eq!(record.parent_index, 0);
        assert_eq!(record.record_ordinal, 1);
        assert_eq!(record.timestamp_skew_ms, 0);
        let err = check_ordering(&events, None, None, None, Some(0)).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn second_child_updates_count_and_keeps_first_anchor() {
        let events = vec![
            session_event("evt-parent-synthetic", None, "2024-01-01T00:00:02Z"),
            session_event(
                "evt-child-a-synthetic",
                Some("evt-parent-synthetic"),
                "2024-01-01T00:00:00Z",
            ),
            session_event(
                "evt-child-b-synthetic",
                Some("evt-parent-synthetic"),
                "2023-12-31T23:59:59Z",
            ),
        ];
        let record = ordering_record(&events, None, Some(0))
            .unwrap()
            .expect("violation");
        assert_eq!(record.count, 2);
        assert_eq!(record.max_delta_ms, 3000);
        assert_eq!(record.ts_delta_ms, -2000);
        assert_eq!(record.record_id, "evt-child-a-synthetic");
        assert_eq!(record.child_index, 1);
        assert_eq!(record.record_ordinal, 1);
        assert_eq!(record.parent_id, "evt-parent-synthetic");
        let err = check_ordering(&events, None, None, None, Some(0)).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn negative_skew_returns_value_error_text() {
        let events = parent_child("2024-01-01T00:00:00Z", "2024-01-01T00:00:02Z");
        let err = ordering_record(&events, None, Some(-1)).unwrap_err();
        assert_eq!(err.to_string(), TIMESTAMP_SKEW_MS_MUST_BE_NONNEGATIVE);
        assert_eq!(
            err.message(),
            "timestamp_skew_ms must be a nonnegative integer"
        );
        let err = check_ordering(&events, None, None, None, Some(-1)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "timestamp_skew_ms must be a nonnegative integer"
        );
    }

    #[test]
    fn unparseable_timestamp_is_skipped() {
        let events = parent_child("2024-01-01T00:00:00Z", "not-a-timestamp");
        let record = ordering_record(&events, None, Some(0)).unwrap();
        assert!(record.is_none());
        let findings = check_ordering(&events, None, None, None, Some(0)).unwrap();
        assert!(findings.is_empty());

        let events = parent_child("not-a-timestamp", "2024-01-01T00:00:02Z");
        let record = ordering_record(&events, None, Some(0)).unwrap();
        assert!(record.is_none());
        let findings = check_ordering(&events, None, None, None, Some(0)).unwrap();
        assert!(findings.is_empty());
    }
}
