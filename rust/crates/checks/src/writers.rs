//! SL010 interleaved writer-marker detector (detector-depth T-02).
//!
//! Port of `src/sesslint/checks/writers.py` lines 1–133
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`check_writers`] calls [`make_finding`] with the fingerprint omitted.
//! That returns the codec error and does not produce a digest. This module
//! does not call [`crate::graph::compute_graph_fingerprint`] and does not
//! call a pairing fingerprint helper.
//!
//! Flags session files whose records carry *interleaved* writer-identity
//! markers — the corruption precondition behind dropped writes (SL101
//! orphans, SL003 id collisions). A marker is an adapter-normalized
//! `extra_fields["writer"]` mapping: `instance` when the vendor records a
//! per-process discriminator, else `version` (application build). Adapters
//! that emit no markers produce an empty sequence and zero findings —
//! absence is never a violation.
//!
//! Firing rule (conservative):
//! - One SL010 per file, only when a marker *reappears* after a different
//!   marker (A→B→A). Interleaving is the concurrency proof.
//! - A clean ordered transition A*→B* (all A records precede all B) is a
//!   legitimate mid-session upgrade — no finding.
//! - Marker values are hashed (sha256-8) for evidence: a version string is
//!   near-public, but hashing keeps the content-free contract uniform and
//!   still lets operators diff writer sets across files.
//!
//! [`writer_interleave_record`] reports the single first-interleave record.
//! It does not hash a finding digest. [`check_writers`] calls
//! [`make_finding`] only when that function returns a record, and
//! propagates the codec error.
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Distinct-writer and transition counts use
//!   `i64`. Overflow is [`PYTHON_INT_UNBOUNDED`], not a wrap and not a
//!   panic.
//! * [`MapLookup::Borrowed`] is a failed borrow, not a missing key
//!   ([`BORROWED_LOOKUP`]). [`MapLookup::NotAMap`] and
//!   [`MapLookup::Absent`] skip that level and the event is not a marker.
//! * A [`model::events::EventValue::Mapping`] has no `extra_fields`
//!   attribute. It is skipped. A top-level `writer` key is not a marker.
//! * A bool is not a string. A whitespace-only `instance` falls through to
//!   `version`. [`model::canonical::SessionEvent::source_line`] is
//!   `Option<i64>` and cannot be a bool.
//! * Overflow [`make_finding`] does not produce a digest
//!   ([`model::finding::FINGERPRINT_CODEC_UNAVAILABLE`]).

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use model::canonical::{MapLookup, Payload};
use model::codes::{Repairability, Severity, SL010};
use model::errors::FindingError;
use model::events::EventValue;
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef};
use sha2::{Digest, Sha256};

use crate::context::CheckContext;
use crate::graph::{resolve_source_coords, safe_id, GraphError};

/// Python: `_MSG_SL010`.
pub const MSG_SL010: &str = "Interleaved writer markers in session file for record {record_id}";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// [`MapLookup::Borrowed`] is not a missing key.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

/// Python `__all__`, in that order.
pub const ALL: [&str; 1] = ["check_writers"];

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WritersError {
    BorrowedLookup,
    PythonIntUnbounded,
    Finding(FindingError),
    Graph(GraphError),
}

impl WritersError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::Finding(error) => error.message(),
            Self::Graph(error) => error.message(),
        }
    }
}

impl fmt::Display for WritersError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for WritersError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::Graph(error) => Some(error),
            Self::BorrowedLookup | Self::PythonIntUnbounded => None,
        }
    }
}

impl From<FindingError> for WritersError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

impl From<GraphError> for WritersError {
    fn from(error: GraphError) -> Self {
        match error {
            GraphError::Finding(error) => Self::Finding(error),
            other => Self::Graph(other),
        }
    }
}

/// First interleave plus file-level counts. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterInterleaveRecord {
    pub event_index: usize,
    pub distinct_writer_count: i64,
    pub transition_count: i64,
    pub writer_hashes: Vec<String>,
}

struct MarkerEntry {
    marker: String,
    event_index: usize,
}

fn usize_to_i64(value: usize) -> Result<i64, WritersError> {
    i64::try_from(value).map_err(|_| WritersError::PythonIntUnbounded)
}

fn map_field(payload: &Payload, key: &str) -> Result<Option<Payload>, WritersError> {
    match payload.map_string(key) {
        MapLookup::Borrowed => Err(WritersError::BorrowedLookup),
        MapLookup::NotAMap | MapLookup::Absent => Ok(None),
        MapLookup::Present(value) => Ok(Some(value)),
    }
}

fn nonempty_stripped_str(value: &Payload) -> Option<&str> {
    let text = value.as_str()?;
    let stripped = text.trim();
    if stripped.is_empty() {
        None
    } else {
        Some(stripped)
    }
}

/// Python: `_writer_marker`.
///
/// A [`SessionEvent`] whose `extra_fields` is not a mapping is not a
/// marker. A mapping [`EventValue`] has no `extra_fields` attribute and is
/// skipped. A bool is not a string.
pub fn writer_marker(ev: &EventValue) -> Result<Option<String>, WritersError> {
    let EventValue::Session(event) = ev else {
        return Ok(None);
    };
    if !event.extra_fields.is_map() {
        return Ok(None);
    }
    let Some(writer) = map_field(&event.extra_fields, "writer")? else {
        return Ok(None);
    };
    if !writer.is_map() {
        return Ok(None);
    }
    if let Some(instance) = map_field(&writer, "instance")? {
        if let Some(stripped) = nonempty_stripped_str(&instance) {
            return Ok(Some(format!("i:{stripped}")));
        }
    }
    if let Some(version) = map_field(&writer, "version")? {
        if let Some(stripped) = nonempty_stripped_str(&version) {
            return Ok(Some(format!("v:{stripped}")));
        }
    }
    Ok(None)
}

/// Python: `_marker_hash`. sha256-8 of the marker's UTF-8 bytes.
pub fn marker_hash(marker: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(marker.as_bytes());
    let mut out = String::with_capacity(8);
    for byte in digest.iter().take(4) {
        out.push(char::from(HEX[usize::from(*byte >> 4)]));
        out.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    out
}

fn source_line(ev: &EventValue) -> Option<i64> {
    match ev {
        EventValue::Session(event) => event.source_line,
        EventValue::Mapping(_) | EventValue::Other => None,
    }
}

fn record_id(ev: &EventValue) -> Option<String> {
    match ev {
        EventValue::Session(event) => {
            let stripped = event.id.trim();
            if stripped.is_empty() {
                None
            } else {
                Some(safe_id(stripped))
            }
        }
        EventValue::Mapping(_) | EventValue::Other => None,
    }
}

/// Ordered unique `(source_line, marker)` entries. One per pair, first
/// encounter kept. Does not collapse consecutive duplicates.
fn writer_seq(events: &[EventValue]) -> Result<Vec<MarkerEntry>, WritersError> {
    let mut seq = Vec::new();
    let mut seen_line_marker: HashSet<(Option<i64>, String)> = HashSet::new();
    for (event_index, ev) in events.iter().enumerate() {
        let Some(marker) = writer_marker(ev)? else {
            continue;
        };
        let line = source_line(ev);
        if !seen_line_marker.insert((line, marker.clone())) {
            continue;
        }
        seq.push(MarkerEntry {
            marker,
            event_index,
        });
    }
    Ok(seq)
}

fn writers_evidence(
    record: &WriterInterleaveRecord,
    first_interleave_line: Option<i64>,
) -> PyValue {
    PyValue::map(vec![
        (
            PyValue::string("distinct_writer_count"),
            PyValue::int(record.distinct_writer_count),
        ),
        (
            PyValue::string("transition_count"),
            PyValue::int(record.transition_count),
        ),
        (
            PyValue::string("first_interleave_line"),
            match first_interleave_line {
                Some(line) => PyValue::int(line),
                None => PyValue::None,
            },
        ),
        (
            PyValue::string("writer_hashes"),
            PyValue::tuple(
                record
                    .writer_hashes
                    .iter()
                    .map(|hash| PyValue::string(hash.clone()))
                    .collect(),
            ),
        ),
    ])
}

/// The single first-interleave record, or `None` when the file is silent.
/// Does not call [`make_finding`].
pub fn writer_interleave_record(
    events: &[EventValue],
) -> Result<Option<WriterInterleaveRecord>, WritersError> {
    let seq = writer_seq(events)?;
    if seq.len() < 3 {
        return Ok(None);
    }

    let mut reduced: Vec<&MarkerEntry> = Vec::new();
    for entry in &seq {
        if reduced.last().map(|prev| prev.marker.as_str()) != Some(entry.marker.as_str()) {
            reduced.push(entry);
        }
    }

    let mut seen_markers: HashSet<&str> = HashSet::new();
    let mut interleave_index = None;
    for entry in &reduced {
        if !seen_markers.insert(entry.marker.as_str()) {
            interleave_index = Some(entry.event_index);
            break;
        }
    }
    let Some(event_index) = interleave_index else {
        return Ok(None);
    };

    let mut distinct: HashSet<&str> = HashSet::new();
    for entry in &seq {
        distinct.insert(entry.marker.as_str());
    }
    let distinct_writer_count = usize_to_i64(distinct.len())?;
    let mut writer_hashes: Vec<String> =
        distinct.iter().map(|marker| marker_hash(marker)).collect();
    writer_hashes.sort();
    let transition_count = usize_to_i64(reduced.len())?
        .checked_sub(1)
        .ok_or(WritersError::PythonIntUnbounded)?;

    Ok(Some(WriterInterleaveRecord {
        event_index,
        distinct_writer_count,
        transition_count,
        writer_hashes,
    }))
}

/// Python: `check_writers`.
///
/// Fewer than three unique `(source_line, marker)` entries, a clean
/// ordered upgrade, or a single marker returns an empty list and does not
/// call [`make_finding`]. An interleave calls [`make_finding`] with the
/// fingerprint omitted; that codec error is propagated. Context `None` is
/// [`CheckContext::default`].
pub fn check_writers(
    events: &[EventValue],
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, WritersError> {
    let Some(record) = writer_interleave_record(events)? else {
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
        code: PyValue::string(SL010),
        severity: PyValue::severity(Severity::Warning),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_SL010),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence: writers_evidence(&record, line_num),
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
        check_writers, marker_hash, writer_interleave_record, writer_marker, writer_seq, ALL,
        MSG_SL010,
    };
    use model::canonical::{Payload, SessionEvent};
    use model::events::{EventField, EventMapping, EventValue};
    use model::finding::FINGERPRINT_CODEC_UNAVAILABLE;

    fn session(id: &str, line: Option<i64>, extra: Payload) -> EventValue {
        let mut event = SessionEvent::new(id, None, 0, "", "user", "user_message");
        event.source_line = line;
        event.extra_fields = extra;
        EventValue::from_session(event)
    }

    fn writer_extra(instance: Option<Payload>, version: Option<Payload>) -> Payload {
        let mut fields = Vec::new();
        if let Some(value) = instance {
            fields.push((Payload::string("instance"), value));
        }
        if let Some(value) = version {
            fields.push((Payload::string("version"), value));
        }
        Payload::map(vec![(Payload::string("writer"), Payload::map(fields))])
    }

    fn version_event(id: &str, line: i64, version: &str) -> EventValue {
        session(
            id,
            Some(line),
            writer_extra(None, Some(Payload::string(version))),
        )
    }

    fn instance_event(id: &str, line: i64, instance: &str) -> EventValue {
        session(
            id,
            Some(line),
            writer_extra(Some(Payload::string(instance)), None),
        )
    }

    fn unmarked(id: &str, line: i64) -> EventValue {
        session(id, Some(line), Payload::map(Vec::new()))
    }

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn assert_codec_unavailable(err: super::WritersError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    fn assert_silent(events: &[EventValue]) {
        let record = writer_interleave_record(events).unwrap();
        assert!(record.is_none());
        let findings = check_writers(events, Some("synth.jsonl"), None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn no_writer_marker_is_empty() {
        let events = vec![
            unmarked("evt-a-synth", 1),
            unmarked("evt-b-synth", 2),
            unmarked("evt-c-synth", 3),
        ];
        assert_silent(&events);
        assert!(writer_seq(&events).unwrap().is_empty());
        assert_eq!(writer_marker(&events[0]).unwrap(), None);
    }

    #[test]
    fn one_marker_on_three_different_lines_is_empty() {
        let events = vec![
            instance_event("evt-a1-synth", 1, "alpha-synth"),
            instance_event("evt-a2-synth", 2, "alpha-synth"),
            instance_event("evt-a3-synth", 3, "alpha-synth"),
        ];
        assert_silent(&events);
        assert_eq!(writer_seq(&events).unwrap().len(), 3);
    }

    #[test]
    fn a_then_b_then_b_on_different_lines_is_empty() {
        let events = vec![
            instance_event("evt-a-synth", 1, "alpha-synth"),
            version_event("evt-b1-synth", 2, "beta-synth"),
            version_event("evt-b2-synth", 3, "beta-synth"),
        ];
        assert_silent(&events);
    }

    #[test]
    fn a_then_b_then_c_is_empty() {
        let events = vec![
            instance_event("evt-a-synth", 1, "alpha-synth"),
            version_event("evt-b-synth", 2, "beta-synth"),
            instance_event("evt-c-synth", 3, "gamma-synth"),
        ];
        assert_silent(&events);
    }

    #[test]
    fn a_b_a_records_counts_and_returns_codec_error() {
        let events = vec![
            instance_event("evt-a1-synth", 1, "alpha-synth"),
            version_event("evt-b-synth", 2, "beta-synth"),
            instance_event("evt-a2-synth", 3, "alpha-synth"),
        ];
        let record = writer_interleave_record(&events)
            .unwrap()
            .expect("interleave");
        assert_eq!(record.event_index, 2);
        assert_eq!(record.distinct_writer_count, 2);
        assert_eq!(record.transition_count, 2);
        assert_eq!(
            record.writer_hashes,
            vec!["c6aff657".to_owned(), "de823d83".to_owned()]
        );
        let err = check_writers(&events, Some("synth.jsonl"), None).unwrap_err();
        assert_codec_unavailable(err);
        assert_eq!(
            MSG_SL010,
            "Interleaved writer markers in session file for record {record_id}"
        );
    }

    #[test]
    fn a_b_a_c_fires_on_second_a_not_c() {
        let events = vec![
            instance_event("evt-a1-synth", 1, "alpha-synth"),
            version_event("evt-b-synth", 2, "beta-synth"),
            instance_event("evt-a2-synth", 3, "alpha-synth"),
            instance_event("evt-c-synth", 4, "gamma-synth"),
        ];
        let record = writer_interleave_record(&events)
            .unwrap()
            .expect("interleave");
        assert_eq!(record.event_index, 2);
        assert_eq!(record.distinct_writer_count, 3);
        assert_eq!(record.transition_count, 3);
        let err = check_writers(&events, Some("synth.jsonl"), None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn same_line_same_marker_enters_the_sequence_once() {
        let events = vec![
            instance_event("evt-a1-synth", 1, "alpha-synth"),
            instance_event("evt-a-dup-synth", 1, "alpha-synth"),
            version_event("evt-b-synth", 2, "beta-synth"),
        ];
        let seq = writer_seq(&events).unwrap();
        assert_eq!(seq.len(), 2);
        assert_eq!(seq[0].marker, "i:alpha-synth");
        assert_eq!(seq[0].event_index, 0);
        assert_eq!(seq[1].marker, "v:beta-synth");
        assert_silent(&events);
    }

    #[test]
    fn instance_wins_over_version_and_whitespace_instance_falls_through() {
        let wins = session(
            "evt-win-synth",
            Some(1),
            writer_extra(
                Some(Payload::string("alpha-synth")),
                Some(Payload::string("beta-synth")),
            ),
        );
        assert_eq!(
            writer_marker(&wins).unwrap().as_deref(),
            Some("i:alpha-synth")
        );

        let whitespace = session(
            "evt-ws-synth",
            Some(2),
            writer_extra(
                Some(Payload::string("  \t  ")),
                Some(Payload::string("beta-synth")),
            ),
        );
        assert_eq!(
            writer_marker(&whitespace).unwrap().as_deref(),
            Some("v:beta-synth")
        );

        let bool_instance = session(
            "evt-bool-synth",
            Some(3),
            writer_extra(
                Some(Payload::bool_value(true)),
                Some(Payload::string("beta-synth")),
            ),
        );
        assert_eq!(
            writer_marker(&bool_instance).unwrap().as_deref(),
            Some("v:beta-synth")
        );
    }

    #[test]
    fn marker_hash_i_alpha_synth_is_c6aff657() {
        assert_eq!(marker_hash("i:alpha-synth"), "c6aff657");
        assert_eq!(marker_hash("v:beta-synth"), "de823d83");
    }

    #[test]
    fn all_is_exactly_check_writers() {
        assert_eq!(ALL, ["check_writers"]);
    }

    #[test]
    fn mapping_event_is_skipped_and_non_map_extra_is_not_a_marker() {
        let top_level = EventValue::Mapping(EventMapping::new(vec![(
            "writer".to_owned(),
            EventField::Mapping(EventMapping::new(vec![(
                "instance".to_owned(),
                EventField::Str("alpha-synth".to_owned()),
            )])),
        )]));
        assert_eq!(writer_marker(&top_level).unwrap(), None);

        let nested = EventValue::Mapping(EventMapping::new(vec![(
            "extra_fields".to_owned(),
            EventField::Mapping(EventMapping::new(vec![(
                "writer".to_owned(),
                EventField::Mapping(EventMapping::new(vec![(
                    "instance".to_owned(),
                    EventField::Str("alpha-synth".to_owned()),
                )])),
            )])),
        )]));
        assert_eq!(writer_marker(&nested).unwrap(), None);

        let not_map = session("evt-not-map-synth", Some(1), Payload::string("not-a-map"));
        assert_eq!(writer_marker(&not_map).unwrap(), None);
        assert_eq!(writer_marker(&EventValue::Other).unwrap(), None);
    }
}
