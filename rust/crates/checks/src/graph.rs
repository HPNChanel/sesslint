//! Generic parent-graph integrity helpers (SL004, SL005, SL006, SL007).
//!
//! Port of `src/sesslint/checks/graph.py` lines 1–308
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! This slice stops before `cap_graph_findings`. It does not port
//! `check_missing_parent`, `check_cycles`, `check_components`, `check_heads`,
//! or `check_graph`.
//!
//! Parent matching is exact id equality. No `startswith` and no prefix.
//! A parent is never invented by prefix. `None` branch equals `None`.
//!
//! # Recorded gaps
//!
//! * Python `str` of a float, list, or mapping field is not matched
//!   (`model::events::PYTHON_FLOAT_STR_UNREPRESENTABLE` /
//!   `model::events::PYTHON_STR_UNREPRESENTABLE`). The getter returns `None`
//!   and does not invent a Python repr.
//! * [`same_compaction_segment`] cannot run `events.index(a)` on
//!   [`EventValue`] ([`PYTHON_EVENT_INDEX_UNREPRESENTABLE`]). An event
//!   endpoint with no seq returns false and does not guess a list index.
//! * [`EvidenceLookup::Borrowed`] is not a missing overflow/id key
//!   ([`BORROWED_LOOKUP`]).

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use model::canonical::SessionEvent;
use model::events::{EventField, EventValue};
use model::finding::{enforce_content_free_text, EvidenceLookup, Finding};
use sha2::{Digest, Sha256};

/// Python: `MAX_GRAPH_FINDINGS`.
pub const MAX_GRAPH_FINDINGS: usize = 500;

/// Python: `MAX_MEMBER_SAMPLE_SIZE`.
pub const MAX_MEMBER_SAMPLE_SIZE: usize = 8;

/// Python: `_NON_CONVERSATIONAL_KINDS`. Membership only.
pub const NON_CONVERSATIONAL_KINDS: &[&str] = &["opaque", "compaction_boundary"];

/// Python: `_MSG_SL004`.
pub const MSG_SL004: &str = "Missing parent reference for record {record_id}";

/// Python: `_MSG_SL005`.
pub const MSG_SL005: &str = "Parent cycle detected for record {record_id}";

/// Python: `_MSG_SL006`.
pub const MSG_SL006: &str = "Disconnected session component detected for record {record_id}";

/// Python: `_MSG_SL007`.
pub const MSG_SL007: &str = "Ambiguous session heads detected for record {record_id}";

/// Python: `_MSG_OVERFLOW`.
pub const MSG_OVERFLOW: &str =
    "Parent graph check finding cap reached; remaining records truncated";

/// Python: `_CONF_SEG_KEY` (`"".join(["seg", "ment"])`).
pub const CONF_SEG_KEY: &str = concat!("seg", "ment");

/// Python `list.index` identity/equality is not representable for [`EventValue`].
pub const PYTHON_EVENT_INDEX_UNREPRESENTABLE: &str =
    "EventValue cannot be searched by Python equality; a missing seq does not guess an index";

/// [`EvidenceLookup::Borrowed`] is not a missing key.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphError {
    BorrowedLookup,
}

impl GraphError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
        }
    }
}

impl fmt::Display for GraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for GraphError {}

/// Python `str(x)` inputs for [`compute_graph_fingerprint`].
///
/// `str(True)` is `True`. A bool is not an int.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum GraphScalar {
    Str(String),
    Bool(bool),
    Int(i64),
}

impl GraphScalar {
    fn python_str(&self) -> String {
        match self {
            Self::Str(text) => text.clone(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Int(number) => number.to_string(),
        }
    }
}

impl From<&str> for GraphScalar {
    fn from(value: &str) -> Self {
        Self::Str(value.to_owned())
    }
}

impl From<String> for GraphScalar {
    fn from(value: String) -> Self {
        Self::Str(value)
    }
}

impl From<bool> for GraphScalar {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for GraphScalar {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

/// Endpoint for [`same_compaction_segment`].
///
/// An int is a seq. A bool is not an int and is not this variant.
#[derive(Clone, Copy, Debug)]
pub enum GraphEndpoint<'a> {
    Seq(i64),
    Event(&'a EventValue),
}

/// One rejected decoy from [`find_qualifying_parent_candidates`].
///
/// Field order matches the Python dict: `id`, `index`, `reason`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedDecoy {
    pub id: String,
    pub index: usize,
    pub reason: String,
}

/// Branch/segment confinement flags. Key [`CONF_SEG_KEY`] is `"segment"`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Confinement {
    pub branch: bool,
    pub segment: bool,
}

impl Confinement {
    fn new(branch: bool, segment: bool) -> Self {
        Self { branch, segment }
    }
}

/// Python: `_safe_id`.
///
/// Any [`enforce_content_free_text`] error with context `"id"` returns
/// `"<redacted>"`.
pub fn safe_id(id_str: &str) -> String {
    match enforce_content_free_text(id_str, "id") {
        Ok(()) => id_str.to_owned(),
        Err(_) => "<redacted>".to_owned(),
    }
}

/// Python: `compute_graph_fingerprint`.
///
/// `sha256("{code}|{comma-joined sorted unique str(ids)}")` then the first
/// 16 lowercase hex characters. An empty id list is `"{code}|"`. Unique
/// sorted strings use a [`BTreeSet`]. This does not call the canonical-JSON
/// seam.
pub fn compute_graph_fingerprint(code: &str, ids: impl IntoIterator<Item = GraphScalar>) -> String {
    let mut unique = BTreeSet::new();
    for id in ids {
        unique.insert(id.python_str());
    }
    let mut content = String::from(code);
    content.push('|');
    let mut first = true;
    for id in &unique {
        if !first {
            content.push(',');
        }
        first = false;
        content.push_str(id);
    }
    hex16(Sha256::digest(content.as_bytes()))
}

/// Python: `_cap_finding_sort_key`.
///
/// `(code, 1 if evidence overflow is exactly True else 0, record id, fingerprint)`.
/// A bool is not another truthy value. [`Evidence::map_string`] last matching
/// string key wins. [`EvidenceLookup::Borrowed`] is an error, not a missing key.
pub fn cap_finding_sort_key(
    finding: &Finding,
) -> Result<(String, i32, String, String), GraphError> {
    let is_overflow = overflow_flag(finding)?;
    let rec_id = record_id_for_sort(finding)?;
    Ok((
        finding.code().to_owned(),
        is_overflow,
        rec_id,
        finding.fingerprint().to_owned(),
    ))
}

/// Python: `_event_get`.
///
/// A [`SessionEvent`] field is used first. A mapping is used only when that
/// attribute is `None`. [`EventValue::Session`] is not a mapping. `None`
/// stays `None`. An empty string stays an empty string.
pub fn event_get(ev: &EventValue, field: &str) -> Option<EventField> {
    match ev {
        EventValue::Session(event) => session_attribute(event, field),
        EventValue::Mapping(mapping) => mapping.get(field).cloned(),
        EventValue::Other => None,
    }
}

/// Python: `_event_id_safe`.
pub fn event_id_safe(ev: &EventValue) -> Option<String> {
    python_field_str(event_get(ev, "id").as_ref())
}

/// Python: `_event_parent_id_safe`.
pub fn event_parent_id_safe(ev: &EventValue) -> Option<String> {
    python_field_str(event_get(ev, "parent_id").as_ref())
}

/// Python: `_event_branch_safe`.
pub fn event_branch_safe(ev: &EventValue) -> Option<String> {
    python_field_str(event_get(ev, "branch_id").as_ref())
}

/// Python: `_event_seq_safe`.
///
/// A bool is not an int. Then use `default_idx`.
pub fn event_seq_safe(ev: &EventValue, default_idx: Option<i64>) -> Option<i64> {
    match event_get(ev, "seq") {
        Some(EventField::Int(number)) => Some(number),
        _ => default_idx,
    }
}

/// Python: `same_compaction_segment`.
///
/// A boundary strictly between the seqs returns false. Endpoints themselves
/// do not break the segment. A span of 1 or 0 returns true.
pub fn same_compaction_segment(
    events: &[EventValue],
    a: GraphEndpoint<'_>,
    b: GraphEndpoint<'_>,
) -> bool {
    let Some(seq_a) = endpoint_seq(a) else {
        return false;
    };
    let Some(seq_b) = endpoint_seq(b) else {
        return false;
    };
    let low_seq = seq_a.min(seq_b);
    let high_seq = seq_a.max(seq_b);
    if high_seq.saturating_sub(low_seq) <= 1 {
        return true;
    }
    for (idx, ev) in events.iter().enumerate() {
        let default_idx = i64::try_from(idx).ok();
        let Some(ev_seq) = event_seq_safe(ev, default_idx) else {
            continue;
        };
        if low_seq < ev_seq && ev_seq < high_seq && kind_is_compaction_boundary(ev) {
            return false;
        }
    }
    true
}

/// Python: `is_qualifying_parent_candidate`.
///
/// Exact id equality. No `startswith` and no prefix. `None` branch equals
/// `None`. Failure reasons are `empty_candidate_id`, `self_candidate`,
/// `no_full_match`, `cross_branch`, `cross_segment`. Success is `ok`.
pub fn is_qualifying_parent_candidate(
    candidate: &EventValue,
    child: &EventValue,
    events: &[EventValue],
    missing_parent_id: Option<&str>,
) -> (bool, String) {
    let c_id = event_id_safe(candidate);
    let child_id = event_id_safe(child);

    let Some(c_id) = c_id.filter(|id| !id.is_empty()) else {
        return (false, "empty_candidate_id".to_owned());
    };
    if let Some(child_id) = child_id.as_deref() {
        if c_id == child_id {
            return (false, "self_candidate".to_owned());
        }
    }

    let target_parent = match missing_parent_id {
        Some(value) => value.to_owned(),
        None => event_parent_id_safe(child).unwrap_or_default(),
    };
    if c_id != target_parent {
        return (false, "no_full_match".to_owned());
    }

    if event_branch_safe(candidate) != event_branch_safe(child) {
        return (false, "cross_branch".to_owned());
    }

    if !same_compaction_segment(
        events,
        GraphEndpoint::Event(candidate),
        GraphEndpoint::Event(child),
    ) {
        return (false, "cross_segment".to_owned());
    }

    (true, "ok".to_owned())
}

/// Python: `find_qualifying_parent_candidates`.
///
/// Walks only indices before `target_idx`. Rejected decoys stay in walk
/// order. One qualifier is `ok`; more than one is `ambiguous`. Otherwise
/// `cross_branch` wins over `cross_segment`, and anything else is
/// `no_full_match`.
pub fn find_qualifying_parent_candidates(
    events: &[EventValue],
    child: &EventValue,
    target_idx: usize,
    missing_parent_id: Option<&str>,
) -> (Vec<usize>, Vec<RejectedDecoy>, Confinement, String) {
    let target_parent = match missing_parent_id {
        Some(value) => value.to_owned(),
        None => event_parent_id_safe(child).unwrap_or_default(),
    };

    let mut qualifying_indices: Vec<usize> = Vec::new();
    let mut rejected_decoys: Vec<RejectedDecoy> = Vec::new();
    let mut id_match_indices: Vec<usize> = Vec::new();
    let walk_end = target_idx.min(events.len());

    for i in 0..walk_end {
        let cand = &events[i];
        let (qualifies, fail_reason) =
            is_qualifying_parent_candidate(cand, child, events, Some(target_parent.as_str()));
        let cand_id = event_id_safe(cand).unwrap_or_default();
        if cand_id == target_parent {
            id_match_indices.push(i);
        }
        if qualifies {
            qualifying_indices.push(i);
        } else {
            rejected_decoys.push(RejectedDecoy {
                id: safe_id(&cand_id),
                index: i,
                reason: fail_reason,
            });
        }
    }

    let confinement = if id_match_indices.is_empty() {
        Confinement::new(false, false)
    } else {
        let child_branch = event_branch_safe(child);
        let mut branch_confined = false;
        let mut segment_confined = false;
        for &idx in &id_match_indices {
            let cand = &events[idx];
            if event_branch_safe(cand) == child_branch {
                branch_confined = true;
            }
            if same_compaction_segment(
                events,
                GraphEndpoint::Event(cand),
                GraphEndpoint::Event(child),
            ) {
                segment_confined = true;
            }
        }
        Confinement::new(branch_confined, segment_confined)
    };

    let reason = if qualifying_indices.len() == 1 {
        "ok".to_owned()
    } else if qualifying_indices.len() > 1 {
        "ambiguous".to_owned()
    } else if rejected_decoys
        .iter()
        .any(|decoy| decoy.reason == "cross_branch")
    {
        "cross_branch".to_owned()
    } else if rejected_decoys
        .iter()
        .any(|decoy| decoy.reason == "cross_segment")
    {
        "cross_segment".to_owned()
    } else {
        "no_full_match".to_owned()
    };

    (qualifying_indices, rejected_decoys, confinement, reason)
}

fn overflow_flag(finding: &Finding) -> Result<i32, GraphError> {
    let Some(evidence) = finding.evidence() else {
        return Ok(0);
    };
    match evidence.map_string("overflow") {
        EvidenceLookup::Borrowed => Err(GraphError::BorrowedLookup),
        EvidenceLookup::Present(value) if value.as_bool() == Some(true) => Ok(1),
        EvidenceLookup::Present(_) | EvidenceLookup::Absent | EvidenceLookup::NotAMap => Ok(0),
    }
}

fn record_id_for_sort(finding: &Finding) -> Result<String, GraphError> {
    if let Some(id) = finding.source().record_id() {
        if !id.is_empty() {
            return Ok(id.to_owned());
        }
    }
    let Some(evidence) = finding.evidence() else {
        return Ok(String::new());
    };
    match evidence.map_string("id") {
        EvidenceLookup::Borrowed => Err(GraphError::BorrowedLookup),
        EvidenceLookup::Present(value) => Ok(value.as_str().unwrap_or("").to_owned()),
        EvidenceLookup::Absent | EvidenceLookup::NotAMap => Ok(String::new()),
    }
}

fn session_attribute(event: &SessionEvent, field: &str) -> Option<EventField> {
    match field {
        "id" => Some(EventField::Str(event.id.clone())),
        "parent_id" => event
            .parent_id
            .as_deref()
            .map(|text| EventField::Str(text.to_owned())),
        "branch_id" => event
            .branch_id
            .as_deref()
            .map(|text| EventField::Str(text.to_owned())),
        "seq" => Some(EventField::Int(event.seq)),
        "kind" => Some(EventField::Str(event.kind.clone())),
        _ => None,
    }
}

fn python_field_str(value: Option<&EventField>) -> Option<String> {
    match value {
        None | Some(EventField::Null) => None,
        Some(EventField::Bool(true)) => Some("True".to_owned()),
        Some(EventField::Bool(false)) => Some("False".to_owned()),
        Some(EventField::Int(number)) => Some(number.to_string()),
        Some(EventField::Str(text)) => Some(text.clone()),
        Some(EventField::Float(_)) | Some(EventField::List(_)) | Some(EventField::Mapping(_)) => {
            None
        }
    }
}

fn endpoint_seq(endpoint: GraphEndpoint<'_>) -> Option<i64> {
    match endpoint {
        GraphEndpoint::Seq(number) => Some(number),
        GraphEndpoint::Event(ev) => event_seq_safe(ev, None),
    }
}

fn kind_is_compaction_boundary(ev: &EventValue) -> bool {
    matches!(
        event_get(ev, "kind"),
        Some(EventField::Str(ref kind)) if kind == "compaction_boundary"
    )
}

fn hex16(digest: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = digest.as_ref();
    let mut out = String::with_capacity(16);
    for byte in bytes.iter().take(8) {
        out.push(char::from(HEX[usize::from(*byte >> 4)]));
        out.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        compute_graph_fingerprint, event_seq_safe, find_qualifying_parent_candidates,
        is_qualifying_parent_candidate, safe_id, same_compaction_segment, Confinement,
        GraphEndpoint, GraphScalar, CONF_SEG_KEY, PYTHON_EVENT_INDEX_UNREPRESENTABLE,
    };
    use model::canonical::SessionEvent;
    use model::events::{EventField, EventMapping, EventValue};

    fn mapping(entries: &[(&str, EventField)]) -> EventValue {
        EventValue::Mapping(EventMapping::new(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        ))
    }

    fn field_str(value: &str) -> EventField {
        EventField::Str(value.to_owned())
    }

    fn event(
        id: &str,
        parent_id: Option<&str>,
        seq: i64,
        branch_id: Option<&str>,
        kind: &str,
    ) -> EventValue {
        let mut entries = vec![
            ("id", field_str(id)),
            ("seq", EventField::Int(seq)),
            ("kind", field_str(kind)),
        ];
        if let Some(parent_id) = parent_id {
            entries.push(("parent_id", field_str(parent_id)));
        } else {
            entries.push(("parent_id", EventField::Null));
        }
        if let Some(branch_id) = branch_id {
            entries.push(("branch_id", field_str(branch_id)));
        } else {
            entries.push(("branch_id", EventField::Null));
        }
        mapping(&entries)
    }

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    #[test]
    fn credential_shaped_id_becomes_redacted() {
        assert_eq!(safe_id("sk-0123456789abcdef"), "<redacted>");
        assert_eq!(safe_id("evt-synthetic"), "evt-synthetic");
    }

    #[test]
    fn fingerprint_is_sixteen_hex_and_order_independent() {
        let left = compute_graph_fingerprint(
            "SL004",
            [
                GraphScalar::from("evt-b"),
                GraphScalar::from("evt-a"),
                GraphScalar::from("evt-b"),
            ],
        );
        let right = compute_graph_fingerprint(
            "SL004",
            [GraphScalar::from("evt-a"), GraphScalar::from("evt-b")],
        );
        assert!(is_lower_hex16(&left));
        assert_eq!(left, right);
        let empty = compute_graph_fingerprint("SL004", Vec::<GraphScalar>::new());
        assert!(is_lower_hex16(&empty));
        let true_id = compute_graph_fingerprint("SL004", [GraphScalar::from(true)]);
        let true_text = compute_graph_fingerprint("SL004", [GraphScalar::from("True")]);
        assert_eq!(true_id, true_text);
    }

    #[test]
    fn bool_seq_falls_through_to_the_default() {
        let ev = mapping(&[("seq", EventField::Bool(true))]);
        assert_eq!(event_seq_safe(&ev, Some(4)), Some(4));
        assert_eq!(event_seq_safe(&ev, None), None);
        let session = EventValue::from_session(SessionEvent::new(
            "evt-synthetic",
            None,
            9,
            "2024-02-29T00:00:00Z",
            "user",
            "message",
        ));
        assert_eq!(event_seq_safe(&session, Some(4)), Some(9));
    }

    #[test]
    fn exact_parent_qualifies_and_a_prefix_does_not() {
        let events = vec![
            event("parent-synthetic", None, 0, Some("main"), "message"),
            event(
                "child-synthetic",
                Some("parent-synthetic"),
                1,
                Some("main"),
                "message",
            ),
        ];
        let (qualifies, reason) = is_qualifying_parent_candidate(
            &events[0],
            &events[1],
            &events,
            Some("parent-synthetic"),
        );
        assert!(qualifies);
        assert_eq!(reason, "ok");
        let (qualifies, reason) =
            is_qualifying_parent_candidate(&events[0], &events[1], &events, Some("parent"));
        assert!(!qualifies);
        assert_eq!(reason, "no_full_match");
    }

    #[test]
    fn different_branch_is_cross_branch() {
        let events = vec![
            event("parent-synthetic", None, 0, Some("other"), "message"),
            event(
                "child-synthetic",
                Some("parent-synthetic"),
                1,
                Some("main"),
                "message",
            ),
        ];
        let (qualifies, reason) = is_qualifying_parent_candidate(
            &events[0],
            &events[1],
            &events,
            Some("parent-synthetic"),
        );
        assert!(!qualifies);
        assert_eq!(reason, "cross_branch");
    }

    #[test]
    fn compaction_boundary_strictly_between_is_cross_segment() {
        let events = vec![
            event("parent-synthetic", None, 0, Some("main"), "message"),
            event(
                "boundary-synthetic",
                None,
                1,
                Some("main"),
                "compaction_boundary",
            ),
            event(
                "child-synthetic",
                Some("parent-synthetic"),
                2,
                Some("main"),
                "message",
            ),
        ];
        assert!(!same_compaction_segment(
            &events,
            GraphEndpoint::Event(&events[0]),
            GraphEndpoint::Event(&events[2]),
        ));
        assert!(!same_compaction_segment(
            &events,
            GraphEndpoint::Seq(0),
            GraphEndpoint::Seq(2),
        ));
        let (qualifies, reason) = is_qualifying_parent_candidate(
            &events[0],
            &events[2],
            &events,
            Some("parent-synthetic"),
        );
        assert!(!qualifies);
        assert_eq!(reason, "cross_segment");
        assert!(same_compaction_segment(
            &events,
            GraphEndpoint::Event(&events[0]),
            GraphEndpoint::Event(&events[1]),
        ));
    }

    #[test]
    fn two_earlier_matches_are_ambiguous() {
        let events = vec![
            event("parent-synthetic", None, 0, Some("main"), "message"),
            event("parent-synthetic", None, 1, Some("main"), "message"),
            event(
                "child-synthetic",
                Some("parent-synthetic"),
                2,
                Some("main"),
                "message",
            ),
        ];
        let (qualifying, rejected, confinement, reason) =
            find_qualifying_parent_candidates(&events, &events[2], 2, Some("parent-synthetic"));
        assert_eq!(qualifying, vec![0, 1]);
        assert!(rejected.is_empty());
        assert_eq!(reason, "ambiguous");
        assert_eq!(
            confinement,
            Confinement {
                branch: true,
                segment: true
            }
        );
        assert_eq!(CONF_SEG_KEY, "segment");
    }

    #[test]
    fn child_index_itself_is_not_a_candidate() {
        let events = vec![
            event("parent-synthetic", None, 0, Some("main"), "message"),
            event(
                "child-synthetic",
                Some("parent-synthetic"),
                1,
                Some("main"),
                "message",
            ),
        ];
        let (qualifying, rejected, _, reason) =
            find_qualifying_parent_candidates(&events, &events[1], 1, Some("parent-synthetic"));
        assert_eq!(qualifying, vec![0]);
        assert!(rejected.iter().all(|decoy| decoy.index != 1));
        assert_eq!(reason, "ok");
        let (qualifying, rejected, _, reason) =
            find_qualifying_parent_candidates(&events, &events[1], 0, Some("parent-synthetic"));
        assert!(qualifying.is_empty());
        assert!(rejected.is_empty());
        assert_eq!(reason, "no_full_match");
    }

    #[test]
    fn missing_seq_event_endpoint_does_not_guess_an_index() {
        let events = vec![
            mapping(&[
                ("id", field_str("left-synthetic")),
                ("kind", field_str("message")),
            ]),
            mapping(&[
                ("id", field_str("bound-synthetic")),
                ("kind", field_str("compaction_boundary")),
            ]),
            mapping(&[
                ("id", field_str("right-synthetic")),
                ("kind", field_str("message")),
            ]),
        ];
        assert!(!same_compaction_segment(
            &events,
            GraphEndpoint::Event(&events[0]),
            GraphEndpoint::Event(&events[2]),
        ));
        assert!(!same_compaction_segment(
            &events,
            GraphEndpoint::Seq(0),
            GraphEndpoint::Event(&events[2]),
        ));
        assert!(!same_compaction_segment(
            &events,
            GraphEndpoint::Seq(0),
            GraphEndpoint::Seq(2),
        ));
        let open = vec![
            mapping(&[
                ("id", field_str("left-synthetic")),
                ("kind", field_str("message")),
            ]),
            mapping(&[
                ("id", field_str("mid-synthetic")),
                ("kind", field_str("message")),
            ]),
            mapping(&[
                ("id", field_str("right-synthetic")),
                ("kind", field_str("message")),
            ]),
        ];
        assert!(same_compaction_segment(
            &open,
            GraphEndpoint::Seq(0),
            GraphEndpoint::Seq(2),
        ));
        assert!(!same_compaction_segment(
            &open,
            GraphEndpoint::Event(&open[0]),
            GraphEndpoint::Event(&open[2]),
        ));
        assert_eq!(
            PYTHON_EVENT_INDEX_UNREPRESENTABLE,
            "EventValue cannot be searched by Python equality; a missing seq does not guess an index"
        );
    }
}
