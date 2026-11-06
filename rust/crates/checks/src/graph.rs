//! Generic parent-graph integrity helpers (SL004, SL005, SL006, SL007).
//!
//! Port of `src/sesslint/checks/graph.py` lines 1–782
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! This slice stops at the end of `check_components`. It does not port
//! `check_heads` or `check_graph`.
//!
//! Parent matching is exact id equality. No `startswith` and no prefix.
//! A parent is never invented by prefix, proximity, or content. `None`
//! branch equals `None`.
//!
//! [`check_missing_parent`], [`check_cycles`], [`check_components`], and
//! overflow [`cap_graph_findings`] call [`make_finding`] with the fingerprint
//! omitted. That returns the codec error and does not produce a digest.
//! This module does not substitute [`compute_graph_fingerprint`].
//!
//! # Recorded gaps
//!
//! * Python `str` of a float, list, or mapping field is not matched
//!   (`model::events::PYTHON_FLOAT_STR_UNREPRESENTABLE` /
//!   `model::events::PYTHON_STR_UNREPRESENTABLE`). The getter returns `None`
//!   and does not invent a Python repr.
//! * A float or container `parent_id` on [`OccurrenceGraph`] is the same
//!   typed error. That parent is skipped; a Python repr is not invented,
//!   and the id is not treated as a root.
//! * A float or container `kind` is not a Python repr. It is not `opaque`
//!   or `compaction_boundary`, so the SL006 non-conversational skip does
//!   not apply.
//! * [`same_compaction_segment`] cannot run `events.index(a)` on
//!   [`EventValue`] ([`PYTHON_EVENT_INDEX_UNREPRESENTABLE`]). An event
//!   endpoint with no seq returns false and does not guess a list index.
//! * [`EvidenceLookup::Borrowed`] is not a missing overflow/id key
//!   ([`BORROWED_LOOKUP`]).
//! * A graph count that does not fit in `i64` is [`COUNT_UNREPRESENTABLE`].

use std::collections::{BTreeSet, HashSet};
use std::error::Error;
use std::fmt;

use model::canonical::SessionEvent;
use model::codes::{Repairability, Severity, SL004, SL005, SL006};
use model::errors::FindingError;
use model::events::{
    EventField, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE, PYTHON_STR_UNREPRESENTABLE,
};
use model::finding::{
    enforce_content_free_text, make_finding, EvidenceLookup, Finding, MakeFindingInput, PyValue,
    SourceLine, SourceRef,
};
use sha2::{Digest, Sha256};

use crate::context::CheckContext;

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

/// A `usize` count that does not fit in `i64`.
pub const COUNT_UNREPRESENTABLE: &str = "A graph count does not fit in i64";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    BorrowedLookup,
    PythonFloatStr,
    PythonStr,
    CountUnrepresentable,
    Finding(FindingError),
}

impl GraphError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::PythonFloatStr => PYTHON_FLOAT_STR_UNREPRESENTABLE,
            Self::PythonStr => PYTHON_STR_UNREPRESENTABLE,
            Self::CountUnrepresentable => COUNT_UNREPRESENTABLE,
            Self::Finding(error) => error.message(),
        }
    }
}

impl fmt::Display for GraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for GraphError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::BorrowedLookup
            | Self::PythonFloatStr
            | Self::PythonStr
            | Self::CountUnrepresentable => None,
        }
    }
}

impl From<FindingError> for GraphError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

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

/// One first-occurrence node. Walk order is [`OccurrenceGraph::id_order`].
#[derive(Debug)]
struct OccurrenceRecord<'a> {
    id: String,
    index: usize,
    parent: Option<String>,
    event: &'a EventValue,
}

/// Python: `_OccurrenceGraph`.
///
/// First-seen order is the record vec. Membership is the id set. A
/// [`std::collections::BTreeMap`] is not the walk order.
#[derive(Debug)]
pub struct OccurrenceGraph<'a> {
    records: Vec<OccurrenceRecord<'a>>,
    ids: HashSet<String>,
    primary_source_path: String,
}

impl<'a> OccurrenceGraph<'a> {
    /// Index `events` in walk order. A non-string id is skipped. An id that
    /// is empty after strip is skipped. The first id wins.
    pub fn new(events: &'a [EventValue], default_path: &str) -> Result<Self, GraphError> {
        let mut records = Vec::new();
        let mut ids = HashSet::new();
        for (idx, event) in events.iter().enumerate() {
            let Some((id, parent)) = event_id_and_parent(event)? else {
                continue;
            };
            if ids.contains(&id) {
                continue;
            }
            ids.insert(id.clone());
            records.push(OccurrenceRecord {
                id,
                index: idx,
                parent,
                event,
            });
        }
        Ok(Self {
            records,
            ids,
            primary_source_path: default_path.replace('\\', "/"),
        })
    }

    pub fn id_order(&self) -> impl Iterator<Item = &str> {
        self.records.iter().map(|record| record.id.as_str())
    }

    pub fn contains_id(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    pub fn index_of(&self, id: &str) -> Option<usize> {
        self.records
            .iter()
            .find(|record| record.id == id)
            .map(|record| record.index)
    }

    pub fn primary_source_path(&self) -> &str {
        &self.primary_source_path
    }

    fn compact_index(&self, id: &str) -> Option<usize> {
        self.records.iter().position(|record| record.id == id)
    }

    fn parent_of(&self, id: &str) -> Option<&str> {
        self.records
            .iter()
            .find(|record| record.id == id)
            .and_then(|record| record.parent.as_deref())
    }

    fn event_of(&self, id: &str) -> Option<&EventValue> {
        self.records
            .iter()
            .find(|record| record.id == id)
            .map(|record| record.event)
    }

    fn uf_position(&self, id: &str, use_event_index: bool) -> Option<usize> {
        self.records
            .iter()
            .enumerate()
            .find_map(|(compact, record)| {
                if record.id == id {
                    Some(if use_event_index {
                        record.index
                    } else {
                        compact
                    })
                } else {
                    None
                }
            })
    }
}

/// One extra weakly-connected component that would emit SL006.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraComponent {
    pub size: usize,
    pub root_id: String,
    pub members: Vec<String>,
}

/// Python: `cap_graph_findings`.
///
/// Omitted `max_findings` is [`MAX_GRAPH_FINDINGS`]. Omitted `source_path`
/// is `"<canonical>"`. Omitted `context` is [`CheckContext::default`].
/// Under the cap, the sorted list is returned and [`make_finding`] is not
/// called. Over the cap, [`make_finding`] is called with the fingerprint
/// omitted; that codec error is propagated.
pub fn cap_graph_findings(
    findings: Vec<Finding>,
    code: &str,
    max_findings: Option<usize>,
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, GraphError> {
    let max_findings = max_findings.unwrap_or(MAX_GRAPH_FINDINGS);
    let source_path = source_path.unwrap_or("<canonical>");

    let mut keyed = Vec::new();
    for finding in findings {
        let key = cap_finding_sort_key(&finding)?;
        keyed.push((key, finding));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let sorted: Vec<Finding> = keyed.into_iter().map(|(_, finding)| finding).collect();

    if sorted.len() <= max_findings {
        return Ok(sorted);
    }

    let total_count = sorted.len();
    let truncated_count = total_count - max_findings;
    let mut kept: Vec<Finding> = sorted.into_iter().take(max_findings).collect();
    let ctx = context.cloned().unwrap_or_default();
    let norm_source_path = source_path.replace('\\', "/");
    let source = SourceRef::try_new(&norm_source_path, None, None)?;
    let overflow_finding = make_finding(&MakeFindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(Severity::Warning),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_OVERFLOW),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence: PyValue::map(vec![
            (
                PyValue::string("cap"),
                PyValue::int(usize_to_i64(max_findings)?),
            ),
            (PyValue::string("overflow"), PyValue::bool_value(true)),
            (
                PyValue::string("total_count"),
                PyValue::int(usize_to_i64(total_count)?),
            ),
            (
                PyValue::string("truncated_count"),
                PyValue::int(usize_to_i64(truncated_count)?),
            ),
            (
                PyValue::string("variant"),
                PyValue::string("overflow-summary"),
            ),
        ]),
        fingerprint: PyValue::None,
        adapter_id: Some(ctx.adapter_id().to_owned()),
        adapter_version: Some(ctx.adapter_version().to_owned()),
        profile_id: Some(ctx.profile_id().to_owned()),
        profile_version: Some(ctx.profile_version().to_owned()),
        ordinal: None,
        context: None,
    })?;
    kept.push(overflow_finding);
    Ok(kept)
}

/// Python: `_resolve_source_coords`.
///
/// A `source_location` is used only when `default_path` is `"<canonical>"`
/// and the location is present. A line is kept only when it is a non-bool
/// int ≥ 1.
pub fn resolve_source_coords(
    event: &EventValue,
    default_path: &str,
) -> Result<(String, Option<i64>), GraphError> {
    let first_loc = source_field(event, "source_location");
    let resolved_path = if default_path != "<canonical>" {
        default_path.to_owned()
    } else if let Some(field) = first_loc.as_ref() {
        match location_text(field)? {
            Some(text) => text,
            None => default_path.to_owned(),
        }
    } else {
        default_path.to_owned()
    }
    .replace('\\', "/");

    let raw_line = source_field(event, "source_line");
    let line_num = match raw_line {
        Some(EventField::Int(number)) if number >= 1 => Some(number),
        _ => None,
    };
    Ok((resolved_path, line_num))
}

/// Python: `check_missing_parent` (SL004).
///
/// `parent_id is None` is a root. An empty-string parent is missing. A
/// parent present anywhere in the first-occurrence set, including a later
/// event and a self-parent, does not fire. Missing-parent evidence does
/// not search for another parent. [`make_finding`] is called with the
/// fingerprint omitted; the codec error is propagated. A session with no
/// missing parent returns an empty list and does not call [`make_finding`].
pub fn check_missing_parent<'a>(
    events: &'a [EventValue],
    source_path: Option<&str>,
    max_findings: Option<usize>,
    context: Option<&CheckContext>,
    occurrence_graph: Option<&OccurrenceGraph<'a>>,
) -> Result<Vec<Finding>, GraphError> {
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
    let owned_graph;
    let graph = match occurrence_graph {
        Some(value) => value,
        None => {
            owned_graph = OccurrenceGraph::new(events, source_path)?;
            &owned_graph
        }
    };

    let mut findings = Vec::new();
    for record in &graph.records {
        let Some(parent_id) = record.parent.as_deref() else {
            continue;
        };
        if graph.ids.contains(parent_id) {
            continue;
        }

        let (resolved_path, line_num) = resolve_source_coords(record.event, source_path)?;
        let clean_rec_id = safe_id(&record.id);
        let clean_parent_id = safe_id(parent_id);

        let mut related = vec![PyValue::string(clean_rec_id.clone())];
        let stripped_parent = clean_parent_id.trim();
        if !stripped_parent.is_empty() {
            related.push(PyValue::string(stripped_parent));
        }

        let source = SourceRef::try_new(
            &resolved_path,
            line_num.map(SourceLine::Int),
            Some(clean_rec_id.as_str()),
        )?;

        let evidence = PyValue::map(vec![
            (PyValue::string("id"), PyValue::string(clean_rec_id)),
            (
                PyValue::string("index"),
                PyValue::int(usize_to_i64(record.index)?),
            ),
            (
                PyValue::string("parent_id"),
                PyValue::string(clean_parent_id),
            ),
            (
                PyValue::string("match_rule"),
                PyValue::string("full-equality"),
            ),
            (
                PyValue::string("confinement"),
                PyValue::map(vec![
                    (PyValue::string("branch"), PyValue::bool_value(false)),
                    (PyValue::string(CONF_SEG_KEY), PyValue::bool_value(false)),
                ]),
            ),
            (PyValue::string("candidate_count"), PyValue::int(0)),
            (
                PyValue::string("rejected_decoys"),
                PyValue::list(Vec::new()),
            ),
            (PyValue::string("reason"), PyValue::string("no_full_match")),
        ]);

        findings.push(make_finding(&MakeFindingInput {
            code: PyValue::string(SL004),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message_template: PyValue::string(MSG_SL004),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::list(related),
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

    cap_graph_findings(
        findings,
        SL004,
        Some(max_findings),
        Some(source_path),
        Some(ctx),
    )
}

/// Observable cycle paths. Does not call [`make_finding`].
///
/// Iterative three-color walk. WHITE 0, GRAY 1, BLACK 2. A self-loop
/// path is `[id, id]`. A missing parent is not a cycle. The same node
/// set is recorded once. Paths are rotated so the lexicographically
/// smallest id is first, then closed with that start id.
pub fn cycle_paths(graph: &OccurrenceGraph<'_>) -> Vec<Vec<String>> {
    const WHITE: u8 = 0;
    const GRAY: u8 = 1;
    const BLACK: u8 = 2;

    let n = graph.records.len();
    let mut color = vec![WHITE; n];
    let mut cycles: Vec<Vec<String>> = Vec::new();
    let mut seen_cycles: BTreeSet<BTreeSet<String>> = BTreeSet::new();

    for start in 0..n {
        if color[start] == BLACK {
            continue;
        }
        let parent_idx = graph.records[start]
            .parent
            .as_deref()
            .and_then(|parent| graph.compact_index(parent));
        match parent_idx {
            Some(parent) if color[parent] != BLACK => {}
            Some(_) | None => {
                color[start] = BLACK;
                continue;
            }
        }

        let mut curr = Some(start);
        let mut path: Vec<usize> = Vec::new();
        let mut path_pos: Vec<Option<usize>> = vec![None; n];

        while let Some(node) = curr {
            let c = color[node];
            if c == GRAY {
                if let Some(cycle_start_idx) = path_pos[node] {
                    let raw_cycle: Vec<String> = path[cycle_start_idx..]
                        .iter()
                        .map(|&item| graph.records[item].id.clone())
                        .collect();
                    let f_set: BTreeSet<String> = raw_cycle.iter().cloned().collect();
                    if seen_cycles.insert(f_set) {
                        cycles.push(rotate_cycle_path(raw_cycle));
                    }
                }
                break;
            }
            if c == BLACK {
                break;
            }

            color[node] = GRAY;
            path_pos[node] = Some(path.len());
            path.push(node);

            curr = graph.records[node]
                .parent
                .as_deref()
                .and_then(|parent| graph.compact_index(parent));
        }

        for &node in &path {
            color[node] = BLACK;
        }
    }

    cycles
}

/// Python: `check_cycles` (SL005).
///
/// No cycle returns an empty list and does not call [`make_finding`].
/// A cycle calls [`make_finding`] with the fingerprint omitted; that
/// codec error is propagated. After a successful [`make_finding`],
/// [`cap_graph_findings`] is called.
pub fn check_cycles<'a>(
    events: &'a [EventValue],
    source_path: Option<&str>,
    max_findings: Option<usize>,
    context: Option<&CheckContext>,
    occurrence_graph: Option<&OccurrenceGraph<'a>>,
) -> Result<Vec<Finding>, GraphError> {
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
    let owned_graph;
    let graph = match occurrence_graph {
        Some(value) => value,
        None => {
            owned_graph = OccurrenceGraph::new(events, source_path)?;
            &owned_graph
        }
    };

    let cycles = cycle_paths(graph);
    if cycles.is_empty() {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    for cycle_path in cycles {
        let Some(primary_id) = cycle_path.first() else {
            continue;
        };
        let Some(event) = graph.event_of(primary_id) else {
            continue;
        };
        let Some(entry_index) = graph.index_of(primary_id) else {
            continue;
        };

        let (resolved_path, line_num) = resolve_source_coords(event, source_path)?;
        let clean_rec_id = safe_id(primary_id);
        let safe_cycle_path: Vec<PyValue> = cycle_path
            .iter()
            .map(|node| PyValue::string(safe_id(node)))
            .collect();
        let related: Vec<PyValue> = sorted_unique_safe_ids(&cycle_path)
            .into_iter()
            .map(PyValue::string)
            .collect();

        let source = SourceRef::try_new(
            &resolved_path,
            line_num.map(SourceLine::Int),
            Some(clean_rec_id.as_str()),
        )?;

        let evidence = PyValue::map(vec![
            (
                PyValue::string("cycle_path"),
                PyValue::list(safe_cycle_path),
            ),
            (
                PyValue::string("entry_index"),
                PyValue::int(usize_to_i64(entry_index)?),
            ),
        ]);

        findings.push(make_finding(&MakeFindingInput {
            code: PyValue::string(SL005),
            severity: PyValue::severity(Severity::Fatal),
            repairability: PyValue::repairability(Repairability::Unsupported),
            message_template: PyValue::string(MSG_SL005),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::list(related),
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

    cap_graph_findings(
        findings,
        SL005,
        Some(max_findings),
        Some(source_path),
        Some(ctx),
    )
}

/// Extra components that would emit SL006. Does not call [`make_finding`].
///
/// Empty id set returns empty before union-find. One component returns
/// empty. Named-branch and non-conversational extras are omitted.
pub fn extra_components(graph: &OccurrenceGraph<'_>, event_count: usize) -> Vec<ExtraComponent> {
    let n = graph.records.len();
    if n == 0 {
        return Vec::new();
    }

    let use_event_index = n == event_count;
    let mut parent_uf: Vec<usize> = (0..n).collect();
    let mut rank_uf = vec![0usize; n];
    let mut component_count = n;

    for (compact, record) in graph.records.iter().enumerate() {
        let index = if use_event_index {
            record.index
        } else {
            compact
        };
        let Some(parent_id) = record.parent.as_deref() else {
            continue;
        };
        let Some(parent) = graph.uf_position(parent_id, use_event_index) else {
            continue;
        };
        let root_i = union_find_find(&mut parent_uf, index);
        let root_j = union_find_find(&mut parent_uf, parent);
        if root_i == root_j {
            continue;
        }
        component_count -= 1;
        if rank_uf[root_i] < rank_uf[root_j] {
            parent_uf[root_i] = root_j;
        } else if rank_uf[root_i] > rank_uf[root_j] {
            parent_uf[root_j] = root_i;
        } else {
            parent_uf[root_j] = root_i;
            rank_uf[root_i] += 1;
        }
    }

    if component_count == 1 {
        return Vec::new();
    }

    let mut groups: Vec<Vec<String>> = vec![Vec::new(); n];
    for (compact, record) in graph.records.iter().enumerate() {
        let index = if use_event_index {
            record.index
        } else {
            compact
        };
        let root = union_find_find(&mut parent_uf, index);
        groups[root].push(record.id.clone());
    }

    let mut component_records: Vec<ExtraComponent> = Vec::new();
    for members in groups {
        if members.is_empty() {
            continue;
        }
        let mut candidate_roots: Vec<&str> = Vec::new();
        for member in &members {
            let parent = graph.parent_of(member);
            if parent.is_none() || parent.is_some_and(|parent_id| !graph.contains_id(parent_id)) {
                candidate_roots.push(member.as_str());
            }
        }
        let root_id = if let Some(root) = candidate_roots.iter().copied().min() {
            root.to_owned()
        } else if let Some(root) = members.iter().min() {
            root.clone()
        } else {
            continue;
        };
        let size = members.len();
        component_records.push(ExtraComponent {
            size,
            root_id,
            members,
        });
    }

    component_records.sort_by(|left, right| {
        right
            .size
            .cmp(&left.size)
            .then(left.root_id.cmp(&right.root_id))
    });

    let mut emitted = Vec::new();
    for extra in component_records.into_iter().skip(1) {
        if named_branch_skip(graph, &extra.members) {
            continue;
        }
        if non_conversational_skip(graph, &extra.members) {
            continue;
        }
        emitted.push(extra);
    }
    emitted
}

/// Python: `check_components` (SL006).
///
/// No extra component returns an empty list and does not call
/// [`make_finding`]. An emitted component calls [`make_finding`] with
/// the fingerprint omitted; that codec error is propagated.
pub fn check_components<'a>(
    events: &'a [EventValue],
    source_path: Option<&str>,
    max_findings: Option<usize>,
    context: Option<&CheckContext>,
    occurrence_graph: Option<&OccurrenceGraph<'a>>,
) -> Result<Vec<Finding>, GraphError> {
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
    let owned_graph;
    let graph = match occurrence_graph {
        Some(value) => value,
        None => {
            owned_graph = OccurrenceGraph::new(events, source_path)?;
            &owned_graph
        }
    };

    let extras = extra_components(graph, events.len());
    if extras.is_empty() {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    for extra in extras {
        let Some(event) = graph.event_of(&extra.root_id) else {
            continue;
        };
        let (resolved_path, line_num) = resolve_source_coords(event, source_path)?;
        let clean_rec_id = safe_id(&extra.root_id);

        let mut sorted_members = extra.members.clone();
        sorted_members.sort();
        let member_sample: Vec<PyValue> = sorted_members
            .iter()
            .take(MAX_MEMBER_SAMPLE_SIZE)
            .map(|node| PyValue::string(safe_id(node)))
            .collect();
        let related: Vec<PyValue> = sorted_unique_safe_ids(&sorted_members)
            .into_iter()
            .map(PyValue::string)
            .collect();

        let source = SourceRef::try_new(
            &resolved_path,
            line_num.map(SourceLine::Int),
            Some(clean_rec_id.as_str()),
        )?;

        let evidence = PyValue::map(vec![
            (
                PyValue::string("member_sample"),
                PyValue::list(member_sample),
            ),
            (PyValue::string("root_id"), PyValue::string(clean_rec_id)),
            (
                PyValue::string("size"),
                PyValue::int(usize_to_i64(extra.size)?),
            ),
        ]);

        findings.push(make_finding(&MakeFindingInput {
            code: PyValue::string(SL006),
            severity: PyValue::severity(Severity::Warning),
            repairability: PyValue::repairability(Repairability::Manual),
            message_template: PyValue::string(MSG_SL006),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::list(related),
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

    cap_graph_findings(
        findings,
        SL006,
        Some(max_findings),
        Some(source_path),
        Some(ctx),
    )
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

fn event_id_and_parent(event: &EventValue) -> Result<Option<(String, Option<String>)>, GraphError> {
    let raw_id = match event {
        EventValue::Session(session) => EventField::Str(session.id.clone()),
        EventValue::Mapping(mapping) => match mapping.get("id") {
            Some(value) => value.clone(),
            None => return Ok(None),
        },
        EventValue::Other => return Ok(None),
    };
    let EventField::Str(id_str) = raw_id else {
        return Ok(None);
    };
    if id_str.trim().is_empty() {
        return Ok(None);
    }

    let raw_parent = match event {
        EventValue::Session(session) => session
            .parent_id
            .as_deref()
            .map(|text| EventField::Str(text.to_owned())),
        EventValue::Mapping(mapping) => mapping.get("parent_id").cloned(),
        EventValue::Other => None,
    };
    let parent = match raw_parent {
        None | Some(EventField::Null) => None,
        Some(EventField::Str(text)) => Some(text),
        Some(EventField::Bool(true)) => Some("True".to_owned()),
        Some(EventField::Bool(false)) => Some("False".to_owned()),
        Some(EventField::Int(number)) => Some(number.to_string()),
        Some(EventField::Float(_)) => return Err(GraphError::PythonFloatStr),
        Some(EventField::List(_) | EventField::Mapping(_)) => return Err(GraphError::PythonStr),
    };
    Ok(Some((id_str, parent)))
}

fn source_field(event: &EventValue, field: &str) -> Option<EventField> {
    match event {
        EventValue::Session(session) => match field {
            "source_location" => session.source_location.clone().map(EventField::Str),
            "source_line" => session.source_line.map(EventField::Int),
            _ => None,
        },
        EventValue::Mapping(mapping) => mapping.get(field).cloned(),
        EventValue::Other => None,
    }
}

fn location_text(field: &EventField) -> Result<Option<String>, GraphError> {
    match field {
        EventField::Null | EventField::Bool(false) => Ok(None),
        EventField::Bool(true) => Ok(Some("True".to_owned())),
        EventField::Int(0) => Ok(None),
        EventField::Int(number) => Ok(Some(number.to_string())),
        EventField::Str(text) if text.is_empty() => Ok(None),
        EventField::Str(text) => Ok(Some(text.clone())),
        EventField::Float(number) if *number == 0.0 => Ok(None),
        EventField::Float(_) => Err(GraphError::PythonFloatStr),
        EventField::List(items) if items.is_empty() => Ok(None),
        EventField::Mapping(mapping) if mapping.entries().is_empty() => Ok(None),
        EventField::List(_) | EventField::Mapping(_) => Err(GraphError::PythonStr),
    }
}

fn usize_to_i64(value: usize) -> Result<i64, GraphError> {
    i64::try_from(value).map_err(|_| GraphError::CountUnrepresentable)
}

fn rotate_cycle_path(raw_cycle: Vec<String>) -> Vec<String> {
    if raw_cycle.is_empty() {
        return raw_cycle;
    }
    let mut min_idx = 0;
    for (idx, id) in raw_cycle.iter().enumerate().skip(1) {
        if id < &raw_cycle[min_idx] {
            min_idx = idx;
        }
    }
    let mut rotated = Vec::with_capacity(raw_cycle.len() + 1);
    rotated.extend_from_slice(&raw_cycle[min_idx..]);
    rotated.extend_from_slice(&raw_cycle[..min_idx]);
    if let Some(start) = rotated.first().cloned() {
        rotated.push(start);
    }
    rotated
}

fn union_find_find(parent_uf: &mut [usize], mut i: usize) -> usize {
    while parent_uf[i] != i {
        let grand = parent_uf[parent_uf[i]];
        parent_uf[i] = grand;
        i = parent_uf[i];
    }
    i
}

fn named_branch_skip(graph: &OccurrenceGraph<'_>, members: &[String]) -> bool {
    let mut first: Option<Option<String>> = None;
    for member in members {
        let branch = graph.event_of(member).and_then(event_branch_safe);
        match &first {
            None => first = Some(branch),
            Some(seen) if *seen != branch => return false,
            Some(_) => {}
        }
    }
    matches!(first, Some(Some(_)))
}

fn non_conversational_skip(graph: &OccurrenceGraph<'_>, members: &[String]) -> bool {
    if members.is_empty() {
        return false;
    }
    for member in members {
        let kind = graph
            .event_of(member)
            .and_then(|event| event_get(event, "kind"));
        match kind {
            Some(EventField::Str(kind)) if NON_CONVERSATIONAL_KINDS.contains(&kind.as_str()) => {}
            _ => return false,
        }
    }
    true
}

fn sorted_unique_safe_ids(ids: &[String]) -> Vec<String> {
    let mut unique = BTreeSet::new();
    for id in ids {
        let clean = safe_id(id);
        if !clean.trim().is_empty() {
            unique.insert(clean);
        }
    }
    unique.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{
        cap_graph_findings, check_components, check_cycles, check_missing_parent,
        compute_graph_fingerprint, cycle_paths, event_seq_safe, extra_components,
        find_qualifying_parent_candidates, is_qualifying_parent_candidate, safe_id,
        same_compaction_segment, Confinement, GraphEndpoint, GraphError, GraphScalar,
        OccurrenceGraph, CONF_SEG_KEY, MSG_SL004, PYTHON_EVENT_INDEX_UNREPRESENTABLE,
    };
    use crate::context::CheckContext;
    use model::canonical::SessionEvent;
    use model::codes::{Repairability, Severity, SL004};
    use model::events::{
        EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };
    use model::finding::{
        make_finding, MakeFindingInput, PyValue, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE,
    };

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

    fn finding_with_id(record_id: &str, fingerprint: &str) -> model::finding::Finding {
        let source = SourceRef::try_new("<canonical>", None, Some(record_id)).unwrap();
        make_finding(&MakeFindingInput {
            code: PyValue::string(SL004),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message_template: PyValue::string(MSG_SL004),
            template_args: PyValue::None,
            source: PyValue::source(source),
            related_ids: PyValue::tuple(vec![PyValue::string(record_id)]),
            evidence: PyValue::None,
            fingerprint: PyValue::string(fingerprint),
            adapter_id: None,
            adapter_version: None,
            profile_id: None,
            profile_version: None,
            ordinal: None,
            context: None,
        })
        .unwrap()
    }

    #[test]
    fn none_parent_and_present_parent_return_no_findings() {
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
        let findings = check_missing_parent(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn later_parent_and_self_parent_do_not_fire() {
        let later = vec![
            event(
                "child-synthetic",
                Some("later-synthetic"),
                0,
                Some("main"),
                "message",
            ),
            event("later-synthetic", None, 1, Some("main"), "message"),
        ];
        let later_findings = check_missing_parent(&later, None, None, None, None).unwrap();
        assert!(later_findings.is_empty());

        let r#loop = vec![event(
            "loop-synthetic",
            Some("loop-synthetic"),
            0,
            Some("main"),
            "message",
        )];
        let loop_findings = check_missing_parent(&r#loop, None, None, None, None).unwrap();
        assert!(loop_findings.is_empty());
    }

    #[test]
    fn empty_string_parent_returns_the_codec_error() {
        let events = vec![event(
            "child-synthetic",
            Some(""),
            0,
            Some("main"),
            "message",
        )];
        let err = check_missing_parent(&events, None, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
        assert!(!matches!(err, GraphError::BorrowedLookup));
    }

    #[test]
    fn duplicate_id_keeps_the_first_index() {
        let events = vec![
            event("dup-synthetic", None, 0, Some("main"), "message"),
            event("other-synthetic", None, 1, Some("main"), "message"),
            event(
                "dup-synthetic",
                Some("missing-synthetic"),
                2,
                Some("main"),
                "message",
            ),
        ];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        assert_eq!(graph.index_of("dup-synthetic"), Some(0));
        assert_ne!(graph.index_of("dup-synthetic"), Some(2));
        let order: Vec<&str> = graph.id_order().collect();
        assert_eq!(order, vec!["dup-synthetic", "other-synthetic"]);
        let findings = check_missing_parent(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn non_string_id_is_skipped() {
        let events = vec![
            mapping(&[
                ("id", EventField::Bool(true)),
                ("parent_id", EventField::Null),
                ("seq", EventField::Int(0)),
                ("kind", field_str("message")),
            ]),
            mapping(&[
                ("id", EventField::Int(7)),
                ("parent_id", field_str("missing-synthetic")),
                ("seq", EventField::Int(1)),
                ("kind", field_str("message")),
            ]),
            event("keep-synthetic", None, 2, Some("main"), "message"),
        ];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        assert!(!graph.contains_id("True"));
        assert!(!graph.contains_id("7"));
        let order: Vec<&str> = graph.id_order().collect();
        assert_eq!(order, vec!["keep-synthetic"]);
        let findings = check_missing_parent(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn cap_under_the_limit_sorts_and_does_not_call_make_finding() {
        let first = finding_with_id("evt-b-synthetic", "bbbbbbbbbbbbbbbb");
        let second = finding_with_id("evt-a-synthetic", "aaaaaaaaaaaaaaaa");
        let out = cap_graph_findings(
            vec![first, second],
            SL004,
            None,
            None,
            Some(&CheckContext::default()),
        )
        .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].source().record_id(), Some("evt-a-synthetic"));
        assert_eq!(out[1].source().record_id(), Some("evt-b-synthetic"));
        assert_eq!(out[0].fingerprint(), "aaaaaaaaaaaaaaaa");
        assert_eq!(out[1].fingerprint(), "bbbbbbbbbbbbbbbb");
        assert!(is_lower_hex16(out[0].fingerprint()));
        assert!(is_lower_hex16(out[1].fingerprint()));
    }

    #[test]
    fn cap_over_the_limit_returns_the_codec_error() {
        let first = finding_with_id("evt-b-synthetic", "bbbbbbbbbbbbbbbb");
        let second = finding_with_id("evt-a-synthetic", "aaaaaaaaaaaaaaaa");
        let err = cap_graph_findings(vec![first, second], SL004, Some(1), None, None).unwrap_err();
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn float_or_container_parent_is_a_typed_error() {
        let float_parent = vec![mapping(&[
            ("id", field_str("child-synthetic")),
            ("parent_id", EventField::Float(1.5)),
            ("seq", EventField::Int(0)),
            ("kind", field_str("message")),
        ])];
        let float_err = OccurrenceGraph::new(&float_parent, "<canonical>").unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        let container_parent = vec![mapping(&[
            ("id", field_str("child-synthetic")),
            (
                "parent_id",
                EventField::List(vec![field_str("missing-synthetic")]),
            ),
            ("seq", EventField::Int(0)),
            ("kind", field_str("message")),
        ])];
        let container_err = OccurrenceGraph::new(&container_parent, "<canonical>").unwrap_err();
        assert_eq!(container_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
    }

    fn assert_codec_unavailable(err: GraphError) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn no_cycle_returns_no_paths_and_check_cycles_is_empty() {
        let events = vec![
            event("parent-synthetic", None, 0, None, "message"),
            event(
                "child-synthetic",
                Some("parent-synthetic"),
                1,
                None,
                "message",
            ),
        ];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        assert!(cycle_paths(&graph).is_empty());
        let findings = check_cycles(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn self_loop_path_is_id_id_and_check_cycles_returns_codec_error() {
        let events = vec![event(
            "loop-synthetic",
            Some("loop-synthetic"),
            0,
            None,
            "message",
        )];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        assert_eq!(
            cycle_paths(&graph),
            vec![vec![
                "loop-synthetic".to_owned(),
                "loop-synthetic".to_owned()
            ]]
        );
        let err = check_cycles(&events, None, None, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn two_node_cycle_rotates_to_smaller_id_and_closes() {
        let events = vec![
            event(
                "evt-b-synthetic",
                Some("evt-a-synthetic"),
                0,
                None,
                "message",
            ),
            event(
                "evt-a-synthetic",
                Some("evt-b-synthetic"),
                1,
                None,
                "message",
            ),
        ];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        let paths = cycle_paths(&graph);
        assert_eq!(
            paths,
            vec![vec![
                "evt-a-synthetic".to_owned(),
                "evt-b-synthetic".to_owned(),
                "evt-a-synthetic".to_owned(),
            ]]
        );
        let err = check_cycles(&events, None, None, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn the_same_cycle_is_recorded_once() {
        let events = vec![
            event(
                "evt-b-synthetic",
                Some("evt-a-synthetic"),
                0,
                None,
                "message",
            ),
            event(
                "evt-a-synthetic",
                Some("evt-b-synthetic"),
                1,
                None,
                "message",
            ),
            event(
                "tail-synthetic",
                Some("evt-b-synthetic"),
                2,
                None,
                "message",
            ),
        ];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        let paths = cycle_paths(&graph);
        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0],
            vec![
                "evt-a-synthetic".to_owned(),
                "evt-b-synthetic".to_owned(),
                "evt-a-synthetic".to_owned(),
            ]
        );
    }

    #[test]
    fn one_component_returns_no_extras_and_check_components_is_empty() {
        let events = vec![
            event("parent-synthetic", None, 0, None, "message"),
            event(
                "child-synthetic",
                Some("parent-synthetic"),
                1,
                None,
                "message",
            ),
        ];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        assert!(extra_components(&graph, events.len()).is_empty());
        let findings = check_components(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn two_disconnected_message_nodes_select_primary_by_size_then_root() {
        let unequal = vec![
            event("root-a-synthetic", None, 0, None, "message"),
            event(
                "child-a-synthetic",
                Some("root-a-synthetic"),
                1,
                None,
                "message",
            ),
            event("root-c-synthetic", None, 2, None, "message"),
        ];
        let unequal_graph = OccurrenceGraph::new(&unequal, "<canonical>").unwrap();
        let extras = extra_components(&unequal_graph, unequal.len());
        assert_eq!(extras.len(), 1);
        assert_eq!(extras[0].root_id, "root-c-synthetic");
        assert_eq!(extras[0].size, 1);
        let err = check_components(&unequal, None, None, None, None).unwrap_err();
        assert_codec_unavailable(err);

        let equal = vec![
            event("root-a-synthetic", None, 0, None, "message"),
            event("root-c-synthetic", None, 1, None, "message"),
        ];
        let equal_graph = OccurrenceGraph::new(&equal, "<canonical>").unwrap();
        let extras = extra_components(&equal_graph, equal.len());
        assert_eq!(extras.len(), 1);
        assert_eq!(extras[0].root_id, "root-c-synthetic");
        assert_eq!(extras[0].size, 1);
        let err = check_components(&equal, None, None, None, None).unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn shared_non_null_branch_does_not_emit() {
        let events = vec![
            event("aaa-main-synthetic", None, 0, None, "message"),
            event(
                "aaa-child-synthetic",
                Some("aaa-main-synthetic"),
                1,
                None,
                "message",
            ),
            event(
                "bbb-side-synthetic",
                None,
                2,
                Some("side-synthetic"),
                "message",
            ),
            event(
                "ccc-side-synthetic",
                Some("bbb-side-synthetic"),
                3,
                Some("side-synthetic"),
                "message",
            ),
        ];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        assert!(extra_components(&graph, events.len()).is_empty());
        let findings = check_components(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn opaque_and_compaction_boundary_kinds_do_not_emit() {
        let events = vec![
            event("msg-root-synthetic", None, 0, None, "message"),
            event(
                "msg-child-synthetic",
                Some("msg-root-synthetic"),
                1,
                None,
                "message",
            ),
            event("opaque-synthetic", None, 2, None, "opaque"),
            event(
                "bound-synthetic",
                Some("opaque-synthetic"),
                3,
                None,
                "compaction_boundary",
            ),
        ];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        assert!(extra_components(&graph, events.len()).is_empty());
        let findings = check_components(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn self_loop_is_a_cycle_and_not_an_extra_component() {
        let events = vec![event(
            "loop-synthetic",
            Some("loop-synthetic"),
            0,
            None,
            "message",
        )];
        let graph = OccurrenceGraph::new(&events, "<canonical>").unwrap();
        assert_eq!(
            cycle_paths(&graph),
            vec![vec![
                "loop-synthetic".to_owned(),
                "loop-synthetic".to_owned()
            ]]
        );
        assert!(extra_components(&graph, events.len()).is_empty());
        let err = check_cycles(&events, None, None, None, None).unwrap_err();
        assert_codec_unavailable(err);
        let findings = check_components(&events, None, None, None, None).unwrap();
        assert!(findings.is_empty());
    }
}
