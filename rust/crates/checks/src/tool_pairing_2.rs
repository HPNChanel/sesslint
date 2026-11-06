//! Generic tool-pairing integrity checks part 2 (SL105, SL106, SL107, SL108).
//!
//! Port of `src/sesslint/checks/tool_pairing_2.py` lines 1–326
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! This module implements four vendor-neutral tool-pairing placement and order rules over
//! canonical events:
//! - SL105 (Reversed tool pairing): tool_result index precedes tool call index.
//!   Severity: error, Repairability: manual.
//!   Rationale: A response preceding its request violates session causal ordering.
//! - SL106 (Cross-branch tool pairing): tool call and tool result reside on different parent branches.
//!   Severity: error, Repairability: manual.
//!   Rationale: Cross-branch pairing indicates an invalid tree merge or divergent execution.
//! - SL107 (Non-adjacent tool pairing / gap): Unrelated events intervene between call and result.
//!   Severity: warning, Repairability: manual.
//!   Rationale: Interleaved non-tool events disrupt the request-response cycle; suppressed
//!   when all intervening events belong to valid concurrent tool pairs (parallel-exemption).
//! - SL108 (Split compaction boundary): A compaction_boundary event splits call and result.
//!   Severity: warning, Repairability: manual.
//!   Rationale: A compaction boundary between a call and its result indicates truncation or
//!   loss of contextual continuity.
//!
//! Precedence & Clean-Pair Gate:
//! - Placement checks (SL105-SL108) run ONLY on clean pairs (exactly 1 call + 1 result per corr).
//! - Correlation IDs flagged with cardinality errors (SL103 reused or SL104 multi-result) are
//!   skipped here (precedence belongs to TASK-014).
//!
//! This slice ports placement helpers and [`ToolPairing2Indexer`]. It does
//! not port `check_reversed_order`, `check_cross_branch`,
//! `_resolve_rule_severity`, `check_adjacency`, `check_compaction_split`,
//! `check_tool_pairing_2`, or `__all__`. It does not import
//! `sesslint.profiles`.
//!
//! [`compute_pairing_fingerprint`] hashes locally:
//! `sha256("{code}|{comma-join of sorted unique items}")` then the first 16
//! lowercase hex characters. It does not call
//! [`model::canonical::compute_content_hash`].
//!
//! Pairing sort key is `(code, overflow flag, primary, fingerprint)`.
//! Overflow is 1 only when evidence `overflow` is JSON true. Primary is the
//! evidence `correlation_id` string when that value is a string, even if
//! `source.record_id` is also set. Otherwise primary is `source.record_id`
//! when that is non-empty. Otherwise `""`. This module does not call
//! [`crate::graph::cap_finding_sort_key`].
//!
//! Under the cap, [`cap_pairing_findings`] returns the sorted list and does
//! not call [`make_finding`]. Over the cap, [`make_finding`] is called with
//! the fingerprint omitted and returns [`FINGERPRINT_CODEC_UNAVAILABLE`].
//! That error is propagated. This module does not append a synthetic overflow
//! finding and does not return the kept prefix as if that finding existed.
//!
//! [`ToolPairing2Indexer`] does not build parent components in [`ToolPairing2Indexer::new`].
//! [`ToolPairing2Indexer::component`] of `None` or a whitespace-only id
//! returns `"<unknown>"` and does not build components.
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Counts that do not fit in `i64` are
//!   [`PYTHON_INT_UNBOUNDED`], not a wrap and not a panic.
//! * [`EvidenceLookup::Borrowed`] is a failed borrow, not a missing
//!   `overflow` / `correlation_id` key ([`BORROWED_LOOKUP`]).
//! * [`EvidenceLookup::NotAMap`] is [`EVIDENCE_NOT_A_MAP`]. Python would
//!   call `.get` on a non-mapping. [`Finding::try_new`] only stores a
//!   mapping or `None`, so this is not reachable from a constructed
//!   finding.
//! * Overflow [`make_finding`] does not produce a digest
//!   ([`FINGERPRINT_CODEC_UNAVAILABLE`]).
//! * A float `source_location`, `kind`, `id`, `correlation_id`, or
//!   `parent_id` is [`model::events::PYTHON_FLOAT_STR_UNREPRESENTABLE`].
//!   Rust `Display` is not used.
//! * A list or mapping `source_location`, `kind`, `id`, `correlation_id`,
//!   or `parent_id` is [`model::events::PYTHON_STR_UNREPRESENTABLE`]. A
//!   Python repr is not invented.
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

use model::canonical::SessionEvent;
use model::codes::{Repairability, Severity};
use model::errors::FindingError;
use model::events::{
    EventField, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE, PYTHON_STR_UNREPRESENTABLE,
};
use model::finding::{
    enforce_content_free_text, make_finding, EvidenceLookup, Finding, MakeFindingInput, PyValue,
    SourceRef, FINGERPRINT_CODEC_UNAVAILABLE,
};
use sha2::{Digest, Sha256};

use crate::context::CheckContext;

/// Python: `MAX_PAIRING_FINDINGS`.
pub const MAX_PAIRING_FINDINGS: i64 = 500;

/// Python: `MAX_INDEX_SAMPLE_SIZE`.
pub const MAX_INDEX_SAMPLE_SIZE: i64 = 32;

/// Python: `MAX_INTERVENING_KINDS_SAMPLE`.
pub const MAX_INTERVENING_KINDS_SAMPLE: i64 = 16;

/// Python: `_KIND_TOOL_USE`.
pub const KIND_TOOL_USE: &str = "tool_use";

/// Python: `_KIND_TOOL_CALL`.
pub const KIND_TOOL_CALL: &str = "tool_call";

/// Python: `_KIND_TOOL_RESULT`.
pub const KIND_TOOL_RESULT: &str = "tool_result";

/// Python: `_KIND_COMPACTION`.
pub const KIND_COMPACTION: &str = "compaction_boundary";

/// Python: `CALL_KINDS`. Membership is exact.
pub const CALL_KINDS: &[&str] = &[KIND_TOOL_CALL, KIND_TOOL_USE];

/// Python: `RESULT_KINDS`. Membership is exact.
pub const RESULT_KINDS: &[&str] = &[KIND_TOOL_RESULT];

/// Python: `TOOL_KINDS`. Membership is exact.
pub const TOOL_KINDS: &[&str] = &[KIND_TOOL_CALL, KIND_TOOL_USE, KIND_TOOL_RESULT];

/// Python: `COMPACTION_KINDS`. Membership is exact.
pub const COMPACTION_KINDS: &[&str] = &[KIND_COMPACTION];

/// Python: `_ADJACENCY_TRANSPARENT_KINDS`. Membership is exact.
pub const ADJACENCY_TRANSPARENT_KINDS: &[&str] =
    &[KIND_TOOL_CALL, KIND_TOOL_USE, KIND_TOOL_RESULT, "opaque"];

/// Python: `_MSG_SL105`.
pub const MSG_SL105: &str = "Reversed tool-pairing order detected for record {record_id}";

/// Python: `_MSG_SL106`.
pub const MSG_SL106: &str = "Cross-branch tool pairing detected for record {record_id}";

/// Python: `_MSG_SL107`.
pub const MSG_SL107: &str = "Non-adjacent tool pairing detected for record {record_id}";

/// Python: `_MSG_SL108`.
pub const MSG_SL108: &str = "Split compaction boundary detected for record {record_id}";

/// Python: `_MSG_OVERFLOW`.
pub const MSG_OVERFLOW: &str =
    "Tool pairing check finding cap reached; remaining records truncated";

/// Python `int` is unbounded; an `i64` overflow is not a wrap.
pub const PYTHON_INT_UNBOUNDED: &str =
    "Python ints are unbounded; an i64 overflow is not a wrap and not a panic";

/// [`EvidenceLookup::Borrowed`] is not a missing key.
pub const BORROWED_LOOKUP: &str = "A borrowed map lookup is not a missing key";

/// [`EvidenceLookup::NotAMap`]: Python would call `.get` on a non-mapping.
pub const EVIDENCE_NOT_A_MAP: &str =
    "Evidence is not a mapping; Python would call .get on a non-mapping";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolPairing2Error {
    BorrowedLookup,
    EvidenceNotAMap,
    PythonIntUnbounded,
    PythonFloatStr,
    PythonStr,
    Finding(FindingError),
}

impl ToolPairing2Error {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::EvidenceNotAMap => EVIDENCE_NOT_A_MAP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::PythonFloatStr => PYTHON_FLOAT_STR_UNREPRESENTABLE,
            Self::PythonStr => PYTHON_STR_UNREPRESENTABLE,
            Self::Finding(error) => error.message(),
        }
    }
}

impl fmt::Display for ToolPairing2Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ToolPairing2Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::BorrowedLookup
            | Self::EvidenceNotAMap
            | Self::PythonIntUnbounded
            | Self::PythonFloatStr
            | Self::PythonStr => None,
        }
    }
}

impl From<FindingError> for ToolPairing2Error {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

/// Python: `_safe_id`.
///
/// `None` returns `"<redacted>"`. Any [`enforce_content_free_text`] error
/// with context `"id"` returns `"<redacted>"`. On success the original
/// text is kept, including surrounding spaces.
pub fn safe_id(id_str: Option<&str>) -> String {
    let Some(text) = id_str else {
        return "<redacted>".to_owned();
    };
    match enforce_content_free_text(text, "id") {
        Ok(()) => text.to_owned(),
        Err(_) => "<redacted>".to_owned(),
    }
}

/// Python: `_source_record_id`.
///
/// `None` and whitespace-only text return `None`. Strip is only the
/// emptiness test. A non-empty strip returns [`safe_id`] of the original
/// text, not the stripped text.
pub fn source_record_id(id_str: Option<&str>) -> Option<String> {
    let text = id_str?;
    if text.trim().is_empty() {
        return None;
    }
    Some(safe_id(Some(text)))
}

/// Python: `compute_pairing_fingerprint`.
///
/// `sha256("{code}|{comma-join of sorted unique items}")` then the first
/// 16 lowercase hex characters. Python uses `set` then `sorted`, so
/// duplicates collapse. This does not call [`make_finding`] or
/// [`model::canonical::compute_content_hash`].
pub fn compute_pairing_fingerprint(
    code: &str,
    items: impl IntoIterator<Item = impl AsRef<str>>,
) -> String {
    let mut unique = HashSet::new();
    for item in items {
        unique.insert(item.as_ref().to_owned());
    }
    let mut sorted_items: Vec<String> = unique.into_iter().collect();
    sorted_items.sort();
    let mut content = String::from(code);
    content.push('|');
    let mut first = true;
    for item in &sorted_items {
        if !first {
            content.push(',');
        }
        first = false;
        content.push_str(item);
    }
    hex16(Sha256::digest(content.as_bytes()))
}

/// Python: `_cap_finding_sort_key`.
///
/// `(code, 1 if evidence overflow is JSON true else 0, primary, fingerprint)`.
/// A bool is not another truthy value. Missing, `false`, `1`, and the
/// string `"true"` are 0. Primary is evidence `correlation_id` when that
/// value is a string, even if `source.record_id` is also set. Otherwise
/// `source.record_id` when non-empty, otherwise `""`.
pub fn cap_finding_sort_key(
    finding: &Finding,
) -> Result<(String, i32, String, String), ToolPairing2Error> {
    let is_overflow = overflow_flag(finding)?;
    let primary = primary_for_sort(finding)?;
    Ok((
        finding.code().to_owned(),
        is_overflow,
        primary,
        finding.fingerprint().to_owned(),
    ))
}

/// Python: `cap_pairing_findings`.
///
/// Omitted `max_findings` is [`MAX_PAIRING_FINDINGS`]. Omitted `source_path`
/// is `"<canonical>"`. Omitted `context` is [`CheckContext::default`].
/// Comparison is the Python `<=`. A negative max is not special-cased: an
/// empty list with `max_findings == -1` takes the overflow path because
/// `0 <= -1` is false.
pub fn cap_pairing_findings(
    findings: Vec<Finding>,
    code: &str,
    max_findings: Option<i64>,
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, ToolPairing2Error> {
    let max_findings = max_findings.unwrap_or(MAX_PAIRING_FINDINGS);

    let mut keyed = Vec::new();
    for finding in findings {
        let key = cap_finding_sort_key(&finding)?;
        keyed.push((key, finding));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    let sorted: Vec<Finding> = keyed.into_iter().map(|(_, finding)| finding).collect();

    let total_count = usize_to_i64(sorted.len())?;
    if total_count <= max_findings {
        return Ok(sorted);
    }

    let truncated_count = total_count
        .checked_sub(max_findings)
        .ok_or(ToolPairing2Error::PythonIntUnbounded)?;
    let ctx = context.cloned().unwrap_or_default();
    let norm_source_path = source_path.unwrap_or("<canonical>").replace('\\', "/");
    let source = SourceRef::try_new(&norm_source_path, None, None)?;
    match make_finding(&MakeFindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(Severity::Warning),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_OVERFLOW),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence: PyValue::map(vec![
            (PyValue::string("cap"), PyValue::int(max_findings)),
            (PyValue::string("overflow"), PyValue::bool_value(true)),
            (PyValue::string("total_count"), PyValue::int(total_count)),
            (
                PyValue::string("truncated_count"),
                PyValue::int(truncated_count),
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
    }) {
        Err(error) => Err(error.into()),
        Ok(_finding) => Err(ToolPairing2Error::Finding(FindingError::new(
            FINGERPRINT_CODEC_UNAVAILABLE,
        ))),
    }
}

/// Python: `_resolve_source_coords`.
///
/// `source_location` is the event attribute, else a mapping key. When
/// `default_path` is not exactly `"<canonical>"`, the path is
/// `default_path`. When `default_path` is `"<canonical>"` and the location
/// is missing or falsy, the path is `"<canonical>"`. Otherwise the path is
/// the string form of the location. Backslashes are then replaced.
/// A line is kept only when it is a non-bool int ≥ 1.
pub fn resolve_source_coords(
    event: &EventValue,
    default_path: &str,
) -> Result<(String, Option<i64>), ToolPairing2Error> {
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

/// Python: `_DisjointSet`.
///
/// Path compression and union by rank. A missing item becomes its own root
/// with rank 0. Equal rank attaches `root_b` under `root_a` and increments
/// `root_a`'s rank. A lower rank attaches under the higher rank. Union of
/// the same root does nothing.
#[derive(Debug, Default)]
pub struct DisjointSet {
    parent: HashMap<String, String>,
    rank: HashMap<String, i64>,
}

impl DisjointSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Python: `_DisjointSet.find`.
    pub fn find(&mut self, item: &str) -> String {
        if !self.parent.contains_key(item) {
            self.parent.insert(item.to_owned(), item.to_owned());
            self.rank.insert(item.to_owned(), 0);
            return item.to_owned();
        }
        let mut root = item.to_owned();
        loop {
            let Some(next) = self.parent.get(&root) else {
                break;
            };
            if next == &root {
                break;
            }
            root = next.clone();
        }
        let mut curr = item.to_owned();
        while curr != root {
            let Some(nxt) = self.parent.get(&curr).cloned() else {
                break;
            };
            self.parent.insert(curr, root.clone());
            curr = nxt;
        }
        root
    }

    /// Python: `_DisjointSet.union`.
    pub fn union(&mut self, a: &str, b: &str) -> Result<(), ToolPairing2Error> {
        let root_a = self.find(a);
        let root_b = self.find(b);
        if root_a == root_b {
            return Ok(());
        }
        let rank_a = self.rank.get(&root_a).copied().unwrap_or(0);
        let rank_b = self.rank.get(&root_b).copied().unwrap_or(0);
        if rank_a < rank_b {
            self.parent.insert(root_a, root_b);
        } else if rank_a > rank_b {
            self.parent.insert(root_b, root_a);
        } else {
            self.parent.insert(root_b, root_a.clone());
            let next_rank = rank_a
                .checked_add(1)
                .ok_or(ToolPairing2Error::PythonIntUnbounded)?;
            self.rank.insert(root_a, next_rank);
        }
        Ok(())
    }
}

/// Python: `_ToolPairing2Indexer`.
///
/// Two passes in [`Self::new`] plus a lazy component pass. Group order is
/// first-seen key order, not [`HashMap`] iteration. Stored pairs are
/// `(index, event)` in encounter order. There is no null correlation bucket.
#[derive(Debug)]
pub struct ToolPairing2Indexer<'a> {
    events: &'a [EventValue],
    source_path: String,
    uses_order: Vec<String>,
    uses_by_corr: HashMap<String, Vec<(usize, &'a EventValue)>>,
    results_order: Vec<String>,
    results_by_corr: HashMap<String, Vec<(usize, &'a EventValue)>>,
    compaction_indices: Vec<usize>,
    event_kinds: Vec<String>,
    id_set: HashSet<String>,
    ds: DisjointSet,
    components_built: bool,
    clean_corrs: Vec<String>,
}

impl<'a> ToolPairing2Indexer<'a> {
    /// Python: `_ToolPairing2Indexer.__init__`.
    ///
    /// Omitted `source_path` is `"<canonical>"`. A [`SessionEvent`] uses
    /// `kind`, `id`, and `correlation_id` fields. A mapping uses those keys.
    /// Kind `None` becomes `"unknown"`. Components are not built here.
    pub fn new(
        events: &'a [EventValue],
        source_path: Option<&str>,
    ) -> Result<Self, ToolPairing2Error> {
        let mut indexer = Self {
            events,
            source_path: source_path.unwrap_or("<canonical>").to_owned(),
            uses_order: Vec::new(),
            uses_by_corr: HashMap::new(),
            results_order: Vec::new(),
            results_by_corr: HashMap::new(),
            compaction_indices: Vec::new(),
            event_kinds: Vec::new(),
            id_set: HashSet::new(),
            ds: DisjointSet::new(),
            components_built: false,
            clean_corrs: Vec::new(),
        };

        for (idx, ev) in events.iter().enumerate() {
            let (raw_kind, raw_id, corr) = kind_id_and_corr(ev);
            let kind_str = kind_string(raw_kind.as_ref())?;
            indexer.event_kinds.push(kind_str.clone());

            if let Some(id_field) = raw_id.as_ref() {
                if !matches!(id_field, EventField::Null) {
                    let ev_id_str = python_str(id_field)?;
                    if !ev_id_str.trim().is_empty() {
                        indexer.id_set.insert(ev_id_str);
                    }
                }
            }

            if is_compaction_kind(&kind_str) {
                indexer.compaction_indices.push(idx);
            }

            match corr.as_ref() {
                None | Some(EventField::Null) => {}
                Some(corr_field) => {
                    if is_call_kind(&kind_str) {
                        let corr_str = python_str(corr_field)?;
                        push_group(
                            &mut indexer.uses_order,
                            &mut indexer.uses_by_corr,
                            corr_str,
                            idx,
                            ev,
                        );
                    } else if is_result_kind(&kind_str) {
                        let corr_str = python_str(corr_field)?;
                        push_group(
                            &mut indexer.results_order,
                            &mut indexer.results_by_corr,
                            corr_str,
                            idx,
                            ev,
                        );
                    }
                }
            }
        }

        let result_keys: HashSet<&str> = indexer.results_order.iter().map(String::as_str).collect();
        let mut clean_corrs = Vec::new();
        for corr in &indexer.uses_order {
            if result_keys.contains(corr.as_str())
                && indexer.uses_by_corr.get(corr).map(Vec::len) == Some(1)
                && indexer.results_by_corr.get(corr).map(Vec::len) == Some(1)
            {
                clean_corrs.push(corr.clone());
            }
        }
        clean_corrs.sort();
        indexer.clean_corrs = clean_corrs;
        Ok(indexer)
    }

    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    pub fn clean_corrs(&self) -> &[String] {
        &self.clean_corrs
    }

    pub fn compaction_indices(&self) -> &[usize] {
        &self.compaction_indices
    }

    pub fn event_kinds(&self) -> &[String] {
        &self.event_kinds
    }

    pub fn uses_keys(&self) -> &[String] {
        &self.uses_order
    }

    pub fn results_keys(&self) -> &[String] {
        &self.results_order
    }

    pub fn uses(&self, corr: &str) -> &[(usize, &'a EventValue)] {
        self.uses_by_corr
            .get(corr)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn results(&self, corr: &str) -> &[(usize, &'a EventValue)] {
        self.results_by_corr
            .get(corr)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Python: `_ToolPairing2Indexer.component`.
    ///
    /// `None` and whitespace-only ids return `"<unknown>"` and do not build
    /// components. Any other id builds components once, then returns
    /// [`DisjointSet::find`] of that id.
    pub fn component(&mut self, event_id: Option<&str>) -> Result<String, ToolPairing2Error> {
        let Some(text) = event_id else {
            return Ok("<unknown>".to_owned());
        };
        if text.trim().is_empty() {
            return Ok("<unknown>".to_owned());
        }
        self.ensure_components()?;
        Ok(self.ds.find(text))
    }

    /// Python: `_ToolPairing2Indexer._ensure_components`.
    fn ensure_components(&mut self) -> Result<(), ToolPairing2Error> {
        if self.components_built {
            return Ok(());
        }
        self.components_built = true;
        for ev in self.events {
            let (raw_id, raw_parent) = id_and_parent(ev);
            let ev_id = match raw_id.as_ref() {
                None | Some(EventField::Null) => continue,
                Some(id_field) => {
                    let ev_id = python_str(id_field)?;
                    if ev_id.trim().is_empty() {
                        continue;
                    }
                    ev_id
                }
            };
            match raw_parent.as_ref() {
                None | Some(EventField::Null) => {}
                Some(parent_field) => {
                    let parent_id = python_str(parent_field)?;
                    if !parent_id.trim().is_empty() && self.id_set.contains(&parent_id) {
                        self.ds.union(&ev_id, &parent_id)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn overflow_flag(finding: &Finding) -> Result<i32, ToolPairing2Error> {
    let Some(evidence) = finding.evidence() else {
        return Ok(0);
    };
    match evidence.map_string("overflow") {
        EvidenceLookup::Borrowed => Err(ToolPairing2Error::BorrowedLookup),
        EvidenceLookup::NotAMap => Err(ToolPairing2Error::EvidenceNotAMap),
        EvidenceLookup::Present(value) if value.as_bool() == Some(true) => Ok(1),
        EvidenceLookup::Present(_) | EvidenceLookup::Absent => Ok(0),
    }
}

fn primary_for_sort(finding: &Finding) -> Result<String, ToolPairing2Error> {
    if let Some(evidence) = finding.evidence() {
        match evidence.map_string("correlation_id") {
            EvidenceLookup::Borrowed => return Err(ToolPairing2Error::BorrowedLookup),
            EvidenceLookup::NotAMap => return Err(ToolPairing2Error::EvidenceNotAMap),
            EvidenceLookup::Present(value) => {
                if let Some(text) = value.as_str() {
                    return Ok(text.to_owned());
                }
            }
            EvidenceLookup::Absent => {}
        }
    }
    match finding.source().record_id() {
        Some(id) if !id.is_empty() => Ok(id.to_owned()),
        _ => Ok(String::new()),
    }
}

fn source_field(event: &EventValue, field: &str) -> Option<EventField> {
    match event {
        EventValue::Session(session) => session_source_field(session, field),
        EventValue::Mapping(mapping) => mapping.get(field).cloned(),
        EventValue::Other => None,
    }
}

fn session_source_field(session: &SessionEvent, field: &str) -> Option<EventField> {
    match field {
        "source_location" => session.source_location.clone().map(EventField::Str),
        "source_line" => session.source_line.map(EventField::Int),
        _ => None,
    }
}

fn location_text(field: &EventField) -> Result<Option<String>, ToolPairing2Error> {
    match field {
        EventField::Null | EventField::Bool(false) => Ok(None),
        EventField::Bool(true) => Ok(Some("True".to_owned())),
        EventField::Int(0) => Ok(None),
        EventField::Int(number) => Ok(Some(number.to_string())),
        EventField::Str(text) if text.is_empty() => Ok(None),
        EventField::Str(text) => Ok(Some(text.clone())),
        EventField::Float(number) if *number == 0.0 => Ok(None),
        EventField::Float(_) => Err(ToolPairing2Error::PythonFloatStr),
        EventField::List(items) if items.is_empty() => Ok(None),
        EventField::Mapping(mapping) if mapping.entries().is_empty() => Ok(None),
        EventField::List(_) | EventField::Mapping(_) => Err(ToolPairing2Error::PythonStr),
    }
}

fn kind_id_and_corr(
    event: &EventValue,
) -> (Option<EventField>, Option<EventField>, Option<EventField>) {
    match event {
        EventValue::Session(session) => (
            Some(EventField::Str(session.kind.clone())),
            Some(EventField::Str(session.id.clone())),
            session
                .correlation_id
                .as_deref()
                .map(|text| EventField::Str(text.to_owned())),
        ),
        EventValue::Mapping(mapping) => (
            mapping.get("kind").cloned(),
            mapping.get("id").cloned(),
            mapping.get("correlation_id").cloned(),
        ),
        EventValue::Other => (None, None, None),
    }
}

fn id_and_parent(event: &EventValue) -> (Option<EventField>, Option<EventField>) {
    match event {
        EventValue::Session(session) => (
            Some(EventField::Str(session.id.clone())),
            session
                .parent_id
                .as_deref()
                .map(|text| EventField::Str(text.to_owned())),
        ),
        EventValue::Mapping(mapping) => (
            mapping.get("id").cloned(),
            mapping.get("parent_id").cloned(),
        ),
        EventValue::Other => (None, None),
    }
}

fn kind_string(kind: Option<&EventField>) -> Result<String, ToolPairing2Error> {
    match kind {
        None | Some(EventField::Null) => Ok("unknown".to_owned()),
        Some(field) => python_str(field),
    }
}

fn python_str(field: &EventField) -> Result<String, ToolPairing2Error> {
    match field {
        EventField::Null => Ok("None".to_owned()),
        EventField::Bool(true) => Ok("True".to_owned()),
        EventField::Bool(false) => Ok("False".to_owned()),
        EventField::Int(number) => Ok(number.to_string()),
        EventField::Str(text) => Ok(text.clone()),
        EventField::Float(_) => Err(ToolPairing2Error::PythonFloatStr),
        EventField::List(_) | EventField::Mapping(_) => Err(ToolPairing2Error::PythonStr),
    }
}

fn is_call_kind(kind: &str) -> bool {
    CALL_KINDS.contains(&kind)
}

fn is_result_kind(kind: &str) -> bool {
    RESULT_KINDS.contains(&kind)
}

fn is_compaction_kind(kind: &str) -> bool {
    COMPACTION_KINDS.contains(&kind)
}

fn push_group<'a>(
    order: &mut Vec<String>,
    by_corr: &mut HashMap<String, Vec<(usize, &'a EventValue)>>,
    key: String,
    idx: usize,
    event: &'a EventValue,
) {
    if !by_corr.contains_key(&key) {
        order.push(key.clone());
    }
    by_corr.entry(key).or_default().push((idx, event));
}

fn usize_to_i64(value: usize) -> Result<i64, ToolPairing2Error> {
    i64::try_from(value).map_err(|_| ToolPairing2Error::PythonIntUnbounded)
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
        cap_finding_sort_key, cap_pairing_findings, compute_pairing_fingerprint,
        resolve_source_coords, safe_id, source_record_id, DisjointSet, ToolPairing2Error,
        ToolPairing2Indexer, ADJACENCY_TRANSPARENT_KINDS, CALL_KINDS, COMPACTION_KINDS,
        KIND_COMPACTION, KIND_TOOL_CALL, KIND_TOOL_RESULT, KIND_TOOL_USE, MAX_INDEX_SAMPLE_SIZE,
        MAX_INTERVENING_KINDS_SAMPLE, MAX_PAIRING_FINDINGS, MSG_OVERFLOW, MSG_SL105, MSG_SL106,
        MSG_SL107, MSG_SL108, RESULT_KINDS, TOOL_KINDS,
    };
    use crate::context::CheckContext;
    use model::canonical::SessionEvent;
    use model::codes::{Repairability, Severity, SL105};
    use model::events::{
        EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };
    use model::finding::{
        Finding, FindingInput, PyValue, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE, SCHEMA_VERSION,
    };

    fn is_lower_hex16(text: &str) -> bool {
        text.len() == 16 && text.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f'))
    }

    fn finding(
        code: &str,
        record_id: Option<&str>,
        fingerprint: &str,
        evidence: PyValue,
    ) -> Finding {
        let source = SourceRef::try_new("<canonical>", None, record_id).unwrap();
        Finding::try_new(FindingInput {
            code: PyValue::string(code),
            severity: PyValue::severity(Severity::Warning),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic pairing marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string(fingerprint),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence,
        })
        .unwrap()
    }

    fn session(id: &str, kind: &str, corr: Option<&str>) -> EventValue {
        let mut event = SessionEvent::new(id, None, 0, "2024-02-29T00:00:00Z", "assistant", kind);
        event.correlation_id = corr.map(str::to_owned);
        EventValue::from_session(event)
    }

    fn session_with_parent(
        id: &str,
        parent: Option<&str>,
        kind: &str,
        corr: Option<&str>,
    ) -> EventValue {
        let mut event = SessionEvent::new(
            id,
            parent.map(str::to_owned),
            0,
            "2024-02-29T00:00:00Z",
            "assistant",
            kind,
        );
        event.correlation_id = corr.map(str::to_owned);
        EventValue::from_session(event)
    }

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

    fn assert_codec_unavailable(err: ToolPairing2Error) {
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
        assert!(matches!(err, ToolPairing2Error::Finding(_)));
    }

    #[test]
    fn constants_match_the_pin() {
        assert_eq!(MAX_PAIRING_FINDINGS, 500);
        assert_eq!(MAX_INDEX_SAMPLE_SIZE, 32);
        assert_eq!(MAX_INTERVENING_KINDS_SAMPLE, 16);
        assert_eq!(KIND_TOOL_CALL, "tool_call");
        assert_eq!(KIND_TOOL_USE, "tool_use");
        assert_eq!(KIND_TOOL_RESULT, "tool_result");
        assert_eq!(KIND_COMPACTION, "compaction_boundary");
        assert_eq!(CALL_KINDS, &["tool_call", "tool_use"]);
        assert_eq!(RESULT_KINDS, &["tool_result"]);
        assert_eq!(TOOL_KINDS, &["tool_call", "tool_use", "tool_result"]);
        assert_eq!(COMPACTION_KINDS, &["compaction_boundary"]);
        assert_eq!(
            ADJACENCY_TRANSPARENT_KINDS,
            &["tool_call", "tool_use", "tool_result", "opaque"]
        );
        assert_eq!(
            MSG_SL105,
            "Reversed tool-pairing order detected for record {record_id}"
        );
        assert_eq!(
            MSG_SL106,
            "Cross-branch tool pairing detected for record {record_id}"
        );
        assert_eq!(
            MSG_SL107,
            "Non-adjacent tool pairing detected for record {record_id}"
        );
        assert_eq!(
            MSG_SL108,
            "Split compaction boundary detected for record {record_id}"
        );
        assert_eq!(
            MSG_OVERFLOW,
            "Tool pairing check finding cap reached; remaining records truncated"
        );
    }

    #[test]
    fn safe_id_none_is_redacted_and_content_free_text_is_kept() {
        assert_eq!(safe_id(None), "<redacted>");
        assert_eq!(safe_id(Some("evt-a-synthetic")), "evt-a-synthetic");
        assert_eq!(safe_id(Some("  a  ")), "  a  ");
        assert_eq!(safe_id(Some("sk-0123456789abcdef")), "<redacted>");
    }

    #[test]
    fn source_record_id_strips_only_to_test_emptiness() {
        assert_eq!(source_record_id(None), None);
        assert_eq!(source_record_id(Some("")), None);
        assert_eq!(source_record_id(Some("   ")), None);
        assert_eq!(source_record_id(Some("\t")), None);
        assert_eq!(source_record_id(Some("  a  ")).as_deref(), Some("  a  "));
        assert_eq!(
            source_record_id(Some("evt-a-synthetic")).as_deref(),
            Some("evt-a-synthetic")
        );
    }

    #[test]
    fn fingerprint_example_collapses_duplicates() {
        assert_eq!(
            compute_pairing_fingerprint("SL105", ["b", "a", "a"]),
            "fd7f5d41cb93b80a"
        );
        assert_eq!(
            compute_pairing_fingerprint("SL105", ["a", "b"]),
            "fd7f5d41cb93b80a"
        );
        assert!(is_lower_hex16(&compute_pairing_fingerprint(
            "SL105",
            ["b", "a", "a"]
        )));
    }

    #[test]
    fn sort_key_prefers_string_correlation_id_over_record_id() {
        let preferred = finding(
            SL105,
            Some("evt-z-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(
                PyValue::string("correlation_id"),
                PyValue::string("corr-a-synthetic"),
            )]),
        );
        let by_record = finding(
            SL105,
            Some("evt-a-synthetic"),
            "bbbbbbbbbbbbbbbb",
            PyValue::None,
        );
        assert_eq!(
            cap_finding_sort_key(&preferred).unwrap().2,
            "corr-a-synthetic"
        );
        assert_eq!(
            cap_finding_sort_key(&by_record).unwrap().2,
            "evt-a-synthetic"
        );
        let out = cap_pairing_findings(
            vec![preferred, by_record],
            SL105,
            None,
            None,
            Some(&CheckContext::default()),
        )
        .unwrap();
        assert_eq!(out[0].source().record_id(), Some("evt-z-synthetic"));
        assert_eq!(out[1].source().record_id(), Some("evt-a-synthetic"));
    }

    #[test]
    fn cap_under_the_limit_sorts_and_does_not_call_make_finding() {
        let first = finding(
            SL105,
            Some("evt-b-synthetic"),
            "bbbbbbbbbbbbbbbb",
            PyValue::None,
        );
        let second = finding(
            SL105,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::None,
        );
        let out = cap_pairing_findings(
            vec![first, second],
            SL105,
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
        let item = finding(
            SL105,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::None,
        );
        let err = cap_pairing_findings(vec![item], SL105, Some(0), None, None).unwrap_err();
        assert_codec_unavailable(err);
        let empty_err =
            cap_pairing_findings(Vec::new(), SL105, Some(-1), Some("a\\b"), None).unwrap_err();
        assert_codec_unavailable(empty_err);
    }

    #[test]
    fn overflow_flag_is_one_only_for_json_true() {
        let overflow = finding(
            SL105,
            Some("evt-a-synthetic"),
            "aaaaaaaaaaaaaaaa",
            PyValue::map(vec![(
                PyValue::string("overflow"),
                PyValue::bool_value(true),
            )]),
        );
        let missing = finding(
            SL105,
            Some("evt-a-synthetic"),
            "bbbbbbbbbbbbbbbb",
            PyValue::None,
        );
        let as_false = finding(
            SL105,
            Some("evt-a-synthetic"),
            "cccccccccccccccc",
            PyValue::map(vec![(
                PyValue::string("overflow"),
                PyValue::bool_value(false),
            )]),
        );
        let as_one = finding(
            SL105,
            Some("evt-a-synthetic"),
            "dddddddddddddddd",
            PyValue::map(vec![(PyValue::string("overflow"), PyValue::int(1))]),
        );
        let as_text = finding(
            SL105,
            Some("evt-a-synthetic"),
            "eeeeeeeeeeeeeeee",
            PyValue::map(vec![(PyValue::string("overflow"), PyValue::string("true"))]),
        );
        assert_eq!(cap_finding_sort_key(&overflow).unwrap().1, 1);
        assert_eq!(cap_finding_sort_key(&missing).unwrap().1, 0);
        assert_eq!(cap_finding_sort_key(&as_false).unwrap().1, 0);
        assert_eq!(cap_finding_sort_key(&as_one).unwrap().1, 0);
        assert_eq!(cap_finding_sort_key(&as_text).unwrap().1, 0);
    }

    #[test]
    fn disjoint_set_equal_rank_attaches_b_under_a() {
        let mut ds = DisjointSet::new();
        ds.union("a-synth", "b-synth").unwrap();
        assert_eq!(ds.find("a-synth"), "a-synth");
        assert_eq!(ds.find("b-synth"), "a-synth");
        ds.union("a-synth", "b-synth").unwrap();
        assert_eq!(ds.find("b-synth"), "a-synth");
        ds.union("c-synth", "a-synth").unwrap();
        assert_eq!(ds.find("c-synth"), "a-synth");
    }

    #[test]
    fn clean_pair_is_sorted_into_clean_corrs() {
        let events = [
            session("evt-b-synthetic", KIND_TOOL_CALL, Some("corr-b-synthetic")),
            session(
                "evt-b-result-synthetic",
                KIND_TOOL_RESULT,
                Some("corr-b-synthetic"),
            ),
            session("evt-a-synthetic", KIND_TOOL_CALL, Some("corr-a-synthetic")),
            session(
                "evt-a-result-synthetic",
                KIND_TOOL_RESULT,
                Some("corr-a-synthetic"),
            ),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(
            indexer.clean_corrs(),
            &["corr-a-synthetic".to_owned(), "corr-b-synthetic".to_owned()]
        );
        assert_eq!(
            indexer.uses_keys(),
            &["corr-b-synthetic", "corr-a-synthetic"]
        );
        assert_eq!(indexer.source_path(), "<canonical>");
    }

    #[test]
    fn two_calls_are_not_clean() {
        let events = [
            session("evt-a-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-b-synthetic", KIND_TOOL_USE, Some("corr-synth")),
            session("evt-r-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert!(indexer.clean_corrs().is_empty());
        assert_eq!(indexer.uses("corr-synth").len(), 2);
        assert_eq!(indexer.results("corr-synth").len(), 1);
    }

    #[test]
    fn null_correlation_is_absent() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, None),
            mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("id", field_str("evt-result-synthetic")),
                ("correlation_id", EventField::Null),
            ]),
            mapping(&[("kind", field_str(KIND_TOOL_USE))]),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert!(indexer.uses_keys().is_empty());
        assert!(indexer.results_keys().is_empty());
        assert!(indexer.clean_corrs().is_empty());
    }

    #[test]
    fn compaction_boundary_index_is_recorded() {
        let events = [
            session("evt-a-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-msg-synthetic", "message", None),
            mapping(&[
                ("kind", field_str(KIND_COMPACTION)),
                ("id", field_str("evt-comp-synthetic")),
            ]),
            session("evt-r-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(indexer.compaction_indices(), &[2]);
        assert_eq!(
            indexer.event_kinds(),
            &[
                KIND_TOOL_CALL.to_owned(),
                "message".to_owned(),
                KIND_COMPACTION.to_owned(),
                KIND_TOOL_RESULT.to_owned()
            ]
        );
    }

    #[test]
    fn kind_none_is_unknown() {
        let events = [
            mapping(&[]),
            EventValue::Other,
            mapping(&[("kind", EventField::Null)]),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(
            indexer.event_kinds(),
            &[
                "unknown".to_owned(),
                "unknown".to_owned(),
                "unknown".to_owned()
            ]
        );
    }

    #[test]
    fn component_unions_parent_in_id_set() {
        let events = [
            session("evt-parent-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session_with_parent(
                "evt-child-synthetic",
                Some("evt-parent-synthetic"),
                KIND_TOOL_RESULT,
                Some("corr-synth"),
            ),
        ];
        let mut indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        let child = indexer.component(Some("evt-child-synthetic")).unwrap();
        let parent = indexer.component(Some("evt-parent-synthetic")).unwrap();
        assert_eq!(child, parent);
        assert_eq!(child, "evt-child-synthetic");
    }

    #[test]
    fn component_missing_parent_does_not_union() {
        let events = [session_with_parent(
            "evt-child-synthetic",
            Some("evt-missing-synthetic"),
            KIND_TOOL_CALL,
            Some("corr-synth"),
        )];
        let mut indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(
            indexer.component(Some("evt-child-synthetic")).unwrap(),
            "evt-child-synthetic"
        );
    }

    #[test]
    fn component_whitespace_is_unknown() {
        let events = [session(
            "evt-parent-synthetic",
            KIND_TOOL_CALL,
            Some("corr-synth"),
        )];
        let mut indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(indexer.component(None).unwrap(), "<unknown>");
        assert_eq!(indexer.component(Some("")).unwrap(), "<unknown>");
        assert_eq!(indexer.component(Some("  ")).unwrap(), "<unknown>");
        assert_eq!(indexer.component(Some("\t")).unwrap(), "<unknown>");
        assert_eq!(
            indexer.component(Some("evt-parent-synthetic")).unwrap(),
            "evt-parent-synthetic"
        );
    }

    #[test]
    fn bool_line_is_omitted_and_noncanonical_path_wins() {
        let ev = mapping(&[
            ("kind", field_str(KIND_TOOL_CALL)),
            ("source_line", EventField::Bool(true)),
            ("source_location", field_str("a\\b")),
        ]);
        let (path, line) = resolve_source_coords(&ev, "<canonical>").unwrap();
        assert_eq!(path, "a/b");
        assert_eq!(line, None);
        let int_line = mapping(&[("source_line", EventField::Int(4))]);
        assert_eq!(
            resolve_source_coords(&int_line, "<canonical>").unwrap().1,
            Some(4)
        );
        let zero = mapping(&[("source_line", EventField::Int(0))]);
        assert_eq!(resolve_source_coords(&zero, "<canonical>").unwrap().1, None);
        let skipped = resolve_source_coords(
            &mapping(&[("source_location", EventField::Float(1.5))]),
            "kept\\path",
        )
        .unwrap();
        assert_eq!(skipped.0, "kept/path");
    }

    #[test]
    fn location_string_forms_and_typed_errors() {
        let true_loc = mapping(&[("source_location", EventField::Bool(true))]);
        assert_eq!(
            resolve_source_coords(&true_loc, "<canonical>").unwrap().0,
            "True"
        );
        let false_loc = mapping(&[("source_location", EventField::Bool(false))]);
        assert_eq!(
            resolve_source_coords(&false_loc, "<canonical>").unwrap().0,
            "<canonical>"
        );
        let int_zero = mapping(&[("source_location", EventField::Int(0))]);
        assert_eq!(
            resolve_source_coords(&int_zero, "<canonical>").unwrap().0,
            "<canonical>"
        );
        let empty = mapping(&[("source_location", field_str(""))]);
        assert_eq!(
            resolve_source_coords(&empty, "<canonical>").unwrap().0,
            "<canonical>"
        );
        let float_zero = mapping(&[("source_location", EventField::Float(0.0))]);
        assert_eq!(
            resolve_source_coords(&float_zero, "<canonical>").unwrap().0,
            "<canonical>"
        );
        let float_err = resolve_source_coords(
            &mapping(&[("source_location", EventField::Float(1.5))]),
            "<canonical>",
        )
        .unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(float_err, ToolPairing2Error::PythonFloatStr));
        let empty_list = mapping(&[("source_location", EventField::List(Vec::new()))]);
        assert_eq!(
            resolve_source_coords(&empty_list, "<canonical>").unwrap().0,
            "<canonical>"
        );
        let list_err = resolve_source_coords(
            &mapping(&[("source_location", EventField::List(vec![field_str("a")]))]),
            "<canonical>",
        )
        .unwrap_err();
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        let empty_map = mapping(&[(
            "source_location",
            EventField::Mapping(EventMapping::new(Vec::new())),
        )]);
        assert_eq!(
            resolve_source_coords(&empty_map, "<canonical>").unwrap().0,
            "<canonical>"
        );
        let map_err = resolve_source_coords(
            &mapping(&[(
                "source_location",
                EventField::Mapping(EventMapping::new(vec![("a".to_owned(), field_str("b"))])),
            )]),
            "<canonical>",
        )
        .unwrap_err();
        assert_eq!(map_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
    }

    #[test]
    fn empty_string_correlation_is_kept_as_a_key() {
        let events = [
            session("evt-a-synthetic", KIND_TOOL_CALL, Some("")),
            mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("id", field_str("evt-b-synthetic")),
                ("correlation_id", field_str("")),
            ]),
            session("evt-c-synthetic", KIND_TOOL_USE, Some("  ")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(indexer.uses_keys(), &["", "  "]);
        assert_eq!(indexer.results_keys(), &[""]);
        assert_eq!(indexer.clean_corrs(), &["".to_owned()]);
    }

    #[test]
    fn bool_and_int_kinds_and_corr_keys_use_python_str() {
        let events = [
            mapping(&[
                ("kind", EventField::Bool(true)),
                ("id", field_str("evt-true-synthetic")),
            ]),
            mapping(&[
                ("kind", EventField::Int(7)),
                ("correlation_id", EventField::Bool(false)),
            ]),
            mapping(&[
                ("kind", field_str(KIND_TOOL_CALL)),
                ("id", field_str("evt-call-synthetic")),
                ("correlation_id", EventField::Int(-3)),
            ]),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(indexer.event_kinds(), &["True", "7", KIND_TOOL_CALL]);
        assert_eq!(indexer.uses_keys(), &["-3"]);
    }

    #[test]
    fn float_kind_and_container_corr_are_typed_errors() {
        let kind_err =
            ToolPairing2Indexer::new(&[mapping(&[("kind", EventField::Float(1.5))])], None)
                .unwrap_err();
        assert_eq!(kind_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(kind_err, ToolPairing2Error::PythonFloatStr));
        let corr_err = ToolPairing2Indexer::new(
            &[mapping(&[
                ("kind", field_str(KIND_TOOL_CALL)),
                ("correlation_id", EventField::List(vec![field_str("a")])),
            ])],
            None,
        )
        .unwrap_err();
        assert_eq!(corr_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert!(matches!(corr_err, ToolPairing2Error::PythonStr));
    }
}
