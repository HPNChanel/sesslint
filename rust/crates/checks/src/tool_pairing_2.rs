//! Generic tool-pairing integrity checks part 2 (SL105, SL106, SL107, SL108).
//!
//! Port of `src/sesslint/checks/tool_pairing_2.py`
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
//! This module ports placement helpers, [`ToolPairing2Indexer`],
//! [`extract_scope`], [`record_reversed_order`], [`check_reversed_order`],
//! [`record_cross_branch`], [`check_cross_branch`], [`record_adjacency`],
//! [`check_adjacency`], [`record_compaction_split`],
//! [`check_compaction_split`], [`check_tool_pairing_2`], the four aliases,
//! [`ALL`], and [`resolve_rule_severity`]. It does not import
//! `sesslint.profiles`. [`resolve_rule_severity`] does not invent
//! `rule_severities`. A string profile on adjacency or compaction with
//! omitted severity returns [`PROFILES_UNAVAILABLE`] before the walk and
//! does not call [`cap_pairing_findings`]. Python's missing-module except
//! is not followed.
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
//! * Offender [`make_finding`] does not produce a digest
//!   ([`FINGERPRINT_CODEC_UNAVAILABLE`]).
//! * [`resolve_rule_severity`] on a string or other profile returns
//!   [`PROFILES_UNAVAILABLE`]. It does not catch a missing module and
//!   does not return the default. `rule_severities` is not invented.
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
use model::codes::{Repairability, Severity, SL105, SL106, SL107, SL108};
use model::errors::FindingError;
use model::events::{
    EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
    PYTHON_STR_UNREPRESENTABLE,
};
use model::finding::{
    enforce_content_free_text, make_finding, EvidenceLookup, Finding, MakeFindingInput, PyValue,
    SourceLine, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE,
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

/// Late import. This crate does not depend on `sesslint.profiles`.
pub const PROFILES_UNAVAILABLE: &str = "sesslint.profiles is not available";

const REDACTED_ID: &str = "<redacted>";
const UNKNOWN_COMPONENT: &str = "<unknown>";

/// Failure from this slice. [`Display`] is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolPairing2Error {
    BorrowedLookup,
    EvidenceNotAMap,
    PythonIntUnbounded,
    PythonFloatStr,
    PythonStr,
    ProfilesUnavailable,
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
            Self::ProfilesUnavailable => PROFILES_UNAVAILABLE,
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
            | Self::PythonStr
            | Self::ProfilesUnavailable => None,
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

/// Python: `_resolve_rule_severity` `profile` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSeverityProfile<'a> {
    /// Python `None`.
    None,
    /// A Python `str` profile name.
    Name(&'a str),
    /// Any other Python value. `rule_severities` is not invented.
    Other,
}

/// One reversed-order pair that would emit SL105. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReversedOrderRecord {
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub related_ids: Vec<String>,
    pub correlation_id: String,
    pub result_index: i64,
    pub use_index: i64,
}

/// One cross-branch pair that would emit SL106. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossBranchRecord {
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub related_ids: Vec<String>,
    pub correlation_id: String,
    pub result_id: String,
    pub result_index: i64,
    pub use_id: String,
    pub use_index: i64,
    pub scope_mismatch: bool,
    pub call_agent_id: Option<String>,
    pub result_agent_id: Option<String>,
    pub call_branch_id: Option<String>,
    pub result_branch_id: Option<String>,
    pub call_interaction_id: Option<String>,
    pub result_interaction_id: Option<String>,
}

/// Python: `_extract_scope` return `(agent, branch, interaction)`.
pub type ExtractedScope = (Option<String>, Option<String>, Option<String>);

/// Python: `_extract_scope`.
///
/// A [`SessionEvent`] uses `agent_id`, `branch_id`, and `interaction_id`
/// only. It does not read camelCase. `None` and whitespace-only strings
/// become `None`. A mapping reads `agent_id`, then if that value is missing
/// or Python-falsy it reads `agentId`. Same for branch and interaction.
/// A whitespace string is truthy for `or`, then strip makes it `None`.
/// Bool `true` is `"True"`. A non-zero int is decimal. A float, list, or
/// mapping is a typed error, not a Python repr.
pub fn extract_scope(event: &EventValue) -> Result<ExtractedScope, ToolPairing2Error> {
    match event {
        EventValue::Session(session) => Ok((
            stripped_optional(session.agent_id.as_deref()),
            stripped_optional(session.branch_id.as_deref()),
            stripped_optional(session.interaction_id.as_deref()),
        )),
        EventValue::Mapping(mapping) => Ok((
            scope_from_mapping(mapping, "agent_id", "agentId")?,
            scope_from_mapping(mapping, "branch_id", "branchId")?,
            scope_from_mapping(mapping, "interaction_id", "interactionId")?,
        )),
        EventValue::Other => Ok((None, None, None)),
    }
}

/// Python: `check_reversed_order` record walk. Does not call [`make_finding`].
///
/// Only clean pairs. Walks [`ToolPairing2Indexer::clean_corrs`] in stored
/// sorted order. Fires only when the result index is strictly less than the
/// call index. Equal indexes are silent. A dirty pair is silent.
pub fn record_reversed_order(
    indexer: &ToolPairing2Indexer<'_>,
    source_path: &str,
) -> Result<Vec<ReversedOrderRecord>, ToolPairing2Error> {
    let mut records = Vec::new();
    for corr in indexer.clean_corrs() {
        let Some(&(use_idx, use_ev)) = indexer.uses(corr).first() else {
            continue;
        };
        let Some(&(res_idx, res_ev)) = indexer.results(corr).first() else {
            continue;
        };
        if res_idx < use_idx {
            let use_id_str = optional_event_id(use_ev)?;
            let safe_corr = safe_id(Some(corr));
            let rec_id = source_record_id(use_id_str.as_deref());
            let (path, line) = resolve_source_coords(res_ev, source_path)?;
            records.push(ReversedOrderRecord {
                path,
                line,
                record_id: rec_id,
                related_ids: related_ids(&safe_corr),
                correlation_id: safe_corr,
                result_index: usize_to_i64(res_idx)?,
                use_index: usize_to_i64(use_idx)?,
            });
        }
    }
    Ok(records)
}

/// Python: `check_reversed_order`.
///
/// Context `None` is [`CheckContext::default`]. An optional indexer is used
/// when supplied; otherwise one is built from `events`. A non-empty record
/// list calls [`make_finding`] with the fingerprint omitted; the first
/// record returns [`FINGERPRINT_CODEC_UNAVAILABLE`]. An empty list still
/// calls [`cap_pairing_findings`]. Default max 500 returns `Ok([])`.
/// `max_findings == -1` takes the overflow path because `0 <= -1` is false.
pub fn check_reversed_order(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    context: Option<&CheckContext>,
    indexer: Option<&ToolPairing2Indexer<'_>>,
) -> Result<Vec<Finding>, ToolPairing2Error> {
    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };
    let owned_indexer;
    let indexer = match indexer {
        Some(value) => value,
        None => {
            owned_indexer = ToolPairing2Indexer::new(events, Some(source_path))?;
            &owned_indexer
        }
    };
    let records = record_reversed_order(indexer, source_path)?;
    let mut findings = Vec::new();
    for record in &records {
        findings.push(reversed_order_finding(record, ctx)?);
    }
    cap_pairing_findings(findings, SL105, max_findings, Some(source_path), Some(ctx))
}

/// Python: `check_cross_branch` record walk. Does not call [`make_finding`].
///
/// Only clean pairs. Always calls [`ToolPairing2Indexer::component`] on both
/// ids, even when scope is explicit. An explicit scope field on either side
/// triggers only on a scope mismatch. No scope field triggers only when both
/// components are not `"<unknown>"` and they differ.
pub fn record_cross_branch(
    indexer: &mut ToolPairing2Indexer<'_>,
    source_path: &str,
) -> Result<Vec<CrossBranchRecord>, ToolPairing2Error> {
    let mut records = Vec::new();
    for corr in indexer.clean_corrs().to_vec() {
        let Some(&(use_idx, use_ev)) = indexer.uses(&corr).first() else {
            continue;
        };
        let Some(&(res_idx, res_ev)) = indexer.results(&corr).first() else {
            continue;
        };
        let use_id_str = optional_event_id(use_ev)?;
        let res_id_str = optional_event_id(res_ev)?;
        let (use_agent, use_branch, use_inter) = extract_scope(use_ev)?;
        let (res_agent, res_branch, res_inter) = extract_scope(res_ev)?;
        let has_explicit_scope = use_agent.is_some()
            || use_branch.is_some()
            || use_inter.is_some()
            || res_agent.is_some()
            || res_branch.is_some()
            || res_inter.is_some();
        let mut scope_mismatch = false;
        let mut call_agent_id = None;
        let mut result_agent_id = None;
        let mut call_branch_id = None;
        let mut result_branch_id = None;
        let mut call_interaction_id = None;
        let mut result_interaction_id = None;
        let comp_use = indexer.component(use_id_str.as_deref())?;
        let comp_res = indexer.component(res_id_str.as_deref())?;
        let should_trigger = if has_explicit_scope {
            if use_agent != res_agent {
                scope_mismatch = true;
                if let Some(value) = &use_agent {
                    call_agent_id = Some(safe_id(Some(value)));
                }
                if let Some(value) = &res_agent {
                    result_agent_id = Some(safe_id(Some(value)));
                }
            }
            if use_branch != res_branch {
                scope_mismatch = true;
                if let Some(value) = &use_branch {
                    call_branch_id = Some(safe_id(Some(value)));
                }
                if let Some(value) = &res_branch {
                    result_branch_id = Some(safe_id(Some(value)));
                }
            }
            if use_inter != res_inter {
                scope_mismatch = true;
                if let Some(value) = &use_inter {
                    call_interaction_id = Some(safe_id(Some(value)));
                }
                if let Some(value) = &res_inter {
                    result_interaction_id = Some(safe_id(Some(value)));
                }
            }
            scope_mismatch
        } else {
            comp_use != comp_res && comp_use != UNKNOWN_COMPONENT && comp_res != UNKNOWN_COMPONENT
        };
        if should_trigger {
            let safe_corr = safe_id(Some(&corr));
            let safe_use_id = safe_id(use_id_str.as_deref());
            let safe_res_id = safe_id(res_id_str.as_deref());
            let rec_id = source_record_id(use_id_str.as_deref());
            let (path, line) = resolve_source_coords(res_ev, source_path)?;
            records.push(CrossBranchRecord {
                path,
                line,
                record_id: rec_id,
                related_ids: related_ids(&safe_res_id),
                correlation_id: safe_corr,
                result_id: safe_res_id,
                result_index: usize_to_i64(res_idx)?,
                use_id: safe_use_id,
                use_index: usize_to_i64(use_idx)?,
                scope_mismatch,
                call_agent_id,
                result_agent_id,
                call_branch_id,
                result_branch_id,
                call_interaction_id,
                result_interaction_id,
            });
        }
    }
    Ok(records)
}

/// Python: `check_cross_branch`.
///
/// Context `None` is [`CheckContext::default`]. An optional indexer is used
/// when supplied; otherwise one is built from `events`. A non-empty record
/// list calls [`make_finding`] with the fingerprint omitted; the first
/// record returns [`FINGERPRINT_CODEC_UNAVAILABLE`]. An empty list still
/// calls [`cap_pairing_findings`]. Default max 500 returns `Ok([])`.
/// `max_findings == -1` takes the overflow path because `0 <= -1` is false.
pub fn check_cross_branch(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    context: Option<&CheckContext>,
    indexer: Option<&mut ToolPairing2Indexer<'_>>,
) -> Result<Vec<Finding>, ToolPairing2Error> {
    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };
    let records = match indexer {
        Some(value) => record_cross_branch(value, source_path)?,
        None => {
            let mut owned_indexer = ToolPairing2Indexer::new(events, Some(source_path))?;
            record_cross_branch(&mut owned_indexer, source_path)?
        }
    };
    let mut findings = Vec::new();
    for record in &records {
        findings.push(cross_branch_finding(record, ctx)?);
    }
    cap_pairing_findings(findings, SL106, max_findings, Some(source_path), Some(ctx))
}

/// Python: `_resolve_rule_severity`.
///
/// `profile` [`RuleSeverityProfile::None`] returns `default_severity`. A
/// string or any other profile returns [`PROFILES_UNAVAILABLE`]. This does
/// not catch a missing module and does not invent `rule_severities`.
pub fn resolve_rule_severity(
    _code: &str,
    profile: RuleSeverityProfile<'_>,
    default_severity: Severity,
) -> Result<Severity, ToolPairing2Error> {
    match profile {
        RuleSeverityProfile::None => Ok(default_severity),
        RuleSeverityProfile::Name(_) | RuleSeverityProfile::Other => {
            Err(ToolPairing2Error::ProfilesUnavailable)
        }
    }
}

fn stripped_optional(text: Option<&str>) -> Option<String> {
    let text = text?;
    let stripped = text.trim();
    if stripped.is_empty() {
        None
    } else {
        Some(stripped.to_owned())
    }
}

fn is_python_falsy(field: &EventField) -> bool {
    match field {
        EventField::Null | EventField::Bool(false) | EventField::Int(0) => true,
        EventField::Str(text) if text.is_empty() => true,
        EventField::Float(number) if *number == 0.0 => true,
        EventField::List(items) if items.is_empty() => true,
        EventField::Mapping(mapping) if mapping.entries().is_empty() => true,
        _ => false,
    }
}

fn scope_from_mapping(
    mapping: &EventMapping,
    snake: &str,
    camel: &str,
) -> Result<Option<String>, ToolPairing2Error> {
    let chosen = match mapping.get(snake) {
        Some(field) if !is_python_falsy(field) => Some(field),
        _ => match mapping.get(camel) {
            None | Some(EventField::Null) => None,
            Some(field) => Some(field),
        },
    };
    match chosen {
        None => Ok(None),
        Some(field) => {
            let text = python_str(field)?;
            let stripped = text.trim();
            if stripped.is_empty() {
                Ok(None)
            } else {
                Ok(Some(stripped.to_owned()))
            }
        }
    }
}

fn optional_event_id(event: &EventValue) -> Result<Option<String>, ToolPairing2Error> {
    match event {
        EventValue::Session(session) => Ok(Some(session.id.clone())),
        EventValue::Mapping(mapping) => match mapping.get("id") {
            None | Some(EventField::Null) => Ok(None),
            Some(field) => Ok(Some(python_str(field)?)),
        },
        EventValue::Other => Ok(None),
    }
}

fn related_ids(safe_id: &str) -> Vec<String> {
    if safe_id == REDACTED_ID {
        Vec::new()
    } else {
        vec![safe_id.to_owned()]
    }
}

fn py_strings(items: &[String]) -> Vec<PyValue> {
    items
        .iter()
        .map(|item| PyValue::string(item.clone()))
        .collect()
}

fn pairing_source(
    path: &str,
    line: Option<i64>,
    record_id: Option<&str>,
) -> Result<SourceRef, ToolPairing2Error> {
    Ok(SourceRef::try_new(
        path,
        line.map(SourceLine::Int),
        record_id,
    )?)
}

fn context_fields(
    ctx: &CheckContext,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    (
        Some(ctx.adapter_id().to_owned()),
        Some(ctx.adapter_version().to_owned()),
        Some(ctx.profile_id().to_owned()),
        Some(ctx.profile_version().to_owned()),
    )
}

fn reversed_order_evidence(record: &ReversedOrderRecord) -> PyValue {
    PyValue::map(vec![
        (
            PyValue::string("correlation_id"),
            PyValue::string(record.correlation_id.clone()),
        ),
        (
            PyValue::string("result_index"),
            PyValue::int(record.result_index),
        ),
        (PyValue::string("use_index"), PyValue::int(record.use_index)),
    ])
}

fn push_scope_id(entries: &mut Vec<(PyValue, PyValue)>, key: &str, value: Option<&String>) {
    if let Some(text) = value {
        entries.push((PyValue::string(key), PyValue::string(text.clone())));
    }
}

fn cross_branch_evidence(record: &CrossBranchRecord) -> PyValue {
    let mut entries = vec![
        (
            PyValue::string("correlation_id"),
            PyValue::string(record.correlation_id.clone()),
        ),
        (
            PyValue::string("result_id"),
            PyValue::string(record.result_id.clone()),
        ),
        (
            PyValue::string("result_index"),
            PyValue::int(record.result_index),
        ),
        (
            PyValue::string("use_id"),
            PyValue::string(record.use_id.clone()),
        ),
        (PyValue::string("use_index"), PyValue::int(record.use_index)),
    ];
    if record.scope_mismatch {
        entries.push((PyValue::string("scope_mismatch"), PyValue::bool_value(true)));
        push_scope_id(&mut entries, "call_agent_id", record.call_agent_id.as_ref());
        push_scope_id(
            &mut entries,
            "result_agent_id",
            record.result_agent_id.as_ref(),
        );
        push_scope_id(
            &mut entries,
            "call_branch_id",
            record.call_branch_id.as_ref(),
        );
        push_scope_id(
            &mut entries,
            "result_branch_id",
            record.result_branch_id.as_ref(),
        );
        push_scope_id(
            &mut entries,
            "call_interaction_id",
            record.call_interaction_id.as_ref(),
        );
        push_scope_id(
            &mut entries,
            "result_interaction_id",
            record.result_interaction_id.as_ref(),
        );
    }
    PyValue::map(entries)
}

fn reversed_order_finding(
    record: &ReversedOrderRecord,
    ctx: &CheckContext,
) -> Result<Finding, ToolPairing2Error> {
    let source = pairing_source(&record.path, record.line, record.record_id.as_deref())?;
    let (adapter_id, adapter_version, profile_id, profile_version) = context_fields(ctx);
    Ok(make_finding(&MakeFindingInput {
        code: PyValue::string(SL105),
        severity: PyValue::severity(Severity::Error),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_SL105),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(py_strings(&record.related_ids)),
        evidence: reversed_order_evidence(record),
        fingerprint: PyValue::None,
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        ordinal: None,
        context: None,
    })?)
}

fn cross_branch_finding(
    record: &CrossBranchRecord,
    ctx: &CheckContext,
) -> Result<Finding, ToolPairing2Error> {
    let source = pairing_source(&record.path, record.line, record.record_id.as_deref())?;
    let (adapter_id, adapter_version, profile_id, profile_version) = context_fields(ctx);
    Ok(make_finding(&MakeFindingInput {
        code: PyValue::string(SL106),
        severity: PyValue::severity(Severity::Error),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_SL106),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(py_strings(&record.related_ids)),
        evidence: cross_branch_evidence(record),
        fingerprint: PyValue::None,
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        ordinal: None,
        context: None,
    })?)
}

/// One non-adjacent pair that would emit SL107. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdjacencyRecord {
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub related_ids: Vec<String>,
    pub correlation_id: String,
    pub intervening_count: i64,
    pub intervening_kinds: Vec<String>,
    pub result_index: i64,
    pub use_index: i64,
}

/// One compaction-split pair that would emit SL108. Does not call [`make_finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactionSplitRecord {
    pub path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub related_ids: Vec<String>,
    pub boundary_index: i64,
    pub correlation_id: String,
    pub result_index: i64,
    pub use_index: i64,
    pub repairability: Repairability,
}

/// Python: `check_adjacency` record walk. Does not call [`make_finding`].
///
/// Only clean pairs. Walks [`ToolPairing2Indexer::clean_corrs`] in stored
/// sorted order. Silent when `max(index) - min(index) <= 1`. Intervening
/// kinds are `event_kinds[min + 1 .. max]`. All-transparent gaps are
/// silent. `intervening_count` is the non-transparent count, not the full
/// gap length. `intervening_kinds` is the sorted unique non-transparent
/// set, then the first [`MAX_INTERVENING_KINDS_SAMPLE`].
pub fn record_adjacency(
    indexer: &ToolPairing2Indexer<'_>,
    source_path: &str,
) -> Result<Vec<AdjacencyRecord>, ToolPairing2Error> {
    let mut records = Vec::new();
    for corr in indexer.clean_corrs() {
        let Some(&(use_idx, use_ev)) = indexer.uses(corr).first() else {
            continue;
        };
        let Some(&(res_idx, _)) = indexer.results(corr).first() else {
            continue;
        };
        let min_idx = use_idx.min(res_idx);
        let max_idx = use_idx.max(res_idx);
        if max_idx - min_idx <= 1 {
            continue;
        }
        let intervening = &indexer.event_kinds()[min_idx + 1..max_idx];
        if intervening
            .iter()
            .all(|kind| is_adjacency_transparent_kind(kind))
        {
            continue;
        }
        let mut intervening_count: i64 = 0;
        let mut unique = HashSet::new();
        for kind in intervening {
            if is_adjacency_transparent_kind(kind) {
                continue;
            }
            intervening_count = intervening_count
                .checked_add(1)
                .ok_or(ToolPairing2Error::PythonIntUnbounded)?;
            unique.insert(kind.clone());
        }
        let mut intervening_kinds: Vec<String> = unique.into_iter().collect();
        intervening_kinds.sort();
        let sample_cap = usize::try_from(MAX_INTERVENING_KINDS_SAMPLE)
            .map_err(|_| ToolPairing2Error::PythonIntUnbounded)?;
        if intervening_kinds.len() > sample_cap {
            intervening_kinds.truncate(sample_cap);
        }
        let use_id_str = optional_event_id(use_ev)?;
        let safe_corr = safe_id(Some(corr));
        let rec_id = source_record_id(use_id_str.as_deref());
        let (path, line) = resolve_source_coords(use_ev, source_path)?;
        records.push(AdjacencyRecord {
            path,
            line,
            record_id: rec_id,
            related_ids: related_ids(&safe_corr),
            correlation_id: safe_corr,
            intervening_count,
            intervening_kinds,
            result_index: usize_to_i64(res_idx)?,
            use_index: usize_to_i64(use_idx)?,
        });
    }
    Ok(records)
}

/// Python: `check_adjacency`.
///
/// An explicit [`Severity`] is used and [`resolve_rule_severity`] is not
/// called, even when `profile` is a string. [`Severity`] `None` calls
/// [`resolve_rule_severity`] with [`SL107`] and default [`Severity::Warning`]
/// before the walk. A string profile then returns [`PROFILES_UNAVAILABLE`]
/// and does not call [`cap_pairing_findings`].
#[allow(clippy::too_many_arguments)]
pub fn check_adjacency(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    profile: RuleSeverityProfile<'_>,
    severity: Option<Severity>,
    context: Option<&CheckContext>,
    indexer: Option<&ToolPairing2Indexer<'_>>,
) -> Result<Vec<Finding>, ToolPairing2Error> {
    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };
    let owned_indexer;
    let indexer = match indexer {
        Some(value) => value,
        None => {
            owned_indexer = ToolPairing2Indexer::new(events, Some(source_path))?;
            &owned_indexer
        }
    };
    let target_severity =
        explicit_or_resolved_severity(SL107, profile, severity, Severity::Warning)?;
    let records = record_adjacency(indexer, source_path)?;
    let mut findings = Vec::new();
    for record in &records {
        findings.push(adjacency_finding(record, ctx, target_severity)?);
    }
    cap_pairing_findings(findings, SL107, max_findings, Some(source_path), Some(ctx))
}

/// Python: `check_compaction_split` record walk. Does not call [`make_finding`].
///
/// Only clean pairs. A boundary counts only when its stored index is
/// strictly between min and max. Walks compaction indices in stored
/// encounter order. The first match is `boundary_index`. One boundary is
/// [`Repairability::Deterministic`]. Two or more is
/// [`Repairability::LossyExplicit`].
pub fn record_compaction_split(
    indexer: &ToolPairing2Indexer<'_>,
    source_path: &str,
) -> Result<Vec<CompactionSplitRecord>, ToolPairing2Error> {
    let mut records = Vec::new();
    for corr in indexer.clean_corrs() {
        let Some(&(use_idx, use_ev)) = indexer.uses(corr).first() else {
            continue;
        };
        let Some(&(res_idx, _)) = indexer.results(corr).first() else {
            continue;
        };
        let min_idx = use_idx.min(res_idx);
        let max_idx = use_idx.max(res_idx);
        let mut first_boundary = None;
        let mut split_count: i64 = 0;
        for &k in indexer.compaction_indices() {
            if min_idx < k && k < max_idx {
                if first_boundary.is_none() {
                    first_boundary = Some(k);
                }
                split_count = split_count
                    .checked_add(1)
                    .ok_or(ToolPairing2Error::PythonIntUnbounded)?;
            }
        }
        let Some(first_boundary_idx) = first_boundary else {
            continue;
        };
        let repairability = if split_count == 1 {
            Repairability::Deterministic
        } else {
            Repairability::LossyExplicit
        };
        let use_id_str = optional_event_id(use_ev)?;
        let safe_corr = safe_id(Some(corr));
        let rec_id = source_record_id(use_id_str.as_deref());
        let (path, line) = resolve_source_coords(use_ev, source_path)?;
        records.push(CompactionSplitRecord {
            path,
            line,
            record_id: rec_id,
            related_ids: related_ids(&safe_corr),
            boundary_index: usize_to_i64(first_boundary_idx)?,
            correlation_id: safe_corr,
            result_index: usize_to_i64(res_idx)?,
            use_index: usize_to_i64(use_idx)?,
            repairability,
        });
    }
    Ok(records)
}

/// Python: `check_compaction_split`.
///
/// An explicit [`Severity`] is used and [`resolve_rule_severity`] is not
/// called, even when `profile` is a string. [`Severity`] `None` calls
/// [`resolve_rule_severity`] with [`SL108`] and default [`Severity::Warning`]
/// before the walk. A string profile then returns [`PROFILES_UNAVAILABLE`]
/// and does not call [`cap_pairing_findings`].
#[allow(clippy::too_many_arguments)]
pub fn check_compaction_split(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    profile: RuleSeverityProfile<'_>,
    severity: Option<Severity>,
    context: Option<&CheckContext>,
    indexer: Option<&ToolPairing2Indexer<'_>>,
) -> Result<Vec<Finding>, ToolPairing2Error> {
    let source_path = source_path.unwrap_or("<canonical>");
    let owned_ctx;
    let ctx = match context {
        Some(value) => value,
        None => {
            owned_ctx = CheckContext::default();
            &owned_ctx
        }
    };
    let owned_indexer;
    let indexer = match indexer {
        Some(value) => value,
        None => {
            owned_indexer = ToolPairing2Indexer::new(events, Some(source_path))?;
            &owned_indexer
        }
    };
    let target_severity =
        explicit_or_resolved_severity(SL108, profile, severity, Severity::Warning)?;
    let records = record_compaction_split(indexer, source_path)?;
    let mut findings = Vec::new();
    for record in &records {
        findings.push(compaction_split_finding(record, ctx, target_severity)?);
    }
    cap_pairing_findings(findings, SL108, max_findings, Some(source_path), Some(ctx))
}

/// Python: `check_tool_pairing_2`.
///
/// Builds one [`ToolPairing2Indexer`] and passes that same indexer to
/// reversed, cross-branch, adjacency, and compaction, in that order.
/// Cross-branch may mutate components; later checks see that indexer.
/// `profile` is passed only to adjacency and compaction. No severity
/// override is passed. The first family error returns immediately.
/// Successful lists are concatenated and sorted with
/// [`cap_finding_sort_key`]. This does not call [`cap_pairing_findings`]
/// or [`make_finding`].
pub fn check_tool_pairing_2(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings_per_family: Option<i64>,
    profile: RuleSeverityProfile<'_>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, ToolPairing2Error> {
    let source_path = source_path.unwrap_or("<canonical>");
    let mut indexer = ToolPairing2Indexer::new(events, Some(source_path))?;
    let mut all_findings = Vec::new();
    all_findings.extend(check_reversed_order(
        events,
        Some(source_path),
        max_findings_per_family,
        context,
        Some(&indexer),
    )?);
    all_findings.extend(check_cross_branch(
        events,
        Some(source_path),
        max_findings_per_family,
        context,
        Some(&mut indexer),
    )?);
    all_findings.extend(check_adjacency(
        events,
        Some(source_path),
        max_findings_per_family,
        profile,
        None,
        context,
        Some(&indexer),
    )?);
    all_findings.extend(check_compaction_split(
        events,
        Some(source_path),
        max_findings_per_family,
        profile,
        None,
        context,
        Some(&indexer),
    )?);
    let mut keyed = Vec::new();
    for finding in all_findings {
        let key = cap_finding_sort_key(&finding)?;
        keyed.push((key, finding));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(keyed.into_iter().map(|(_, finding)| finding).collect())
}

/// Python: `check_sl107 = check_adjacency`.
pub use check_adjacency as check_sl107;
/// Python: `check_sl108 = check_compaction_split`.
pub use check_compaction_split as check_sl108;
/// Python: `check_sl106 = check_cross_branch`.
pub use check_cross_branch as check_sl106;
/// Python: `check_sl105 = check_reversed_order`.
pub use check_reversed_order as check_sl105;

/// Python `__all__`, in that order. [`ADJACENCY_TRANSPARENT_KINDS`] is not in `ALL`.
pub const ALL: [&str; 18] = [
    "CALL_KINDS",
    "COMPACTION_KINDS",
    "MAX_INDEX_SAMPLE_SIZE",
    "MAX_INTERVENING_KINDS_SAMPLE",
    "MAX_PAIRING_FINDINGS",
    "RESULT_KINDS",
    "TOOL_KINDS",
    "cap_pairing_findings",
    "check_adjacency",
    "check_compaction_split",
    "check_cross_branch",
    "check_reversed_order",
    "check_sl105",
    "check_sl106",
    "check_sl107",
    "check_sl108",
    "check_tool_pairing_2",
    "compute_pairing_fingerprint",
];

fn is_adjacency_transparent_kind(kind: &str) -> bool {
    ADJACENCY_TRANSPARENT_KINDS.contains(&kind)
}

fn explicit_or_resolved_severity(
    code: &str,
    profile: RuleSeverityProfile<'_>,
    severity: Option<Severity>,
    default_severity: Severity,
) -> Result<Severity, ToolPairing2Error> {
    match severity {
        Some(value) => Ok(value),
        None => resolve_rule_severity(code, profile, default_severity),
    }
}

fn adjacency_evidence(record: &AdjacencyRecord) -> PyValue {
    PyValue::map(vec![
        (
            PyValue::string("correlation_id"),
            PyValue::string(record.correlation_id.clone()),
        ),
        (
            PyValue::string("intervening_count"),
            PyValue::int(record.intervening_count),
        ),
        (
            PyValue::string("intervening_kinds"),
            PyValue::list(py_strings(&record.intervening_kinds)),
        ),
        (
            PyValue::string("result_index"),
            PyValue::int(record.result_index),
        ),
        (PyValue::string("use_index"), PyValue::int(record.use_index)),
    ])
}

fn compaction_split_evidence(record: &CompactionSplitRecord) -> PyValue {
    PyValue::map(vec![
        (
            PyValue::string("boundary_index"),
            PyValue::int(record.boundary_index),
        ),
        (
            PyValue::string("correlation_id"),
            PyValue::string(record.correlation_id.clone()),
        ),
        (
            PyValue::string("result_index"),
            PyValue::int(record.result_index),
        ),
        (PyValue::string("use_index"), PyValue::int(record.use_index)),
    ])
}

fn adjacency_finding(
    record: &AdjacencyRecord,
    ctx: &CheckContext,
    severity: Severity,
) -> Result<Finding, ToolPairing2Error> {
    let source = pairing_source(&record.path, record.line, record.record_id.as_deref())?;
    let (adapter_id, adapter_version, profile_id, profile_version) = context_fields(ctx);
    Ok(make_finding(&MakeFindingInput {
        code: PyValue::string(SL107),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(Repairability::Manual),
        message_template: PyValue::string(MSG_SL107),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(py_strings(&record.related_ids)),
        evidence: adjacency_evidence(record),
        fingerprint: PyValue::None,
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        ordinal: None,
        context: None,
    })?)
}

fn compaction_split_finding(
    record: &CompactionSplitRecord,
    ctx: &CheckContext,
    severity: Severity,
) -> Result<Finding, ToolPairing2Error> {
    let source = pairing_source(&record.path, record.line, record.record_id.as_deref())?;
    let (adapter_id, adapter_version, profile_id, profile_version) = context_fields(ctx);
    Ok(make_finding(&MakeFindingInput {
        code: PyValue::string(SL108),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(record.repairability),
        message_template: PyValue::string(MSG_SL108),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(py_strings(&record.related_ids)),
        evidence: compaction_split_evidence(record),
        fingerprint: PyValue::None,
        adapter_id,
        adapter_version,
        profile_id,
        profile_version,
        ordinal: None,
        context: None,
    })?)
}

#[cfg(test)]
mod tests {
    use super::{
        cap_finding_sort_key, cap_pairing_findings, check_adjacency, check_compaction_split,
        check_cross_branch, check_reversed_order, check_sl105, check_sl106, check_sl107,
        check_sl108, check_tool_pairing_2, compute_pairing_fingerprint, extract_scope,
        record_adjacency, record_compaction_split, record_cross_branch, record_reversed_order,
        resolve_rule_severity, resolve_source_coords, safe_id, source_record_id, DisjointSet,
        RuleSeverityProfile, ToolPairing2Error, ToolPairing2Indexer, ADJACENCY_TRANSPARENT_KINDS,
        ALL, CALL_KINDS, COMPACTION_KINDS, KIND_COMPACTION, KIND_TOOL_CALL, KIND_TOOL_RESULT,
        KIND_TOOL_USE, MAX_INDEX_SAMPLE_SIZE, MAX_INTERVENING_KINDS_SAMPLE, MAX_PAIRING_FINDINGS,
        MSG_OVERFLOW, MSG_SL105, MSG_SL106, MSG_SL107, MSG_SL108, PROFILES_UNAVAILABLE,
        RESULT_KINDS, TOOL_KINDS,
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

    fn session_named_parent(
        id: &str,
        parent: Option<&str>,
        kind: &str,
        corr: Option<&str>,
        agent: Option<&str>,
        branch: Option<&str>,
        interaction: Option<&str>,
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
        event.agent_id = agent.map(str::to_owned);
        event.branch_id = branch.map(str::to_owned);
        event.interaction_id = interaction.map(str::to_owned);
        EventValue::from_session(event)
    }

    #[test]
    fn extract_scope_session_strips_and_ignores_camel_case() {
        let none = session("evt-a-synthetic", KIND_TOOL_CALL, Some("corr-synth"));
        assert_eq!(extract_scope(&none).unwrap(), (None, None, None));
        let spaces = session_named_parent(
            "evt-a-synthetic",
            None,
            KIND_TOOL_CALL,
            Some("corr-synth"),
            Some("   "),
            Some("\t"),
            Some(""),
        );
        assert_eq!(extract_scope(&spaces).unwrap(), (None, None, None));
        let kept = session_named_parent(
            "evt-a-synthetic",
            None,
            KIND_TOOL_CALL,
            Some("corr-synth"),
            Some("  agent-a-synth  "),
            Some("branch-a-synth"),
            Some("inter-a-synth"),
        );
        assert_eq!(
            extract_scope(&kept).unwrap(),
            (
                Some("agent-a-synth".to_owned()),
                Some("branch-a-synth".to_owned()),
                Some("inter-a-synth".to_owned())
            )
        );
        assert_eq!(
            extract_scope(&EventValue::Other).unwrap(),
            (None, None, None)
        );
    }

    #[test]
    fn extract_scope_mapping_or_camel_case_and_typed_errors() {
        let camel = mapping(&[
            ("agentId", field_str("agent-camel-synth")),
            ("branchId", field_str("branch-camel-synth")),
            ("interactionId", field_str("inter-camel-synth")),
        ]);
        assert_eq!(
            extract_scope(&camel).unwrap(),
            (
                Some("agent-camel-synth".to_owned()),
                Some("branch-camel-synth".to_owned()),
                Some("inter-camel-synth".to_owned())
            )
        );
        let falsy_then_camel = mapping(&[
            ("agent_id", EventField::Int(0)),
            ("agentId", field_str("agent-fallback-synth")),
            ("branch_id", EventField::Bool(false)),
            ("branchId", field_str("branch-fallback-synth")),
            ("interaction_id", field_str("")),
            ("interactionId", field_str("inter-fallback-synth")),
        ]);
        assert_eq!(
            extract_scope(&falsy_then_camel).unwrap(),
            (
                Some("agent-fallback-synth".to_owned()),
                Some("branch-fallback-synth".to_owned()),
                Some("inter-fallback-synth".to_owned())
            )
        );
        let whitespace_truthy = mapping(&[
            ("agent_id", field_str("  ")),
            ("agentId", field_str("agent-skipped-synth")),
        ]);
        assert_eq!(
            extract_scope(&whitespace_truthy).unwrap(),
            (None, None, None)
        );
        let typed = mapping(&[
            ("agent_id", EventField::Bool(true)),
            ("branch_id", EventField::Int(7)),
        ]);
        assert_eq!(
            extract_scope(&typed).unwrap(),
            (Some("True".to_owned()), Some("7".to_owned()), None)
        );
        let float_err =
            extract_scope(&mapping(&[("agent_id", EventField::Float(1.5))])).unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(float_err, ToolPairing2Error::PythonFloatStr));
        let list_err = extract_scope(&mapping(&[(
            "agent_id",
            EventField::List(vec![field_str("a")]),
        )]))
        .unwrap_err();
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        let map_err = extract_scope(&mapping(&[(
            "agent_id",
            EventField::Mapping(EventMapping::new(vec![("a".to_owned(), field_str("b"))])),
        )]))
        .unwrap_err();
        assert_eq!(map_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        let second_false = mapping(&[
            ("agent_id", EventField::Int(0)),
            ("agentId", EventField::Bool(false)),
        ]);
        assert_eq!(
            extract_scope(&second_false).unwrap(),
            (Some("False".to_owned()), None, None)
        );
    }

    #[test]
    fn reversed_order_result_before_call_record_has_indexes_and_check_is_codec_error() {
        let events = [
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        let records = record_reversed_order(&indexer, "<canonical>").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].result_index, 0);
        assert_eq!(records[0].use_index, 1);
        assert_eq!(records[0].correlation_id, "corr-synth");
        assert_eq!(records[0].related_ids, vec!["corr-synth".to_owned()]);
        assert_eq!(records[0].record_id.as_deref(), Some("evt-call-synthetic"));
        assert_codec_unavailable(
            check_reversed_order(&events, None, None, None, None).unwrap_err(),
        );
        assert_codec_unavailable(
            check_reversed_order(&[], None, None, None, Some(&indexer)).unwrap_err(),
        );
    }

    #[test]
    fn reversed_order_equal_indexes_are_empty() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(indexer.uses("corr-synth")[0].0, 0);
        assert_eq!(indexer.results("corr-synth")[0].0, 1);
        assert!(record_reversed_order(&indexer, "<canonical>")
            .unwrap()
            .is_empty());
        assert!(check_reversed_order(&events, None, None, None, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reversed_order_two_calls_and_one_result_are_empty() {
        let events = [
            session("evt-a-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-b-synthetic", KIND_TOOL_USE, Some("corr-synth")),
            session("evt-r-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert!(indexer.clean_corrs().is_empty());
        assert!(record_reversed_order(&indexer, "<canonical>")
            .unwrap()
            .is_empty());
        assert!(check_reversed_order(&events, None, None, None, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reversed_order_empty_list_default_max_is_ok_negative_max_is_codec_error() {
        assert!(check_reversed_order(&[], None, None, None, None)
            .unwrap()
            .is_empty());
        assert_codec_unavailable(
            check_reversed_order(&[], None, Some(-1), None, None).unwrap_err(),
        );
        assert!(check_cross_branch(&[], None, None, None, None)
            .unwrap()
            .is_empty());
        assert_codec_unavailable(check_cross_branch(&[], None, Some(-1), None, None).unwrap_err());
    }

    #[test]
    fn reversed_order_missing_call_id_is_none_not_a_placeholder() {
        let events = [
            mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("id", field_str("evt-result-synthetic")),
                ("correlation_id", field_str("corr-synth")),
            ]),
            mapping(&[
                ("kind", field_str(KIND_TOOL_CALL)),
                ("correlation_id", field_str("corr-synth")),
            ]),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        let records = record_reversed_order(&indexer, "<canonical>").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id, None);
        assert_eq!(records[0].result_index, 0);
        assert_eq!(records[0].use_index, 1);
    }

    #[test]
    fn cross_branch_no_scope_different_components_is_codec_error() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let mut indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        let records = record_cross_branch(&mut indexer, "<canonical>").unwrap();
        assert_eq!(records.len(), 1);
        assert!(!records[0].scope_mismatch);
        assert_eq!(records[0].use_id, "evt-call-synthetic");
        assert_eq!(records[0].result_id, "evt-result-synthetic");
        assert_eq!(
            records[0].related_ids,
            vec!["evt-result-synthetic".to_owned()]
        );
        assert_codec_unavailable(check_cross_branch(&events, None, None, None, None).unwrap_err());
    }

    #[test]
    fn cross_branch_no_scope_same_component_is_empty() {
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
        assert!(record_cross_branch(&mut indexer, "<canonical>")
            .unwrap()
            .is_empty());
        assert!(check_cross_branch(&events, None, None, None, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn cross_branch_no_scope_one_missing_id_is_empty() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            mapping(&[
                ("kind", field_str(KIND_TOOL_RESULT)),
                ("correlation_id", field_str("corr-synth")),
            ]),
        ];
        let mut indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert!(record_cross_branch(&mut indexer, "<canonical>")
            .unwrap()
            .is_empty());
        assert!(check_cross_branch(&events, None, None, None, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn cross_branch_same_explicit_branch_different_components_is_empty() {
        let events = [
            session_named_parent(
                "evt-call-synthetic",
                None,
                KIND_TOOL_CALL,
                Some("corr-synth"),
                None,
                Some("branch-shared-synth"),
                None,
            ),
            session_named_parent(
                "evt-result-synthetic",
                None,
                KIND_TOOL_RESULT,
                Some("corr-synth"),
                None,
                Some("branch-shared-synth"),
                None,
            ),
        ];
        let mut indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        let call_comp = indexer.component(Some("evt-call-synthetic")).unwrap();
        let result_comp = indexer.component(Some("evt-result-synthetic")).unwrap();
        assert_ne!(call_comp, result_comp);
        assert!(record_cross_branch(&mut indexer, "<canonical>")
            .unwrap()
            .is_empty());
        assert!(check_cross_branch(&events, None, None, None, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn cross_branch_different_explicit_branch_has_scope_mismatch_and_codec_error() {
        let events = [
            session_named_parent(
                "evt-call-synthetic",
                None,
                KIND_TOOL_CALL,
                Some("corr-synth"),
                None,
                Some("branch-a-synth"),
                None,
            ),
            session_named_parent(
                "evt-result-synthetic",
                None,
                KIND_TOOL_RESULT,
                Some("corr-synth"),
                None,
                Some("branch-b-synth"),
                None,
            ),
        ];
        let mut indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        let records = record_cross_branch(&mut indexer, "<canonical>").unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].scope_mismatch);
        assert_eq!(records[0].call_branch_id.as_deref(), Some("branch-a-synth"));
        assert_eq!(
            records[0].result_branch_id.as_deref(),
            Some("branch-b-synth")
        );
        assert_eq!(records[0].call_agent_id, None);
        assert_eq!(records[0].result_agent_id, None);
        assert_codec_unavailable(check_cross_branch(&events, None, None, None, None).unwrap_err());
    }

    #[test]
    fn resolve_rule_severity_none_is_default_string_is_profiles_message() {
        let default =
            resolve_rule_severity(SL105, RuleSeverityProfile::None, Severity::Error).unwrap();
        assert_eq!(default, Severity::Error);
        let named = resolve_rule_severity(
            SL105,
            RuleSeverityProfile::Name("neutral"),
            Severity::Warning,
        )
        .unwrap_err();
        assert_eq!(named.to_string(), PROFILES_UNAVAILABLE);
        assert_eq!(named.message(), "sesslint.profiles is not available");
        assert!(matches!(named, ToolPairing2Error::ProfilesUnavailable));
        let other = resolve_rule_severity(SL105, RuleSeverityProfile::Other, Severity::Warning)
            .unwrap_err();
        assert_eq!(other.to_string(), PROFILES_UNAVAILABLE);
        assert!(matches!(other, ToolPairing2Error::ProfilesUnavailable));
    }

    fn same_item<T>(left: T, right: T) {
        let _ = (left, right);
    }

    #[test]
    fn adjacency_message_gap_record_and_codec_error() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-msg-synthetic", "message", None),
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        let records = record_adjacency(&indexer, "<canonical>").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].intervening_count, 1);
        assert_eq!(records[0].intervening_kinds, vec!["message".to_owned()]);
        assert_eq!(records[0].use_index, 0);
        assert_eq!(records[0].result_index, 2);
        assert_eq!(records[0].correlation_id, "corr-synth");
        assert_eq!(records[0].related_ids, vec!["corr-synth".to_owned()]);
        assert_eq!(records[0].record_id.as_deref(), Some("evt-call-synthetic"));
        assert_codec_unavailable(
            check_adjacency(
                &events,
                None,
                None,
                RuleSeverityProfile::None,
                None,
                None,
                None,
            )
            .unwrap_err(),
        );
    }

    #[test]
    fn adjacency_transparent_tool_call_is_empty() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session(
                "evt-other-synthetic",
                KIND_TOOL_CALL,
                Some("corr-other-synth"),
            ),
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert!(record_adjacency(&indexer, "<canonical>")
            .unwrap()
            .is_empty());
        assert!(check_adjacency(
            &events,
            None,
            None,
            RuleSeverityProfile::None,
            None,
            None,
            None,
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn adjacency_no_gap_is_empty() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(indexer.uses("corr-synth")[0].0, 0);
        assert_eq!(indexer.results("corr-synth")[0].0, 1);
        assert!(record_adjacency(&indexer, "<canonical>")
            .unwrap()
            .is_empty());
        assert!(check_adjacency(
            &events,
            None,
            None,
            RuleSeverityProfile::None,
            None,
            None,
            None,
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn adjacency_explicit_warning_with_string_profile_is_ok() {
        assert!(check_adjacency(
            &[],
            None,
            None,
            RuleSeverityProfile::Name("neutral"),
            Some(Severity::Warning),
            None,
            None,
        )
        .unwrap()
        .is_empty());
        assert!(check_compaction_split(
            &[],
            None,
            None,
            RuleSeverityProfile::Name("neutral"),
            Some(Severity::Warning),
            None,
            None,
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn adjacency_omitted_severity_string_profile_is_profiles_error() {
        let err = check_adjacency(
            &[],
            None,
            None,
            RuleSeverityProfile::Name("neutral"),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), PROFILES_UNAVAILABLE);
        assert_eq!(err.message(), "sesslint.profiles is not available");
        assert!(matches!(err, ToolPairing2Error::ProfilesUnavailable));
        let compact_err = check_compaction_split(
            &[],
            None,
            None,
            RuleSeverityProfile::Name("neutral"),
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(compact_err.message(), "sesslint.profiles is not available");
        assert!(matches!(
            compact_err,
            ToolPairing2Error::ProfilesUnavailable
        ));
    }

    #[test]
    fn adjacency_empty_default_max_is_ok_negative_max_is_codec_error() {
        assert!(
            check_adjacency(&[], None, None, RuleSeverityProfile::None, None, None, None,)
                .unwrap()
                .is_empty()
        );
        assert_codec_unavailable(
            check_adjacency(
                &[],
                None,
                Some(-1),
                RuleSeverityProfile::None,
                None,
                None,
                None,
            )
            .unwrap_err(),
        );
        assert!(check_compaction_split(
            &[],
            None,
            None,
            RuleSeverityProfile::None,
            None,
            None,
            None,
        )
        .unwrap()
        .is_empty());
        assert_codec_unavailable(
            check_compaction_split(
                &[],
                None,
                Some(-1),
                RuleSeverityProfile::None,
                None,
                None,
                None,
            )
            .unwrap_err(),
        );
        assert!(
            check_tool_pairing_2(&[], None, None, RuleSeverityProfile::None, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn compaction_one_boundary_is_deterministic_and_codec_error() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-bound-synthetic", KIND_COMPACTION, None),
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        let records = record_compaction_split(&indexer, "<canonical>").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].repairability, Repairability::Deterministic);
        assert_eq!(records[0].boundary_index, 1);
        assert_eq!(records[0].use_index, 0);
        assert_eq!(records[0].result_index, 2);
        assert_eq!(records[0].record_id.as_deref(), Some("evt-call-synthetic"));
        assert_codec_unavailable(
            check_compaction_split(
                &events,
                None,
                None,
                RuleSeverityProfile::None,
                None,
                None,
                None,
            )
            .unwrap_err(),
        );
    }

    #[test]
    fn compaction_two_boundaries_is_lossy_explicit_first_index() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-bound-a-synthetic", KIND_COMPACTION, None),
            session("evt-bound-b-synthetic", KIND_COMPACTION, None),
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(indexer.compaction_indices(), &[1, 2]);
        let records = record_compaction_split(&indexer, "<canonical>").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].repairability, Repairability::LossyExplicit);
        assert_eq!(records[0].boundary_index, 1);
    }

    #[test]
    fn compaction_boundary_on_call_index_is_silent() {
        let events = [
            session("evt-bound-synthetic", KIND_COMPACTION, None),
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
            session("evt-bound-after-synthetic", KIND_COMPACTION, None),
        ];
        let indexer = ToolPairing2Indexer::new(&events, None).unwrap();
        assert_eq!(indexer.uses("corr-synth")[0].0, 1);
        assert_eq!(indexer.compaction_indices(), &[0, 3]);
        assert!(record_compaction_split(&indexer, "<canonical>")
            .unwrap()
            .is_empty());
        assert!(check_compaction_split(
            &events,
            None,
            None,
            RuleSeverityProfile::None,
            None,
            None,
            None,
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn aggregator_clean_adjacent_same_component_is_empty() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session_with_parent(
                "evt-result-synthetic",
                Some("evt-call-synthetic"),
                KIND_TOOL_RESULT,
                Some("corr-synth"),
            ),
        ];
        assert!(
            check_tool_pairing_2(&events, None, None, RuleSeverityProfile::None, None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn aggregator_different_components_string_profile_is_codec_error() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session("evt-result-synthetic", KIND_TOOL_RESULT, Some("corr-synth")),
        ];
        let err = check_tool_pairing_2(
            &events,
            None,
            None,
            RuleSeverityProfile::Name("neutral"),
            None,
        )
        .unwrap_err();
        assert_codec_unavailable(err);
    }

    #[test]
    fn aggregator_message_gap_same_component_string_profile_is_profiles_error() {
        let events = [
            session("evt-call-synthetic", KIND_TOOL_CALL, Some("corr-synth")),
            session_with_parent(
                "evt-msg-synthetic",
                Some("evt-call-synthetic"),
                "message",
                None,
            ),
            session_with_parent(
                "evt-result-synthetic",
                Some("evt-call-synthetic"),
                KIND_TOOL_RESULT,
                Some("corr-synth"),
            ),
        ];
        let err = check_tool_pairing_2(
            &events,
            None,
            None,
            RuleSeverityProfile::Name("neutral"),
            None,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), PROFILES_UNAVAILABLE);
        assert_eq!(err.message(), "sesslint.profiles is not available");
        assert!(matches!(err, ToolPairing2Error::ProfilesUnavailable));
    }

    #[test]
    fn all_matches_the_python_list() {
        assert_eq!(
            ALL,
            [
                "CALL_KINDS",
                "COMPACTION_KINDS",
                "MAX_INDEX_SAMPLE_SIZE",
                "MAX_INTERVENING_KINDS_SAMPLE",
                "MAX_PAIRING_FINDINGS",
                "RESULT_KINDS",
                "TOOL_KINDS",
                "cap_pairing_findings",
                "check_adjacency",
                "check_compaction_split",
                "check_cross_branch",
                "check_reversed_order",
                "check_sl105",
                "check_sl106",
                "check_sl107",
                "check_sl108",
                "check_tool_pairing_2",
                "compute_pairing_fingerprint",
            ]
        );
        assert!(!ALL.contains(&"ADJACENCY_TRANSPARENT_KINDS"));
        same_item(check_sl105, check_reversed_order);
        same_item(check_sl106, check_cross_branch);
        same_item(check_sl107, check_adjacency);
        same_item(check_sl108, check_compaction_split);
    }
}
