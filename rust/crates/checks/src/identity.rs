//! Vendor-neutral SL003 identity helpers: fingerprint, field-name diff, cap,
//! and duplicate grouping.
//!
//! Port of `src/sesslint/checks/identity.py` through the pin `__all__`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`compute_identity_fingerprint`] hashes locally. It is not a finding
//! digest and does not call [`make_finding`].
//!
//! [`diff_field_names`] with fewer than two events returns an empty list
//! and does not call [`to_canonical_dict`]. Two or more events call
//! [`SessionEvent::to_canonical_dict`], which returns
//! [`CanonicalUnavailable`] and does not build a dict. That typed error is
//! propagated. This slice does not walk event fields and does not invent
//! differing names.
//!
//! Identity sort key is `(code, record id, fingerprint)`. This module does
//! not call [`crate::graph::cap_finding_sort_key`]. That key also has an
//! overflow flag; this one does not.
//!
//! Under the cap, [`cap_findings`] returns the sorted list and does not
//! call [`make_finding`]. Over the cap, [`make_finding`] is called with the
//! fingerprint omitted and returns [`FINGERPRINT_CODEC_UNAVAILABLE`]. That
//! error is propagated. This module does not append a synthetic overflow
//! finding and does not return the kept prefix as if that finding existed.
//!
//! [`identity_overflow`] describes overflow evidence without hashing.
//!
//! [`identity_groups`] groups duplicate ids without hashing. Indexes stay
//! in walk order. Evidence indexes are truncated to
//! [`MAX_RECORD_INDEXES_IN_EVIDENCE`]. Emit order is sorted id text.
//! [`check_identities`] does not use [`model::events::event_id`].
//!
//! A [`SessionEvent`] duplicate calls [`SessionEvent::to_canonical_dict`]
//! and returns that error for the first duplicate id in sorted order. A
//! mapping duplicate returns
//! [`model::canonical::CANONICAL_JSON_BYTES_UNAVAILABLE`] without building
//! a dict and without hashing. This slice does not call [`make_finding`]
//! on a duplicate and does not invent identical-duplicate or
//! conflicting-duplicate. No duplicate group returns an empty list;
//! [`cap_findings`] on that empty list does not call [`make_finding`].
//!
//! # Recorded gaps
//!
//! * Python `int` is unbounded. Counts that do not fit in `i64` are
//!   [`PYTHON_INT_UNBOUNDED`], not a wrap and not a panic.
//! * [`EvidenceLookup::Borrowed`] is a failed borrow, not a missing `id`
//!   key ([`BORROWED_LOOKUP`]).
//! * [`EvidenceLookup::NotAMap`] is [`EVIDENCE_NOT_A_MAP`]. Python would
//!   call `.get` on a non-mapping. [`Finding::try_new`] only stores a
//!   mapping or `None`, so this is not reachable from a constructed
//!   finding.
//! * [`to_canonical_dict`] does not build a dict
//!   ([`model::canonical::NORMALIZE_CANONICAL_UNAVAILABLE`]). Differing
//!   field names are not invented.
//! * Overflow [`make_finding`] does not produce a digest
//!   ([`FINGERPRINT_CODEC_UNAVAILABLE`]).
//! * A float id is [`model::events::PYTHON_FLOAT_STR_UNREPRESENTABLE`].
//!   Rust `Display` is not used.
//! * A list or mapping id is [`model::events::PYTHON_STR_UNREPRESENTABLE`].
//!   A Python repr is not invented.
//! * Duplicate [`SessionEvent`] members call
//!   [`SessionEvent::to_canonical_dict`]
//!   ([`model::canonical::NORMALIZE_CANONICAL_UNAVAILABLE`]). Later ids are
//!   not classified.
//! * Duplicate mappings do not drop provenance fields or `seq` into a
//!   dict ([`model::canonical::CANONICAL_JSON_BYTES_UNAVAILABLE`]).
//! * `content_identity_hash` and `canonical_bytes` are not hashed.
//! * `enforce_content_free_text` runs after the hash in Python, so it is
//!   not reached. A credential-shaped duplicate still returns the
//!   canonical error first.
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt;

use model::canonical::{canonical_bytes, to_canonical_json, CanonicalUnavailable, SessionEvent};
use model::codes::{Repairability, Severity, SL003};
use model::errors::FindingError;
use model::events::{
    EventField, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE, PYTHON_STR_UNREPRESENTABLE,
};
use model::finding::{
    make_finding, EvidenceLookup, Finding, MakeFindingInput, PyValue, SourceRef,
    FINGERPRINT_CODEC_UNAVAILABLE,
};
use sha2::{Digest, Sha256};

use crate::context::CheckContext;

/// Python: `MAX_IDENTITY_FINDINGS`.
pub const MAX_IDENTITY_FINDINGS: i64 = 1000;

/// Python: `MAX_RECORD_INDEXES_IN_EVIDENCE`.
pub const MAX_RECORD_INDEXES_IN_EVIDENCE: i64 = 32;

/// Python: `_MSG_IDENTICAL`.
pub const MSG_IDENTICAL: &str =
    "Duplicate event ID detected with identical content for record {record_id}";

/// Python: `_MSG_CONFLICTING`.
pub const MSG_CONFLICTING: &str =
    "Duplicate event ID detected with conflicting content for record {record_id}";

/// Python: `_MSG_OVERFLOW`.
pub const MSG_OVERFLOW: &str =
    "Identity check finding cap reached; remaining duplicate IDs truncated";

/// Python evidence `variant` for the overflow summary.
pub const VARIANT_OVERFLOW: &str = "overflow-summary";

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
pub enum IdentityError {
    BorrowedLookup,
    EvidenceNotAMap,
    PythonIntUnbounded,
    PythonFloatStr,
    PythonStr,
    Canonical(CanonicalUnavailable),
    Finding(FindingError),
}

impl IdentityError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::EvidenceNotAMap => EVIDENCE_NOT_A_MAP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
            Self::PythonFloatStr => PYTHON_FLOAT_STR_UNREPRESENTABLE,
            Self::PythonStr => PYTHON_STR_UNREPRESENTABLE,
            Self::Canonical(error) => error.message(),
            Self::Finding(error) => error.message(),
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for IdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Finding(error) => Some(error),
            Self::BorrowedLookup
            | Self::EvidenceNotAMap
            | Self::PythonIntUnbounded
            | Self::PythonFloatStr
            | Self::PythonStr => None,
        }
    }
}

impl From<FindingError> for IdentityError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

impl From<CanonicalUnavailable> for IdentityError {
    fn from(error: CanonicalUnavailable) -> Self {
        Self::Canonical(error)
    }
}

/// Overflow-summary evidence. Does not call [`make_finding`].
///
/// `overflow` is true. `variant` is [`VARIANT_OVERFLOW`]. Code is [`SL003`],
/// severity is Warning, repairability is Manual, message is [`MSG_OVERFLOW`].
/// Line and `record_id` are `None`. Source path has backslash replaced with
/// slash. Omitted path is `"<canonical>"`. Omitted context is
/// [`CheckContext::default`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityOverflow {
    pub cap: i64,
    pub overflow: bool,
    pub total_duplicate_ids: i64,
    pub truncated_count: i64,
    pub variant: &'static str,
    pub code: &'static str,
    pub severity: Severity,
    pub repairability: Repairability,
    pub message: &'static str,
    pub source_path: String,
    pub line: Option<i64>,
    pub record_id: Option<String>,
    pub adapter_id: String,
    pub adapter_version: String,
    pub profile_id: String,
    pub profile_version: String,
}

/// Python: `compute_identity_fingerprint`.
///
/// `sha256("SL003|{id}|{comma-join of sorted hashes}")` then the first 16
/// lowercase hex characters. Sort is lexicographic and keeps duplicates. An
/// empty hash list leaves the text ending in a pipe. This does not call
/// [`make_finding`].
pub fn compute_identity_fingerprint(
    id: &str,
    payload_hashes: impl IntoIterator<Item = impl AsRef<str>>,
) -> String {
    let mut sorted_hashes: Vec<String> = payload_hashes
        .into_iter()
        .map(|hash| hash.as_ref().to_owned())
        .collect();
    sorted_hashes.sort();
    let mut content = String::from("SL003|");
    content.push_str(id);
    content.push('|');
    let mut first = true;
    for hash in &sorted_hashes {
        if !first {
            content.push(',');
        }
        first = false;
        content.push_str(hash);
    }
    hex16(Sha256::digest(content.as_bytes()))
}

/// Python: `diff_field_names`.
pub fn diff_field_names(events: &[SessionEvent]) -> Result<Vec<String>, IdentityError> {
    if events.len() < 2 {
        return Ok(Vec::new());
    }
    for event in events {
        event.to_canonical_dict()?;
    }
    Ok(Vec::new())
}

/// Overflow evidence without hashing. Counts that do not fit the Python
/// subtraction are [`PYTHON_INT_UNBOUNDED`].
pub fn identity_overflow(
    cap: i64,
    total_duplicate_ids: i64,
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<IdentityOverflow, IdentityError> {
    let truncated_count = total_duplicate_ids
        .checked_sub(cap)
        .ok_or(IdentityError::PythonIntUnbounded)?;
    let ctx = context.cloned().unwrap_or_default();
    let source_path = source_path.unwrap_or("<canonical>").replace('\\', "/");
    Ok(IdentityOverflow {
        cap,
        overflow: true,
        total_duplicate_ids,
        truncated_count,
        variant: VARIANT_OVERFLOW,
        code: SL003,
        severity: Severity::Warning,
        repairability: Repairability::Manual,
        message: MSG_OVERFLOW,
        source_path,
        line: None,
        record_id: None,
        adapter_id: ctx.adapter_id().to_owned(),
        adapter_version: ctx.adapter_version().to_owned(),
        profile_id: ctx.profile_id().to_owned(),
        profile_version: ctx.profile_version().to_owned(),
    })
}

/// Python: `cap_findings`.
///
/// Omitted `max_findings` is [`MAX_IDENTITY_FINDINGS`]. Omitted `source_path`
/// is `"<canonical>"`. Omitted `context` is [`CheckContext::default`].
/// Comparison is the Python `<=`. A negative max is not special-cased: an
/// empty list with `max_findings == -1` takes the overflow path because
/// `0 <= -1` is false.
pub fn cap_findings(
    findings: Vec<Finding>,
    max_findings: Option<i64>,
    source_path: Option<&str>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, IdentityError> {
    let max_findings = max_findings.unwrap_or(MAX_IDENTITY_FINDINGS);

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

    let overflow = identity_overflow(max_findings, total_count, source_path, context)?;
    let source = SourceRef::try_new(&overflow.source_path, None, overflow.record_id.as_deref())?;
    match make_finding(&MakeFindingInput {
        code: PyValue::string(overflow.code),
        severity: PyValue::severity(overflow.severity),
        repairability: PyValue::repairability(overflow.repairability),
        message_template: PyValue::string(overflow.message),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence: PyValue::map(vec![
            (PyValue::string("cap"), PyValue::int(overflow.cap)),
            (
                PyValue::string("overflow"),
                PyValue::bool_value(overflow.overflow),
            ),
            (
                PyValue::string("total_duplicate_ids"),
                PyValue::int(overflow.total_duplicate_ids),
            ),
            (
                PyValue::string("truncated_count"),
                PyValue::int(overflow.truncated_count),
            ),
            (
                PyValue::string("variant"),
                PyValue::string(overflow.variant),
            ),
        ]),
        fingerprint: PyValue::None,
        adapter_id: Some(overflow.adapter_id),
        adapter_version: Some(overflow.adapter_version),
        profile_id: Some(overflow.profile_id),
        profile_version: Some(overflow.profile_version),
        ordinal: None,
        context: None,
    }) {
        Err(error) => Err(error.into()),
        Ok(_finding) => Err(IdentityError::Finding(FindingError::new(
            FINGERPRINT_CODEC_UNAVAILABLE,
        ))),
    }
}

/// Duplicate-id group without hashing. No payload content.
///
/// `indexes` is the walk-order prefix truncated to
/// [`MAX_RECORD_INDEXES_IN_EVIDENCE`]. `truncated` is true when the raw
/// count is larger. `coerced` is true when any member's id was a non-string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityGroup {
    pub id: String,
    pub indexes: Vec<i64>,
    pub first_index: i64,
    pub coerced: bool,
    pub truncated: bool,
}

struct ResolvedId {
    id: String,
    coerced: bool,
}

/// Duplicate groups in sorted id order. Does not hash.
pub fn identity_groups(events: &[EventValue]) -> Result<Vec<IdentityGroup>, IdentityError> {
    let mut occurrences: BTreeMap<String, Vec<i64>> = BTreeMap::new();
    let mut coerced_ids: HashSet<String> = HashSet::new();

    for (idx_usize, event) in events.iter().enumerate() {
        let idx = usize_to_i64(idx_usize)?;
        let Some(resolved) = resolved_event_id(event)? else {
            continue;
        };
        if resolved.coerced {
            coerced_ids.insert(resolved.id.clone());
        }
        occurrences.entry(resolved.id).or_default().push(idx);
    }

    let cap = usize::try_from(MAX_RECORD_INDEXES_IN_EVIDENCE)
        .map_err(|_| IdentityError::PythonIntUnbounded)?;
    let mut groups = Vec::new();
    for (id, indexes) in occurrences {
        if indexes.len() < 2 {
            continue;
        }
        let Some(&first_index) = indexes.first() else {
            continue;
        };
        let truncated = indexes.len() > cap;
        let coerced = coerced_ids.contains(&id);
        groups.push(IdentityGroup {
            id,
            indexes: indexes.into_iter().take(cap).collect(),
            first_index,
            coerced,
            truncated,
        });
    }
    Ok(groups)
}

/// Python: `check_identities`.
///
/// Omitted `source_path` is `"<canonical>"`. Omitted `max_findings` is
/// [`MAX_IDENTITY_FINDINGS`]. Omitted `context` is
/// [`CheckContext::default`]. Classification needs canonical JSON and does
/// not hash. A duplicate returns the first typed codec error in sorted id
/// order and does not call [`make_finding`].
pub fn check_identities(
    events: &[EventValue],
    source_path: Option<&str>,
    max_findings: Option<i64>,
    context: Option<&CheckContext>,
) -> Result<Vec<Finding>, IdentityError> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let groups = identity_groups(events)?;
    for group in &groups {
        classify_duplicate_group(events, group)?;
    }
    cap_findings(Vec::new(), max_findings, source_path, context)
}

fn classify_duplicate_group(
    events: &[EventValue],
    group: &IdentityGroup,
) -> Result<(), IdentityError> {
    for index in &group.indexes {
        let idx = usize::try_from(*index).map_err(|_| IdentityError::PythonIntUnbounded)?;
        let Some(event) = events.get(idx) else {
            continue;
        };
        classify_duplicate_event(event)?;
    }
    Ok(())
}

fn classify_duplicate_event(event: &EventValue) -> Result<(), IdentityError> {
    match event {
        EventValue::Session(session) => match session.to_canonical_dict() {
            Err(error) => Err(error.into()),
            Ok(()) => match to_canonical_json(session) {
                Err(error) => Err(error.into()),
                Ok(_json) => Err(CanonicalUnavailable::canonical_json_bytes().into()),
            },
        },
        EventValue::Mapping(_) => Err(CanonicalUnavailable::canonical_json_bytes().into()),
        EventValue::Other => match canonical_bytes(event) {
            Err(error) => Err(error.into()),
            Ok(_bytes) => Err(CanonicalUnavailable::canonical_json_bytes().into()),
        },
    }
}

fn resolved_event_id(event: &EventValue) -> Result<Option<ResolvedId>, IdentityError> {
    match event {
        EventValue::Session(session) => Ok(string_id(&session.id, false)),
        EventValue::Mapping(mapping) => match mapping.get("id") {
            None | Some(EventField::Null) => Ok(None),
            Some(EventField::Str(text)) => Ok(string_id(text, false)),
            Some(EventField::Bool(true)) => Ok(string_id("True", true)),
            Some(EventField::Bool(false)) => Ok(string_id("False", true)),
            Some(EventField::Int(number)) => Ok(string_id(&number.to_string(), true)),
            Some(EventField::Float(_)) => Err(IdentityError::PythonFloatStr),
            Some(EventField::List(_) | EventField::Mapping(_)) => Err(IdentityError::PythonStr),
        },
        EventValue::Other => Ok(None),
    }
}

fn string_id(id: &str, coerced: bool) -> Option<ResolvedId> {
    if id.trim().is_empty() {
        None
    } else {
        Some(ResolvedId {
            id: id.to_owned(),
            coerced,
        })
    }
}

/// Python `__all__`, in that order.
pub const ALL: [&str; 6] = [
    "MAX_IDENTITY_FINDINGS",
    "MAX_RECORD_INDEXES_IN_EVIDENCE",
    "cap_findings",
    "check_identities",
    "compute_identity_fingerprint",
    "diff_field_names",
];

/// Python: `_cap_finding_sort_key`.
///
/// `(code, record id, fingerprint)`. Record id is `source.record_id`, or
/// `""` when it is missing. An empty string is falsy, so then read evidence
/// key `id` through [`Evidence::map_string`](model::finding::Evidence::map_string).
fn cap_finding_sort_key(finding: &Finding) -> Result<(String, String, String), IdentityError> {
    let rec_id = record_id_for_sort(finding)?;
    Ok((
        finding.code().to_owned(),
        rec_id,
        finding.fingerprint().to_owned(),
    ))
}

fn record_id_for_sort(finding: &Finding) -> Result<String, IdentityError> {
    if let Some(id) = finding.source().record_id() {
        if !id.is_empty() {
            return Ok(id.to_owned());
        }
    }
    let Some(evidence) = finding.evidence() else {
        return Ok(String::new());
    };
    match evidence.map_string("id") {
        EvidenceLookup::Borrowed => Err(IdentityError::BorrowedLookup),
        EvidenceLookup::NotAMap => Err(IdentityError::EvidenceNotAMap),
        EvidenceLookup::Absent => Ok(String::new()),
        EvidenceLookup::Present(value) => Ok(value.as_str().unwrap_or("").to_owned()),
    }
}

fn usize_to_i64(value: usize) -> Result<i64, IdentityError> {
    i64::try_from(value).map_err(|_| IdentityError::PythonIntUnbounded)
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
        cap_findings, check_identities, compute_identity_fingerprint, diff_field_names,
        identity_groups, identity_overflow, IdentityError, ALL, MAX_IDENTITY_FINDINGS,
        MAX_RECORD_INDEXES_IN_EVIDENCE, MSG_CONFLICTING, MSG_IDENTICAL, MSG_OVERFLOW,
        VARIANT_OVERFLOW,
    };
    use crate::context::CheckContext;
    use model::canonical::{
        SessionEvent, CANONICAL_JSON_BYTES_UNAVAILABLE, NORMALIZE_CANONICAL_UNAVAILABLE,
    };
    use model::codes::{Repairability, Severity, SL003};
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
        evidence_id: Option<PyValue>,
    ) -> Finding {
        let source = SourceRef::try_new("<canonical>", None, record_id).unwrap();
        let evidence = match evidence_id {
            Some(id) => PyValue::map(vec![(PyValue::string("id"), id)]),
            None => PyValue::None,
        };
        Finding::try_new(FindingInput {
            code: PyValue::string(code),
            severity: PyValue::severity(Severity::Warning),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic identity marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string(fingerprint),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence,
        })
        .unwrap()
    }

    fn session(id: &str) -> SessionEvent {
        SessionEvent::new(id, None, 0, "2024-02-29T00:00:00Z", "assistant", "message")
    }

    fn session_value(id: &str) -> EventValue {
        EventValue::from_session(session(id))
    }

    fn mapping_id(id: EventField) -> EventValue {
        EventValue::Mapping(EventMapping::new(vec![("id".to_owned(), id)]))
    }

    #[test]
    fn fingerprint_examples_and_sort_keeps_order_independence() {
        assert_eq!(
            compute_identity_fingerprint("evt", ["b", "a"]),
            "74556ae4dabbb1fa"
        );
        assert_eq!(
            compute_identity_fingerprint("evt", ["a", "b"]),
            "74556ae4dabbb1fa"
        );
        assert_eq!(
            compute_identity_fingerprint("evt", ["b", "a"]),
            compute_identity_fingerprint("evt", ["a", "b"])
        );
        assert_eq!(
            compute_identity_fingerprint("evt", None::<&str>),
            "d4fa9909a0dcc505"
        );
        assert!(is_lower_hex16(&compute_identity_fingerprint(
            "evt",
            ["b", "a"]
        )));
        assert_ne!(
            compute_identity_fingerprint("evt", ["a", "a"]),
            compute_identity_fingerprint("evt", ["a"])
        );
    }

    #[test]
    fn diff_of_zero_or_one_event_is_empty() {
        assert_eq!(diff_field_names(&[]).unwrap(), Vec::<String>::new());
        assert_eq!(
            diff_field_names(&[session("evt-a-synthetic")]).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn diff_of_two_events_is_canonical_unavailable() {
        let err = diff_field_names(&[session("evt-a-synthetic"), session("evt-b-synthetic")])
            .unwrap_err();
        assert_eq!(err.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert_eq!(err.message(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert!(matches!(err, IdentityError::Canonical(_)));
        assert!(!matches!(err, IdentityError::Finding(_)));
    }

    #[test]
    fn cap_of_empty_list_at_default_max_returns_empty() {
        let out = cap_findings(Vec::new(), None, None, None).unwrap();
        assert!(out.is_empty());
        assert_eq!(MAX_IDENTITY_FINDINGS, 1000);
        assert_eq!(MAX_RECORD_INDEXES_IN_EVIDENCE, 32);
        assert_eq!(
            MSG_IDENTICAL,
            "Duplicate event ID detected with identical content for record {record_id}"
        );
        assert_eq!(
            MSG_CONFLICTING,
            "Duplicate event ID detected with conflicting content for record {record_id}"
        );
        assert_eq!(
            MSG_OVERFLOW,
            "Identity check finding cap reached; remaining duplicate IDs truncated"
        );
    }

    #[test]
    fn two_findings_under_the_max_sort_by_code_record_id_fingerprint() {
        let first = finding(SL003, Some("evt-b-synthetic"), "bbbbbbbbbbbbbbbb", None);
        let second = finding(SL003, Some("evt-a-synthetic"), "aaaaaaaaaaaaaaaa", None);
        let out = cap_findings(
            vec![first, second],
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
    fn one_finding_over_a_max_of_zero_returns_the_codec_error() {
        let item = finding(SL003, Some("evt-a-synthetic"), "aaaaaaaaaaaaaaaa", None);
        let err = cap_findings(vec![item], Some(0), None, None).unwrap_err();
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
        assert!(matches!(err, IdentityError::Finding(_)));
    }

    #[test]
    fn empty_record_id_falls_through_to_a_string_evidence_id() {
        let missing = finding(
            SL003,
            None,
            "aaaaaaaaaaaaaaaa",
            Some(PyValue::string("evt-z-synthetic")),
        );
        let present = finding(SL003, Some("evt-a-synthetic"), "bbbbbbbbbbbbbbbb", None);
        let out = cap_findings(vec![missing, present], None, None, None).unwrap();
        assert_eq!(out[0].source().record_id(), Some("evt-a-synthetic"));
        assert_eq!(out[1].source().record_id(), None);
        assert_eq!(
            out[1]
                .evidence()
                .and_then(|evidence| match evidence.map_string("id") {
                    model::finding::EvidenceLookup::Present(value) => {
                        value.as_str().map(str::to_owned)
                    }
                    _ => None,
                })
                .as_deref(),
            Some("evt-z-synthetic")
        );
    }

    #[test]
    fn overflow_helper_describes_evidence_without_hashing() {
        let overflow = identity_overflow(-1, 0, Some("a\\b"), None).unwrap();
        assert_eq!(overflow.cap, -1);
        assert!(overflow.overflow);
        assert_eq!(overflow.total_duplicate_ids, 0);
        assert_eq!(overflow.truncated_count, 1);
        assert_eq!(overflow.variant, VARIANT_OVERFLOW);
        assert_eq!(overflow.code, SL003);
        assert_eq!(overflow.severity, Severity::Warning);
        assert_eq!(overflow.repairability, Repairability::Manual);
        assert_eq!(overflow.message, MSG_OVERFLOW);
        assert_eq!(overflow.source_path, "a/b");
        assert_eq!(overflow.line, None);
        assert_eq!(overflow.record_id, None);
        let err = cap_findings(Vec::new(), Some(-1), None, None).unwrap_err();
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn all_is_the_pin_order() {
        assert_eq!(
            ALL,
            [
                "MAX_IDENTITY_FINDINGS",
                "MAX_RECORD_INDEXES_IN_EVIDENCE",
                "cap_findings",
                "check_identities",
                "compute_identity_fingerprint",
                "diff_field_names",
            ]
        );
    }

    #[test]
    fn empty_input_is_silent() {
        let out = check_identities(&[], None, None, None).unwrap();
        assert!(out.is_empty());
        assert!(identity_groups(&[]).unwrap().is_empty());
    }

    #[test]
    fn two_different_string_ids_are_silent() {
        let events = [
            session_value("evt-a-synthetic"),
            session_value("evt-b-synthetic"),
        ];
        let out = check_identities(&events, None, None, None).unwrap();
        assert!(out.is_empty());
        assert!(identity_groups(&events).unwrap().is_empty());
    }

    #[test]
    fn empty_and_whitespace_ids_are_ignored() {
        let events = [
            session_value(""),
            session_value("   "),
            session_value("\t"),
            mapping_id(EventField::Str(String::new())),
            mapping_id(EventField::Str(" \n ".to_owned())),
            mapping_id(EventField::Null),
            EventValue::Mapping(EventMapping::new(Vec::new())),
            EventValue::Other,
            session_value("evt-only-synthetic"),
        ];
        let out = check_identities(&events, None, None, None).unwrap();
        assert!(out.is_empty());
        assert!(identity_groups(&events).unwrap().is_empty());
    }

    #[test]
    fn spaced_string_and_trimmed_string_are_different() {
        let events = [session_value(" a "), session_value("a")];
        let out = check_identities(&events, None, None, None).unwrap();
        assert!(out.is_empty());
        assert!(identity_groups(&events).unwrap().is_empty());
    }

    #[test]
    fn two_session_events_with_the_same_id_are_canonical_unavailable() {
        let events = [
            session_value("evt-dup-synthetic"),
            session_value("evt-dup-synthetic"),
        ];
        let err = check_identities(&events, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert_eq!(err.message(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert!(matches!(err, IdentityError::Canonical(_)));
        assert!(!matches!(err, IdentityError::Finding(_)));
        assert!(!is_lower_hex16(&err.to_string()));
        assert!(!err.to_string().contains("identical"));
        assert!(!err.to_string().contains("conflicting"));
    }

    #[test]
    fn two_mappings_with_the_same_string_id_are_json_bytes_unavailable() {
        let events = [
            mapping_id(EventField::Str("evt-map-synthetic".to_owned())),
            mapping_id(EventField::Str("evt-map-synthetic".to_owned())),
        ];
        let err = check_identities(&events, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), CANONICAL_JSON_BYTES_UNAVAILABLE);
        assert_eq!(err.message(), CANONICAL_JSON_BYTES_UNAVAILABLE);
        assert!(matches!(err, IdentityError::Canonical(_)));
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn bool_true_id_is_silent_once_and_json_bytes_error_when_duplicated() {
        let one = [mapping_id(EventField::Bool(true))];
        assert!(check_identities(&one, None, None, None).unwrap().is_empty());
        assert!(identity_groups(&one).unwrap().is_empty());

        let two = [
            mapping_id(EventField::Bool(true)),
            mapping_id(EventField::Bool(true)),
        ];
        let groups = identity_groups(&two).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, "True");
        assert_eq!(groups[0].indexes, vec![0, 1]);
        assert_eq!(groups[0].first_index, 0);
        assert!(groups[0].coerced);
        assert!(!groups[0].truncated);
        let err = check_identities(&two, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), CANONICAL_JSON_BYTES_UNAVAILABLE);
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn float_id_and_list_id_are_typed_errors() {
        let float_err =
            check_identities(&[mapping_id(EventField::Float(1.0))], None, None, None).unwrap_err();
        assert_eq!(float_err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert_eq!(float_err.message(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(float_err, IdentityError::PythonFloatStr));
        assert!(!is_lower_hex16(&float_err.to_string()));

        let list_err = check_identities(
            &[mapping_id(EventField::List(Vec::new()))],
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(list_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert_eq!(list_err.message(), PYTHON_STR_UNREPRESENTABLE);
        assert!(matches!(list_err, IdentityError::PythonStr));
        assert!(!is_lower_hex16(&list_err.to_string()));

        let mapping_err = check_identities(
            &[mapping_id(EventField::Mapping(EventMapping::new(
                Vec::new(),
            )))],
            None,
            None,
            None,
        )
        .unwrap_err();
        assert_eq!(mapping_err.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert!(matches!(mapping_err, IdentityError::PythonStr));
    }

    #[test]
    fn duplicate_ids_return_the_canonical_error_of_a_first() {
        let events = [
            session_value("b"),
            session_value("a"),
            session_value("b"),
            session_value("a"),
        ];
        let groups = identity_groups(&events).unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].id, "a");
        assert_eq!(groups[0].indexes, vec![1, 3]);
        assert_eq!(groups[0].first_index, 1);
        assert_eq!(groups[1].id, "b");
        assert_eq!(groups[1].indexes, vec![0, 2]);
        let err = check_identities(&events, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
        assert!(!matches!(err, IdentityError::Finding(_)));
        assert!(!is_lower_hex16(&err.to_string()));
    }

    #[test]
    fn negative_int_id_is_coerced_decimal_text() {
        let one = [mapping_id(EventField::Int(-7))];
        assert!(check_identities(&one, None, None, None).unwrap().is_empty());
        let two = [
            mapping_id(EventField::Int(-7)),
            mapping_id(EventField::Int(-7)),
        ];
        let groups = identity_groups(&two).unwrap();
        assert_eq!(groups[0].id, "-7");
        assert!(groups[0].coerced);
        let err = check_identities(&two, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), CANONICAL_JSON_BYTES_UNAVAILABLE);
    }

    #[test]
    fn evidence_indexes_truncate_at_the_cap() {
        let events: Vec<EventValue> = (0..33)
            .map(|_| session_value("evt-cap-synthetic"))
            .collect();
        let groups = identity_groups(&events).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].indexes.len(), 32);
        assert_eq!(groups[0].indexes[0], 0);
        assert_eq!(groups[0].indexes[31], 31);
        assert_eq!(groups[0].first_index, 0);
        assert!(groups[0].truncated);
        let err = check_identities(&events, None, None, None).unwrap_err();
        assert_eq!(err.to_string(), NORMALIZE_CANONICAL_UNAVAILABLE);
    }
}
