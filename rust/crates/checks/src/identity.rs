//! Vendor-neutral SL003 identity helpers: fingerprint, field-name diff, and cap.
//!
//! Port of `src/sesslint/checks/identity.py` lines 1–136
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! This slice ends at the return of [`cap_findings`]. It does not include
//! `check_identities`. The pin `__all__` is after this slice and names that
//! function; this module does not invent `ALL`.
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

use std::error::Error;
use std::fmt;

use model::canonical::{CanonicalUnavailable, SessionEvent};
use model::codes::{Repairability, Severity, SL003};
use model::errors::FindingError;
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
    Canonical(CanonicalUnavailable),
    Finding(FindingError),
}

impl IdentityError {
    pub fn message(&self) -> &str {
        match self {
            Self::BorrowedLookup => BORROWED_LOOKUP,
            Self::EvidenceNotAMap => EVIDENCE_NOT_A_MAP,
            Self::PythonIntUnbounded => PYTHON_INT_UNBOUNDED,
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
            Self::BorrowedLookup | Self::EvidenceNotAMap | Self::PythonIntUnbounded => None,
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
        cap_findings, compute_identity_fingerprint, diff_field_names, identity_overflow,
        IdentityError, MAX_IDENTITY_FINDINGS, MAX_RECORD_INDEXES_IN_EVIDENCE, MSG_CONFLICTING,
        MSG_IDENTICAL, MSG_OVERFLOW, VARIANT_OVERFLOW,
    };
    use crate::context::CheckContext;
    use model::canonical::{SessionEvent, NORMALIZE_CANONICAL_UNAVAILABLE};
    use model::codes::{Repairability, Severity, SL003};
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
}
