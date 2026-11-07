//! Independent reference reconstruction for A4 assurance (T-14, AC-027).
//!
//! Port of `src/sesslint/reference.py` lines 1–117
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Empty input and inputs above [`MAX_REFERENCE_EVENTS`] are `Ok(false)`,
//! which keeps the 250k-record bench off this path (AC-023). A finding whose
//! severity is error, fatal, or warning is also `Ok(false)` and does not
//! reconstruct. The next call on any other input is
//! `sesslint.adapters.canonical.dump_canonical`. This crate does not depend on
//! adapters. That call is [`DumpCanonicalUnavailable`]. This module does not
//! call `dump_canonical` or `load_canonical`.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use crate::canonical::SessionEvent;
use crate::codes::Severity;
use crate::finding::Finding;

/// Python: `MAX_REFERENCE_EVENTS`.
pub const MAX_REFERENCE_EVENTS: usize = 50000;

/// Python: `_BLOCKING_SEVERITIES` (declaration order).
const BLOCKING_SEVERITIES: [Severity; 3] = [Severity::Error, Severity::Fatal, Severity::Warning];

const DUMP_CANONICAL_UNAVAILABLE: &str =
    "sesslint.adapters.canonical.dump_canonical is not available";

/// `sesslint.adapters.canonical.dump_canonical` is not available in this crate.
///
/// [`Display`](fmt::Display) is exactly
/// `sesslint.adapters.canonical.dump_canonical is not available`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DumpCanonicalUnavailable;

impl fmt::Display for DumpCanonicalUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(DUMP_CANONICAL_UNAVAILABLE)
    }
}

impl Error for DumpCanonicalUnavailable {}

/// One item of the Python `Sequence[Any]` read by [`_identity_multiset`].
///
/// [`Self::Other`] is any object that is not a [`SessionEvent`].
#[derive(Debug, Clone, Copy)]
pub enum ReferenceItem<'a> {
    /// A [`SessionEvent`].
    Event(&'a SessionEvent),
    /// A non-[`SessionEvent`].
    Other,
}

/// Python: `_identity_multiset`.
///
/// Returns the multiset of content-identity hashes. A non-[`SessionEvent`]
/// is `None`. [`SessionEvent::content_identity_hash`] is called as written;
/// `Err` is `None` and the counts collected so far are dropped.
#[must_use]
pub fn _identity_multiset(events: &[ReferenceItem<'_>]) -> Option<BTreeMap<String, usize>> {
    let mut identities = BTreeMap::new();
    for event in events {
        let ReferenceItem::Event(event) = event else {
            return None;
        };
        let hash = match event.content_identity_hash() {
            Ok(hash) => hash,
            Err(_error) => return None,
        };
        *identities.entry(hash).or_default() += 1;
    }
    Some(identities)
}

/// Python: `reference_equivalent`.
///
/// `None`, an empty sequence, and a sequence longer than [`MAX_REFERENCE_EVENTS`]
/// are `Ok(false)`. Any other sequence is [`DumpCanonicalUnavailable`]. Python
/// would call `dump_canonical` next and return `False` if that call raised.
/// This crate does not call it, does not call `load_canonical`, and does not
/// return `Ok(false)` or `Ok(true)` for that arm.
///
/// # Errors
///
/// Returns [`DumpCanonicalUnavailable`] when reconstruction would call
/// `sesslint.adapters.canonical.dump_canonical`. This function does not panic.
pub fn reference_equivalent<T>(events: Option<&[T]>) -> Result<bool, DumpCanonicalUnavailable> {
    let Some(events) = events else {
        return Ok(false);
    };
    if events.is_empty() {
        return Ok(false);
    }
    if events.len() > MAX_REFERENCE_EVENTS {
        return Ok(false);
    }
    Err(DumpCanonicalUnavailable)
}

/// Python: `reference_equivalent_if_clean`.
///
/// A finding whose severity is error, fatal, or warning is `Ok(false)` and
/// does not call [`reference_equivalent`]. Otherwise that result is returned
/// unchanged, including [`DumpCanonicalUnavailable`].
///
/// # Errors
///
/// Propagates [`DumpCanonicalUnavailable`] from [`reference_equivalent`].
/// A blocking finding does not become that error, and that error does not
/// become `Ok(false)`. This function does not panic.
pub fn reference_equivalent_if_clean<T>(
    events: Option<&[T]>,
    findings: &[Finding],
) -> Result<bool, DumpCanonicalUnavailable> {
    if findings
        .iter()
        .any(|finding| BLOCKING_SEVERITIES.contains(&finding.severity()))
    {
        return Ok(false);
    }
    reference_equivalent(events)
}

/// Python `__all__` (reference.py lines 113–117), declaration order.
pub const ALL: [&str; 3] = [
    "MAX_REFERENCE_EVENTS",
    "reference_equivalent",
    "reference_equivalent_if_clean",
];

#[cfg(test)]
mod tests {
    use super::{
        reference_equivalent, reference_equivalent_if_clean, DumpCanonicalUnavailable,
        ReferenceItem, ALL, MAX_REFERENCE_EVENTS,
    };
    use crate::canonical::SessionEvent;
    use crate::codes::{Repairability, Severity};
    use crate::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};
    use std::collections::BTreeMap;

    const DUMP_SEAM: &str = "sesslint.adapters.canonical.dump_canonical is not available";

    fn synthetic_event() -> SessionEvent {
        SessionEvent::new(
            "synthetic-event-1",
            None,
            1,
            "2020-01-01T00:00:00Z",
            "actor",
            "note",
        )
    }

    fn finding(severity: Severity) -> Finding {
        let source = SourceRef::try_new("a.jsonl", Some(SourceLine::Int(1)), None)
            .unwrap_or_else(|error| panic!("{error}"));
        Finding::try_new(FindingInput {
            code: PyValue::string("SL001"),
            severity: PyValue::severity(severity),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence: PyValue::None,
        })
        .unwrap_or_else(|error| panic!("{error}"))
    }

    fn assert_dump_seam(result: Result<bool, DumpCanonicalUnavailable>) {
        assert_ne!(result, Ok(false));
        assert_eq!(result, Err(DumpCanonicalUnavailable));
        assert_eq!(result.unwrap_err().to_string(), DUMP_SEAM);
    }

    #[test]
    fn constants_match_the_pin() {
        assert_eq!(MAX_REFERENCE_EVENTS, 50000);
        assert_eq!(
            ALL,
            [
                "MAX_REFERENCE_EVENTS",
                "reference_equivalent",
                "reference_equivalent_if_clean",
            ]
        );
    }

    #[test]
    fn empty_and_over_cap_are_false() {
        let none: Option<&[SessionEvent]> = None;
        assert_eq!(reference_equivalent(none), Ok(false));
        assert_eq!(reference_equivalent_if_clean(none, &[]), Ok(false));

        let empty: &[SessionEvent] = &[];
        assert_eq!(reference_equivalent(Some(empty)), Ok(false));
        assert_eq!(reference_equivalent_if_clean(Some(empty), &[]), Ok(false));

        let over = vec![(); MAX_REFERENCE_EVENTS + 1];
        assert_eq!(reference_equivalent(Some(over.as_slice())), Ok(false));
        let info = finding(Severity::Info);
        assert_eq!(
            reference_equivalent_if_clean(Some(over.as_slice()), &[info]),
            Ok(false)
        );
    }

    #[test]
    fn clean_finding_with_one_event_returns_the_dump_seam() {
        let events = [synthetic_event()];
        let clean = [finding(Severity::Info)];
        assert_dump_seam(reference_equivalent(Some(events.as_slice())));
        assert_dump_seam(reference_equivalent_if_clean(
            Some(events.as_slice()),
            &clean,
        ));
        let at_cap = vec![(); MAX_REFERENCE_EVENTS];
        assert_dump_seam(reference_equivalent(Some(at_cap.as_slice())));
    }

    #[test]
    fn warning_finding_returns_false() {
        let events = [synthetic_event()];
        for severity in [Severity::Warning, Severity::Error, Severity::Fatal] {
            let blocking = [finding(severity)];
            assert_eq!(
                reference_equivalent_if_clean(Some(events.as_slice()), &blocking),
                Ok(false)
            );
        }
    }

    #[test]
    fn identity_multiset_fails_closed() {
        let event = synthetic_event();
        assert_eq!(super::_identity_multiset(&[]), Some(BTreeMap::new()));
        assert_eq!(super::_identity_multiset(&[ReferenceItem::Other]), None);
        assert_eq!(
            super::_identity_multiset(&[ReferenceItem::Event(&event)]),
            None
        );
        assert_eq!(
            super::_identity_multiset(&[ReferenceItem::Event(&event), ReferenceItem::Other]),
            None
        );
        assert_eq!(
            super::_identity_multiset(&[ReferenceItem::Other, ReferenceItem::Event(&event)]),
            None
        );
    }
}
