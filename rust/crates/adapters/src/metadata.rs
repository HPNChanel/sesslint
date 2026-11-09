//! Bounded advisory evidence for unknown non-linking metadata (SL306, W1-1/W1-2).
//!
//! Port of `src/sesslint/adapters/metadata.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–98.
//!
//! [`has_semantic_fields`] walks a mapping in the pin's stack order. A string
//! key whose value is not `None` is critical when it is in [`SEMANTIC_KEYS`],
//! starts with `critical_`, or starts with `unknown_critical`, checked in
//! that order. Lists are the only sequence that is entered. Session
//! membership and timestamps are not semantic.
//!
//! [`UnknownMetadataTracker`] keeps at most 32 safe discriminators plus one
//! `<other-types>` overflow group. [`UnknownMetadataTracker::findings`] emits
//! one SL306 row per group, sorted by the discriminator.
//!
//! Gaps vs Python (recorded, not papered over):
//! - [`UnknownMetadataTracker::findings`] calls [`make_finding`] with the
//!   fingerprint omitted. Each group builds evidence, then [`SourceRef`], then
//!   reaches `sesslint.determinism.canonical_json_bytes`, which is not in this
//!   crate. The first such call returns [`FindingError`] whose Display is
//!   `sesslint.determinism.canonical_json_bytes is not available`. No digest
//!   is invented. An empty tracker returns before that call and does not read
//!   the path. A rejected [`SourceRef`] returns before it too. A later group
//!   is not visited once that error is raised.
//! - `line` is `i64`. Python `int` is unbounded. `bool` is not an `int` here,
//!   so a boolean line cannot be passed.
//! - The group count saturates at `i64::MAX`. Python `int` does not.
//! - A Rust `&str` cannot contain a lone surrogate.
//! - [`UnknownMetadataTracker::note`] takes `&str`, which is the pin's
//!   annotation. A non-`str` runtime argument is not representable.
//! - A cyclic mapping is not representable. The pin would not terminate.
//!   This walk owns an acyclic tree and uses a heap stack.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;

use model::codes::SL306;
use model::errors::FindingError;
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef};

use crate::safe_value::{safe_discriminator, PyValue as SafeValue};

/// Presence of these fields makes an unknown record potentially replay-critical.
///
/// Python: `SEMANTIC_KEYS`. The slice is the set literal in source order.
/// Membership does not iterate the set into output. Session membership and
/// timestamps alone do not establish record identity.
pub const SEMANTIC_KEYS: [&str; 33] = [
    "id",
    "uuid",
    "record_id",
    "message_id",
    "parentId",
    "parent_id",
    "parentUuid",
    "parent_uuid",
    "logicalParentUuid",
    "call_id",
    "callId",
    "toolUseId",
    "tool_use_id",
    "tool_call_id",
    "correlation_id",
    "turn_id",
    "turnId",
    "previous_response_id",
    "parent_thread_id",
    "forked_from_id",
    "leafUuid",
    "message",
    "messages",
    "content",
    "role",
    "input",
    "output",
    "items",
    "events",
    "history",
    "checkpoint",
    "checkpoints",
    "snapshot",
];

/// Pin: `len(self._groups) >= 32`, checked before the overflow key is inserted.
const MAX_TYPE_GROUPS: usize = 32;

/// Pin overflow discriminator. `safe_discriminator` cannot echo this text.
const OTHER_TYPES: &str = "<other-types>";

const MESSAGE_TEMPLATE: &str = "Unknown non-linking metadata on line {line}";

/// Key of one metadata mapping entry.
///
/// [`MetadataKey::Str`] is the only key for which `isinstance(key, str)` holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataKey {
    /// Python `str`, including a `str` subclass the caller has already mapped.
    Str(String),
    /// Any other key. Its text is not stored.
    NonStr,
}

/// Value in a metadata mapping or list.
///
/// The walk distinguishes `None`, `list`, and `Mapping`. Every other object
/// is [`MetadataValue::Scalar`], including `False`, `0`, `""`, tuples, and
/// sets. Tuple and set members are not visited, matching
/// `isinstance(child, (Mapping, list))`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataValue {
    /// Python `None`.
    NoneValue,
    /// Not `None`, not a `list`, and not a `Mapping`.
    Scalar,
    /// Python `list`, in index order.
    List(Vec<MetadataValue>),
    /// Python `dict.items()` order. This is not a `HashMap` or a `BTreeMap`.
    Map(Vec<(MetadataKey, MetadataValue)>),
}

enum Pending<'a> {
    Map(&'a [(MetadataKey, MetadataValue)]),
    List(&'a [MetadataValue]),
}

/// Fail closed for identity, linkage, payload, or explicit critical fields.
///
/// Python: `has_semantic_fields`. The root is pushed and then popped, so a
/// non-mapping root follows the same loop the pin runs when the annotation
/// is ignored. Containers are stored on a heap stack (`list.pop`), so a deep
/// tree does not grow the native stack. Map entries are checked in [`Vec`]
/// order. List containers are appended in index order, so the last container
/// is visited next.
#[must_use]
pub fn has_semantic_fields(value: &MetadataValue) -> bool {
    let mut pending = Vec::new();
    push_pending(value, &mut pending);
    while let Some(item) = pending.pop() {
        match item {
            Pending::Map(entries) => {
                for (key, child) in entries {
                    if semantic_hit(key, child) {
                        return true;
                    }
                    push_pending(child, &mut pending);
                }
            }
            Pending::List(items) => {
                for child in items {
                    push_pending(child, &mut pending);
                }
            }
        }
    }
    false
}

fn semantic_hit(key: &MetadataKey, child: &MetadataValue) -> bool {
    let MetadataKey::Str(name) = key else {
        return false;
    };
    !matches!(child, MetadataValue::NoneValue)
        && (SEMANTIC_KEYS.contains(&name.as_str())
            || name.starts_with("critical_")
            || name.starts_with("unknown_critical"))
}

fn push_pending<'a>(value: &'a MetadataValue, pending: &mut Vec<Pending<'a>>) {
    match value {
        MetadataValue::Map(entries) => pending.push(Pending::Map(entries)),
        MetadataValue::List(items) => pending.push(Pending::List(items)),
        MetadataValue::NoneValue | MetadataValue::Scalar => {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Group {
    count: i64,
    first: i64,
    redacted: bool,
}

/// Aggregate at most 32 safe discriminators plus one overflow finding.
///
/// Python: `UnknownMetadataTracker`. Group order is the discriminator text,
/// which is `sorted(self._groups.items())`.
#[derive(Debug, Default)]
pub struct UnknownMetadataTracker {
    groups: BTreeMap<String, Group>,
}

impl UnknownMetadataTracker {
    /// Python: `UnknownMetadataTracker()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one unknown type on `line`.
    ///
    /// Python: `note(raw_type, *, line)`. `line` is the keyword-only argument.
    /// The first observation of a discriminator keeps its line and redacted
    /// flag. A new discriminator at [`MAX_TYPE_GROUPS`] joins `<other-types>`
    /// with `redacted = True`. This does not validate `line`.
    pub fn note(&mut self, raw_type: &str, line: i64) {
        let (mut value, mut redacted) = safe_discriminator(SafeValue::Str(raw_type));
        if !self.groups.contains_key(&value) && self.groups.len() >= MAX_TYPE_GROUPS {
            value = OTHER_TYPES.to_owned();
            redacted = true;
        }
        match self.groups.entry(value) {
            Entry::Occupied(mut occupied) => {
                let group = occupied.get_mut();
                group.count = group.count.saturating_add(1);
            }
            Entry::Vacant(vacant) => {
                vacant.insert(Group {
                    count: 1,
                    first: line,
                    redacted,
                });
            }
        }
    }

    /// Materialize one SL306 finding per group, in discriminator order.
    ///
    /// Python: `findings`. An empty tracker returns before [`make_finding`]
    /// and does not read `path`. Otherwise each group builds evidence, then
    /// [`SourceRef`], then [`make_finding`]. The omitted fingerprint fails
    /// closed. The first error aborts the list.
    pub fn findings(&self, path: &str) -> Result<Vec<Finding>, FindingError> {
        if self.groups.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(self.groups.len());
        for (value, group) in &self.groups {
            out.push(finding_from_group(path, value, group)?);
        }
        Ok(out)
    }
}

fn group_evidence(value: &str, group: &Group) -> PyValue {
    PyValue::map(vec![
        (PyValue::string("count"), PyValue::int(group.count)),
        (PyValue::string("type_value"), PyValue::string(value)),
        (
            PyValue::string("type_truncated"),
            PyValue::bool_value(group.redacted),
        ),
    ])
}

fn finding_from_group(path: &str, value: &str, group: &Group) -> Result<Finding, FindingError> {
    let evidence = group_evidence(value, group);
    let source = SourceRef::try_new(path, Some(SourceLine::Int(group.first)), None)?;
    make_finding(&MakeFindingInput {
        code: PyValue::string(SL306),
        severity: PyValue::None,
        repairability: PyValue::None,
        message_template: PyValue::string(MESSAGE_TEMPLATE),
        template_args: PyValue::None,
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        evidence,
        fingerprint: PyValue::None,
        adapter_id: None,
        adapter_version: None,
        profile_id: None,
        profile_version: None,
        ordinal: None,
        context: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        group_evidence, has_semantic_fields, Group, MetadataKey, MetadataValue,
        UnknownMetadataTracker, MAX_TYPE_GROUPS, MESSAGE_TEMPLATE, OTHER_TYPES, SEMANTIC_KEYS,
    };
    use model::finding::{PyValue, SourceLine, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE};

    fn named(name: &str, value: MetadataValue) -> (MetadataKey, MetadataValue) {
        (MetadataKey::Str(name.to_owned()), value)
    }

    fn object(entries: Vec<(MetadataKey, MetadataValue)>) -> MetadataValue {
        MetadataValue::Map(entries)
    }

    fn stored(tracker: &UnknownMetadataTracker, key: &str) -> Option<(i64, i64, bool)> {
        tracker
            .groups
            .get(key)
            .map(|group| (group.count, group.first, group.redacted))
    }

    fn assert_before_codec(err: &model::errors::FindingError, needle: &str) {
        let text = err.to_string();
        assert!(text.contains(needle), "{text}");
        assert_ne!(text, FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(text, err.message());
    }

    #[test]
    fn semantic_keys_match_the_pin_literal() {
        assert_eq!(SEMANTIC_KEYS.len(), 33);
        assert_eq!(
            SEMANTIC_KEYS,
            [
                "id",
                "uuid",
                "record_id",
                "message_id",
                "parentId",
                "parent_id",
                "parentUuid",
                "parent_uuid",
                "logicalParentUuid",
                "call_id",
                "callId",
                "toolUseId",
                "tool_use_id",
                "tool_call_id",
                "correlation_id",
                "turn_id",
                "turnId",
                "previous_response_id",
                "parent_thread_id",
                "forked_from_id",
                "leafUuid",
                "message",
                "messages",
                "content",
                "role",
                "input",
                "output",
                "items",
                "events",
                "history",
                "checkpoint",
                "checkpoints",
                "snapshot",
            ]
        );
        let mut sorted = SEMANTIC_KEYS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), SEMANTIC_KEYS.len());
        assert_eq!(MAX_TYPE_GROUPS, 32);
        assert_eq!(
            MESSAGE_TEMPLATE,
            "Unknown non-linking metadata on line {line}"
        );
        assert_eq!(OTHER_TYPES, "<other-types>");
    }

    #[test]
    fn semantic_key_presence_follows_the_pin() {
        for name in SEMANTIC_KEYS {
            assert!(
                has_semantic_fields(&object(vec![named(name, MetadataValue::Scalar)])),
                "{name}"
            );
            assert!(
                !has_semantic_fields(&object(vec![named(name, MetadataValue::NoneValue)])),
                "{name}"
            );
        }
        assert!(has_semantic_fields(&object(vec![named(
            "items",
            MetadataValue::List(Vec::new())
        )])));
        assert!(!has_semantic_fields(&object(vec![named(
            "items",
            MetadataValue::NoneValue
        )])));
        assert!(!has_semantic_fields(&MetadataValue::NoneValue));
        assert!(!has_semantic_fields(&MetadataValue::Scalar));
        assert!(!has_semantic_fields(&object(Vec::new())));
        assert!(has_semantic_fields(&MetadataValue::List(vec![object(
            vec![named("id", MetadataValue::Scalar)]
        )])));
        assert!(!has_semantic_fields(&MetadataValue::List(vec![
            MetadataValue::Scalar
        ])));
    }

    #[test]
    fn prefixes_and_bookkeeping_keys_follow_the_pin() {
        for name in [
            "critical_",
            "critical_state",
            "unknown_critical",
            "unknown_critical_state",
            "unknown_criticality",
            "critical_unknown_critical",
        ] {
            assert!(
                has_semantic_fields(&object(vec![named(name, MetadataValue::Scalar)])),
                "{name}"
            );
        }
        for name in ["critical_state", "unknown_critical", "unknown_criticality"] {
            assert!(
                !has_semantic_fields(&object(vec![named(name, MetadataValue::NoneValue)])),
                "{name}"
            );
        }
        for name in [
            "type",
            "sessionId",
            "session_id",
            "timestamp",
            "cwd",
            "subtype",
            "name",
            "uuid_extra",
            "parent",
            "critical",
            "unknown",
            "Critical_state",
            "Unknown_critical",
        ] {
            assert!(
                !has_semantic_fields(&object(vec![named(name, MetadataValue::Scalar)])),
                "{name}"
            );
        }
    }

    #[test]
    fn nested_lists_and_non_string_keys_follow_the_walk() {
        assert!(has_semantic_fields(&object(vec![
            named("id", MetadataValue::NoneValue),
            named("role", MetadataValue::Scalar),
        ])));
        assert!(!has_semantic_fields(&object(vec![
            named("id", MetadataValue::NoneValue),
            named(
                "payload",
                object(vec![named("note", MetadataValue::Scalar)])
            ),
        ])));
        assert!(has_semantic_fields(&object(vec![
            named("left", object(vec![named("role", MetadataValue::Scalar)])),
            named("right", object(vec![named("note", MetadataValue::Scalar)])),
        ])));
        assert!(has_semantic_fields(&object(vec![
            named("left", object(vec![named("note", MetadataValue::Scalar)])),
            named("right", object(vec![named("role", MetadataValue::Scalar)])),
        ])));
        assert!(has_semantic_fields(&object(vec![named(
            "wrap",
            MetadataValue::List(vec![
                MetadataValue::Scalar,
                MetadataValue::NoneValue,
                MetadataValue::List(vec![object(vec![named("note", MetadataValue::Scalar)])]),
                object(vec![named("snapshot", MetadataValue::Scalar)]),
            ]),
        )])));
        assert!(!has_semantic_fields(&object(vec![named(
            "wrap",
            MetadataValue::List(vec![
                MetadataValue::Scalar,
                MetadataValue::NoneValue,
                MetadataValue::List(vec![object(vec![named("note", MetadataValue::Scalar)])]),
            ]),
        )])));
        assert!(has_semantic_fields(&object(vec![(
            MetadataKey::NonStr,
            object(vec![named("role", MetadataValue::Scalar)]),
        )])));
        assert!(!has_semantic_fields(&object(vec![(
            MetadataKey::NonStr,
            MetadataValue::Scalar,
        )])));
        assert!(has_semantic_fields(&object(vec![named(
            "critical_",
            object(vec![named("note", MetadataValue::Scalar)])
        )])));

        let mut deep = object(vec![named("content", MetadataValue::Scalar)]);
        for _ in 0..64 {
            deep = object(vec![named("wrap", deep)]);
        }
        assert!(has_semantic_fields(&deep));
        let mut plain = MetadataValue::Scalar;
        for _ in 0..64 {
            plain = object(vec![named("wrap", plain)]);
        }
        assert!(!has_semantic_fields(&plain));
    }

    #[test]
    fn evidence_keeps_pin_insertion_order() {
        let group = Group {
            count: 2,
            first: 3,
            redacted: false,
        };
        assert_eq!(
            group_evidence("future_status", &group),
            PyValue::map(vec![
                (PyValue::string("count"), PyValue::int(2)),
                (
                    PyValue::string("type_value"),
                    PyValue::string("future_status")
                ),
                (
                    PyValue::string("type_truncated"),
                    PyValue::bool_value(false)
                ),
            ])
        );
        let overflow = Group {
            count: 4,
            first: 8,
            redacted: true,
        };
        assert_eq!(
            group_evidence(OTHER_TYPES, &overflow),
            PyValue::map(vec![
                (PyValue::string("count"), PyValue::int(4)),
                (PyValue::string("type_value"), PyValue::string(OTHER_TYPES)),
                (PyValue::string("type_truncated"), PyValue::bool_value(true)),
            ])
        );
    }

    #[test]
    fn repeated_notes_keep_the_first_line_and_redacted_flag() {
        let mut tracker = UnknownMetadataTracker::new();
        tracker.note("future_status", 3);
        tracker.note("future_status", 9);
        assert_eq!(stored(&tracker, "future_status"), Some((2, 3, false)));
        tracker.note("", 4);
        assert_eq!(stored(&tracker, "<str:len=0>"), Some((1, 4, true)));
        let echoed = "a".repeat(64);
        let truncated = "a".repeat(65);
        tracker.note(&echoed, 1);
        tracker.note(&truncated, 2);
        assert_eq!(stored(&tracker, &echoed), Some((1, 1, false)));
        assert_eq!(stored(&tracker, "<str:len=65>"), Some((1, 2, true)));
        let accented = "\u{00e9}\u{00e9}";
        tracker.note(accented, 6);
        assert_eq!(stored(&tracker, "<str:len=2>"), Some((1, 6, true)));
        assert!(!tracker.groups.contains_key(accented));
    }

    #[test]
    fn truncated_discriminators_share_one_group() {
        let mut tracker = UnknownMetadataTracker::new();
        tracker.note("foo bar", 2);
        tracker.note("baz qux", 5);
        assert_eq!(tracker.groups.len(), 1);
        assert_eq!(stored(&tracker, "<str:len=7>"), Some((2, 2, true)));
    }

    #[test]
    fn overflow_bucket_is_the_33rd_group() {
        let mut exact = UnknownMetadataTracker::new();
        for index in 0..MAX_TYPE_GROUPS {
            exact.note(&format!("kind{index}"), 1);
        }
        assert_eq!(exact.groups.len(), MAX_TYPE_GROUPS);
        assert!(!exact.groups.contains_key(OTHER_TYPES));
        assert_eq!(stored(&exact, "kind0"), Some((1, 1, false)));
        assert_eq!(stored(&exact, "kind31"), Some((1, 1, false)));

        let mut tracker = UnknownMetadataTracker::new();
        let mut line = 1_i64;
        for index in 0..200 {
            tracker.note(&format!("future_{index}"), line);
            line = line.saturating_add(1);
        }
        assert_eq!(tracker.groups.len(), 33);
        let sum: i64 = tracker.groups.values().map(|group| group.count).sum();
        assert_eq!(sum, 200);
        assert_eq!(stored(&tracker, "future_0"), Some((1, 1, false)));
        assert_eq!(stored(&tracker, "future_31"), Some((1, 32, false)));
        assert!(!tracker.groups.contains_key("future_32"));
        assert!(!tracker.groups.contains_key("future_199"));
        assert_eq!(stored(&tracker, OTHER_TYPES), Some((168, 33, true)));
        tracker.note("future_0", 500);
        assert_eq!(stored(&tracker, "future_0"), Some((2, 1, false)));
        assert_eq!(stored(&tracker, OTHER_TYPES), Some((168, 33, true)));
        tracker.note("future_32", 501);
        assert_eq!(stored(&tracker, OTHER_TYPES), Some((169, 33, true)));
        assert!(!tracker.groups.contains_key("future_32"));
        let sum: i64 = tracker.groups.values().map(|group| group.count).sum();
        assert_eq!(sum, 202);
    }

    #[test]
    fn count_saturates_at_i64_max() {
        let mut tracker = UnknownMetadataTracker::new();
        tracker.note("kind", 4);
        let group = tracker.groups.get_mut("kind").expect("kind");
        group.count = i64::MAX;
        tracker.note("kind", 9);
        assert_eq!(stored(&tracker, "kind"), Some((i64::MAX, 4, false)));
    }

    #[test]
    fn empty_result_returns_before_make_finding() {
        let tracker = UnknownMetadataTracker::new();
        assert!(tracker.findings("").expect("empty path").is_empty());
        assert!(tracker.findings("   ").expect("whitespace path").is_empty());
        assert!(tracker.findings("a\nb").expect("newline path").is_empty());
        assert!(tracker
            .findings("synth.jsonl")
            .expect("plain path")
            .is_empty());
        assert!(UnknownMetadataTracker::default()
            .findings("")
            .expect("default")
            .is_empty());
    }

    #[test]
    fn rejected_source_fails_before_the_missing_codec() {
        let mut tracker = UnknownMetadataTracker::new();
        tracker.note("future_status", 0);
        let line_err = tracker.findings("synth.jsonl").expect_err("line");
        assert_before_codec(&line_err, "SourceRef.line");
        assert!(line_err.to_string().contains("got 0"));

        let mut negative = UnknownMetadataTracker::new();
        negative.note("future_status", -1);
        let negative_err = negative.findings("synth.jsonl").expect_err("negative");
        assert_before_codec(&negative_err, "got -1");

        let mut lowest = UnknownMetadataTracker::new();
        lowest.note("future_status", i64::MIN);
        let lowest_err = lowest.findings("synth.jsonl").expect_err("min");
        assert_before_codec(&lowest_err, "SourceRef.line");
        assert!(lowest_err.to_string().contains(&i64::MIN.to_string()));

        let mut empty_path = UnknownMetadataTracker::new();
        empty_path.note("future_status", 1);
        let empty_err = empty_path.findings("").expect_err("empty");
        assert_before_codec(&empty_err, "SourceRef.path must be a non-empty string");

        let mut whitespace = UnknownMetadataTracker::new();
        whitespace.note("future_status", 1);
        let whitespace_err = whitespace.findings("   ").expect_err("whitespace");
        assert_before_codec(&whitespace_err, "SourceRef.path must be a non-empty string");

        let mut newline = UnknownMetadataTracker::new();
        newline.note("future_status", 1);
        let newline_err = newline.findings("a\nb").expect_err("newline");
        assert_before_codec(&newline_err, "SourceRef.path");
        assert!(newline_err.to_string().contains("Forbidden"));
        assert!(!newline_err
            .to_string()
            .contains("must be a non-empty string"));

        let mut ordered = UnknownMetadataTracker::new();
        for index in 0..MAX_TYPE_GROUPS {
            ordered.note(&format!("kind{index}"), 1);
        }
        ordered.note("kind32", 0);
        let ordered_err = ordered.findings("synth.jsonl").expect_err("sorted");
        assert_before_codec(&ordered_err, "SourceRef.line");
        assert!(ordered_err.to_string().contains("got 0"));
        assert_eq!(ordered.groups.len(), 33);
    }

    #[test]
    fn valid_notes_stop_at_the_missing_codec() {
        let mut tracker = UnknownMetadataTracker::new();
        tracker.note("future_status", 3);
        tracker.note("future_status", 9);
        let source = SourceRef::try_new("synth.jsonl", Some(SourceLine::Int(3)), None);
        assert!(source.is_ok());
        let err = tracker.findings("synth.jsonl").expect_err("codec");
        assert_eq!(
            err.to_string(),
            "sesslint.determinism.canonical_json_bytes is not available"
        );
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(stored(&tracker, "future_status"), Some((2, 3, false)));
        let again = tracker.findings("synth.jsonl").expect_err("again");
        assert_eq!(again.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let mut padded = UnknownMetadataTracker::new();
        padded.note("future_status", i64::MAX);
        let padded_err = padded.findings("  synth.jsonl  ").expect_err("padded");
        assert_eq!(padded_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let mut slashed = UnknownMetadataTracker::new();
        slashed.note("future_status", 1);
        let slashed_err = slashed.findings("dir\\synth.jsonl").expect_err("slash");
        assert_eq!(slashed_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let mut later_bad = UnknownMetadataTracker::new();
        later_bad.note("a_kind", 1);
        later_bad.note("m_kind", 0);
        let later_err = later_bad.findings("synth.jsonl").expect_err("later");
        assert_eq!(later_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let mut many = UnknownMetadataTracker::new();
        for index in 0..=MAX_TYPE_GROUPS {
            many.note(&format!("kind{index}"), 2);
        }
        let many_err = many.findings("synth.jsonl").expect_err("many");
        assert_eq!(many_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(many.groups.len(), 33);
    }
}
