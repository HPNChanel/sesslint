//! Bounded cross-file resume-link extraction shared by adapters (SL401).
//!
//! Port of `src/sesslint/adapters/links.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–97.
//!
//! Adapters surface declared resume/continuation pointers as bounded structural
//! metadata — `{kind, target, record_id, line}` stored on the adapter's
//! `SourceMetadata` under `"links"`. The scan layer resolves each link against
//! the scanned file set; extraction here is read-only, deduplicated per file,
//! and capped. Values are structural identifiers only — payload content is
//! never copied.
//!
//! Gaps vs Python (recorded, not papered over):
//! - A Rust `&str` cannot hold a lone surrogate, so this port never sees one.
//! - Non-bool ints are `i64`. Python `int` is unbounded; values outside `i64`
//!   are not representable in [`ObjectValue::Int`].

use std::collections::{BTreeMap, BTreeSet};

/// Python: `MAX_CROSS_LINKS`.
pub const MAX_CROSS_LINKS: usize = 16;

/// Declared pointers to a predecessor session/file (`session_ref` kind).
///
/// Python: `SESSION_LINK_KEYS`. Walked in this declaration order.
pub const SESSION_LINK_KEYS: [&str; 16] = [
    "parent_session_id",
    "parentSessionId",
    "resume_from",
    "resumeFrom",
    "source_session_id",
    "sourceSessionId",
    "previous_session_id",
    "previousSessionId",
    "continued_from",
    "continuedFrom",
    "forked_from_session",
    "forkedFromSession",
    "forked_from_id",
    "forkedFromId",
    "parent_thread_id",
    "parentThreadId",
];

/// Declared pointers to a predecessor session's head/tip event (`head_ref`).
///
/// Python: `HEAD_LINK_KEYS`. Walked in this declaration order after
/// [`SESSION_LINK_KEYS`].
pub const HEAD_LINK_KEYS: [&str; 7] = [
    "resume_head_id",
    "resumeHeadId",
    "resume_from_head",
    "continued_from_event",
    "continuedFromEvent",
    "parent_event_id",
    "parentEventId",
];

/// One extracted resume/continuation pointer.
///
/// Field order matches the Python dict: `kind`, `target`, `record_id`, `line`.
/// No other input field is copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub kind: String,
    pub target: String,
    pub record_id: Option<String>,
    pub line: Option<i64>,
}

/// Looked-up value from an adapter object.
///
/// Only [`ObjectValue::Str`] and [`ObjectValue::Int`] become targets. Bool is
/// a distinct variant because Python `bool` is an `int` subclass and is
/// ignored. Every other JSON/Python type is [`ObjectValue::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Other,
}

/// Append bounded `{kind, target, record_id, line}` link rows from `obj`.
///
/// Python: `extract_links`. Keys are read from [`SESSION_LINK_KEYS`] then
/// [`HEAD_LINK_KEYS`]; `obj` is never iterated, so its key order does not
/// change extraction order. Stops once [`MAX_CROSS_LINKS`] rows are stored.
pub fn extract_links(
    obj: &BTreeMap<String, ObjectValue>,
    links: &mut Vec<Link>,
    record_id: Option<&str>,
    line: Option<i64>,
) {
    if links.len() >= MAX_CROSS_LINKS {
        return;
    }
    let mut existing: BTreeSet<(String, String)> = links
        .iter()
        .map(|link| (link.kind.clone(), link.target.clone()))
        .collect();
    for key in SESSION_LINK_KEYS {
        add(
            obj,
            key,
            "session_ref",
            links,
            &mut existing,
            record_id,
            line,
        );
    }
    for key in HEAD_LINK_KEYS {
        add(obj, key, "head_ref", links, &mut existing, record_id, line);
    }
}

/// Python: `_add`.
fn add(
    obj: &BTreeMap<String, ObjectValue>,
    key: &str,
    kind: &str,
    links: &mut Vec<Link>,
    existing: &mut BTreeSet<(String, String)>,
    record_id: Option<&str>,
    line: Option<i64>,
) {
    if links.len() >= MAX_CROSS_LINKS {
        return;
    }
    let target = match obj.get(key) {
        Some(ObjectValue::Str(value)) => python_str_strip(value).to_string(),
        Some(ObjectValue::Int(value)) => value.to_string(),
        Some(ObjectValue::Bool(_) | ObjectValue::Other) | None => return,
    };
    if target.is_empty() || target.chars().count() > 512 {
        return;
    }
    let pair = (kind.to_string(), target);
    if !existing.insert(pair.clone()) {
        return;
    }
    links.push(Link {
        kind: pair.0,
        target: pair.1,
        record_id: record_id.map(str::to_owned),
        line,
    });
}

/// Python `str.strip()` with no `chars` argument.
///
/// `char::is_whitespace` is Unicode White_Space, which includes U+2028/U+2029
/// (Zl/Zp) and omits U+001C..U+001F. Python `str.isspace` is the opposite on
/// those five code points.
fn python_str_strip(value: &str) -> &str {
    value.trim_matches(is_python_str_space)
}

fn is_python_str_space(c: char) -> bool {
    matches!(c, '\u{1C}' | '\u{1D}' | '\u{1E}' | '\u{1F}')
        || (c.is_whitespace() && !matches!(c, '\u{2028}' | '\u{2029}'))
}

#[cfg(test)]
mod tests {
    use super::{
        extract_links, is_python_str_space, python_str_strip, HEAD_LINK_KEYS, MAX_CROSS_LINKS,
        SESSION_LINK_KEYS,
    };
    use super::{Link, ObjectValue};
    use std::collections::BTreeMap;

    const SYN_PARENT: &str = "syn-parent-01";
    const SYN_PARENT_B: &str = "syn-parent-02";
    const SYN_HEAD: &str = "syn-head-01";
    const SYN_RECORD: &str = "syn-rec-01";

    fn obj(pairs: &[(&str, ObjectValue)]) -> BTreeMap<String, ObjectValue> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect()
    }

    fn session_link(target: &str, record_id: Option<&str>, line: Option<i64>) -> Link {
        Link {
            kind: "session_ref".to_string(),
            target: target.to_string(),
            record_id: record_id.map(str::to_owned),
            line,
        }
    }

    fn head_link(target: &str, record_id: Option<&str>, line: Option<i64>) -> Link {
        Link {
            kind: "head_ref".to_string(),
            target: target.to_string(),
            record_id: record_id.map(str::to_owned),
            line,
        }
    }

    #[test]
    fn happy_path_session_then_head_with_record_and_line() {
        let map = obj(&[
            ("resume_head_id", ObjectValue::Str(SYN_HEAD.to_string())),
            (
                "parent_session_id",
                ObjectValue::Str(SYN_PARENT.to_string()),
            ),
        ]);
        let mut links = Vec::new();
        extract_links(&map, &mut links, Some(SYN_RECORD), Some(7));
        assert_eq!(
            links,
            vec![
                session_link(SYN_PARENT, Some(SYN_RECORD), Some(7)),
                head_link(SYN_HEAD, Some(SYN_RECORD), Some(7)),
            ]
        );
    }

    #[test]
    fn declaration_order_not_btree_or_input_order() {
        // BTreeMap orders `parentSessionId` before `parent_session_id` ('S' < '_
        // '_'). Declaration order is the reverse. Input insertion is HEAD-first.
        let map = obj(&[
            ("resume_head_id", ObjectValue::Str(SYN_HEAD.to_string())),
            (
                "parentSessionId",
                ObjectValue::Str(SYN_PARENT_B.to_string()),
            ),
            (
                "parent_session_id",
                ObjectValue::Str(SYN_PARENT.to_string()),
            ),
        ]);
        let mut links = Vec::new();
        extract_links(&map, &mut links, None, None);
        assert_eq!(
            links,
            vec![
                session_link(SYN_PARENT, None, None),
                session_link(SYN_PARENT_B, None, None),
                head_link(SYN_HEAD, None, None),
            ]
        );
    }

    #[test]
    fn string_is_stripped_int_becomes_decimal_bool_and_other_ignored() {
        let map = obj(&[
            (
                "parent_session_id",
                ObjectValue::Str(format!("  {SYN_PARENT}  ")),
            ),
            ("parentSessionId", ObjectValue::Int(-42)),
            ("resume_from", ObjectValue::Bool(true)),
            ("resumeFrom", ObjectValue::Bool(false)),
            ("source_session_id", ObjectValue::Other),
            ("sourceSessionId", ObjectValue::Int(0)),
        ]);
        let mut links = Vec::new();
        extract_links(&map, &mut links, Some(SYN_RECORD), Some(-1));
        assert_eq!(
            links,
            vec![
                session_link(SYN_PARENT, Some(SYN_RECORD), Some(-1)),
                session_link("-42", Some(SYN_RECORD), Some(-1)),
                session_link("0", Some(SYN_RECORD), Some(-1)),
            ]
        );
    }

    #[test]
    fn empty_after_strip_and_missing_keys_are_ignored() {
        let map = obj(&[
            ("parent_session_id", ObjectValue::Str("   ".to_string())),
            ("parentSessionId", ObjectValue::Str(String::new())),
        ]);
        let mut links = Vec::new();
        extract_links(&map, &mut links, Some(SYN_RECORD), Some(1));
        assert!(links.is_empty());
    }

    #[test]
    fn target_longer_than_512_scalars_is_ignored_512_is_kept() {
        let kept = "é".repeat(512);
        let dropped = "é".repeat(513);
        assert_eq!(kept.len(), 1024);
        let map = obj(&[
            ("parent_session_id", ObjectValue::Str(kept.clone())),
            ("parentSessionId", ObjectValue::Str(dropped)),
        ]);
        let mut links = Vec::new();
        extract_links(&map, &mut links, None, None);
        assert_eq!(links, vec![session_link(&kept, None, None)]);
    }

    #[test]
    fn duplicate_kind_target_is_ignored_different_kind_is_kept() {
        let map = obj(&[
            (
                "parent_session_id",
                ObjectValue::Str(SYN_PARENT.to_string()),
            ),
            ("parentSessionId", ObjectValue::Str(SYN_PARENT.to_string())),
            ("resume_head_id", ObjectValue::Str(SYN_PARENT.to_string())),
        ]);
        let mut links = Vec::new();
        extract_links(&map, &mut links, None, Some(3));
        assert_eq!(
            links,
            vec![
                session_link(SYN_PARENT, None, Some(3)),
                head_link(SYN_PARENT, None, Some(3)),
            ]
        );
    }

    #[test]
    fn extra_input_fields_are_not_copied() {
        let map = obj(&[
            (
                "parent_session_id",
                ObjectValue::Str(SYN_PARENT.to_string()),
            ),
            ("payload", ObjectValue::Str("not-copied".to_string())),
            ("record_id", ObjectValue::Str("obj-rec".to_string())),
            ("line", ObjectValue::Int(99)),
            ("kind", ObjectValue::Str("forged".to_string())),
            ("target", ObjectValue::Str("forged-target".to_string())),
        ]);
        let mut links = Vec::new();
        extract_links(&map, &mut links, Some(SYN_RECORD), Some(4));
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].kind, "session_ref");
        assert_eq!(links[0].target, SYN_PARENT);
        assert_eq!(links[0].record_id.as_deref(), Some(SYN_RECORD));
        assert_eq!(links[0].line, Some(4));
    }

    #[test]
    fn cap_stops_at_sixteen_session_keys_before_head() {
        let mut pairs = Vec::new();
        for (index, key) in SESSION_LINK_KEYS.iter().enumerate() {
            pairs.push((*key, ObjectValue::Str(format!("syn-session-{index:02}"))));
        }
        pairs.push(("resume_head_id", ObjectValue::Str(SYN_HEAD.to_string())));
        let map = obj(&pairs);
        let mut links = Vec::new();
        extract_links(&map, &mut links, None, None);
        assert_eq!(links.len(), MAX_CROSS_LINKS);
        assert!(links.iter().all(|link| link.kind == "session_ref"));
        assert_eq!(links[0].target, "syn-session-00");
        assert_eq!(links[15].target, "syn-session-15");
    }

    #[test]
    fn cap_allows_head_when_session_slots_remain() {
        let map = obj(&[("resume_head_id", ObjectValue::Str(SYN_HEAD.to_string()))]);
        let mut links: Vec<Link> = (0..15)
            .map(|index| session_link(&format!("syn-prior-{index:02}"), None, None))
            .collect();
        extract_links(&map, &mut links, Some(SYN_RECORD), Some(2));
        assert_eq!(links.len(), MAX_CROSS_LINKS);
        assert_eq!(links[15], head_link(SYN_HEAD, Some(SYN_RECORD), Some(2)));
    }

    #[test]
    fn already_at_cap_returns_without_looking_up() {
        let map = obj(&[(
            "parent_session_id",
            ObjectValue::Str(SYN_PARENT.to_string()),
        )]);
        let mut links: Vec<Link> = (0..MAX_CROSS_LINKS)
            .map(|index| session_link(&format!("syn-full-{index:02}"), None, None))
            .collect();
        extract_links(&map, &mut links, Some(SYN_RECORD), Some(9));
        assert_eq!(links.len(), MAX_CROSS_LINKS);
        assert!(links
            .iter()
            .all(|link| link.target.starts_with("syn-full-")));
    }

    #[test]
    fn existing_membership_skips_preloaded_pair() {
        let map = obj(&[(
            "parent_session_id",
            ObjectValue::Str(SYN_PARENT.to_string()),
        )]);
        let mut links = vec![session_link(SYN_PARENT, Some("syn-old"), Some(1))];
        extract_links(&map, &mut links, Some(SYN_RECORD), Some(8));
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].record_id.as_deref(), Some("syn-old"));
    }

    #[test]
    fn python_strip_matches_isspace_not_rust_whitespace() {
        let padded = format!("\u{1c}\u{00a0}{SYN_PARENT}\u{00a0}\u{1f}");
        assert_eq!(python_str_strip(&padded), SYN_PARENT);
        assert!(is_python_str_space('\u{1c}'));
        assert!(!is_python_str_space('\u{2028}'));
        assert!(!is_python_str_space('\u{2029}'));
        let map = obj(&[(
            "parent_session_id",
            ObjectValue::Str(format!("\u{2028}{SYN_PARENT}")),
        )]);
        let mut links = Vec::new();
        extract_links(&map, &mut links, None, None);
        assert_eq!(links[0].target, format!("\u{2028}{SYN_PARENT}"));
    }

    #[test]
    fn key_tables_match_pinned_declaration_order() {
        assert_eq!(MAX_CROSS_LINKS, 16);
        assert_eq!(SESSION_LINK_KEYS[0], "parent_session_id");
        assert_eq!(SESSION_LINK_KEYS[1], "parentSessionId");
        assert_eq!(SESSION_LINK_KEYS[15], "parentThreadId");
        assert_eq!(HEAD_LINK_KEYS[0], "resume_head_id");
        assert_eq!(HEAD_LINK_KEYS[6], "parentEventId");
    }
}
