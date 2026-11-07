//! Assurance lattice and downgrade cap for repair planning (TASK-020).
//!
//! Lattice, ascending quality:
//! `unrepairable` < `salvaged` < `repaired-lossless` < `clean`.
//!
//! Port of `src/sesslint/repair/assurance.py` lines 1–163
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! No I/O, no network, and no state mutation. Invalid input returns
//! [`AssuranceError`]. This module does not read or write a ledger.

use std::error::Error;
use std::fmt;

/// Python: `ASSURANCE_LATTICE`, ascending quality. Not alphabetical.
pub const ASSURANCE_LATTICE: [&str; 4] = ["unrepairable", "salvaged", "repaired-lossless", "clean"];

/// One policy row of [`ASSURANCE_CEILING_TABLE`].
///
/// `levels` is A0 through A4 in that order. The salvage row stores A2 for both
/// A3 and A4; nothing in this module rewrites those cells upward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeilingRow {
    pub policy: &'static str,
    pub levels: [(&'static str, &'static str); 5],
}

/// Python: `ASSURANCE_CEILING_TABLE` (insertion order: conservative, then salvage).
pub const ASSURANCE_CEILING_TABLE: [CeilingRow; 2] = [
    CeilingRow {
        policy: "conservative",
        levels: [
            ("A0", "A0"),
            ("A1", "A1"),
            ("A2", "A2"),
            ("A3", "A3"),
            ("A4", "A4"),
        ],
    },
    CeilingRow {
        policy: "salvage",
        levels: [
            ("A0", "A0"),
            ("A1", "A1"),
            ("A2", "A2"),
            ("A3", "A2"),
            ("A4", "A2"),
        ],
    },
];

const VALID_A_LEVELS: [&str; 5] = ["A0", "A1", "A2", "A3", "A4"];

/// Order is the literal in `compute_assurance_ceiling`, not lattice order and not `sorted`.
const POLICY_NAMES: [&str; 5] = [
    "conservative",
    "salvage",
    "repaired-lossless",
    "salvaged",
    "clean",
];

/// Python `ValueError` from [`cap_assurance`] or [`compute_assurance_ceiling`].
///
/// [`Display`](fmt::Display) is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssuranceError {
    UnknownBase { base: String },
    InvalidRevalidation { value: String },
    InvalidPolicy { value: String },
}

impl fmt::Display for AssuranceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBase { base } => write!(
                formatter,
                "Unknown base assurance: {}. Must be one of {}",
                python_str_repr(base),
                sorted_lattice_repr(),
            ),
            Self::InvalidRevalidation { value } => write!(
                formatter,
                "Invalid revalidation assurance: {}. Must be one of {}",
                python_str_repr(value),
                python_seq_repr(&VALID_A_LEVELS, '(', ')'),
            ),
            Self::InvalidPolicy { value } => write!(
                formatter,
                "Invalid policy or pedigree: {}. Must be one of {}",
                python_str_repr(value),
                python_seq_repr(&POLICY_NAMES, '(', ')'),
            ),
        }
    }
}

impl Error for AssuranceError {}

/// Value of a `lossy` flag. Python truthiness: `None`, `0`, and `""` are false.
///
/// [`LossyFlag::Other`] is the stand-in for a Python object whose truth value is
/// already known (empty containers are false; ordinary objects are true).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossyFlag<'a> {
    None,
    Bool(bool),
    Int(i64),
    Str(&'a str),
    Other(bool),
}

/// One plan step after the Python `hasattr` / `Mapping` checks.
///
/// `lossy_attribute` is `Some` when `hasattr(step, "lossy")`. That wins over
/// `mapping_lossy`. `mapping_lossy` is `Some` when the step is a mapping;
/// the inner `Option` is the `"lossy"` key (`None` means missing, which is false).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<'a> {
    lossy_attribute: Option<LossyFlag<'a>>,
    mapping_lossy: Option<Option<LossyFlag<'a>>>,
}

impl<'a> Step<'a> {
    pub const fn attribute(flag: LossyFlag<'a>) -> Self {
        Self {
            lossy_attribute: Some(flag),
            mapping_lossy: None,
        }
    }

    /// Mapping step. `None` means the `"lossy"` key is absent.
    pub const fn mapping(lossy: Option<LossyFlag<'a>>) -> Self {
        Self {
            lossy_attribute: None,
            mapping_lossy: Some(lossy),
        }
    }

    pub const fn other() -> Self {
        Self {
            lossy_attribute: None,
            mapping_lossy: None,
        }
    }

    /// Both views are present. [`is_step_lossy`] reads the attribute and ignores the mapping.
    pub const fn attribute_and_mapping(
        attribute: LossyFlag<'a>,
        mapping: Option<LossyFlag<'a>>,
    ) -> Self {
        Self {
            lossy_attribute: Some(attribute),
            mapping_lossy: Some(mapping),
        }
    }
}

/// Payload of a mapping that contains the `"steps"` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingSteps<'a> {
    /// `list(raw_steps)` when the value is iterable, including a `str` or `bytes` payload.
    Iterable(&'a [Step<'a>]),
    /// Key present, value not iterable. Python stores no steps.
    NotIterable,
}

/// Repair plan after the same branch order as `cap_assurance`.
///
/// 1. [`Plan::AttributeSteps`] when `hasattr(plan, "steps")`.
/// 2. [`Plan::Mapping`] when it is a mapping that contains `"steps"`.
/// 3. [`Plan::Str`] and [`Plan::Bytes`] are not step lists.
/// 4. [`Plan::Iterable`] for any other iterable. A mapping with no `"steps"` key
///    falls through to this branch: pass `list(mapping)` (its keys) as the steps.
/// 5. [`Plan::Other`] for a non-iterable such as an int.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan<'a> {
    AttributeSteps(&'a [Step<'a>]),
    Mapping(MappingSteps<'a>),
    Str,
    Bytes,
    Iterable(&'a [Step<'a>]),
    Other,
}

/// Python: `_is_step_lossy`.
#[must_use]
pub fn is_step_lossy(step: &Step<'_>) -> bool {
    if let Some(flag) = step.lossy_attribute {
        return is_truthy(flag);
    }
    if let Some(mapping_flag) = step.mapping_lossy {
        return match mapping_flag {
            Some(flag) => is_truthy(flag),
            None => false,
        };
    }
    false
}

/// Python: `cap_assurance`.
///
/// Empty steps leave `base` unchanged. That includes a blocked-only plan.
/// Any lossy step returns `min(base, "salvaged")`. Steps with none lossy return
/// `min(base, "repaired-lossless")`.
pub fn cap_assurance(base: &str, plan: &Plan<'_>) -> Result<&'static str, AssuranceError> {
    if lattice_rank(base).is_none() {
        return Err(AssuranceError::UnknownBase {
            base: base.to_owned(),
        });
    }
    let steps = plan_steps(plan);
    if steps.is_empty() {
        return Ok(static_level(base));
    }
    if steps.iter().any(is_step_lossy) {
        return cap_min(base, "salvaged");
    }
    cap_min(base, "repaired-lossless")
}

/// Python: `compute_assurance_ceiling`.
///
/// The A-level is stripped and uppercased. The policy is stripped and lowercased.
/// Error text uses the original strings. Salvage and salvaged cap A3 and A4 at A2.
pub fn compute_assurance_ceiling(
    revalidation_assurance: &str,
    policy_or_pedigree: &str,
) -> Result<&'static str, AssuranceError> {
    let clean_reval = python_strip(revalidation_assurance).to_uppercase();
    if !VALID_A_LEVELS.contains(&clean_reval.as_str()) {
        return Err(AssuranceError::InvalidRevalidation {
            value: revalidation_assurance.to_owned(),
        });
    }
    let norm_pol = python_strip(policy_or_pedigree).to_lowercase();
    let key =
        if norm_pol == "conservative" || norm_pol == "repaired-lossless" || norm_pol == "clean" {
            "conservative"
        } else if norm_pol == "salvage" || norm_pol == "salvaged" {
            "salvage"
        } else {
            return Err(AssuranceError::InvalidPolicy {
                value: policy_or_pedigree.to_owned(),
            });
        };
    match ceiling_value(key, &clean_reval) {
        Some(level) => Ok(level),
        None => Err(AssuranceError::InvalidRevalidation {
            value: revalidation_assurance.to_owned(),
        }),
    }
}

fn plan_steps<'a>(plan: &'a Plan<'a>) -> &'a [Step<'a>] {
    match plan {
        Plan::AttributeSteps(steps) => steps,
        Plan::Mapping(MappingSteps::Iterable(steps)) => steps,
        Plan::Mapping(MappingSteps::NotIterable) => &[],
        Plan::Str | Plan::Bytes => &[],
        Plan::Iterable(steps) => steps,
        Plan::Other => &[],
    }
}

fn lattice_rank(name: &str) -> Option<usize> {
    ASSURANCE_LATTICE
        .iter()
        .position(|candidate| *candidate == name)
}

fn static_level(name: &str) -> &'static str {
    match ASSURANCE_LATTICE
        .iter()
        .copied()
        .find(|candidate| *candidate == name)
    {
        Some(level) => level,
        None => "unrepairable",
    }
}

fn cap_min(base: &str, ceiling: &'static str) -> Result<&'static str, AssuranceError> {
    let base_rank = match lattice_rank(base) {
        Some(rank) => rank,
        None => {
            return Err(AssuranceError::UnknownBase {
                base: base.to_owned(),
            });
        }
    };
    let ceiling_rank = match lattice_rank(ceiling) {
        Some(rank) => rank,
        None => return Ok("unrepairable"),
    };
    if base_rank < ceiling_rank {
        Ok(static_level(base))
    } else {
        Ok(ceiling)
    }
}

fn ceiling_value(policy: &str, level: &str) -> Option<&'static str> {
    ASSURANCE_CEILING_TABLE.iter().find_map(|row| {
        if row.policy != policy {
            return None;
        }
        row.levels
            .iter()
            .find_map(|(name, value)| (*name == level).then_some(*value))
    })
}

fn is_truthy(flag: LossyFlag<'_>) -> bool {
    match flag {
        LossyFlag::None => false,
        LossyFlag::Bool(value) => value,
        LossyFlag::Int(value) => value != 0,
        LossyFlag::Str(value) => !value.is_empty(),
        LossyFlag::Other(value) => value,
    }
}

fn python_isspace(ch: char) -> bool {
    // Python `str.isspace` includes U+001C..=U+001F. Rust `char::is_whitespace` does not.
    matches!(ch, '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{1f}') || ch.is_whitespace()
}

fn python_strip(value: &str) -> &str {
    let start = value
        .char_indices()
        .find(|(_, ch)| !python_isspace(*ch))
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    let tail = &value[start..];
    let end = tail
        .char_indices()
        .rev()
        .find(|(_, ch)| !python_isspace(*ch))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    &tail[..end]
}

fn sorted_lattice_repr() -> String {
    let mut names = ASSURANCE_LATTICE;
    names.sort();
    python_seq_repr(&names, '[', ']')
}

fn python_seq_repr(values: &[&str], open: char, close: char) -> String {
    let mut out = String::new();
    out.push(open);
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(value));
    }
    out.push(close);
    out
}

fn python_str_repr(value: &str) -> String {
    let use_double = value.contains('\'') && !value.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\'' if !use_double => out.push_str("\\'"),
            '"' if use_double => out.push_str("\\\""),
            other if is_python_printable(other) => out.push(other),
            other => push_python_escape(&mut out, other),
        }
    }
    out.push(quote);
    out
}

fn is_python_printable(ch: char) -> bool {
    if ch == ' ' || ch.is_ascii_graphic() {
        return true;
    }
    if ch.is_ascii() {
        return false;
    }
    !is_python_nonprintable_non_ascii(ch)
}

fn is_python_nonprintable_non_ascii(ch: char) -> bool {
    if ch.is_control() || ch.is_whitespace() || is_noncharacter(u32::from(ch)) {
        return true;
    }
    const RANGES: [(u32, u32); 18] = [
        (0x00AD, 0x00AD),
        (0x0600, 0x0605),
        (0x061C, 0x061C),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x0890, 0x0891),
        (0x08E2, 0x08E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0xE000, 0xF8FF),
        (0xF0000, 0xFFFFD),
        (0x100000, 0x10FFFD),
        (0xE0001, 0xE0001),
    ];
    let code = u32::from(ch);
    RANGES
        .iter()
        .any(|(start, end)| code >= *start && code <= *end)
        || matches!(
            code,
            0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A
        )
        || (0xE0020..=0xE007F).contains(&code)
        || (0xE0100..=0xE01EF).contains(&code)
}

fn is_noncharacter(code: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&code) || (code & 0xFFFE) == 0xFFFE
}

fn push_python_escape(out: &mut String, ch: char) {
    let code = u32::from(ch);
    if code < 0x100 {
        push_hex(out, "\\x", code, 2);
    } else if code < 0x10000 {
        push_hex(out, "\\u", code, 4);
    } else {
        push_hex(out, "\\U", code, 8);
    }
}

fn push_hex(out: &mut String, prefix: &str, value: u32, width: usize) {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    out.push_str(prefix);
    for shift in (0..width).rev() {
        let nibble = ((value >> (shift * 4)) & 0xf) as usize;
        out.push(char::from(HEX[nibble]));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        cap_assurance, compute_assurance_ceiling, is_step_lossy, AssuranceError, CeilingRow,
        LossyFlag, MappingSteps, Plan, Step, ASSURANCE_CEILING_TABLE, ASSURANCE_LATTICE,
    };
    use std::error::Error;

    const SORTED_LIST: &str = "['clean', 'repaired-lossless', 'salvaged', 'unrepairable']";
    const A_TUPLE: &str = "('A0', 'A1', 'A2', 'A3', 'A4')";
    const POLICY_TUPLE: &str =
        "('conservative', 'salvage', 'repaired-lossless', 'salvaged', 'clean')";

    fn lossy_step() -> Step<'static> {
        Step::attribute(LossyFlag::Bool(true))
    }

    fn lossless_step() -> Step<'static> {
        Step::attribute(LossyFlag::Bool(false))
    }

    fn assert_message(err: &AssuranceError, expected: &str) {
        assert_eq!(err.to_string(), expected);
        assert!(err.source().is_none());
        assert!(!expected.starts_with("AssuranceError"));
        assert!(!expected.starts_with("ValueError"));
    }

    #[test]
    fn lattice_slice_is_ascending_quality() {
        assert_eq!(
            ASSURANCE_LATTICE,
            ["unrepairable", "salvaged", "repaired-lossless", "clean",]
        );
    }

    #[test]
    fn ceiling_table_is_fixed_and_salvage_stops_at_a2() {
        assert_eq!(
            ASSURANCE_CEILING_TABLE.map(|row| row.policy),
            ["conservative", "salvage"]
        );
        for row in ASSURANCE_CEILING_TABLE {
            let keys = row.levels.map(|(name, _)| name);
            assert_eq!(keys, ["A0", "A1", "A2", "A3", "A4"]);
        }
        assert_eq!(salvage_row().levels[3], ("A3", "A2"));
        assert_eq!(salvage_row().levels[4], ("A4", "A2"));
        for (_, value) in salvage_row().levels {
            assert!(value == "A0" || value == "A1" || value == "A2");
        }
    }

    fn salvage_row() -> &'static CeilingRow {
        &ASSURANCE_CEILING_TABLE[1]
    }

    #[test]
    fn truthiness_and_attribute_before_mapping() {
        assert!(!is_step_lossy(&Step::attribute(LossyFlag::None)));
        assert!(!is_step_lossy(&Step::attribute(LossyFlag::Bool(false))));
        assert!(!is_step_lossy(&Step::attribute(LossyFlag::Int(0))));
        assert!(!is_step_lossy(&Step::attribute(LossyFlag::Str(""))));
        assert!(!is_step_lossy(&Step::attribute(LossyFlag::Other(false))));
        assert!(is_step_lossy(&Step::attribute(LossyFlag::Bool(true))));
        assert!(is_step_lossy(&Step::attribute(LossyFlag::Int(1))));
        assert!(is_step_lossy(&Step::attribute(LossyFlag::Int(-2))));
        assert!(is_step_lossy(&Step::attribute(LossyFlag::Str("x"))));
        assert!(is_step_lossy(&Step::attribute(LossyFlag::Str("0"))));
        assert!(is_step_lossy(&Step::attribute(LossyFlag::Str(" "))));
        assert!(is_step_lossy(&Step::attribute(LossyFlag::Other(true))));

        assert!(!is_step_lossy(&Step::mapping(None)));
        assert!(!is_step_lossy(&Step::mapping(Some(LossyFlag::None))));
        assert!(!is_step_lossy(&Step::mapping(Some(LossyFlag::Int(0)))));
        assert!(!is_step_lossy(&Step::mapping(Some(LossyFlag::Str("")))));
        assert!(is_step_lossy(&Step::mapping(Some(LossyFlag::Bool(true)))));
        assert!(!is_step_lossy(&Step::other()));

        let attribute_wins =
            Step::attribute_and_mapping(LossyFlag::Bool(false), Some(LossyFlag::Bool(true)));
        assert!(!is_step_lossy(&attribute_wins));
        let attribute_lossy =
            Step::attribute_and_mapping(LossyFlag::Int(0), Some(LossyFlag::Str("x")));
        assert!(!is_step_lossy(&attribute_lossy));
    }

    #[test]
    fn twelve_cell_matrix_on_attribute_mapping_and_iterable() {
        let lossy = [lossy_step()];
        let lossless = [lossless_step()];
        let cases = [
            ("clean", true, "salvaged"),
            ("clean", false, "repaired-lossless"),
            ("repaired-lossless", true, "salvaged"),
            ("repaired-lossless", false, "repaired-lossless"),
            ("salvaged", true, "salvaged"),
            ("salvaged", false, "salvaged"),
            ("unrepairable", true, "unrepairable"),
            ("unrepairable", false, "unrepairable"),
        ];
        for (base, is_lossy, expected) in cases {
            let steps: &[Step<'_>] = if is_lossy { &lossy } else { &lossless };
            assert_eq!(
                cap_assurance(base, &Plan::AttributeSteps(steps)),
                Ok(expected)
            );
            assert_eq!(
                cap_assurance(base, &Plan::Mapping(MappingSteps::Iterable(steps))),
                Ok(expected)
            );
            assert_eq!(cap_assurance(base, &Plan::Iterable(steps)), Ok(expected));
        }
    }

    #[test]
    fn no_steps_leave_every_base_unchanged() {
        let plans = [
            Plan::AttributeSteps(&[]),
            Plan::Mapping(MappingSteps::Iterable(&[])),
            Plan::Mapping(MappingSteps::NotIterable),
            Plan::Iterable(&[]),
            Plan::Str,
            Plan::Bytes,
            Plan::Other,
        ];
        for base in ASSURANCE_LATTICE {
            for plan in &plans {
                assert_eq!(cap_assurance(base, plan), Ok(base));
            }
        }
    }

    #[test]
    fn mixed_steps_follow_any_lossy() {
        let lossy_then_clean = [lossy_step(), lossless_step()];
        let clean_then_lossy = [lossless_step(), lossy_step()];
        let both_clean = [lossless_step(), Step::other(), Step::mapping(None)];
        assert_eq!(
            cap_assurance("clean", &Plan::Iterable(&lossy_then_clean)),
            Ok("salvaged")
        );
        assert_eq!(
            cap_assurance("clean", &Plan::AttributeSteps(&clean_then_lossy)),
            Ok("salvaged")
        );
        assert_eq!(
            cap_assurance("clean", &Plan::Mapping(MappingSteps::Iterable(&both_clean))),
            Ok("repaired-lossless")
        );
        assert_eq!(
            cap_assurance("unrepairable", &Plan::Iterable(&clean_then_lossy)),
            Ok("unrepairable")
        );
    }

    #[test]
    fn listed_non_lossy_characters_cap_clean() {
        // Python `{"steps": "ab"}` does list("ab") and neither character is lossy.
        let characters = [Step::other(), Step::other()];
        assert_eq!(
            cap_assurance("clean", &Plan::Mapping(MappingSteps::Iterable(&characters))),
            Ok("repaired-lossless")
        );
    }

    #[test]
    fn mapping_without_steps_key_iterates_keys() {
        // Python falls through and lists the mapping keys. A string key is not lossy.
        let keys = [Step::other()];
        assert_eq!(
            cap_assurance("clean", &Plan::Iterable(&keys)),
            Ok("repaired-lossless")
        );
        assert_eq!(cap_assurance("clean", &Plan::Iterable(&[])), Ok("clean"));
    }

    #[test]
    fn unknown_base_uses_sorted_lattice_and_python_repr() {
        let plan = Plan::AttributeSteps(&[lossy_step()]);
        let cases = [
            (
                "invalid-level",
                format!("Unknown base assurance: 'invalid-level'. Must be one of {SORTED_LIST}"),
            ),
            (
                " clean ",
                format!("Unknown base assurance: ' clean '. Must be one of {SORTED_LIST}"),
            ),
            (
                "Clean",
                format!("Unknown base assurance: 'Clean'. Must be one of {SORTED_LIST}"),
            ),
            (
                "a\\b",
                format!("Unknown base assurance: 'a\\\\b'. Must be one of {SORTED_LIST}"),
            ),
            (
                "a\nb",
                format!("Unknown base assurance: 'a\\nb'. Must be one of {SORTED_LIST}"),
            ),
            (
                "x\u{0}y",
                format!("Unknown base assurance: 'x\\x00y'. Must be one of {SORTED_LIST}"),
            ),
            (
                "\u{a0}",
                format!("Unknown base assurance: '\\xa0'. Must be one of {SORTED_LIST}"),
            ),
            (
                "\u{200b}",
                format!("Unknown base assurance: '\\u200b'. Must be one of {SORTED_LIST}"),
            ),
            (
                "é",
                format!("Unknown base assurance: 'é'. Must be one of {SORTED_LIST}"),
            ),
            (
                "nope'quote",
                format!("Unknown base assurance: \"nope'quote\". Must be one of {SORTED_LIST}"),
            ),
            (
                "a\"b",
                format!("Unknown base assurance: 'a\"b'. Must be one of {SORTED_LIST}"),
            ),
            (
                "a'\"b",
                format!("Unknown base assurance: 'a\\'\"b'. Must be one of {SORTED_LIST}"),
            ),
        ];
        for (base, expected) in cases {
            let err = cap_assurance(base, &plan).expect_err("unknown base");
            assert_eq!(
                err,
                AssuranceError::UnknownBase {
                    base: base.to_owned()
                }
            );
            assert_message(&err, &expected);
        }
    }

    #[test]
    fn ceiling_matrix_preserves_conservative_and_caps_salvage() {
        for level in ["A0", "A1", "A2", "A3", "A4"] {
            assert_eq!(compute_assurance_ceiling(level, "conservative"), Ok(level));
            assert_eq!(
                compute_assurance_ceiling(level, "repaired-lossless"),
                Ok(level)
            );
            assert_eq!(compute_assurance_ceiling(level, "clean"), Ok(level));
        }
        assert_eq!(compute_assurance_ceiling("A0", "salvage"), Ok("A0"));
        assert_eq!(compute_assurance_ceiling("A1", "salvage"), Ok("A1"));
        assert_eq!(compute_assurance_ceiling("A2", "salvage"), Ok("A2"));
        assert_eq!(compute_assurance_ceiling("A3", "salvage"), Ok("A2"));
        assert_eq!(compute_assurance_ceiling("A4", "salvage"), Ok("A2"));
        assert_eq!(compute_assurance_ceiling("A3", "salvaged"), Ok("A2"));
        assert_eq!(compute_assurance_ceiling("A4", "salvaged"), Ok("A2"));
        assert_eq!(compute_assurance_ceiling("A4", "  SaLvAgE "), Ok("A2"));
        assert_eq!(
            compute_assurance_ceiling("\u{1c}A3", "\tSalvaged\n"),
            Ok("A2")
        );
        assert_eq!(
            compute_assurance_ceiling("\u{a0}a4 ", " RePaired-Lossless "),
            Ok("A4")
        );
        assert_eq!(compute_assurance_ceiling(" a1 ", " Clean "), Ok("A1"));
    }

    #[test]
    fn ceiling_errors_keep_original_repr_and_check_a_level_first() {
        let invalid_level =
            compute_assurance_ceiling("INVALID", "conservative").expect_err("invalid level");
        assert_message(
            &invalid_level,
            &format!("Invalid revalidation assurance: 'INVALID'. Must be one of {A_TUPLE}"),
        );
        let spaced = compute_assurance_ceiling(" A9 ", "conservative").expect_err("spaced level");
        assert_eq!(
            spaced,
            AssuranceError::InvalidRevalidation {
                value: " A9 ".to_owned(),
            }
        );
        assert_message(
            &spaced,
            &format!("Invalid revalidation assurance: ' A9 '. Must be one of {A_TUPLE}"),
        );
        let empty = compute_assurance_ceiling("", "conservative").expect_err("empty level");
        assert_message(
            &empty,
            &format!("Invalid revalidation assurance: ''. Must be one of {A_TUPLE}"),
        );

        let policy = compute_assurance_ceiling("A3", "unknown_policy").expect_err("bad policy");
        assert_message(
            &policy,
            &format!("Invalid policy or pedigree: 'unknown_policy'. Must be one of {POLICY_TUPLE}"),
        );
        let spaced_policy =
            compute_assurance_ceiling("A3", " unknown ").expect_err("spaced policy");
        assert_eq!(
            spaced_policy,
            AssuranceError::InvalidPolicy {
                value: " unknown ".to_owned(),
            }
        );
        assert_message(
            &spaced_policy,
            &format!("Invalid policy or pedigree: ' unknown '. Must be one of {POLICY_TUPLE}"),
        );
        let lossy_alias =
            compute_assurance_ceiling("A2", "lossy").expect_err("lossy is not a policy");
        assert_message(
            &lossy_alias,
            &format!("Invalid policy or pedigree: 'lossy'. Must be one of {POLICY_TUPLE}"),
        );
        let unrepairable = compute_assurance_ceiling("A2", "unrepairable")
            .expect_err("lattice name is not a policy");
        assert_message(
            &unrepairable,
            &format!("Invalid policy or pedigree: 'unrepairable'. Must be one of {POLICY_TUPLE}"),
        );

        let both = compute_assurance_ceiling("nope", "bad").expect_err("both invalid");
        assert_message(
            &both,
            &format!("Invalid revalidation assurance: 'nope'. Must be one of {A_TUPLE}"),
        );
    }
}
