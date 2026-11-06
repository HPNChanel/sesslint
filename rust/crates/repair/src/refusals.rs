//! Documented, content-free rationale for an intentional repair refusal.
//!
//! Port of `src/sesslint/repair/refusals.py` lines 1-118
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Stops before `REFUSAL_REGISTRY` (line 121). That registry is not ported.
//! This module does not invent a bypass for SL203.
//!
//! No I/O. Rationale text is policy text. Invalid input returns [`RefusalError`]
//! and does not panic.

use std::error::Error;
use std::fmt;

use model::errors::FindingError;

/// `REFUSAL_REGISTRY` at `refusals.py` line 121 is not ported.
///
/// This module stops after [`RefusalRationale::render`]. It does not invent a
/// bypass for SL203.
pub const REFUSAL_REGISTRY_NOT_PORTED: &str = "REFUSAL_REGISTRY at refusals.py line 121 is not ported. This module stops after RefusalRationale::render and does not invent a bypass for SL203.";

/// Python `__post_init__` raises `ValueError` for an unknown code, an empty
/// rationale, an unrecognized citation, and an empty salvage path.
///
/// [`RefusalError`] `Display` is that message. This port returns the error and
/// does not panic. Content-free failures are `FindingError`, not `ValueError`.
pub const PYTHON_VALUE_ERROR: &str = "Unknown code, empty rationale, unrecognized citation, and empty salvage_path are Python ValueError. Display is the message only. This port returns RefusalError and does not panic.";

/// Python `__post_init__` also rejects a non-`str` rationale with `ValueError`.
///
/// [`RefusalRationale::try_new`] takes `&str`, so that branch is not
/// representable. This constructor does not panic to imitate it.
pub const NON_STRING_RATIONALE_UNREPRESENTABLE: &str = "A non-string rationale is not representable in &str. Python __post_init__ raises ValueError when rationale is not a str. This constructor does not panic to imitate that branch.";

/// Citation digit runs accept ASCII `0`-`9` only.
///
/// Python `re` `\d` (no `re.ASCII` flag) matches Unicode category Nd, including
/// U+0661. Those digits are rejected here and are not treated as digits.
pub const CITATION_UNICODE_DIGIT_GAP: &str = "Citation digit runs accept ASCII digits only. Python re \\d matches Unicode Nd digits such as U+0661. Those are rejected and are not treated as digits.";

/// Python `ValueError` from [`RefusalRationale::try_new`], or `FindingError`
/// from `enforce_content_free_text`.
///
/// [`Display`](fmt::Display) is the Python exception message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalError {
    /// Python `ValueError`: code is not in `CODE_REGISTRY`.
    UnknownCode { code: String },
    /// Python `ValueError`: rationale is empty after `str.strip`.
    EmptyRationale { code: String },
    /// Python `ValueError`: citation failed `_is_valid_citation`.
    UnrecognizedCitation { code: String, citation: String },
    /// Python `ValueError`: salvage path is empty after `str.strip`.
    EmptySalvagePath { code: String },
    /// Python `FindingError` from `model::finding::enforce_content_free_text`.
    ContentFree(FindingError),
}

impl fmt::Display for RefusalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCode { code } => write!(
                formatter,
                "Refusal rationale references unknown code: {}",
                python_str_repr(code)
            ),
            Self::EmptyRationale { code } => {
                write!(formatter, "Refusal rationale for {code} must be non-empty")
            }
            Self::UnrecognizedCitation { code, citation } => write!(
                formatter,
                "Refusal citation for {code} is not a recognized DEMAND anchor: {}",
                python_str_repr(citation)
            ),
            Self::EmptySalvagePath { code } => write!(
                formatter,
                "Refusal salvage_path for {code} must be non-empty or None"
            ),
            Self::ContentFree(error) => error.fmt(formatter),
        }
    }
}

impl Error for RefusalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UnknownCode { .. }
            | Self::EmptyRationale { .. }
            | Self::UnrecognizedCitation { .. }
            | Self::EmptySalvagePath { .. } => None,
            Self::ContentFree(error) => Some(error),
        }
    }
}

/// Documented, content-free rationale for an intentional repair refusal.
///
/// Python: `RefusalRationale` (`frozen=True`, `slots=True`).
///
/// Fields keep the caller's text. `str.strip` is only the emptiness check.
/// `render` does not run the content-free check on its path argument or on the
/// rendered string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalRationale {
    code: String,
    rationale: String,
    demand_citation: String,
    salvage_path: Option<String>,
}

impl RefusalRationale {
    /// Validate and build a rationale.
    ///
    /// Python: `RefusalRationale.__post_init__`. Check order is fixed:
    /// known code, non-empty rationale, citation, salvage path, then
    /// content-free checks on rationale, citation, and (when present) salvage.
    ///
    /// `salvage_path: None` is Python `None`. A non-string rationale is not
    /// representable in `&str` ([`NON_STRING_RATIONALE_UNREPRESENTABLE`]).
    ///
    /// # Errors
    ///
    /// Returns [`RefusalError`]. Unknown code, empty text, and a bad citation
    /// are Python `ValueError` ([`PYTHON_VALUE_ERROR`]). Content-free failures
    /// are `FindingError`. This function does not panic.
    pub fn try_new(
        code: &str,
        rationale: &str,
        demand_citation: &str,
        salvage_path: Option<&str>,
    ) -> Result<Self, RefusalError> {
        if !model::codes::is_valid_code(code) {
            return Err(RefusalError::UnknownCode {
                code: code.to_owned(),
            });
        }
        if python_strip(rationale).is_empty() {
            return Err(RefusalError::EmptyRationale {
                code: code.to_owned(),
            });
        }
        if !is_valid_citation(demand_citation) {
            return Err(RefusalError::UnrecognizedCitation {
                code: code.to_owned(),
                citation: demand_citation.to_owned(),
            });
        }
        if let Some(path) = salvage_path {
            if python_strip(path).is_empty() {
                return Err(RefusalError::EmptySalvagePath {
                    code: code.to_owned(),
                });
            }
        }
        enforce_content_free(rationale, &format!("refusal rationale {code}"))?;
        enforce_content_free(demand_citation, &format!("refusal citation {code}"))?;
        if let Some(path) = salvage_path {
            enforce_content_free(path, &format!("refusal salvage path {code}"))?;
        }
        Ok(Self {
            code: code.to_owned(),
            rationale: rationale.to_owned(),
            demand_citation: demand_citation.to_owned(),
            salvage_path: salvage_path.map(str::to_owned),
        })
    }

    /// Python: `code`.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Python: `rationale`.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Python: `demand_citation`.
    pub fn demand_citation(&self) -> &str {
        &self.demand_citation
    }

    /// Python: `salvage_path` (`None` when absent).
    pub fn salvage_path(&self) -> Option<&str> {
        self.salvage_path.as_deref()
    }

    /// Render the rationale, citation, and optional salvage path.
    ///
    /// Python: `render(*, path="<file>")`. Pass `None` for that default.
    /// When salvage text contains the literal substring `{path}`, each
    /// occurrence is replaced with `path` (`str.replace`, not `str.format`).
    /// The path argument and the rendered string are not content-free checked.
    pub fn render(&self, path: Option<&str>) -> String {
        let path = path.unwrap_or("<file>");
        let mut detail = format!("{} (DEMAND: {})", self.rationale, self.demand_citation);
        if let Some(salvage) = &self.salvage_path {
            detail.push_str("; salvage path: ");
            detail.push_str(&salvage.replace("{path}", path));
        }
        detail
    }
}

/// Python: `_is_valid_citation`.
///
/// True when the whole string matches one accepted DEMAND anchor. Digit runs
/// are ASCII only ([`CITATION_UNICODE_DIGIT_GAP`]).
fn is_valid_citation(citation: &str) -> bool {
    is_requirement_citation(citation)
        || is_non_goal_citation(citation)
        || is_named_policy_citation(citation)
}

fn is_requirement_citation(citation: &str) -> bool {
    let Some((prefix, digits)) = citation.split_once('-') else {
        return false;
    };
    matches!(prefix, "AC" | "FR" | "NFR" | "DEV" | "RVW") && is_exact_ascii_digits(digits, 3)
}

fn is_non_goal_citation(citation: &str) -> bool {
    let Some(digits) = citation.strip_prefix("Non-goal #") else {
        return false;
    };
    is_one_or_more_ascii_digits(digits)
}

fn is_named_policy_citation(citation: &str) -> bool {
    matches!(
        citation,
        "Conservative policy MUST refuse" | "Salvage policy MUST refuse"
    )
}

fn is_exact_ascii_digits(text: &str, exact: usize) -> bool {
    let mut count = 0usize;
    for ch in text.chars() {
        if !ch.is_ascii_digit() {
            return false;
        }
        count += 1;
        if count > exact {
            return false;
        }
    }
    count == exact
}

fn is_one_or_more_ascii_digits(text: &str) -> bool {
    let mut saw_digit = false;
    for ch in text.chars() {
        if !ch.is_ascii_digit() {
            return false;
        }
        saw_digit = true;
    }
    saw_digit
}

fn enforce_content_free(text: &str, context: &str) -> Result<(), RefusalError> {
    model::finding::enforce_content_free_text(text, context).map_err(RefusalError::ContentFree)
}

/// Python `str.strip()` with no `chars` argument.
///
/// Includes U+2028 and U+2029 (Unicode White_Space, which Rust `trim` already
/// drops) and U+001C through U+001F (Python `str.isspace`, which Rust `trim`
/// does not). Do not replace this with `str::trim` alone.
fn python_strip(value: &str) -> &str {
    let start = value
        .char_indices()
        .find(|(_, ch)| !is_python_space(*ch))
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    let tail = &value[start..];
    let end = tail
        .char_indices()
        .rev()
        .find(|(_, ch)| !is_python_space(*ch))
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    &tail[..end]
}

fn is_python_space(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{001C}'..='\u{001F}')
}

/// Python `repr` for `str` (prefer single quotes), used for `{value!r}`.
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
        is_valid_citation, RefusalError, RefusalRationale, CITATION_UNICODE_DIGIT_GAP,
        NON_STRING_RATIONALE_UNREPRESENTABLE, PYTHON_VALUE_ERROR, REFUSAL_REGISTRY_NOT_PORTED,
    };
    use std::error::Error;

    const POLICY: &str = "malformed records stay untouched";

    fn rationale(citation: &str, salvage: Option<&str>) -> Result<RefusalRationale, RefusalError> {
        RefusalRationale::try_new("SL001", POLICY, citation, salvage)
    }

    #[test]
    fn eight_citation_shapes_and_rejections() {
        let accepted = [
            "AC-004",
            "FR-023",
            "NFR-001",
            "DEV-013",
            "RVW-011",
            "Non-goal #13",
            "Conservative policy MUST refuse",
            "Salvage policy MUST refuse",
        ];
        for citation in accepted {
            assert!(is_valid_citation(citation), "{citation}");
            let built = rationale(citation, None).unwrap_or_else(|err| panic!("{citation}: {err}"));
            assert_eq!(built.demand_citation(), citation);
            assert_eq!(built.code(), "SL001");
        }

        let rejected = ["AC-04", "AC-0004", "non-goal #13"];
        for citation in rejected {
            assert!(!is_valid_citation(citation), "{citation}");
            let err = rationale(citation, None).expect_err(citation);
            assert_eq!(
                err.to_string(),
                format!(
                    "Refusal citation for SL001 is not a recognized DEMAND anchor: '{citation}'"
                )
            );
            assert!(err.source().is_none());
        }
    }

    #[test]
    fn unicode_nd_digits_are_not_citation_digits() {
        assert!(CITATION_UNICODE_DIGIT_GAP.contains("Nd"));
        assert!(CITATION_UNICODE_DIGIT_GAP.contains("U+0661"));
        assert!(!is_valid_citation("AC-\u{0660}\u{0660}\u{0664}"));
        assert!(!is_valid_citation("Non-goal #\u{0661}\u{0663}"));
        let err = rationale("AC-\u{0660}\u{0660}\u{0664}", None).expect_err("Nd digits");
        assert!(err
            .to_string()
            .starts_with("Refusal citation for SL001 is not a recognized DEMAND anchor: "));
    }

    #[test]
    fn sl001_with_ac004_succeeds() {
        let built = rationale("AC-004", None).expect("SL001 is registered");
        assert_eq!(built.rationale(), POLICY);
        assert_eq!(built.salvage_path(), None);
        assert_eq!(
            built.render(None),
            "malformed records stay untouched (DEMAND: AC-004)"
        );
    }

    #[test]
    fn unknown_code_fails_before_citation_check() {
        assert!(PYTHON_VALUE_ERROR.contains("ValueError"));
        assert!(PYTHON_VALUE_ERROR.contains("does not panic"));
        let err = RefusalRationale::try_new("SL999", "", "AC-04", Some("")).expect_err("SL999");
        assert_eq!(
            err.to_string(),
            "Refusal rationale references unknown code: 'SL999'"
        );
        assert!(err.source().is_none());
        assert!(matches!(err, RefusalError::UnknownCode { .. }));
    }

    #[test]
    fn empty_rationale_fails() {
        let cases = [
            "",
            "   ",
            "\u{001c}\u{001d}\u{001e}\u{001f}",
            "\u{2028}\u{2029}",
        ];
        for rationale_text in cases {
            let err = RefusalRationale::try_new("SL001", rationale_text, "AC-04", None)
                .expect_err("empty rationale");
            assert_eq!(
                err.to_string(),
                "Refusal rationale for SL001 must be non-empty"
            );
            assert!(matches!(err, RefusalError::EmptyRationale { .. }));
        }
    }

    #[test]
    fn bad_citation_fails() {
        let err = rationale("AC-04", Some("")).expect_err("bad citation");
        assert_eq!(
            err.to_string(),
            "Refusal citation for SL001 is not a recognized DEMAND anchor: 'AC-04'"
        );
        assert!(matches!(err, RefusalError::UnrecognizedCitation { .. }));
    }

    #[test]
    fn empty_salvage_path_fails() {
        for salvage in ["", "   ", "\u{001c}", "\u{2028}\u{2029}"] {
            let err = rationale("AC-004", Some(salvage)).expect_err("empty salvage");
            assert_eq!(
                err.to_string(),
                "Refusal salvage_path for SL001 must be non-empty or None"
            );
            assert!(matches!(err, RefusalError::EmptySalvagePath { .. }));
        }
    }

    #[test]
    fn rationale_with_email_is_rejected_by_content_free_check() {
        let rationale_text = "operator mailbox ops@example.com is out of policy";
        let err =
            RefusalRationale::try_new("SL001", rationale_text, "AC-004", None).expect_err("email");
        assert_eq!(
            err.to_string(),
            "Forbidden content-bearing pattern (e.g., email/PII) in refusal rationale SL001: 'operator mailbox ops@example.com is out of policy'"
        );
        assert!(err.source().is_some());
    }

    #[test]
    fn render_defaults_to_file_and_replaces_every_path_placeholder() {
        let salvage = "open {path} then copy {path}";
        let built = rationale("AC-004", Some(salvage)).expect("salvage");
        assert_eq!(
            built.render(None),
            "malformed records stay untouched (DEMAND: AC-004); salvage path: open <file> then copy <file>"
        );
        assert_eq!(
            built.render(Some("ledger.jsonl")),
            "malformed records stay untouched (DEMAND: AC-004); salvage path: open ledger.jsonl then copy ledger.jsonl"
        );
        assert_eq!(
            built.render(Some("ops@example.com")),
            "malformed records stay untouched (DEMAND: AC-004); salvage path: open ops@example.com then copy ops@example.com"
        );
    }

    #[test]
    fn recorded_gaps_stay_explicit() {
        assert!(REFUSAL_REGISTRY_NOT_PORTED.contains("not ported"));
        assert!(REFUSAL_REGISTRY_NOT_PORTED.contains("SL203"));
        assert!(NON_STRING_RATIONALE_UNREPRESENTABLE.contains("not representable"));
        assert!(NON_STRING_RATIONALE_UNREPRESENTABLE.contains("ValueError"));
        assert!(NON_STRING_RATIONALE_UNREPRESENTABLE.contains("does not panic"));
    }
}
