//! Safe value formatting and bounded discriminator echo for adapter findings (DEV-008, FR-081).
//!
//! Port of `src/sesslint/adapters/safe_value.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–98.
//!
//! Helpers format finding evidence without leaking sensitive field values or
//! unconstrained hostile type strings into diagnostic reports.
//!
//! [`safe_discriminator`] echoes a string only when every byte is in
//! `[A-Za-z0-9_.-]`, the length is 1 through 64, and the later checks all miss.
//! Every other value is the [`safe_type_value`] shape with `truncated = true`.
//!
//! Check order matches Python: allowlist, [`SECRET_FAMILIES`] on the ASCII
//! bytes, [`enforce_content_free_text`], then the lowercased credential
//! prefixes and the sensitive-discriminator walk. A [`FindingError`] from
//! content-free enforcement becomes that truncated shape. It is not a new
//! error type.
//!
//! The allowlist and the sensitive pattern are walked on bytes. There is no
//! `regex` dependency. The sensitive walk runs only after the allowlist, so
//! the input is ASCII and `(?i)` is ASCII case-folding.
//!
//! Gaps vs Python (recorded, not papered over):
//! - A `str` subclass keeps its own `__name__` and still passes `isinstance(val, str)`.
//!   [`PyValue::Str`] is always reported as `str`.
//! - A Rust `&str` cannot contain a lone surrogate, so this port never sees one.

use model::errors::FindingError;
use model::finding::enforce_content_free_text;
use model::secret_families::SECRET_FAMILIES;

/// Python `__all__`, in that order.
pub const ALL: [&str; 2] = ["safe_discriminator", "safe_type_value"];

/// Python: `_CREDENTIAL_PREFIXES`. Compared after ASCII lowercasing.
const CREDENTIAL_PREFIXES: [&str; 21] = [
    "sk-",
    "sk_",
    "rk-",
    "rk_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "akia",
    "asia",
    "aiza",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "xoxa-",
    "xoxr-",
    "slack_token_",
    "bearer-",
    "bearer_",
];

/// Python `_DISCRIMINATOR_ALLOWLIST` minimum, inclusive.
const DISCRIMINATOR_MIN_LEN: usize = 1;
/// Python `_DISCRIMINATOR_ALLOWLIST` maximum, inclusive.
const DISCRIMINATOR_MAX_LEN: usize = 64;

/// Python value observed by [`safe_type_value`] and [`safe_discriminator`].
///
/// Sized containers store a length only. Their elements are not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyValue<'a> {
    /// Python `str`.
    Str(&'a str),
    /// Python `bytes`. The length is `len(val)`.
    Bytes(usize),
    /// Python `list`.
    List(usize),
    /// Python `dict`.
    Dict(usize),
    /// Python `set`. `frozenset` is not a `set`; callers use [`Self::Other`].
    Set(usize),
    /// Python `tuple`.
    Tuple(usize),
    /// Python `None`.
    None,
    /// Python `int`. `bool` is [`Self::Bool`], even though `bool` subclasses `int`.
    Int,
    /// Python `float`.
    Float,
    /// Python `bool`.
    Bool,
    /// Any other type. `type_name` is `type(val).__name__`.
    Other(&'a str),
}

/// Return a safe type and size descriptor without leaking field content (FR-081, FR-082).
///
/// Python: `safe_type_value`. `str` length is the Unicode scalar count, which
/// matches Python `len` for every string Rust can represent.
pub fn safe_type_value(val: PyValue<'_>) -> String {
    match val {
        PyValue::Str(text) => {
            let len = text.chars().count();
            format!("<str:len={len}>")
        }
        PyValue::Bytes(len) => format!("<bytes:len={len}>"),
        PyValue::List(len) => format!("<list:len={len}>"),
        PyValue::Dict(len) => format!("<dict:len={len}>"),
        PyValue::Set(len) => format!("<set:len={len}>"),
        PyValue::Tuple(len) => format!("<tuple:len={len}>"),
        PyValue::None => "<NoneType>".to_owned(),
        PyValue::Int => "<int>".to_owned(),
        PyValue::Float => "<float>".to_owned(),
        PyValue::Bool => "<bool>".to_owned(),
        PyValue::Other(name) => format!("<{name}>"),
    }
}

/// Echo `val` verbatim when it is an allowlisted, content-free discriminator.
///
/// Python: `safe_discriminator`. Returns `(type_value, is_truncated)`.
///
/// Echo verbatim only for `^[A-Za-z0-9_.-]{1,64}$` with no secret-family span,
/// no [`FindingError`] from [`enforce_content_free_text`], no credential
/// prefix, and no sensitive-discriminator hit. Otherwise return
/// [`safe_type_value`] and `true`.
pub fn safe_discriminator(val: PyValue<'_>) -> (String, bool) {
    let PyValue::Str(text) = val else {
        return (safe_type_value(val), true);
    };
    let shape = safe_type_value(PyValue::Str(text));
    if !discriminator_allowlist(text) {
        return (shape, true);
    }
    let bytes = text.as_bytes();
    if secret_family_hit(bytes) {
        return (shape, true);
    }
    let content_free: Result<(), FindingError> =
        enforce_content_free_text(text, "safe_discriminator");
    if content_free.is_err() {
        return (shape, true);
    }
    if credential_prefix(bytes) || sensitive_discriminator(bytes) {
        return (shape, true);
    }
    (text.to_owned(), false)
}

/// Python `_DISCRIMINATOR_ALLOWLIST`: `^[A-Za-z0-9_.-]{1,64}$`.
///
/// A non-ASCII scalar encodes to bytes outside that class, so a byte walk
/// matches Python's character walk on every `str` this port can see.
fn discriminator_allowlist(text: &str) -> bool {
    let bytes = text.as_bytes();
    (DISCRIMINATOR_MIN_LEN..=DISCRIMINATOR_MAX_LEN).contains(&bytes.len())
        && bytes.iter().copied().all(is_allowlist_byte)
}

const fn is_allowlist_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

/// Python: `any(pattern.search(val.encode("ascii")) for _, pattern, _ in SECRET_FAMILIES)`.
///
/// A returned span is a hit. The allowlist has already required ASCII, so
/// these bytes are `val.encode("ascii")`.
fn secret_family_hit(bytes: &[u8]) -> bool {
    SECRET_FAMILIES
        .iter()
        .any(|family| (family.search)(bytes).is_some())
}

/// Python: `any(val.lower().startswith(prefix) for prefix in _CREDENTIAL_PREFIXES)`.
fn credential_prefix(bytes: &[u8]) -> bool {
    CREDENTIAL_PREFIXES
        .iter()
        .any(|prefix| starts_with_ignore_ascii_case(bytes, prefix.as_bytes()))
}

fn starts_with_ignore_ascii_case(haystack: &[u8], prefix: &[u8]) -> bool {
    match haystack.get(..prefix.len()) {
        Some(slice) => slice
            .iter()
            .zip(prefix.iter())
            .all(|(got, want)| got.eq_ignore_ascii_case(want)),
        None => false,
    }
}

/// Python `_SENSITIVE_DISCRIMINATOR_PATTERN.search`.
///
/// Existence walk of the pinned `(?i)` expression. `^` is the start of the
/// string. A delimiter is `_`, `-`, or `.`.
fn sensitive_discriminator(haystack: &[u8]) -> bool {
    if sensitive_alternative(haystack, 0) {
        return true;
    }
    haystack.iter().enumerate().any(|(index, byte)| {
        matches!(byte, b'_' | b'-' | b'.') && sensitive_alternative(haystack, index + 1)
    })
}

fn sensitive_alternative(haystack: &[u8], at: usize) -> bool {
    marker_sk_rk(haystack, at)
        || marker_github(haystack, at)
        || marker_gitlab(haystack, at)
        || marker_aws(haystack, at)
        || marker_google(haystack, at)
        || marker_xox(haystack, at)
        || marker_npm(haystack, at)
        || marker_huggingface(haystack, at)
        || marker_slack_token(haystack, at)
        || marker_bearer(haystack, at)
        || marker_cloud_account(haystack, at)
}

/// `(?:sk|rk)[_\-]`.
fn marker_sk_rk(haystack: &[u8], at: usize) -> bool {
    let Some(after) =
        ascii_prefix(haystack, at, b"sk").or_else(|| ascii_prefix(haystack, at, b"rk"))
    else {
        return false;
    };
    one_separator(haystack, after).is_some()
}

/// `gh[pousr]_[A-Za-z0-9]`.
fn marker_github(haystack: &[u8], at: usize) -> bool {
    let Some(after_gh) = ascii_prefix(haystack, at, b"gh") else {
        return false;
    };
    let Some(letter) = haystack.get(after_gh) else {
        return false;
    };
    if !matches!(
        letter.to_ascii_lowercase(),
        b'p' | b'o' | b'u' | b's' | b'r'
    ) {
        return false;
    }
    let Some(underscore) = after_gh.checked_add(1) else {
        return false;
    };
    if haystack.get(underscore) != Some(&b'_') {
        return false;
    }
    let Some(alnum) = underscore.checked_add(1) else {
        return false;
    };
    haystack
        .get(alnum)
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
}

/// `glpat-[A-Za-z0-9]`.
fn marker_gitlab(haystack: &[u8], at: usize) -> bool {
    let Some(after) = ascii_prefix(haystack, at, b"glpat-") else {
        return false;
    };
    haystack
        .get(after)
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
}

/// `(?:akia|asia)[0-9a-z]{16}` under `(?i)`, so the body is ASCII alphanumeric.
fn marker_aws(haystack: &[u8], at: usize) -> bool {
    let Some(after) =
        ascii_prefix(haystack, at, b"akia").or_else(|| ascii_prefix(haystack, at, b"asia"))
    else {
        return false;
    };
    run_at_least(haystack, after, 16, is_ascii_alnum)
}

/// `aiza[0-9a-z_\-]{20,}`.
fn marker_google(haystack: &[u8], at: usize) -> bool {
    let Some(after) = ascii_prefix(haystack, at, b"aiza") else {
        return false;
    };
    run_at_least(haystack, after, 20, is_google_body)
}

/// `xox[a-z]-[0-9a-z]`.
fn marker_xox(haystack: &[u8], at: usize) -> bool {
    let Some(after) = ascii_prefix(haystack, at, b"xox") else {
        return false;
    };
    let Some(letter) = haystack.get(after) else {
        return false;
    };
    if !letter.is_ascii_alphabetic() {
        return false;
    }
    let Some(hyphen) = after.checked_add(1) else {
        return false;
    };
    if haystack.get(hyphen) != Some(&b'-') {
        return false;
    }
    let Some(alnum) = hyphen.checked_add(1) else {
        return false;
    };
    haystack
        .get(alnum)
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
}

/// `npm_[a-z0-9]{20,}`.
fn marker_npm(haystack: &[u8], at: usize) -> bool {
    let Some(after) = ascii_prefix(haystack, at, b"npm_") else {
        return false;
    };
    run_at_least(haystack, after, 20, is_ascii_alnum)
}

/// `hf_[a-z0-9]{20,}`.
fn marker_huggingface(haystack: &[u8], at: usize) -> bool {
    let Some(after) = ascii_prefix(haystack, at, b"hf_") else {
        return false;
    };
    run_at_least(haystack, after, 20, is_ascii_alnum)
}

/// `slack[_\-]token[_\-]`.
fn marker_slack_token(haystack: &[u8], at: usize) -> bool {
    let Some(after_slack) = ascii_prefix(haystack, at, b"slack") else {
        return false;
    };
    let Some(after_sep) = one_separator(haystack, after_slack) else {
        return false;
    };
    let Some(after_token) = ascii_prefix(haystack, after_sep, b"token") else {
        return false;
    };
    one_separator(haystack, after_token).is_some()
}

/// `bearer[_\-]`.
fn marker_bearer(haystack: &[u8], at: usize) -> bool {
    let Some(after) = ascii_prefix(haystack, at, b"bearer") else {
        return false;
    };
    one_separator(haystack, after).is_some()
}

/// `(?:azure|gcp)[_\-](?:client[_\-]?secret|service[_\-]?account|private[_\-]?key)[_\-][a-z0-9]{8,}`.
fn marker_cloud_account(haystack: &[u8], at: usize) -> bool {
    let Some(after_vendor) =
        ascii_prefix(haystack, at, b"azure").or_else(|| ascii_prefix(haystack, at, b"gcp"))
    else {
        return false;
    };
    let Some(after_sep) = one_separator(haystack, after_vendor) else {
        return false;
    };
    cloud_pair(haystack, after_sep, b"client", b"secret")
        || cloud_pair(haystack, after_sep, b"service", b"account")
        || cloud_pair(haystack, after_sep, b"private", b"key")
}

/// `head[_\-]?tail[_\-][a-z0-9]{8,}`. The optional separator is greedy, then backtracks.
fn cloud_pair(haystack: &[u8], at: usize, head: &[u8], tail: &[u8]) -> bool {
    let Some(after_head) = ascii_prefix(haystack, at, head) else {
        return false;
    };
    if let Some(after_sep) = one_separator(haystack, after_head) {
        if let Some(after_tail) = ascii_prefix(haystack, after_sep, tail) {
            if cloud_suffix(haystack, after_tail) {
                return true;
            }
        }
    }
    let Some(after_tail) = ascii_prefix(haystack, after_head, tail) else {
        return false;
    };
    cloud_suffix(haystack, after_tail)
}

fn cloud_suffix(haystack: &[u8], at: usize) -> bool {
    let Some(after_sep) = one_separator(haystack, at) else {
        return false;
    };
    run_at_least(haystack, after_sep, 8, is_ascii_alnum)
}

fn one_separator(haystack: &[u8], at: usize) -> Option<usize> {
    match haystack.get(at) {
        Some(b'_' | b'-') => at.checked_add(1),
        _ => None,
    }
}

fn ascii_prefix(haystack: &[u8], at: usize, literal: &[u8]) -> Option<usize> {
    let end = at.checked_add(literal.len())?;
    let slice = haystack.get(at..end)?;
    slice
        .iter()
        .zip(literal.iter())
        .all(|(got, want)| got.eq_ignore_ascii_case(want))
        .then_some(end)
}

fn run_at_least(haystack: &[u8], start: usize, min: usize, class: fn(u8) -> bool) -> bool {
    let mut seen = 0;
    let mut index = start;
    while seen < min {
        let Some(byte) = haystack.get(index) else {
            return false;
        };
        if !class(*byte) {
            return false;
        }
        seen += 1;
        index = match index.checked_add(1) {
            Some(next) => next,
            None => return false,
        };
    }
    true
}

const fn is_ascii_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

const fn is_google_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

#[cfg(test)]
mod tests {
    use super::{
        credential_prefix, safe_discriminator, safe_type_value, secret_family_hit,
        sensitive_discriminator, PyValue, ALL, CREDENTIAL_PREFIXES,
    };
    use model::errors::FindingError;
    use model::finding::enforce_content_free_text;

    fn assert_echo(text: &str) {
        let (shown, truncated) = safe_discriminator(PyValue::Str(text));
        assert!(!truncated);
        assert_eq!(shown, text);
    }

    fn assert_truncated(text: &str) {
        let (shown, truncated) = safe_discriminator(PyValue::Str(text));
        assert!(truncated);
        let len = text.chars().count();
        assert_eq!(shown, format!("<str:len={len}>"));
    }

    fn assert_non_string(val: PyValue<'_>, shape: &str) {
        assert_eq!(safe_type_value(val), shape);
        let (shown, truncated) = safe_discriminator(val);
        assert!(truncated);
        assert_eq!(shown, shape);
    }

    fn filled(prefix: &str, fill: u8, count: usize) -> String {
        let mut out = String::with_capacity(prefix.len() + count);
        out.push_str(prefix);
        out.extend(std::iter::repeat_n(char::from(fill), count));
        out
    }

    #[test]
    fn export_list_matches_python_all() {
        assert_eq!(ALL, ["safe_discriminator", "safe_type_value"]);
    }

    #[test]
    fn credential_prefixes_match_pin_order() {
        assert_eq!(
            CREDENTIAL_PREFIXES,
            [
                "sk-",
                "sk_",
                "rk-",
                "rk_",
                "ghp_",
                "gho_",
                "ghu_",
                "ghs_",
                "ghr_",
                "glpat-",
                "akia",
                "asia",
                "aiza",
                "xoxb-",
                "xoxp-",
                "xapp-",
                "xoxa-",
                "xoxr-",
                "slack_token_",
                "bearer-",
                "bearer_",
            ]
        );
    }

    #[test]
    fn safe_type_value_shapes() {
        assert_eq!(safe_type_value(PyValue::Str("hello")), "<str:len=5>");
        assert_eq!(safe_type_value(PyValue::Bytes(5)), "<bytes:len=5>");
        assert_eq!(safe_type_value(PyValue::List(3)), "<list:len=3>");
        assert_eq!(safe_type_value(PyValue::Dict(1)), "<dict:len=1>");
        assert_eq!(safe_type_value(PyValue::Set(2)), "<set:len=2>");
        assert_eq!(safe_type_value(PyValue::Tuple(1)), "<tuple:len=1>");
        assert_eq!(safe_type_value(PyValue::None), "<NoneType>");
        assert_eq!(safe_type_value(PyValue::Int), "<int>");
        assert_eq!(safe_type_value(PyValue::Float), "<float>");
        assert_eq!(safe_type_value(PyValue::Bool), "<bool>");
        assert_eq!(safe_type_value(PyValue::Other("bytearray")), "<bytearray>");
    }

    #[test]
    fn non_strings_fall_back_to_shape() {
        assert_non_string(PyValue::None, "<NoneType>");
        assert_non_string(PyValue::Int, "<int>");
        assert_non_string(PyValue::Float, "<float>");
        assert_non_string(PyValue::Bool, "<bool>");
        assert_non_string(PyValue::List(2), "<list:len=2>");
        assert_non_string(PyValue::Dict(1), "<dict:len=1>");
        assert_non_string(PyValue::Set(2), "<set:len=2>");
        assert_non_string(PyValue::Tuple(1), "<tuple:len=1>");
        assert_non_string(PyValue::Bytes(4), "<bytes:len=4>");
        assert_non_string(PyValue::Bytes(0), "<bytes:len=0>");
        assert_non_string(PyValue::List(0), "<list:len=0>");
        assert_non_string(PyValue::Other("frozenset"), "<frozenset>");
    }

    #[test]
    fn allowlist_length_boundaries() {
        assert_truncated("");
        assert_echo("a");
        assert_echo(&"a".repeat(64));
        assert_truncated(&"a".repeat(65));
        assert_echo(&"-".repeat(64));
        assert_truncated(&"-".repeat(65));
    }

    #[test]
    fn allowlist_accepts_pinned_samples() {
        for sample in [
            "message",
            "futureWidget",
            "custom_type",
            "event-v2",
            "dotted.name",
            "mixed.type_name-123",
            "UPPER_LOWER-123.test",
            "npm_package_metadata",
        ] {
            assert_echo(sample);
        }
    }

    #[test]
    fn allowlist_rejects_symbols_whitespace_and_non_ascii() {
        for sample in [
            "type with spaces",
            "type:with:colons",
            "type/with/slashes",
            "type\\with\\backslashes",
            "custom<xml>tag",
            "custom;sql-inject",
            "type@domain.com",
            "type#anchor",
            "type$var",
            "type%percent",
            "type!exclamation",
            "type=assignment",
            "type\nnewline",
            "type\ttab",
        ] {
            assert_truncated(sample);
        }
        let cafe = "caf\u{00e9}";
        assert_eq!(cafe.len(), 5);
        assert_eq!(cafe.chars().count(), 4);
        assert_truncated(cafe);
        let emoji = "ab\u{1f389}";
        assert_eq!(emoji.chars().count(), 3);
        assert_truncated(emoji);
        let accents = "\u{00e9}".repeat(64);
        assert_eq!(accents.len(), 128);
        assert_truncated(&accents);
        assert_truncated("sk-\u{00e9}");
    }

    #[test]
    fn every_ascii_byte_follows_the_allowlist_class() {
        for byte in 0u8..=127 {
            let text = char::from(byte).to_string();
            let class = byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-');
            if class {
                assert_echo(&text);
            } else {
                assert_truncated(&text);
            }
        }
    }

    #[test]
    fn every_credential_prefix_truncates_on_its_own() {
        for prefix in CREDENTIAL_PREFIXES {
            assert_truncated(prefix);
            assert!(credential_prefix(prefix.as_bytes()));
        }
    }

    #[test]
    fn casefolded_prefix_truncates_when_the_pattern_does_not() {
        let text = "GHP_";
        assert!(credential_prefix(text.as_bytes()));
        assert!(!sensitive_discriminator(text.as_bytes()));
        assert!(!secret_family_hit(text.as_bytes()));
        assert_truncated(text);
        for sample in ["SK-", "Rk_", "AKiA", "AiZa", "XOXB-", "BeArEr_"] {
            assert_truncated(sample);
        }
    }

    #[test]
    fn prefix_requires_the_pinned_separator() {
        for sample in [
            "sk",
            "rk",
            "ghp",
            "glpat",
            "aiz",
            "aki",
            "xoxb",
            "bearer",
            "slack_token",
        ] {
            assert_echo(sample);
        }
        assert_truncated("slack_token-");
        assert_truncated("slack-token-");
        assert_truncated("SLACK-TOKEN-");
        assert_echo("slack-token");
        assert_echo("slack.token-");
    }

    #[test]
    fn secret_family_hit_truncates_when_later_checks_would_echo() {
        for (prefix, fill, enough, short) in [
            ("whsec_", b'a', 24, 23),
            ("github_pat_", b'a', 22, 21),
            ("sbp_", b'a', 40, 39),
        ] {
            let hit = filled(prefix, fill, enough);
            assert!(secret_family_hit(hit.as_bytes()));
            assert!(!credential_prefix(hit.as_bytes()));
            assert!(!sensitive_discriminator(hit.as_bytes()));
            assert_truncated(&hit);
            let miss = filled(prefix, fill, short);
            assert!(!secret_family_hit(miss.as_bytes()));
            assert_echo(&miss);
        }
    }

    #[test]
    fn shared_families_truncate_at_their_minimum() {
        assert_truncated(&filled("sk-", b'a', 20));
        assert_truncated(&filled("npm_", b'a', 20));
        assert_truncated(&filled("hf_", b'a', 20));
        assert_truncated(&filled("AIza", b'A', 20));
        assert_truncated(&(filled("foo.", b'A', 0) + &filled("AKIA", b'A', 16)));
        assert_echo(&filled("npm_", b'a', 19));
        assert_echo(&filled("hf_", b'a', 19));
        assert_echo(&filled("npm_", b'_', 20));
        assert_echo(&filled("hf_", b'_', 20));
    }

    #[test]
    fn content_free_error_is_the_truncated_shape() {
        let hit = filled("ghp-", b'a', 16);
        let checked: Result<(), FindingError> =
            enforce_content_free_text(&hit, "safe_discriminator");
        assert!(checked.is_err());
        assert!(!credential_prefix(hit.as_bytes()));
        assert!(!sensitive_discriminator(hit.as_bytes()));
        assert!(!secret_family_hit(hit.as_bytes()));
        assert_truncated(&hit);

        let gho = filled("gho-", b'a', 16);
        assert!(enforce_content_free_text(&gho, "safe_discriminator").is_err());
        assert_truncated(&gho);

        let miss = filled("ghp-", b'a', 15);
        assert!(enforce_content_free_text(&miss, "safe_discriminator").is_ok());
        assert_echo(&miss);
        assert_echo(&filled("ghs-", b'a', 16));
        assert_echo(&filled("ghu-", b'a', 16));
        assert_echo(&filled("ghr-", b'a', 16));
    }

    #[test]
    fn sensitive_pattern_matches_delimiter_bounded_markers() {
        assert_truncated("xoxc-a");
        assert_truncated("XOXC-A");
        assert_echo("xoxc-");
        assert_echo("xoxc-_");
        assert_echo("xox1-a");
        assert_truncated("foo.GHP_a");
        assert_truncated("foo.ghP_Z");
        assert_echo("GHPa");
        assert_echo("foo.ghp__");
        assert_echo("foo.ghq_a");
        assert_truncated("foo.glpat-9");
        assert_truncated("foo.glpat-Z");
        assert_echo("foo.glpat-");
        assert_echo("foo.glpat-_");
        assert_truncated(&filled("x-akia", b'a', 16));
        assert_truncated(&filled("foo.asia", b'0', 16));
        assert_truncated(&(filled("foo_", b'A', 0) + &filled("AKIA", b'A', 16)));
        assert_echo(&(filled("foo.akia", b'a', 15) + "_"));
        assert_truncated(&filled("foo.aiza", b'_', 20));
        assert_truncated(&filled("foo.aiza", b'-', 20));
        assert_truncated(&filled("foo.AIZA", b'A', 20));
        assert_echo(&filled("foo.aiza", b'_', 19));
        assert_echo(&filled("foo.aiza.", b'a', 20));
        assert_echo("xbearer-");
        assert_truncated("foo.bearer-");
        assert_truncated(&filled("foo_sk-", b'a', 20));
        assert_truncated(&filled("foo-sk-", b'a', 15));
        assert_echo(&filled("xxsk-", b'a', 20));
    }

    #[test]
    fn cloud_account_pattern_respects_optional_separators() {
        assert_truncated(&filled("azure-client-secret-", b'a', 8));
        assert_truncated(&filled("azure-client-secret-", b'a', 16));
        assert_echo(&filled("azure-client-secret-", b'a', 7));
        assert_truncated(&filled("azure-clientsecret-", b'a', 8));
        assert_truncated(&filled("azure_client_secret_", b'a', 8));
        assert_truncated(&filled("azure-client_secret-", b'a', 8));
        assert_truncated(&filled("AZURE-CLIENT-SECRET-", b'A', 8));
        assert_truncated(&filled("gcp-service-account-", b'a', 8));
        assert_truncated(&filled("gcp-service-account-", b'a', 16));
        assert_truncated(&filled("gcp-serviceaccount-", b'a', 8));
        assert_truncated(&filled("gcp-service_account-", b'a', 8));
        assert_truncated(&filled("gcp-private-key-", b'a', 8));
        assert_truncated(&filled("gcp-privatekey-", b'a', 8));
        assert_truncated(&filled("azure-privatekey-", b'a', 8));
        assert_echo(&filled("azure-privatekey-", b'a', 7));
        assert_truncated(&filled("gcp-client-secret-", b'a', 8));
        assert_echo(&filled("azure.client-secret-", b'a', 8));
        assert_echo(&filled("gcpx-client-secret-", b'a', 8));
        assert_truncated(&filled("foo.azure-client-secret-", b'a', 8));
        assert_echo(&filled("azure-client--secret-", b'a', 8));
        assert_echo(&filled("azure-clientsecretsecret-", b'a', 8));
        assert_echo(&filled("azure-client-secretsecret-", b'a', 8));
        assert_truncated(&filled("azure-client-secret-", b'a', 50));
    }

    #[test]
    fn echoed_discriminator_keeps_original_casing() {
        let (shown, truncated) = safe_discriminator(PyValue::Str("futureWidget"));
        assert!(!truncated);
        assert_eq!(shown, "futureWidget");
    }
}
