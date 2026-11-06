//! Persisted-secret-shape gate and placeholder checks (SL009, transcript-hygiene T-01).
//!
//! Port of `src/sesslint/checks/hygiene.py` lines 1–301
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`, through the end of `_HitAgg`.
//!
//! The gate is a strict superset of the family patterns: a miss skips regex
//! work, and a hit cannot drop a real family match. Scans walk bytes. There
//! is no `regex` dependency. This slice does not hash and does not emit findings.
//!
//! [`SECRET_FAMILY_IDS`] are the names on `model::secret_families::SECRET_FAMILIES`,
//! in that order. Family patterns stay in the model crate.
//!
//! # Left for a later slice
//!
//! `_GENERIC_ASSIGNMENT_LOWER` is the compiled generic-assignment pattern. It
//! is not copied. `_HitKey`, `SecretScanTracker`, `feed`, `feed_blob`,
//! `into_findings`, and `make_finding` sit past `_HitAgg`.

use std::borrow::Cow;
use std::collections::BTreeSet;

use model::secret_families::SECRET_FAMILIES;

/// Python: `SECRET_FAMILY_SET_VERSION`.
pub const SECRET_FAMILY_SET_VERSION: i64 = 4;

/// Python: `MAX_SECRET_FINDINGS_PER_FILE`.
pub const MAX_SECRET_FINDINGS_PER_FILE: i64 = 64;

/// Python: `MAX_DIGESTS_PER_FINDING`.
pub const MAX_DIGESTS_PER_FINDING: i64 = 16;

/// Python: `_GATE_WINDOW_BYTES`.
pub const GATE_WINDOW_BYTES: usize = 65_536;

/// Python: `SECRET_FAMILY_IDS`. Names only, pinned `SECRET_FAMILIES` order.
pub const SECRET_FAMILY_IDS: [&str; 20] = [
    SECRET_FAMILIES[0].name,
    SECRET_FAMILIES[1].name,
    SECRET_FAMILIES[2].name,
    SECRET_FAMILIES[3].name,
    SECRET_FAMILIES[4].name,
    SECRET_FAMILIES[5].name,
    SECRET_FAMILIES[6].name,
    SECRET_FAMILIES[7].name,
    SECRET_FAMILIES[8].name,
    SECRET_FAMILIES[9].name,
    SECRET_FAMILIES[10].name,
    SECRET_FAMILIES[11].name,
    SECRET_FAMILIES[12].name,
    SECRET_FAMILIES[13].name,
    SECRET_FAMILIES[14].name,
    SECRET_FAMILIES[15].name,
    SECRET_FAMILIES[16].name,
    SECRET_FAMILIES[17].name,
    SECRET_FAMILIES[18].name,
    SECRET_FAMILIES[19].name,
];

/// Python: `_GATE_LITERALS`. Necessary anchors, never sufficient matches.
pub const GATE_LITERALS: &[&[u8]] = &[
    b"sk-",
    b"k_live_",
    b"k_test_",
    b"ghp_",
    b"github_pat_",
    b"gho_",
    b"ghs_",
    b"ghr_",
    b"ghu_",
    b"whsec_",
    b"AKIA",
    b"ASIA",
    b"AIza",
    b"glpat-",
    b"sbp_",
    b"eyJ",
    b"-----BEGIN",
];

/// Python: `_GATE_SHORT_PREFIXES`.
pub const GATE_SHORT_PREFIXES: &[&[u8]] = &[b"npm_", b"hf_", b"xox"];

/// Python: `_TOKEN_BYTES`. ASCII letters, digits, underscore, and hyphen.
pub const TOKEN_BYTES: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// Python: `_GATE_KEYWORDS`. Callers pass bytes that are already ASCII-lowered.
pub const GATE_KEYWORDS: &[&[u8]] = &[b"password", b"passwd", b"key", b"secret", b"token"];

/// Python: `_GATE_KW_MID`.
pub const GATE_KW_MID: &[u8] = b"\"'.-\\ \t\r\n";

/// Python: `_GATE_KW_SEP`.
pub const GATE_KW_SEP: &[u8] = b":=";

/// Python: `_CASEFOLDED_GATE_LITERALS`.
pub const CASEFOLDED_GATE_LITERALS: &[&[u8]] = &[b"bearer"];

/// Python: `_CASEFOLDED_FAMILY_LITERALS`.
pub const CASEFOLDED_FAMILY_LITERALS: &[&str] = &["bearer-token"];

/// Python: `_PLACEHOLDER_VALUES`, source order.
pub const PLACEHOLDER_VALUES: &[&[u8]] = &[
    b"redacted",
    b"example",
    b"placeholder",
    b"changeme",
    b"change-me",
    b"password",
    b"passwd",
    b"secret",
    b"token",
    b"none",
    b"null",
    b"true",
    b"false",
    b"undefined",
    b"unknown",
    b"tbd",
    b"n/a",
];

/// Quotes, apostrophes, and backticks stripped from both ends.
const PLACEHOLDER_STRIP: &[u8] = b"\"'`";

/// Python: `bytes.find` from `start`. An empty needle does not match.
fn find_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || start > haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|pos| start + pos)
}

fn is_token_byte(byte: u8) -> bool {
    TOKEN_BYTES.contains(&byte)
}

fn is_escape_letter(byte: u8) -> bool {
    b"nrtbf".contains(&byte)
}

fn is_kw_mid(byte: u8) -> bool {
    GATE_KW_MID.contains(&byte)
}

fn is_kw_sep(byte: u8) -> bool {
    GATE_KW_SEP.contains(&byte)
}

/// `xox` plus a lowercase letter and a hyphen. Both extra bytes must exist.
fn xox_shape(raw: &[u8], offset: usize) -> bool {
    let Some(letter_at) = offset.checked_add(3) else {
        return false;
    };
    let Some(hyphen_at) = offset.checked_add(4) else {
        return false;
    };
    matches!(raw.get(letter_at), Some(byte) if byte.is_ascii_lowercase())
        && matches!(raw.get(hyphen_at), Some(b'-'))
}

/// Start of the buffer, a non-token previous byte, or a `\n`/`\r`/`\t`/`\b`/`\f` escape.
fn short_prefix_at_boundary(raw: &[u8], offset: usize) -> bool {
    if offset == 0 {
        return true;
    }
    let prev = raw[offset - 1];
    if !is_token_byte(prev) {
        return true;
    }
    offset >= 2 && raw[offset - 2] == b'\\' && is_escape_letter(prev)
}

/// Python: `_short_prefix_present`.
///
/// Search each short prefix with `bytes.find`, then continue at
/// `offset + prefix length`. `xox` counts only when the next byte is `a-z`
/// and the byte after that is `-`. A candidate counts at the start of the
/// buffer, when the previous byte is outside [`TOKEN_BYTES`], or when the
/// two bytes before it are a backslash and one of `n`, `r`, `t`, `b`, `f`.
pub fn short_prefix_present(raw: &[u8]) -> bool {
    for prefix in GATE_SHORT_PREFIXES {
        let mut start = 0;
        while let Some(offset) = find_from(raw, prefix, start) {
            let shaped = *prefix != b"xox" || xox_shape(raw, offset);
            if shaped && short_prefix_at_boundary(raw, offset) {
                return true;
            }
            let Some(next) = offset.checked_add(prefix.len()) else {
                break;
            };
            start = next;
        }
    }
    false
}

/// Python: `_kw_assignment_present`.
///
/// `lowered` is already ASCII-lowered. For each keyword hit, skip
/// [`GATE_KW_MID`]. A following colon or equals returns true. The next search
/// starts at `index + 1`.
pub fn kw_assignment_present(lowered: &[u8]) -> bool {
    for keyword in GATE_KEYWORDS {
        let mut start = 0;
        while let Some(index) = find_from(lowered, keyword, start) {
            let Some(mut cursor) = index.checked_add(keyword.len()) else {
                break;
            };
            while cursor < lowered.len() && is_kw_mid(lowered[cursor]) {
                cursor += 1;
            }
            if cursor < lowered.len() && is_kw_sep(lowered[cursor]) {
                return true;
            }
            let Some(next) = index.checked_add(1) else {
                break;
            };
            start = next;
        }
    }
    false
}

/// Python: `:[A-Za-z0-9_-]{35}` via `re.search`.
///
/// Thirty-five token bytes after a colon match, including when more token
/// bytes follow. The pattern has no trailing boundary.
fn gate_token_tail_present(data: &[u8]) -> bool {
    for (index, byte) in data.iter().enumerate() {
        if *byte != b':' {
            continue;
        }
        let Some(end) = index.checked_add(36) else {
            continue;
        };
        if end > data.len() {
            continue;
        }
        if data[index + 1..end].iter().all(|tail| is_token_byte(*tail)) {
            return true;
        }
    }
    false
}

/// Python: `_gate_maybe_contains_secret`.
pub fn gate_maybe_contains_secret(data: &[u8]) -> bool {
    if GATE_LITERALS
        .iter()
        .any(|anchor| find_from(data, anchor, 0).is_some())
    {
        return true;
    }
    if short_prefix_present(data) {
        return true;
    }
    if gate_token_tail_present(data) {
        return true;
    }
    let lowered = data.to_ascii_lowercase();
    CASEFOLDED_GATE_LITERALS
        .iter()
        .any(|anchor| find_from(&lowered, anchor, 0).is_some())
        || kw_assignment_present(&lowered)
}

/// Python: `_line_gate_maybe_contains_secret`.
///
/// Same checks as [`gate_maybe_contains_secret`].
pub fn line_gate_maybe_contains_secret(raw: &[u8]) -> bool {
    gate_maybe_contains_secret(raw)
}

/// Python: `_json_escape_boundary_shadow`.
///
/// No backslash returns the same bytes. Each run of backslashes is kept when
/// its length is even. An odd run whose next byte is `n`, `r`, `t`, `b`, or
/// `f` replaces that last backslash and the letter with two spaces. Every
/// other offset stays put.
pub fn json_escape_boundary_shadow(raw: &[u8]) -> Cow<'_, [u8]> {
    if !raw.contains(&b'\\') {
        return Cow::Borrowed(raw);
    }
    let mut owned: Option<Vec<u8>> = None;
    let mut index = 0;
    while index < raw.len() {
        if raw[index] != b'\\' {
            index += 1;
            continue;
        }
        let start = index;
        while index < raw.len() && raw[index] == b'\\' {
            index += 1;
        }
        let end = index;
        if (end - start) % 2 == 0 {
            continue;
        }
        let Some(&letter) = raw.get(end) else {
            continue;
        };
        if !is_escape_letter(letter) {
            continue;
        }
        let buf = owned.get_or_insert_with(|| raw.to_vec());
        buf[end - 1] = b' ';
        buf[end] = b' ';
    }
    match owned {
        Some(buf) => Cow::Owned(buf),
        None => Cow::Borrowed(raw),
    }
}

fn strip_ends<'a>(bytes: &'a [u8], set: &[u8]) -> &'a [u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && set.contains(&bytes[start]) {
        start += 1;
    }
    while end > start && set.contains(&bytes[end - 1]) {
        end -= 1;
    }
    &bytes[start..end]
}

fn distinct_at_most(bytes: &[u8], limit: usize) -> bool {
    let mut seen = [false; 256];
    let mut count = 0;
    for byte in bytes {
        let slot = usize::from(*byte);
        if !seen[slot] {
            seen[slot] = true;
            count += 1;
            if count > limit {
                return false;
            }
        }
    }
    true
}

/// Python: `_looks_like_placeholder`.
///
/// ASCII-lowercase, then strip leading and trailing quotes, apostrophes, and
/// backticks. True when the result is shorter than 8, has at most two distinct
/// bytes, starts with `<`, `{`, `[`, or `${`, starts with `your-`, `your_`,
/// or `your.`, or is in [`PLACEHOLDER_VALUES`]. Otherwise false. An unsure
/// value is false, so a later scanner still counts it as a hit.
pub fn looks_like_placeholder(value: &[u8]) -> bool {
    let lowered = value.to_ascii_lowercase();
    let trimmed = strip_ends(&lowered, PLACEHOLDER_STRIP);
    if trimmed.len() < 8 {
        return true;
    }
    if distinct_at_most(trimmed, 2) {
        return true;
    }
    if matches!(trimmed.first(), Some(b'<' | b'{' | b'[')) || trimmed.starts_with(b"${") {
        return true;
    }
    if trimmed.starts_with(b"your-")
        || trimmed.starts_with(b"your_")
        || trimmed.starts_with(b"your.")
    {
        return true;
    }
    PLACEHOLDER_VALUES.contains(&trimmed)
}

/// Python: `_HitAgg`.
///
/// Per-(record, family) aggregation: count, distinct digest strings, and max
/// length. This slice does not feed the aggregate and does not emit a finding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HitAgg {
    /// Python: `count`. A Python `int`, stored as `i64`. Stays 0 here.
    pub count: i64,
    /// Python: `digests`. Distinct digest strings. Insertion order is not kept.
    pub digests: BTreeSet<String>,
    /// Python: `max_len`. A Python `int`, stored as `i64`. Stays 0 here.
    pub max_len: i64,
}

#[cfg(test)]
mod tests {
    use super::{
        gate_maybe_contains_secret, json_escape_boundary_shadow, kw_assignment_present,
        line_gate_maybe_contains_secret, looks_like_placeholder, short_prefix_present, HitAgg,
        CASEFOLDED_FAMILY_LITERALS, CASEFOLDED_GATE_LITERALS, GATE_KEYWORDS, GATE_KW_MID,
        GATE_KW_SEP, GATE_LITERALS, GATE_SHORT_PREFIXES, GATE_WINDOW_BYTES,
        MAX_DIGESTS_PER_FINDING, MAX_SECRET_FINDINGS_PER_FILE, PLACEHOLDER_VALUES,
        SECRET_FAMILY_IDS, SECRET_FAMILY_SET_VERSION, TOKEN_BYTES,
    };
    use std::borrow::Cow;
    use std::collections::BTreeSet;

    fn repeated(prefix: &[u8], count: usize, byte: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(prefix.len() + count);
        out.extend_from_slice(prefix);
        out.extend(std::iter::repeat_n(byte, count));
        out
    }

    fn assert_gate(data: &[u8], expected: bool) {
        assert_eq!(gate_maybe_contains_secret(data), expected, "gate {data:?}");
        assert_eq!(
            line_gate_maybe_contains_secret(data),
            expected,
            "line gate {data:?}"
        );
    }

    #[test]
    fn constants_match_the_pin() {
        assert_eq!(SECRET_FAMILY_SET_VERSION, 4);
        assert_eq!(MAX_SECRET_FINDINGS_PER_FILE, 64);
        assert_eq!(MAX_DIGESTS_PER_FINDING, 16);
        assert_eq!(GATE_WINDOW_BYTES, 65_536);
        assert_eq!(
            GATE_LITERALS,
            [
                b"sk-".as_slice(),
                b"k_live_".as_slice(),
                b"k_test_".as_slice(),
                b"ghp_".as_slice(),
                b"github_pat_".as_slice(),
                b"gho_".as_slice(),
                b"ghs_".as_slice(),
                b"ghr_".as_slice(),
                b"ghu_".as_slice(),
                b"whsec_".as_slice(),
                b"AKIA".as_slice(),
                b"ASIA".as_slice(),
                b"AIza".as_slice(),
                b"glpat-".as_slice(),
                b"sbp_".as_slice(),
                b"eyJ".as_slice(),
                b"-----BEGIN".as_slice(),
            ]
        );
        assert_eq!(
            GATE_SHORT_PREFIXES,
            [b"npm_".as_slice(), b"hf_".as_slice(), b"xox".as_slice()]
        );
        assert_eq!(
            GATE_KEYWORDS,
            [
                b"password".as_slice(),
                b"passwd".as_slice(),
                b"key".as_slice(),
                b"secret".as_slice(),
                b"token".as_slice(),
            ]
        );
        assert_eq!(GATE_KW_MID, b"\"'.-\\ \t\r\n");
        assert_eq!(GATE_KW_SEP, b":=");
        assert_eq!(CASEFOLDED_GATE_LITERALS, [b"bearer".as_slice()]);
        assert_eq!(CASEFOLDED_FAMILY_LITERALS, ["bearer-token"]);
        assert_eq!(
            PLACEHOLDER_VALUES,
            [
                b"redacted".as_slice(),
                b"example".as_slice(),
                b"placeholder".as_slice(),
                b"changeme".as_slice(),
                b"change-me".as_slice(),
                b"password".as_slice(),
                b"passwd".as_slice(),
                b"secret".as_slice(),
                b"token".as_slice(),
                b"none".as_slice(),
                b"null".as_slice(),
                b"true".as_slice(),
                b"false".as_slice(),
                b"undefined".as_slice(),
                b"unknown".as_slice(),
                b"tbd".as_slice(),
                b"n/a".as_slice(),
            ]
        );
    }

    #[test]
    fn secret_family_ids_follow_secret_families_order() {
        assert_eq!(model::secret_families::SECRET_FAMILIES.len(), 20);
        assert_eq!(SECRET_FAMILY_IDS.len(), 20);
        for (family, name) in model::secret_families::SECRET_FAMILIES
            .iter()
            .zip(SECRET_FAMILY_IDS)
        {
            assert_eq!(family.name, name);
        }
        assert_eq!(SECRET_FAMILY_IDS[0], "anthropic-api-key");
        assert_eq!(SECRET_FAMILY_IDS[19], "generic-credential-assignment");
        assert_eq!(SECRET_FAMILY_IDS[12], "bearer-token");
    }

    #[test]
    fn token_bytes_are_the_ascii_token_alphabet() {
        let mut expected = Vec::new();
        expected.extend(b'A'..=b'Z');
        expected.extend(b'a'..=b'z');
        expected.extend(b'0'..=b'9');
        expected.push(b'_');
        expected.push(b'-');
        assert_eq!(TOKEN_BYTES, expected.as_slice());
        assert_eq!(TOKEN_BYTES.len(), 64);
        for byte in [b'/', b':', b'.', b' ', b'\\', 0xff] {
            assert!(!TOKEN_BYTES.contains(&byte), "{byte}");
        }
    }

    #[test]
    fn gate_literals_fire_without_a_long_secret_body() {
        for literal in GATE_LITERALS {
            assert_gate(literal, true);
        }
        assert_gate(b"\xffsk-\xff", true);
        assert_gate(b"SK-", false);
        assert_gate(b"eyj", false);
        assert_gate(b"-----begin", false);
        assert_gate(b"----BEGIN", false);
        assert_gate(b"k_live", false);
        assert_gate(b"k_test", false);
        assert_gate(b"", false);
    }

    #[test]
    fn runtime_built_body_trips_only_the_live_fragment() {
        let mut stem = Vec::new();
        stem.push(b's');
        stem.extend_from_slice(b"k_live_");
        assert_gate(&repeated(&stem, 16, b'b'), true);
        assert_gate(&repeated(b"", 16, b'b'), false);
        assert_gate(&repeated(b"k_test_", 16, b'c'), true);
    }

    #[test]
    fn short_prefix_present_matches_find_boundary_rules() {
        let cases: &[(&[u8], bool)] = &[
            (b"npm_", true),
            (b"anpm_", false),
            (b" npm_", true),
            (b"1hf_", false),
            (b".hf_", true),
            (b"hf_", true),
            (b"NPM_", false),
            (b"Hf_", false),
            (b"xoxb-", true),
            (b"xoxB-", false),
            (b"xoxb", false),
            (b"XOXB-", false),
            (b"zxoxb-", false),
            (b" xoxb-", true),
            (b"\\nnpm_", true),
            (b"\\xnpm_", false),
            (b"\\npm_", true),
            (b"\\nxoxb-", true),
            (b"\nnpm_", true),
            (b"_npm_", false),
            (b"-npm_", false),
            (b"xox!xoxb-", true),
            (b"xoxoxb-", false),
            (b"", false),
            (b"hf_hf_", true),
            (b"anpm_ hf_", true),
        ];
        for (input, expected) in cases {
            assert_eq!(short_prefix_present(input), *expected, "{input:?}");
            assert_gate(input, *expected);
        }
        for letter in b"nrtbf" {
            let mut raw = vec![b'\\', *letter];
            raw.extend_from_slice(b"hf_");
            assert!(short_prefix_present(&raw), "escape {letter}");
            assert_gate(&raw, true);
        }
    }

    #[test]
    fn kw_assignment_present_skips_mid_bytes_and_resumes() {
        let cases: &[(&[u8], bool)] = &[
            (b"password:", true),
            (b"passwd=", true),
            (b"key:", true),
            (b"secret=", true),
            (b"token:", true),
            (b"KEY:", false),
            (b"Token:", false),
            (b"key", false),
            (b"key   :", true),
            (b"key\t=", true),
            (b"key\r\n:", true),
            (b"key\"':", true),
            (b"key.-:", true),
            (b"key\\:", true),
            (b"keyboard:", false),
            (b"mykey:", true),
            (b"keyx:", false),
            (b"keyx=:", false),
            (b"xxkey=", true),
            (b"passwordx token:", true),
            (b"token token", false),
            (b"secret\n=", true),
            (b"", false),
            (b"key : =", true),
            (b":", false),
            (b"passwdx:", false),
            (b"keykey:", true),
            (b"keypey:", false),
            (b"password \" =", true),
        ];
        for (input, expected) in cases {
            assert_eq!(kw_assignment_present(input), *expected, "{input:?}");
        }
        for mid in [b'"', b'\'', b'.', b'-', b'\\', b' ', b'\t', b'\r', b'\n'] {
            let mut raw = b"key".to_vec();
            raw.push(mid);
            raw.push(b':');
            assert!(kw_assignment_present(&raw), "mid {mid}");
        }
        for bad in [b'/', b'x', b';', b'a', b'?'] {
            let mut raw = b"key".to_vec();
            raw.push(bad);
            raw.push(b':');
            assert!(!kw_assignment_present(&raw), "bad {bad}");
        }
        assert_gate(b"KEY:", true);
        assert_gate(b"Token:", true);
        assert_gate(b"keyboard:", false);
        assert_gate(b"mykey:", true);
    }

    #[test]
    fn gate_token_tail_is_thirty_five_token_bytes() {
        assert_gate(&repeated(b":", 35, b'a'), true);
        assert_gate(&repeated(b":", 36, b'a'), true);
        assert_gate(&repeated(b":", 34, b'a'), false);
        assert_gate(&repeated(b":", 35, b'-'), true);
        assert_gate(&repeated(b":", 35, b'_'), true);
        assert_gate(&repeated(b":", 35, b'A'), true);
        assert_gate(&repeated(b":", 35, b'7'), true);
        assert_gate(&repeated(b"", 35, b'a'), false);

        let mut bang = repeated(b":", 35, b'a');
        bang.push(b'!');
        assert_gate(&bang, true);

        assert_gate(&repeated(b": ", 35, b'a'), false);
        assert_gate(&repeated(b"::", 35, b'a'), true);

        let mut split = repeated(b":", 34, b'a');
        split.push(b'.');
        split.extend(std::iter::repeat_n(b'a', 10));
        assert_gate(&split, false);

        let mut later = repeated(b":", 34, b'a');
        later.push(b':');
        later.extend(std::iter::repeat_n(b'a', 35));
        assert_gate(&later, true);
    }

    #[test]
    fn gate_bearer_is_an_ascii_casefolded_substring() {
        assert_gate(b"bearer", true);
        assert_gate(b"BEARER", true);
        assert_gate(b"BeArEr", true);
        assert_gate(b"bearers", true);
        assert_gate(b"bear", false);
        assert_gate(b"\xffBearer", true);
        assert_eq!(b"A\xffZ".to_ascii_lowercase(), b"a\xffz");
    }

    #[test]
    fn json_escape_boundary_shadow_replaces_odd_runs_only() {
        let borrowed: &[(&[u8], &[u8])] = &[
            (b"abc", b"abc"),
            (b"", b""),
            (b"\\", b"\\"),
            (b"\\\\n", b"\\\\n"),
            (b"\\a", b"\\a"),
            (b"\\x", b"\\x"),
            (b"\\\\\\", b"\\\\\\"),
            (b"\n", b"\n"),
            (b"a\\\\b", b"a\\\\b"),
            (b"\\N", b"\\N"),
            (b"\\v", b"\\v"),
            (b"\\1", b"\\1"),
        ];
        for (input, expected) in borrowed {
            assert_shadow(input, expected, true);
        }
        let owned: &[(&[u8], &[u8])] = &[
            (b"\\n", b"  "),
            (b"\\\\\\n", b"\\\\  "),
            (b"\\t", b"  "),
            (b"\\r", b"  "),
            (b"\\b", b"  "),
            (b"\\f", b"  "),
            (b"a\\nb", b"a  b"),
            (b"a\\nb\\\\nc\\td", b"a  b\\\\nc  d"),
            (b"\\n\\n", b"    "),
            (b"\\\\n\\n", b"\\\\n  "),
            (b"\\\\\\\\\\n", b"\\\\\\\\  "),
            (b"\xff\\n\xfe", b"\xff  \xfe"),
            (b"XYZ\\nABC", b"XYZ  ABC"),
        ];
        for (input, expected) in owned {
            assert_shadow(input, expected, false);
        }

        let mut odd = b"HEAD".to_vec();
        odd.extend(std::iter::repeat_n(b'\\', 7));
        odd.push(b'n');
        odd.extend_from_slice(b"TAIL");
        let odd_out = json_escape_boundary_shadow(&odd);
        let mut odd_expected = b"HEAD".to_vec();
        odd_expected.extend(std::iter::repeat_n(b'\\', 6));
        odd_expected.extend_from_slice(b"  ");
        odd_expected.extend_from_slice(b"TAIL");
        assert_eq!(odd_out.as_ref(), odd_expected.as_slice());
        assert_eq!(odd_out.len(), odd.len());
        assert_eq!(&odd_out[..4], b"HEAD");
        assert_eq!(&odd_out[odd_out.len() - 4..], b"TAIL");

        let mut even = b"HEAD".to_vec();
        even.extend(std::iter::repeat_n(b'\\', 8));
        even.push(b'n');
        even.extend_from_slice(b"TAIL");
        assert_shadow(&even, &even, true);
    }

    fn assert_shadow(raw: &[u8], expected: &[u8], borrowed: bool) {
        let out = json_escape_boundary_shadow(raw);
        assert_eq!(out.as_ref(), expected, "{raw:?}");
        assert_eq!(out.len(), raw.len());
        match &out {
            Cow::Borrowed(bytes) => {
                assert!(borrowed, "{raw:?}");
                assert!(std::ptr::eq(*bytes, raw));
            }
            Cow::Owned(_) => assert!(!borrowed, "{raw:?}"),
        }
    }

    #[test]
    fn looks_like_placeholder_matches_lower_strip_and_shape() {
        let cases: &[(&[u8], bool)] = &[
            (b"", true),
            (b"secret", true),
            (b"SECRET", true),
            (b"\"secret\"", true),
            (b"''secret''", true),
            (b"`secret`", true),
            (b"  secret", false),
            (b"short", true),
            (b"1234567", true),
            (b"12345678", false),
            (b"aaaaaaaa", true),
            (b"abababab", true),
            (b"abcabcab", false),
            (b"<REDACTED>", true),
            (b"{VARNAME}", true),
            (b"[VARNAME]", true),
            (b"${VARNAME}", true),
            (b"your-api-key-value", true),
            (b"your_api_key_value", true),
            (b"your.api.key.value", true),
            (b"yourapi-key-value-xx", false),
            (b"YOUR-SECRET-VALUE", true),
            (b"change-me", true),
            (b"n/a", true),
            (b"undefined", true),
            (b"undefinedx", false),
            (b"\"\"\"", true),
            (b"abcd\"efgh", false),
            (b"\"abcdefgh\"", false),
            (b"'abcdefgh'", false),
            (b" redacted", false),
            (b"\"UNDEFINED\"", true),
            (b"PASSWORD", true),
            (b"Change-Me", true),
            (b"example", true),
            (b"exampleX", false),
            (b"unknown", true),
            (b"unknownX", false),
            (b"N/AXXXXX", false),
            (b"N/A", true),
            (b"change_me", false),
            (b"falsehood", false),
            (b"trueXXXX", false),
            (b"null", true),
            (b"none", true),
            (b"token", true),
            (b"your-abcdef", true),
            (b"yourXabcdef", false),
            (b"your_abcdef", true),
            (b"your.abcdef", true),
            (b"<abcdefg", true),
            (b"${abcdef", true),
            (b"{abcdefg", true),
            (b"[abcdefg", true),
            (b"abcdefg", true),
            (b"abcdefgh", false),
            (b"redacted", true),
            (b"changeme", true),
            (b"password", true),
            (b"placeholder", true),
            (b" credential", false),
            (b"\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9", true),
            (&[1, 2, 3, 1, 2, 3, 1, 2], false),
            (b"\"<abcdefg\"", true),
            (b"`abcdefgh`", false),
            (b"n/aXXXXX", false),
            (b"\xffUNDEFINED\xff", false),
            (b"\xc1UNDEFINED", false),
            (b"credential-value", false),
        ];
        for (input, expected) in cases {
            assert_eq!(looks_like_placeholder(input), *expected, "{input:?}");
        }
    }

    #[test]
    fn hit_agg_holds_count_digests_and_max_len() {
        let fresh = HitAgg::default();
        assert_eq!(fresh.count, 0);
        assert!(fresh.digests.is_empty());
        assert_eq!(fresh.max_len, 0);

        let mut left = HitAgg {
            count: 2,
            max_len: 4,
            ..Default::default()
        };
        left.digests.insert("zz".to_owned());
        left.digests.insert("aa".to_owned());
        left.digests.insert("aa".to_owned());
        let mut right = HitAgg {
            count: 2,
            max_len: 4,
            digests: BTreeSet::from(["aa".to_owned(), "zz".to_owned()]),
        };
        assert_eq!(left, right);
        assert_eq!(left.digests.len(), 2);
        let ordered: Vec<&str> = left.digests.iter().map(String::as_str).collect();
        assert_eq!(ordered, ["aa", "zz"]);
        right.count = 3;
        assert_ne!(left, right);
    }

    #[test]
    fn source_has_no_stripe_prefix_with_a_long_body() {
        let src = include_str!("hygiene.rs");
        let stems = [
            concat!("s", "k_live_"),
            concat!("s", "k_test_"),
            concat!("r", "k_live_"),
            concat!("r", "k_test_"),
        ];
        for stem in stems {
            let mut rest = src;
            while let Some(index) = rest.find(stem) {
                let after = &rest[index + stem.len()..];
                let run = after
                    .bytes()
                    .take_while(|byte| byte.is_ascii_alphanumeric())
                    .count();
                assert!(run < 16, "{stem} followed by {run} alphanumeric bytes");
                rest = &rest[index + 1..];
            }
        }
        let banned = [
            concat!("re", ".compile"),
            concat!("regex", "::"),
            concat!("Sha", "256"),
            concat!("sha", "2"),
        ];
        for needle in banned {
            assert!(!src.contains(needle), "{needle}");
        }
    }
}
