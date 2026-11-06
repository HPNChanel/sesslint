//! Content-free text checks, [`SourceRef`], the evidence walker, and [`Finding`].
//!
//! Port of `src/sesslint/finding.py` lines 1–426
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Stops before `CANONICAL_EVIDENCE_KEYS`. Does not port `make_finding`.
//!
//! Finding envelope, severity/repairability taxonomies, fingerprinting, and
//! deterministic ordering.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::rc::Rc;

use crate::codes::{is_valid_code, Repairability, Severity, ALL_CODES};
use crate::errors::FindingError;

/// Python: `SCHEMA_VERSION` (`SchemaVersionLiteral`).
pub const SCHEMA_VERSION: &str = "sesslint.finding/v1";

/// Python: `ALLOWED_TEMPLATE_VARS` (`frozenset`, membership only).
///
/// Sorted by code point. A frozenset has no iteration contract.
pub const ALLOWED_TEMPLATE_VARS: [&str; 2] = ["line", "record_id"];

/// Python: `MAX_MESSAGE_LENGTH`.
pub const MAX_MESSAGE_LENGTH: i64 = 500;

/// Python: `TRUNCATION_MARKER`.
pub const TRUNCATION_MARKER: &str = "... [truncated]";

/// Python: `SEVERITY_ORDER` in declaration order (not a `HashMap`).
pub const SEVERITY_ORDER: [(Severity, i64); 4] = [
    (Severity::Fatal, 0),
    (Severity::Error, 1),
    (Severity::Warning, 2),
    (Severity::Info, 3),
];

/// Python: `_FINGERPRINT_PATTERN`.
pub const FINGERPRINT_PATTERN: &str = r"^[0-9a-f]{16}$";

/// Python: `_EMAIL_PATTERN`.
pub const EMAIL_PATTERN: &str = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b";

/// Python: `_PRIVATE_KEY_PATTERN`.
pub const PRIVATE_KEY_PATTERN: &str = r"-----BEGIN [A-Z ]+KEY-----";

/// Python: `_BEARER_PATTERN`.
pub const BEARER_PATTERN: &str = r"\bBearer\s+[A-Za-z0-9_\-\.]{10,}\b";

/// Python: `_API_KEY_PATTERN`.
pub const API_KEY_PATTERN: &str = r"\b(?:sk|ghp|gho|glpat|slack_token)[_\-][A-Za-z0-9_\-]{16,}\b";

/// Python: `_CREDENTIAL_ASSIGN_PATTERN`.
pub const CREDENTIAL_ASSIGN_PATTERN: &str =
    r"(?i)\b(?:password|passwd|api_key|secret|token)\s*[:=]\s*\S+";

/// Python: `_CONTROL_CHAR_PATTERN`.
pub const CONTROL_CHAR_PATTERN: &str = r"[\r\n\t\x00-\x1f\x7f]";

/// Python: `_DANGEROUS_UNICODE_CATEGORIES` (`frozenset`).
pub const DANGEROUS_UNICODE_CATEGORIES: [&str; 4] = ["Cc", "Cf", "Zl", "Zp"];

/// Python: `_CONTENT_REJECT_PATTERN` (existence only; precedence is the ordered checks).
pub const CONTENT_REJECT_PATTERN: &str = r"[\r\n\t\x00-\x1f\x7f]|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|-----BEGIN [A-Z ]+KEY-----|\bBearer\s+[A-Za-z0-9_\-\.]{10,}\b|\b(?:sk|ghp|gho|glpat|slack_token)[_\-][A-Za-z0-9_\-]{16,}\b|(?i:\b(?:password|passwd|api_key|secret|token)\s*[:=]\s*\S+)";

/// Python default for `enforce_content_free_text(..., context="text")`.
pub const DEFAULT_TEXT_CONTEXT: &str = "text";

/// `set` / `frozenset` have no stable Python order.
///
/// The walker sorts string elements by Unicode code point, then non-strings by
/// kind, breaking remaining ties by the caller’s order. Context indexes follow
/// that order.
pub const SET_ITERATION_DEVIATION: &str = "set and frozenset strings are walked in code-point order before non-strings; Python set order is not stable";

/// Pinned Python Cc/Cf/Zl/Zp code points this module does not classify.
///
/// Empty: Cc is [`char::is_control`] (U+0000..=U+001F and U+007F..=U+009F),
/// Zl/Zp are U+2028/U+2029, and Cf is [`CF_RANGES`] from unicodedata 14.0.0.
/// Code points assigned after Unicode 14 are not treated as Cf.
pub const UNCOVERED_DANGEROUS_CODE_POINTS: &[u32] = &[];

/// Unicode 14.0.0 general category Cf (Python 3.11.9 unicodedata).
const CF_RANGES: &[(u32, u32)] = &[
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
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x13438),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// rustc 1.91.1 is_alphanumeric code points that Python 3.11.9 re \w does not match.
const NON_WORD_ALNUM_RANGES: &[(u32, u32)] = &[
    (0x0345, 0x0345),
    (0x0363, 0x036F),
    (0x05B0, 0x05BD),
    (0x05BF, 0x05BF),
    (0x05C1, 0x05C2),
    (0x05C4, 0x05C5),
    (0x05C7, 0x05C7),
    (0x0610, 0x061A),
    (0x064B, 0x0657),
    (0x0659, 0x065F),
    (0x0670, 0x0670),
    (0x06D6, 0x06DC),
    (0x06E1, 0x06E4),
    (0x06E7, 0x06E8),
    (0x06ED, 0x06ED),
    (0x0711, 0x0711),
    (0x0730, 0x073F),
    (0x07A6, 0x07B0),
    (0x0816, 0x0817),
    (0x081B, 0x0823),
    (0x0825, 0x0827),
    (0x0829, 0x082C),
    (0x0897, 0x0897),
    (0x08D4, 0x08DF),
    (0x08E3, 0x08E9),
    (0x08F0, 0x0903),
    (0x093A, 0x093B),
    (0x093E, 0x094C),
    (0x094E, 0x094F),
    (0x0955, 0x0957),
    (0x0962, 0x0963),
    (0x0981, 0x0983),
    (0x09BE, 0x09C4),
    (0x09C7, 0x09C8),
    (0x09CB, 0x09CC),
    (0x09D7, 0x09D7),
    (0x09E2, 0x09E3),
    (0x0A01, 0x0A03),
    (0x0A3E, 0x0A42),
    (0x0A47, 0x0A48),
    (0x0A4B, 0x0A4C),
    (0x0A51, 0x0A51),
    (0x0A70, 0x0A71),
    (0x0A75, 0x0A75),
    (0x0A81, 0x0A83),
    (0x0ABE, 0x0AC5),
    (0x0AC7, 0x0AC9),
    (0x0ACB, 0x0ACC),
    (0x0AE2, 0x0AE3),
    (0x0AFA, 0x0AFC),
    (0x0B01, 0x0B03),
    (0x0B3E, 0x0B44),
    (0x0B47, 0x0B48),
    (0x0B4B, 0x0B4C),
    (0x0B56, 0x0B57),
    (0x0B62, 0x0B63),
    (0x0B82, 0x0B82),
    (0x0BBE, 0x0BC2),
    (0x0BC6, 0x0BC8),
    (0x0BCA, 0x0BCC),
    (0x0BD7, 0x0BD7),
    (0x0C00, 0x0C04),
    (0x0C3E, 0x0C44),
    (0x0C46, 0x0C48),
    (0x0C4A, 0x0C4C),
    (0x0C55, 0x0C56),
    (0x0C62, 0x0C63),
    (0x0C81, 0x0C83),
    (0x0CBE, 0x0CC4),
    (0x0CC6, 0x0CC8),
    (0x0CCA, 0x0CCC),
    (0x0CD5, 0x0CD6),
    (0x0CE2, 0x0CE3),
    (0x0CF3, 0x0CF3),
    (0x0D00, 0x0D03),
    (0x0D3E, 0x0D44),
    (0x0D46, 0x0D48),
    (0x0D4A, 0x0D4C),
    (0x0D57, 0x0D57),
    (0x0D62, 0x0D63),
    (0x0D81, 0x0D83),
    (0x0DCF, 0x0DD4),
    (0x0DD6, 0x0DD6),
    (0x0DD8, 0x0DDF),
    (0x0DF2, 0x0DF3),
    (0x0E31, 0x0E31),
    (0x0E34, 0x0E3A),
    (0x0E4D, 0x0E4D),
    (0x0EB1, 0x0EB1),
    (0x0EB4, 0x0EB9),
    (0x0EBB, 0x0EBC),
    (0x0ECD, 0x0ECD),
    (0x0F71, 0x0F83),
    (0x0F8D, 0x0F97),
    (0x0F99, 0x0FBC),
    (0x102B, 0x1036),
    (0x1038, 0x1038),
    (0x103B, 0x103E),
    (0x1056, 0x1059),
    (0x105E, 0x1060),
    (0x1062, 0x1064),
    (0x1067, 0x106D),
    (0x1071, 0x1074),
    (0x1082, 0x108D),
    (0x108F, 0x108F),
    (0x109A, 0x109D),
    (0x1712, 0x1713),
    (0x1732, 0x1733),
    (0x1752, 0x1753),
    (0x1772, 0x1773),
    (0x17B6, 0x17C8),
    (0x1885, 0x1886),
    (0x18A9, 0x18A9),
    (0x1920, 0x192B),
    (0x1930, 0x1938),
    (0x1A17, 0x1A1B),
    (0x1A55, 0x1A5E),
    (0x1A61, 0x1A74),
    (0x1ABF, 0x1AC0),
    (0x1ACC, 0x1ACE),
    (0x1B00, 0x1B04),
    (0x1B35, 0x1B43),
    (0x1B80, 0x1B82),
    (0x1BA1, 0x1BA9),
    (0x1BAC, 0x1BAD),
    (0x1BE7, 0x1BF1),
    (0x1C24, 0x1C36),
    (0x1C89, 0x1C8A),
    (0x1DD3, 0x1DF4),
    (0x24B6, 0x24E9),
    (0x2DE0, 0x2DFF),
    (0xA674, 0xA67B),
    (0xA69E, 0xA69F),
    (0xA7CB, 0xA7CD),
    (0xA7DA, 0xA7DC),
    (0xA802, 0xA802),
    (0xA80B, 0xA80B),
    (0xA823, 0xA827),
    (0xA880, 0xA881),
    (0xA8B4, 0xA8C3),
    (0xA8C5, 0xA8C5),
    (0xA8FF, 0xA8FF),
    (0xA926, 0xA92A),
    (0xA947, 0xA952),
    (0xA980, 0xA983),
    (0xA9B4, 0xA9BF),
    (0xA9E5, 0xA9E5),
    (0xAA29, 0xAA36),
    (0xAA43, 0xAA43),
    (0xAA4C, 0xAA4D),
    (0xAA7B, 0xAA7D),
    (0xAAB0, 0xAAB0),
    (0xAAB2, 0xAAB4),
    (0xAAB7, 0xAAB8),
    (0xAABE, 0xAABE),
    (0xAAEB, 0xAAEF),
    (0xAAF5, 0xAAF5),
    (0xABE3, 0xABEA),
    (0xFB1E, 0xFB1E),
    (0x10376, 0x1037A),
    (0x105C0, 0x105F3),
    (0x10A01, 0x10A03),
    (0x10A05, 0x10A06),
    (0x10A0C, 0x10A0F),
    (0x10D24, 0x10D27),
    (0x10D40, 0x10D65),
    (0x10D69, 0x10D69),
    (0x10D6F, 0x10D85),
    (0x10EAB, 0x10EAC),
    (0x10EC2, 0x10EC4),
    (0x10EFC, 0x10EFC),
    (0x11000, 0x11002),
    (0x11038, 0x11045),
    (0x11073, 0x11074),
    (0x11080, 0x11082),
    (0x110B0, 0x110B8),
    (0x110C2, 0x110C2),
    (0x11100, 0x11102),
    (0x11127, 0x11132),
    (0x11145, 0x11146),
    (0x11180, 0x11182),
    (0x111B3, 0x111BF),
    (0x111CE, 0x111CF),
    (0x1122C, 0x11234),
    (0x11237, 0x11237),
    (0x1123E, 0x11241),
    (0x112DF, 0x112E8),
    (0x11300, 0x11303),
    (0x1133E, 0x11344),
    (0x11347, 0x11348),
    (0x1134B, 0x1134C),
    (0x11357, 0x11357),
    (0x11362, 0x11363),
    (0x11380, 0x11389),
    (0x1138B, 0x1138B),
    (0x1138E, 0x1138E),
    (0x11390, 0x113B5),
    (0x113B7, 0x113C0),
    (0x113C2, 0x113C2),
    (0x113C5, 0x113C5),
    (0x113C7, 0x113CA),
    (0x113CC, 0x113CD),
    (0x113D1, 0x113D1),
    (0x113D3, 0x113D3),
    (0x11435, 0x11441),
    (0x11443, 0x11445),
    (0x114B0, 0x114C1),
    (0x115AF, 0x115B5),
    (0x115B8, 0x115BE),
    (0x115DC, 0x115DD),
    (0x11630, 0x1163E),
    (0x11640, 0x11640),
    (0x116AB, 0x116B5),
    (0x116D0, 0x116E3),
    (0x1171D, 0x1172A),
    (0x1182C, 0x11838),
    (0x11930, 0x11935),
    (0x11937, 0x11938),
    (0x1193B, 0x1193C),
    (0x11940, 0x11940),
    (0x11942, 0x11942),
    (0x119D1, 0x119D7),
    (0x119DA, 0x119DF),
    (0x119E4, 0x119E4),
    (0x11A01, 0x11A0A),
    (0x11A35, 0x11A39),
    (0x11A3B, 0x11A3E),
    (0x11A51, 0x11A5B),
    (0x11A8A, 0x11A97),
    (0x11BC0, 0x11BE0),
    (0x11BF0, 0x11BF9),
    (0x11C2F, 0x11C36),
    (0x11C38, 0x11C3E),
    (0x11C92, 0x11CA7),
    (0x11CA9, 0x11CB6),
    (0x11D31, 0x11D36),
    (0x11D3A, 0x11D3A),
    (0x11D3C, 0x11D3D),
    (0x11D3F, 0x11D41),
    (0x11D43, 0x11D43),
    (0x11D47, 0x11D47),
    (0x11D8A, 0x11D8E),
    (0x11D90, 0x11D91),
    (0x11D93, 0x11D96),
    (0x11EF3, 0x11EF6),
    (0x11F00, 0x11F10),
    (0x11F12, 0x11F3A),
    (0x11F3E, 0x11F40),
    (0x11F50, 0x11F59),
    (0x1342F, 0x1342F),
    (0x13441, 0x13446),
    (0x13460, 0x143FA),
    (0x16100, 0x1612E),
    (0x16130, 0x16139),
    (0x16D40, 0x16D6C),
    (0x16D70, 0x16D79),
    (0x16F4F, 0x16F4F),
    (0x16F51, 0x16F87),
    (0x16F8F, 0x16F92),
    (0x16FF0, 0x16FF1),
    (0x18CFF, 0x18CFF),
    (0x1B132, 0x1B132),
    (0x1B155, 0x1B155),
    (0x1BC9E, 0x1BC9E),
    (0x1CCF0, 0x1CCF9),
    (0x1D2C0, 0x1D2D3),
    (0x1DF25, 0x1DF2A),
    (0x1E000, 0x1E006),
    (0x1E008, 0x1E018),
    (0x1E01B, 0x1E021),
    (0x1E023, 0x1E024),
    (0x1E026, 0x1E02A),
    (0x1E030, 0x1E06D),
    (0x1E08F, 0x1E08F),
    (0x1E4D0, 0x1E4EB),
    (0x1E4F0, 0x1E4F9),
    (0x1E5D0, 0x1E5ED),
    (0x1E5F0, 0x1E5FA),
    (0x1E947, 0x1E947),
    (0x1F130, 0x1F149),
    (0x1F150, 0x1F169),
    (0x1F170, 0x1F189),
    (0x2B739, 0x2B739),
    (0x2EBF0, 0x2EE5D),
    (0x31350, 0x323AF),
];

/// Python str.isprintable() is false (Unicode 14.0.0), surrogates excluded.
const NONPRINTABLE_RANGES: &[(u32, u32)] = &[
    (0x0000, 0x001F),
    (0x007F, 0x00A0),
    (0x00AD, 0x00AD),
    (0x0378, 0x0379),
    (0x0380, 0x0383),
    (0x038B, 0x038B),
    (0x038D, 0x038D),
    (0x03A2, 0x03A2),
    (0x0530, 0x0530),
    (0x0557, 0x0558),
    (0x058B, 0x058C),
    (0x0590, 0x0590),
    (0x05C8, 0x05CF),
    (0x05EB, 0x05EE),
    (0x05F5, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070E, 0x070F),
    (0x074B, 0x074C),
    (0x07B2, 0x07BF),
    (0x07FB, 0x07FC),
    (0x082E, 0x082F),
    (0x083F, 0x083F),
    (0x085C, 0x085D),
    (0x085F, 0x085F),
    (0x086B, 0x086F),
    (0x088F, 0x0897),
    (0x08E2, 0x08E2),
    (0x0984, 0x0984),
    (0x098D, 0x098E),
    (0x0991, 0x0992),
    (0x09A9, 0x09A9),
    (0x09B1, 0x09B1),
    (0x09B3, 0x09B5),
    (0x09BA, 0x09BB),
    (0x09C5, 0x09C6),
    (0x09C9, 0x09CA),
    (0x09CF, 0x09D6),
    (0x09D8, 0x09DB),
    (0x09DE, 0x09DE),
    (0x09E4, 0x09E5),
    (0x09FF, 0x0A00),
    (0x0A04, 0x0A04),
    (0x0A0B, 0x0A0E),
    (0x0A11, 0x0A12),
    (0x0A29, 0x0A29),
    (0x0A31, 0x0A31),
    (0x0A34, 0x0A34),
    (0x0A37, 0x0A37),
    (0x0A3A, 0x0A3B),
    (0x0A3D, 0x0A3D),
    (0x0A43, 0x0A46),
    (0x0A49, 0x0A4A),
    (0x0A4E, 0x0A50),
    (0x0A52, 0x0A58),
    (0x0A5D, 0x0A5D),
    (0x0A5F, 0x0A65),
    (0x0A77, 0x0A80),
    (0x0A84, 0x0A84),
    (0x0A8E, 0x0A8E),
    (0x0A92, 0x0A92),
    (0x0AA9, 0x0AA9),
    (0x0AB1, 0x0AB1),
    (0x0AB4, 0x0AB4),
    (0x0ABA, 0x0ABB),
    (0x0AC6, 0x0AC6),
    (0x0ACA, 0x0ACA),
    (0x0ACE, 0x0ACF),
    (0x0AD1, 0x0ADF),
    (0x0AE4, 0x0AE5),
    (0x0AF2, 0x0AF8),
    (0x0B00, 0x0B00),
    (0x0B04, 0x0B04),
    (0x0B0D, 0x0B0E),
    (0x0B11, 0x0B12),
    (0x0B29, 0x0B29),
    (0x0B31, 0x0B31),
    (0x0B34, 0x0B34),
    (0x0B3A, 0x0B3B),
    (0x0B45, 0x0B46),
    (0x0B49, 0x0B4A),
    (0x0B4E, 0x0B54),
    (0x0B58, 0x0B5B),
    (0x0B5E, 0x0B5E),
    (0x0B64, 0x0B65),
    (0x0B78, 0x0B81),
    (0x0B84, 0x0B84),
    (0x0B8B, 0x0B8D),
    (0x0B91, 0x0B91),
    (0x0B96, 0x0B98),
    (0x0B9B, 0x0B9B),
    (0x0B9D, 0x0B9D),
    (0x0BA0, 0x0BA2),
    (0x0BA5, 0x0BA7),
    (0x0BAB, 0x0BAD),
    (0x0BBA, 0x0BBD),
    (0x0BC3, 0x0BC5),
    (0x0BC9, 0x0BC9),
    (0x0BCE, 0x0BCF),
    (0x0BD1, 0x0BD6),
    (0x0BD8, 0x0BE5),
    (0x0BFB, 0x0BFF),
    (0x0C0D, 0x0C0D),
    (0x0C11, 0x0C11),
    (0x0C29, 0x0C29),
    (0x0C3A, 0x0C3B),
    (0x0C45, 0x0C45),
    (0x0C49, 0x0C49),
    (0x0C4E, 0x0C54),
    (0x0C57, 0x0C57),
    (0x0C5B, 0x0C5C),
    (0x0C5E, 0x0C5F),
    (0x0C64, 0x0C65),
    (0x0C70, 0x0C76),
    (0x0C8D, 0x0C8D),
    (0x0C91, 0x0C91),
    (0x0CA9, 0x0CA9),
    (0x0CB4, 0x0CB4),
    (0x0CBA, 0x0CBB),
    (0x0CC5, 0x0CC5),
    (0x0CC9, 0x0CC9),
    (0x0CCE, 0x0CD4),
    (0x0CD7, 0x0CDC),
    (0x0CDF, 0x0CDF),
    (0x0CE4, 0x0CE5),
    (0x0CF0, 0x0CF0),
    (0x0CF3, 0x0CFF),
    (0x0D0D, 0x0D0D),
    (0x0D11, 0x0D11),
    (0x0D45, 0x0D45),
    (0x0D49, 0x0D49),
    (0x0D50, 0x0D53),
    (0x0D64, 0x0D65),
    (0x0D80, 0x0D80),
    (0x0D84, 0x0D84),
    (0x0D97, 0x0D99),
    (0x0DB2, 0x0DB2),
    (0x0DBC, 0x0DBC),
    (0x0DBE, 0x0DBF),
    (0x0DC7, 0x0DC9),
    (0x0DCB, 0x0DCE),
    (0x0DD5, 0x0DD5),
    (0x0DD7, 0x0DD7),
    (0x0DE0, 0x0DE5),
    (0x0DF0, 0x0DF1),
    (0x0DF5, 0x0E00),
    (0x0E3B, 0x0E3E),
    (0x0E5C, 0x0E80),
    (0x0E83, 0x0E83),
    (0x0E85, 0x0E85),
    (0x0E8B, 0x0E8B),
    (0x0EA4, 0x0EA4),
    (0x0EA6, 0x0EA6),
    (0x0EBE, 0x0EBF),
    (0x0EC5, 0x0EC5),
    (0x0EC7, 0x0EC7),
    (0x0ECE, 0x0ECF),
    (0x0EDA, 0x0EDB),
    (0x0EE0, 0x0EFF),
    (0x0F48, 0x0F48),
    (0x0F6D, 0x0F70),
    (0x0F98, 0x0F98),
    (0x0FBD, 0x0FBD),
    (0x0FCD, 0x0FCD),
    (0x0FDB, 0x0FFF),
    (0x10C6, 0x10C6),
    (0x10C8, 0x10CC),
    (0x10CE, 0x10CF),
    (0x1249, 0x1249),
    (0x124E, 0x124F),
    (0x1257, 0x1257),
    (0x1259, 0x1259),
    (0x125E, 0x125F),
    (0x1289, 0x1289),
    (0x128E, 0x128F),
    (0x12B1, 0x12B1),
    (0x12B6, 0x12B7),
    (0x12BF, 0x12BF),
    (0x12C1, 0x12C1),
    (0x12C6, 0x12C7),
    (0x12D7, 0x12D7),
    (0x1311, 0x1311),
    (0x1316, 0x1317),
    (0x135B, 0x135C),
    (0x137D, 0x137F),
    (0x139A, 0x139F),
    (0x13F6, 0x13F7),
    (0x13FE, 0x13FF),
    (0x1680, 0x1680),
    (0x169D, 0x169F),
    (0x16F9, 0x16FF),
    (0x1716, 0x171E),
    (0x1737, 0x173F),
    (0x1754, 0x175F),
    (0x176D, 0x176D),
    (0x1771, 0x1771),
    (0x1774, 0x177F),
    (0x17DE, 0x17DF),
    (0x17EA, 0x17EF),
    (0x17FA, 0x17FF),
    (0x180E, 0x180E),
    (0x181A, 0x181F),
    (0x1879, 0x187F),
    (0x18AB, 0x18AF),
    (0x18F6, 0x18FF),
    (0x191F, 0x191F),
    (0x192C, 0x192F),
    (0x193C, 0x193F),
    (0x1941, 0x1943),
    (0x196E, 0x196F),
    (0x1975, 0x197F),
    (0x19AC, 0x19AF),
    (0x19CA, 0x19CF),
    (0x19DB, 0x19DD),
    (0x1A1C, 0x1A1D),
    (0x1A5F, 0x1A5F),
    (0x1A7D, 0x1A7E),
    (0x1A8A, 0x1A8F),
    (0x1A9A, 0x1A9F),
    (0x1AAE, 0x1AAF),
    (0x1ACF, 0x1AFF),
    (0x1B4D, 0x1B4F),
    (0x1B7F, 0x1B7F),
    (0x1BF4, 0x1BFB),
    (0x1C38, 0x1C3A),
    (0x1C4A, 0x1C4C),
    (0x1C89, 0x1C8F),
    (0x1CBB, 0x1CBC),
    (0x1CC8, 0x1CCF),
    (0x1CFB, 0x1CFF),
    (0x1F16, 0x1F17),
    (0x1F1E, 0x1F1F),
    (0x1F46, 0x1F47),
    (0x1F4E, 0x1F4F),
    (0x1F58, 0x1F58),
    (0x1F5A, 0x1F5A),
    (0x1F5C, 0x1F5C),
    (0x1F5E, 0x1F5E),
    (0x1F7E, 0x1F7F),
    (0x1FB5, 0x1FB5),
    (0x1FC5, 0x1FC5),
    (0x1FD4, 0x1FD5),
    (0x1FDC, 0x1FDC),
    (0x1FF0, 0x1FF1),
    (0x1FF5, 0x1FF5),
    (0x1FFF, 0x200F),
    (0x2028, 0x202F),
    (0x205F, 0x206F),
    (0x2072, 0x2073),
    (0x208F, 0x208F),
    (0x209D, 0x209F),
    (0x20C1, 0x20CF),
    (0x20F1, 0x20FF),
    (0x218C, 0x218F),
    (0x2427, 0x243F),
    (0x244B, 0x245F),
    (0x2B74, 0x2B75),
    (0x2B96, 0x2B96),
    (0x2CF4, 0x2CF8),
    (0x2D26, 0x2D26),
    (0x2D28, 0x2D2C),
    (0x2D2E, 0x2D2F),
    (0x2D68, 0x2D6E),
    (0x2D71, 0x2D7E),
    (0x2D97, 0x2D9F),
    (0x2DA7, 0x2DA7),
    (0x2DAF, 0x2DAF),
    (0x2DB7, 0x2DB7),
    (0x2DBF, 0x2DBF),
    (0x2DC7, 0x2DC7),
    (0x2DCF, 0x2DCF),
    (0x2DD7, 0x2DD7),
    (0x2DDF, 0x2DDF),
    (0x2E5E, 0x2E7F),
    (0x2E9A, 0x2E9A),
    (0x2EF4, 0x2EFF),
    (0x2FD6, 0x2FEF),
    (0x2FFC, 0x3000),
    (0x3040, 0x3040),
    (0x3097, 0x3098),
    (0x3100, 0x3104),
    (0x3130, 0x3130),
    (0x318F, 0x318F),
    (0x31E4, 0x31EF),
    (0x321F, 0x321F),
    (0xA48D, 0xA48F),
    (0xA4C7, 0xA4CF),
    (0xA62C, 0xA63F),
    (0xA6F8, 0xA6FF),
    (0xA7CB, 0xA7CF),
    (0xA7D2, 0xA7D2),
    (0xA7D4, 0xA7D4),
    (0xA7DA, 0xA7F1),
    (0xA82D, 0xA82F),
    (0xA83A, 0xA83F),
    (0xA878, 0xA87F),
    (0xA8C6, 0xA8CD),
    (0xA8DA, 0xA8DF),
    (0xA954, 0xA95E),
    (0xA97D, 0xA97F),
    (0xA9CE, 0xA9CE),
    (0xA9DA, 0xA9DD),
    (0xA9FF, 0xA9FF),
    (0xAA37, 0xAA3F),
    (0xAA4E, 0xAA4F),
    (0xAA5A, 0xAA5B),
    (0xAAC3, 0xAADA),
    (0xAAF7, 0xAB00),
    (0xAB07, 0xAB08),
    (0xAB0F, 0xAB10),
    (0xAB17, 0xAB1F),
    (0xAB27, 0xAB27),
    (0xAB2F, 0xAB2F),
    (0xAB6C, 0xAB6F),
    (0xABEE, 0xABEF),
    (0xABFA, 0xABFF),
    (0xD7A4, 0xD7AF),
    (0xD7C7, 0xD7CA),
    (0xD7FC, 0xD7FF),
    (0xE000, 0xF8FF),
    (0xFA6E, 0xFA6F),
    (0xFADA, 0xFAFF),
    (0xFB07, 0xFB12),
    (0xFB18, 0xFB1C),
    (0xFB37, 0xFB37),
    (0xFB3D, 0xFB3D),
    (0xFB3F, 0xFB3F),
    (0xFB42, 0xFB42),
    (0xFB45, 0xFB45),
    (0xFBC3, 0xFBD2),
    (0xFD90, 0xFD91),
    (0xFDC8, 0xFDCE),
    (0xFDD0, 0xFDEF),
    (0xFE1A, 0xFE1F),
    (0xFE53, 0xFE53),
    (0xFE67, 0xFE67),
    (0xFE6C, 0xFE6F),
    (0xFE75, 0xFE75),
    (0xFEFD, 0xFF00),
    (0xFFBF, 0xFFC1),
    (0xFFC8, 0xFFC9),
    (0xFFD0, 0xFFD1),
    (0xFFD8, 0xFFD9),
    (0xFFDD, 0xFFDF),
    (0xFFE7, 0xFFE7),
    (0xFFEF, 0xFFFB),
    (0xFFFE, 0xFFFF),
    (0x1000C, 0x1000C),
    (0x10027, 0x10027),
    (0x1003B, 0x1003B),
    (0x1003E, 0x1003E),
    (0x1004E, 0x1004F),
    (0x1005E, 0x1007F),
    (0x100FB, 0x100FF),
    (0x10103, 0x10106),
    (0x10134, 0x10136),
    (0x1018F, 0x1018F),
    (0x1019D, 0x1019F),
    (0x101A1, 0x101CF),
    (0x101FE, 0x1027F),
    (0x1029D, 0x1029F),
    (0x102D1, 0x102DF),
    (0x102FC, 0x102FF),
    (0x10324, 0x1032C),
    (0x1034B, 0x1034F),
    (0x1037B, 0x1037F),
    (0x1039E, 0x1039E),
    (0x103C4, 0x103C7),
    (0x103D6, 0x103FF),
    (0x1049E, 0x1049F),
    (0x104AA, 0x104AF),
    (0x104D4, 0x104D7),
    (0x104FC, 0x104FF),
    (0x10528, 0x1052F),
    (0x10564, 0x1056E),
    (0x1057B, 0x1057B),
    (0x1058B, 0x1058B),
    (0x10593, 0x10593),
    (0x10596, 0x10596),
    (0x105A2, 0x105A2),
    (0x105B2, 0x105B2),
    (0x105BA, 0x105BA),
    (0x105BD, 0x105FF),
    (0x10737, 0x1073F),
    (0x10756, 0x1075F),
    (0x10768, 0x1077F),
    (0x10786, 0x10786),
    (0x107B1, 0x107B1),
    (0x107BB, 0x107FF),
    (0x10806, 0x10807),
    (0x10809, 0x10809),
    (0x10836, 0x10836),
    (0x10839, 0x1083B),
    (0x1083D, 0x1083E),
    (0x10856, 0x10856),
    (0x1089F, 0x108A6),
    (0x108B0, 0x108DF),
    (0x108F3, 0x108F3),
    (0x108F6, 0x108FA),
    (0x1091C, 0x1091E),
    (0x1093A, 0x1093E),
    (0x10940, 0x1097F),
    (0x109B8, 0x109BB),
    (0x109D0, 0x109D1),
    (0x10A04, 0x10A04),
    (0x10A07, 0x10A0B),
    (0x10A14, 0x10A14),
    (0x10A18, 0x10A18),
    (0x10A36, 0x10A37),
    (0x10A3B, 0x10A3E),
    (0x10A49, 0x10A4F),
    (0x10A59, 0x10A5F),
    (0x10AA0, 0x10ABF),
    (0x10AE7, 0x10AEA),
    (0x10AF7, 0x10AFF),
    (0x10B36, 0x10B38),
    (0x10B56, 0x10B57),
    (0x10B73, 0x10B77),
    (0x10B92, 0x10B98),
    (0x10B9D, 0x10BA8),
    (0x10BB0, 0x10BFF),
    (0x10C49, 0x10C7F),
    (0x10CB3, 0x10CBF),
    (0x10CF3, 0x10CF9),
    (0x10D28, 0x10D2F),
    (0x10D3A, 0x10E5F),
    (0x10E7F, 0x10E7F),
    (0x10EAA, 0x10EAA),
    (0x10EAE, 0x10EAF),
    (0x10EB2, 0x10EFF),
    (0x10F28, 0x10F2F),
    (0x10F5A, 0x10F6F),
    (0x10F8A, 0x10FAF),
    (0x10FCC, 0x10FDF),
    (0x10FF7, 0x10FFF),
    (0x1104E, 0x11051),
    (0x11076, 0x1107E),
    (0x110BD, 0x110BD),
    (0x110C3, 0x110CF),
    (0x110E9, 0x110EF),
    (0x110FA, 0x110FF),
    (0x11135, 0x11135),
    (0x11148, 0x1114F),
    (0x11177, 0x1117F),
    (0x111E0, 0x111E0),
    (0x111F5, 0x111FF),
    (0x11212, 0x11212),
    (0x1123F, 0x1127F),
    (0x11287, 0x11287),
    (0x11289, 0x11289),
    (0x1128E, 0x1128E),
    (0x1129E, 0x1129E),
    (0x112AA, 0x112AF),
    (0x112EB, 0x112EF),
    (0x112FA, 0x112FF),
    (0x11304, 0x11304),
    (0x1130D, 0x1130E),
    (0x11311, 0x11312),
    (0x11329, 0x11329),
    (0x11331, 0x11331),
    (0x11334, 0x11334),
    (0x1133A, 0x1133A),
    (0x11345, 0x11346),
    (0x11349, 0x1134A),
    (0x1134E, 0x1134F),
    (0x11351, 0x11356),
    (0x11358, 0x1135C),
    (0x11364, 0x11365),
    (0x1136D, 0x1136F),
    (0x11375, 0x113FF),
    (0x1145C, 0x1145C),
    (0x11462, 0x1147F),
    (0x114C8, 0x114CF),
    (0x114DA, 0x1157F),
    (0x115B6, 0x115B7),
    (0x115DE, 0x115FF),
    (0x11645, 0x1164F),
    (0x1165A, 0x1165F),
    (0x1166D, 0x1167F),
    (0x116BA, 0x116BF),
    (0x116CA, 0x116FF),
    (0x1171B, 0x1171C),
    (0x1172C, 0x1172F),
    (0x11747, 0x117FF),
    (0x1183C, 0x1189F),
    (0x118F3, 0x118FE),
    (0x11907, 0x11908),
    (0x1190A, 0x1190B),
    (0x11914, 0x11914),
    (0x11917, 0x11917),
    (0x11936, 0x11936),
    (0x11939, 0x1193A),
    (0x11947, 0x1194F),
    (0x1195A, 0x1199F),
    (0x119A8, 0x119A9),
    (0x119D8, 0x119D9),
    (0x119E5, 0x119FF),
    (0x11A48, 0x11A4F),
    (0x11AA3, 0x11AAF),
    (0x11AF9, 0x11BFF),
    (0x11C09, 0x11C09),
    (0x11C37, 0x11C37),
    (0x11C46, 0x11C4F),
    (0x11C6D, 0x11C6F),
    (0x11C90, 0x11C91),
    (0x11CA8, 0x11CA8),
    (0x11CB7, 0x11CFF),
    (0x11D07, 0x11D07),
    (0x11D0A, 0x11D0A),
    (0x11D37, 0x11D39),
    (0x11D3B, 0x11D3B),
    (0x11D3E, 0x11D3E),
    (0x11D48, 0x11D4F),
    (0x11D5A, 0x11D5F),
    (0x11D66, 0x11D66),
    (0x11D69, 0x11D69),
    (0x11D8F, 0x11D8F),
    (0x11D92, 0x11D92),
    (0x11D99, 0x11D9F),
    (0x11DAA, 0x11EDF),
    (0x11EF9, 0x11FAF),
    (0x11FB1, 0x11FBF),
    (0x11FF2, 0x11FFE),
    (0x1239A, 0x123FF),
    (0x1246F, 0x1246F),
    (0x12475, 0x1247F),
    (0x12544, 0x12F8F),
    (0x12FF3, 0x12FFF),
    (0x1342F, 0x143FF),
    (0x14647, 0x167FF),
    (0x16A39, 0x16A3F),
    (0x16A5F, 0x16A5F),
    (0x16A6A, 0x16A6D),
    (0x16ABF, 0x16ABF),
    (0x16ACA, 0x16ACF),
    (0x16AEE, 0x16AEF),
    (0x16AF6, 0x16AFF),
    (0x16B46, 0x16B4F),
    (0x16B5A, 0x16B5A),
    (0x16B62, 0x16B62),
    (0x16B78, 0x16B7C),
    (0x16B90, 0x16E3F),
    (0x16E9B, 0x16EFF),
    (0x16F4B, 0x16F4E),
    (0x16F88, 0x16F8E),
    (0x16FA0, 0x16FDF),
    (0x16FE5, 0x16FEF),
    (0x16FF2, 0x16FFF),
    (0x187F8, 0x187FF),
    (0x18CD6, 0x18CFF),
    (0x18D09, 0x1AFEF),
    (0x1AFF4, 0x1AFF4),
    (0x1AFFC, 0x1AFFC),
    (0x1AFFF, 0x1AFFF),
    (0x1B123, 0x1B14F),
    (0x1B153, 0x1B163),
    (0x1B168, 0x1B16F),
    (0x1B2FC, 0x1BBFF),
    (0x1BC6B, 0x1BC6F),
    (0x1BC7D, 0x1BC7F),
    (0x1BC89, 0x1BC8F),
    (0x1BC9A, 0x1BC9B),
    (0x1BCA0, 0x1CEFF),
    (0x1CF2E, 0x1CF2F),
    (0x1CF47, 0x1CF4F),
    (0x1CFC4, 0x1CFFF),
    (0x1D0F6, 0x1D0FF),
    (0x1D127, 0x1D128),
    (0x1D173, 0x1D17A),
    (0x1D1EB, 0x1D1FF),
    (0x1D246, 0x1D2DF),
    (0x1D2F4, 0x1D2FF),
    (0x1D357, 0x1D35F),
    (0x1D379, 0x1D3FF),
    (0x1D455, 0x1D455),
    (0x1D49D, 0x1D49D),
    (0x1D4A0, 0x1D4A1),
    (0x1D4A3, 0x1D4A4),
    (0x1D4A7, 0x1D4A8),
    (0x1D4AD, 0x1D4AD),
    (0x1D4BA, 0x1D4BA),
    (0x1D4BC, 0x1D4BC),
    (0x1D4C4, 0x1D4C4),
    (0x1D506, 0x1D506),
    (0x1D50B, 0x1D50C),
    (0x1D515, 0x1D515),
    (0x1D51D, 0x1D51D),
    (0x1D53A, 0x1D53A),
    (0x1D53F, 0x1D53F),
    (0x1D545, 0x1D545),
    (0x1D547, 0x1D549),
    (0x1D551, 0x1D551),
    (0x1D6A6, 0x1D6A7),
    (0x1D7CC, 0x1D7CD),
    (0x1DA8C, 0x1DA9A),
    (0x1DAA0, 0x1DAA0),
    (0x1DAB0, 0x1DEFF),
    (0x1DF1F, 0x1DFFF),
    (0x1E007, 0x1E007),
    (0x1E019, 0x1E01A),
    (0x1E022, 0x1E022),
    (0x1E025, 0x1E025),
    (0x1E02B, 0x1E0FF),
    (0x1E12D, 0x1E12F),
    (0x1E13E, 0x1E13F),
    (0x1E14A, 0x1E14D),
    (0x1E150, 0x1E28F),
    (0x1E2AF, 0x1E2BF),
    (0x1E2FA, 0x1E2FE),
    (0x1E300, 0x1E7DF),
    (0x1E7E7, 0x1E7E7),
    (0x1E7EC, 0x1E7EC),
    (0x1E7EF, 0x1E7EF),
    (0x1E7FF, 0x1E7FF),
    (0x1E8C5, 0x1E8C6),
    (0x1E8D7, 0x1E8FF),
    (0x1E94C, 0x1E94F),
    (0x1E95A, 0x1E95D),
    (0x1E960, 0x1EC70),
    (0x1ECB5, 0x1ED00),
    (0x1ED3E, 0x1EDFF),
    (0x1EE04, 0x1EE04),
    (0x1EE20, 0x1EE20),
    (0x1EE23, 0x1EE23),
    (0x1EE25, 0x1EE26),
    (0x1EE28, 0x1EE28),
    (0x1EE33, 0x1EE33),
    (0x1EE38, 0x1EE38),
    (0x1EE3A, 0x1EE3A),
    (0x1EE3C, 0x1EE41),
    (0x1EE43, 0x1EE46),
    (0x1EE48, 0x1EE48),
    (0x1EE4A, 0x1EE4A),
    (0x1EE4C, 0x1EE4C),
    (0x1EE50, 0x1EE50),
    (0x1EE53, 0x1EE53),
    (0x1EE55, 0x1EE56),
    (0x1EE58, 0x1EE58),
    (0x1EE5A, 0x1EE5A),
    (0x1EE5C, 0x1EE5C),
    (0x1EE5E, 0x1EE5E),
    (0x1EE60, 0x1EE60),
    (0x1EE63, 0x1EE63),
    (0x1EE65, 0x1EE66),
    (0x1EE6B, 0x1EE6B),
    (0x1EE73, 0x1EE73),
    (0x1EE78, 0x1EE78),
    (0x1EE7D, 0x1EE7D),
    (0x1EE7F, 0x1EE7F),
    (0x1EE8A, 0x1EE8A),
    (0x1EE9C, 0x1EEA0),
    (0x1EEA4, 0x1EEA4),
    (0x1EEAA, 0x1EEAA),
    (0x1EEBC, 0x1EEEF),
    (0x1EEF2, 0x1EFFF),
    (0x1F02C, 0x1F02F),
    (0x1F094, 0x1F09F),
    (0x1F0AF, 0x1F0B0),
    (0x1F0C0, 0x1F0C0),
    (0x1F0D0, 0x1F0D0),
    (0x1F0F6, 0x1F0FF),
    (0x1F1AE, 0x1F1E5),
    (0x1F203, 0x1F20F),
    (0x1F23C, 0x1F23F),
    (0x1F249, 0x1F24F),
    (0x1F252, 0x1F25F),
    (0x1F266, 0x1F2FF),
    (0x1F6D8, 0x1F6DC),
    (0x1F6ED, 0x1F6EF),
    (0x1F6FD, 0x1F6FF),
    (0x1F774, 0x1F77F),
    (0x1F7D9, 0x1F7DF),
    (0x1F7EC, 0x1F7EF),
    (0x1F7F1, 0x1F7FF),
    (0x1F80C, 0x1F80F),
    (0x1F848, 0x1F84F),
    (0x1F85A, 0x1F85F),
    (0x1F888, 0x1F88F),
    (0x1F8AE, 0x1F8AF),
    (0x1F8B2, 0x1F8FF),
    (0x1FA54, 0x1FA5F),
    (0x1FA6E, 0x1FA6F),
    (0x1FA75, 0x1FA77),
    (0x1FA7D, 0x1FA7F),
    (0x1FA87, 0x1FA8F),
    (0x1FAAD, 0x1FAAF),
    (0x1FABB, 0x1FABF),
    (0x1FAC6, 0x1FACF),
    (0x1FADA, 0x1FADF),
    (0x1FAE8, 0x1FAEF),
    (0x1FAF7, 0x1FAFF),
    (0x1FB93, 0x1FB93),
    (0x1FBCB, 0x1FBEF),
    (0x1FBFA, 0x1FFFF),
    (0x2A6E0, 0x2A6FF),
    (0x2B739, 0x2B73F),
    (0x2B81E, 0x2B81F),
    (0x2CEA2, 0x2CEAF),
    (0x2EBE1, 0x2F7FF),
    (0x2FA1E, 0x2FFFF),
    (0x3134B, 0xE00FF),
    (0xE01F0, 0x10FFFF),
];

const BEGIN_BANNER: [char; 11] = ['-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N', ' '];
const KEY_TAIL: [char; 8] = ['K', 'E', 'Y', '-', '-', '-', '-', '-'];
const BEARER_WORD: [char; 6] = ['B', 'e', 'a', 'r', 'e', 'r'];
const API_PREFIXES: [&[char]; 5] = [
    &['s', 'k'],
    &['g', 'h', 'p'],
    &['g', 'h', 'o'],
    &['g', 'l', 'p', 'a', 't'],
    &['s', 'l', 'a', 'c', 'k', '_', 't', 'o', 'k', 'e', 'n'],
];
const CREDENTIAL_KEYWORDS: [&[u8]; 5] = [b"password", b"passwd", b"api_key", b"secret", b"token"];

/// Python: `line: int | None`, with `bool` rejected even though it subclasses `int`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLine {
    Int(i64),
    Bool(bool),
}

/// Source coordinates for a finding.
///
/// Paths are normalized to forward slashes and stripped so hashes and ordering
/// match across Windows, Linux, and macOS (AC-019, AC-029).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    path: String,
    line: Option<i64>,
    record_id: Option<String>,
}

impl SourceRef {
    /// Validate and store the normalized path, line, and record id.
    ///
    /// `context` defaults are not implicit: pass [`DEFAULT_TEXT_CONTEXT`] only
    /// for free text. This constructor uses `SourceRef.path` and
    /// `SourceRef.record_id`.
    pub fn try_new(
        path: &str,
        line: Option<SourceLine>,
        record_id: Option<&str>,
    ) -> Result<Self, FindingError> {
        if python_strip(path).is_empty() {
            return Err(FindingError::new(format!(
                "SourceRef.path must be a non-empty string, got {}",
                python_str_repr(path)
            )));
        }
        let normalized_path = python_strip(path).replace('\\', "/");
        enforce_content_free_text(&normalized_path, "SourceRef.path")?;

        let line = match line {
            None => None,
            Some(SourceLine::Bool(value)) => {
                let rendered = if value { "True" } else { "False" };
                return Err(FindingError::new(format!(
                    "SourceRef.line must be a positive integer or None, got {rendered}"
                )));
            }
            Some(SourceLine::Int(value)) if value >= 1 => Some(value),
            Some(SourceLine::Int(value)) => {
                return Err(FindingError::new(format!(
                    "SourceRef.line must be a positive integer or None, got {value}"
                )));
            }
        };

        let record_id = match record_id {
            None => None,
            Some(raw) => {
                if python_strip(raw).is_empty() {
                    return Err(FindingError::new(format!(
                        "SourceRef.record_id must be non-empty string or None, got {}",
                        python_str_repr(raw)
                    )));
                }
                let normalized = python_strip(raw).to_owned();
                enforce_content_free_text(&normalized, "SourceRef.record_id")?;
                Some(normalized)
            }
        };

        Ok(Self {
            path: normalized_path,
            line,
            record_id,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn line(&self) -> Option<i64> {
        self.line
    }

    pub fn record_id(&self) -> Option<&str> {
        self.record_id.as_deref()
    }
}

/// Map key in an evidence value. Order of entries is the `Vec` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceKey {
    Text(String),
    /// Non-string keys fail closed. The Python message does not include the key.
    NonString,
}

impl EvidenceKey {
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }
}

/// Evidence tree the content-free walker understands.
///
/// Containers are `Rc` so a cycle has one identity, matching Python `id()`.
/// Scalars (`int`, `bool`, `None`, `float`) are [`Evidence::ignored`] and are
/// not inspected. `dict` order is the `Vec` order, not a `HashMap`.
#[derive(Clone, Debug)]
pub struct Evidence {
    kind: Rc<EvidenceKind>,
}

#[derive(Debug)]
enum EvidenceKind {
    Str(String),
    /// Python `int` that is not `bool`.
    Int(i64),
    Bool(bool),
    /// Python `None`. Distinct from [`EvidenceKind::Ignored`] so readers can tell.
    NoneValue,
    Bytes(Vec<u8>),
    Ignored,
    Map(RefCell<Vec<(EvidenceKey, Evidence)>>),
    List(RefCell<Vec<Evidence>>),
    Tuple(Vec<Evidence>),
    Set(Vec<Evidence>),
    FrozenSet(Vec<Evidence>),
}

impl Evidence {
    pub fn string(value: impl Into<String>) -> Self {
        Self::from_kind(EvidenceKind::Str(value.into()))
    }

    pub fn ignored() -> Self {
        Self::from_kind(EvidenceKind::Ignored)
    }

    pub fn int(value: i64) -> Self {
        Self::from_kind(EvidenceKind::Int(value))
    }

    pub fn bool_value(value: bool) -> Self {
        Self::from_kind(EvidenceKind::Bool(value))
    }

    pub fn none_value() -> Self {
        Self::from_kind(EvidenceKind::NoneValue)
    }

    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::from_kind(EvidenceKind::Bytes(value.into()))
    }

    pub fn map(entries: Vec<(EvidenceKey, Evidence)>) -> Self {
        Self::from_kind(EvidenceKind::Map(RefCell::new(entries)))
    }

    pub fn list(items: Vec<Evidence>) -> Self {
        Self::from_kind(EvidenceKind::List(RefCell::new(items)))
    }

    pub fn tuple(items: Vec<Evidence>) -> Self {
        Self::from_kind(EvidenceKind::Tuple(items))
    }

    pub fn set(items: Vec<Evidence>) -> Self {
        Self::from_kind(EvidenceKind::Set(items))
    }

    pub fn frozenset(items: Vec<Evidence>) -> Self {
        Self::from_kind(EvidenceKind::FrozenSet(items))
    }

    /// Append a map entry. Returns false when `self` is not a map.
    ///
    /// Used to build a cycle after the node exists.
    pub fn push_map_entry(&self, key: EvidenceKey, value: Evidence) -> bool {
        if let EvidenceKind::Map(entries) = &*self.kind {
            entries.borrow_mut().push((key, value));
            true
        } else {
            false
        }
    }

    /// Append a list item. Returns false when `self` is not a list.
    pub fn push_list_item(&self, value: Evidence) -> bool {
        if let EvidenceKind::List(items) = &*self.kind {
            items.borrow_mut().push(value);
            true
        } else {
            false
        }
    }

    fn from_kind(kind: EvidenceKind) -> Self {
        Self {
            kind: Rc::new(kind),
        }
    }
}

/// Validate that text does not contain control characters, line breaks, or credentials/PII.
///
/// Python: `enforce_content_free_text(text, *, context="text")`.
/// Pass [`DEFAULT_TEXT_CONTEXT`] for that default. Rust has no default arguments.
///
/// After the ASCII fast path, the first hit wins:
/// control or newline, then Unicode Cc/Cf/Zl/Zp, then email, private-key banner,
/// bearer token, API-key shape, credential assignment.
pub fn enforce_content_free_text(text: &str, context: &str) -> Result<(), FindingError> {
    let chars: Vec<char> = text.chars().collect();
    // Fast path: the combined reject pattern missed AND the string is ASCII.
    // A non-ASCII string always continues, even when the ASCII patterns miss.
    if text.is_ascii() && !combined_reject(&chars) {
        return Ok(());
    }
    if has_control_pattern(&chars) {
        return Err(forbidden(format!(
            "Forbidden control or newline characters in {context}: {}",
            python_str_repr(text)
        )));
    }
    if !text.is_ascii() {
        if let Some(ch) = first_dangerous_category(&chars) {
            let code = ch as u32;
            return Err(forbidden(format!(
                "Forbidden Unicode control/formatting character U+{code:04X} in {context}: {}",
                python_str_repr(text)
            )));
        }
    }
    if has_email(&chars) {
        return Err(forbidden(format!(
            "Forbidden content-bearing pattern (e.g., email/PII) in {context}: {}",
            python_str_repr(text)
        )));
    }
    if has_private_key(&chars) {
        return Err(forbidden(format!(
            "Forbidden credential pattern (private key) in {context}: {}",
            python_str_repr(text)
        )));
    }
    if has_bearer(&chars) {
        return Err(forbidden(format!(
            "Forbidden credential pattern (bearer token) in {context}: {}",
            python_str_repr(text)
        )));
    }
    if has_api_key(&chars) {
        return Err(forbidden(format!(
            "Forbidden credential pattern (API key) in {context}: {}",
            python_str_repr(text)
        )));
    }
    if has_credential(&chars) {
        return Err(forbidden(format!(
            "Forbidden credential pattern (credential assignment) in {context}: {}",
            python_str_repr(text)
        )));
    }
    Ok(())
}

/// Python: `_enforce_content_free_evidence_recursive(val, context)`.
///
/// The `seen` set is internal. Shared acyclic nodes are allowed; a container
/// re-entered while it is still on the stack raises
/// `Cyclic reference detected in evidence: {context}`.
pub fn enforce_content_free_evidence_recursive(
    val: &Evidence,
    context: &str,
) -> Result<(), FindingError> {
    let mut seen = Vec::new();
    walk(val, context, &mut seen)
}

fn forbidden(message: String) -> FindingError {
    FindingError::new(message)
}

fn combined_reject(chars: &[char]) -> bool {
    has_control_pattern(chars)
        || has_email(chars)
        || has_private_key(chars)
        || has_bearer(chars)
        || has_api_key(chars)
        || has_credential(chars)
}

fn has_control_pattern(chars: &[char]) -> bool {
    chars.iter().any(|ch| {
        let code = u32::from(*ch);
        code <= 0x1F || code == 0x7F
    })
}

fn first_dangerous_category(chars: &[char]) -> Option<char> {
    chars.iter().copied().find(|ch| is_dangerous_category(*ch))
}

fn is_dangerous_category(ch: char) -> bool {
    // Cc on Unicode 14.0.0 is exactly C0 and C1. Zl/Zp are one code point each.
    // Cf is not exposed by std; [`CF_RANGES`] is the pinned Python set.
    ch.is_control() || ch == '\u{2028}' || ch == '\u{2029}' || in_ranges(u32::from(ch), CF_RANGES)
}

fn has_email(chars: &[char]) -> bool {
    chars
        .iter()
        .enumerate()
        .any(|(at, ch)| *ch == '@' && local_has_boundary(chars, at) && domain_has_tld(chars, at))
}

fn local_has_boundary(chars: &[char], at: usize) -> bool {
    if at == 0 || !is_local_char(chars[at - 1]) {
        return false;
    }
    let mut start = at - 1;
    while start > 0 && is_local_char(chars[start - 1]) {
        start -= 1;
    }
    (start..at).any(|index| is_word_boundary(chars, index))
}

fn domain_has_tld(chars: &[char], at: usize) -> bool {
    let Some(mut domain_end) = at.checked_add(1) else {
        return false;
    };
    if domain_end >= chars.len() || !is_domain_char(chars[domain_end]) {
        return false;
    }
    while domain_end < chars.len() && is_domain_char(chars[domain_end]) {
        domain_end += 1;
    }
    let mut dot = at + 1;
    while dot < domain_end {
        if chars[dot] == '.' && dot > at + 1 && tld_boundary(chars, dot) {
            return true;
        }
        dot += 1;
    }
    false
}

fn tld_boundary(chars: &[char], dot: usize) -> bool {
    let tld_start = dot + 1;
    let mut tld_end = tld_start;
    while tld_end < chars.len() && chars[tld_end].is_ascii_alphabetic() {
        tld_end += 1;
    }
    let max_len = tld_end - tld_start;
    if max_len < 2 {
        return false;
    }
    let mut len = max_len;
    while len >= 2 {
        if is_word_boundary(chars, tld_start + len) {
            return true;
        }
        len -= 1;
    }
    false
}

fn has_private_key(chars: &[char]) -> bool {
    let min_len = BEGIN_BANNER.len() + 1 + KEY_TAIL.len();
    if chars.len() < min_len {
        return false;
    }
    let last = chars.len() - BEGIN_BANNER.len();
    for index in 0..=last {
        if !starts_with_chars(chars, index, &BEGIN_BANNER) {
            continue;
        }
        let run_start = index + BEGIN_BANNER.len();
        let mut run_end = run_start;
        while run_end < chars.len() && is_banner_char(chars[run_end]) {
            run_end += 1;
        }
        let mut len = run_end - run_start;
        while len >= 1 {
            if starts_with_chars(chars, run_start + len, &KEY_TAIL) {
                return true;
            }
            len -= 1;
        }
    }
    false
}

fn has_bearer(chars: &[char]) -> bool {
    for index in 0..chars.len() {
        if !is_word_boundary(chars, index) || !starts_with_chars(chars, index, &BEARER_WORD) {
            continue;
        }
        let mut cursor = index + BEARER_WORD.len();
        if cursor >= chars.len() || !is_python_space(chars[cursor]) {
            continue;
        }
        while cursor < chars.len() && is_python_space(chars[cursor]) {
            cursor += 1;
        }
        if class_run_has_boundary(chars, cursor, 10, is_bearer_token_char) {
            return true;
        }
    }
    false
}

fn has_api_key(chars: &[char]) -> bool {
    for index in 0..chars.len() {
        if !is_word_boundary(chars, index) {
            continue;
        }
        for prefix in API_PREFIXES {
            if !starts_with_chars(chars, index, prefix) {
                continue;
            }
            let Some(sep) = index.checked_add(prefix.len()) else {
                continue;
            };
            if sep >= chars.len() || (chars[sep] != '_' && chars[sep] != '-') {
                continue;
            }
            if class_run_has_boundary(chars, sep + 1, 16, is_api_token_char) {
                return true;
            }
        }
    }
    false
}

fn has_credential(chars: &[char]) -> bool {
    for index in 0..chars.len() {
        if !is_word_boundary(chars, index) {
            continue;
        }
        for keyword in CREDENTIAL_KEYWORDS {
            if credential_at(chars, index, keyword) {
                return true;
            }
        }
    }
    false
}

fn credential_at(chars: &[char], index: usize, keyword: &[u8]) -> bool {
    if !starts_with_keyword(chars, index, keyword) {
        return false;
    }
    let mut cursor = index + keyword.len();
    while cursor < chars.len() && is_python_space(chars[cursor]) {
        cursor += 1;
    }
    if cursor >= chars.len() || (chars[cursor] != ':' && chars[cursor] != '=') {
        return false;
    }
    cursor += 1;
    while cursor < chars.len() && is_python_space(chars[cursor]) {
        cursor += 1;
    }
    cursor < chars.len() && !is_python_space(chars[cursor])
}

fn class_run_has_boundary(
    chars: &[char],
    start: usize,
    min_len: usize,
    class: fn(char) -> bool,
) -> bool {
    let mut end = start;
    while end < chars.len() && class(chars[end]) {
        end += 1;
    }
    let available = end - start;
    if available < min_len {
        return false;
    }
    let mut len = available;
    while len >= min_len {
        if is_word_boundary(chars, start + len) {
            return true;
        }
        len -= 1;
    }
    false
}

fn starts_with_chars(chars: &[char], index: usize, needle: &[char]) -> bool {
    match index.checked_add(needle.len()) {
        Some(end) if end <= chars.len() => &chars[index..end] == needle,
        _ => false,
    }
}

fn starts_with_keyword(chars: &[char], index: usize, keyword: &[u8]) -> bool {
    match index.checked_add(keyword.len()) {
        Some(end) if end <= chars.len() => keyword.iter().enumerate().all(|(offset, expected)| {
            fold_credential_char(chars[index + offset]) == Some(char::from(*expected))
        }),
        _ => false,
    }
}

fn fold_credential_char(ch: char) -> Option<char> {
    if ch.is_ascii_alphanumeric() || ch == '_' {
        return Some(ch.to_ascii_lowercase());
    }
    // Python `(?i)` casefold extras for the keyword letters, pinned on 3.11.
    match ch {
        '\u{0130}' | '\u{0131}' => Some('i'),
        '\u{017F}' => Some('s'),
        '\u{212A}' => Some('k'),
        _ => None,
    }
}

fn is_local_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-')
}

fn is_domain_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-')
}

fn is_bearer_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')
}

fn is_api_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')
}

fn is_banner_char(ch: char) -> bool {
    ch.is_ascii_uppercase() || ch == ' '
}

fn is_word_boundary(chars: &[char], index: usize) -> bool {
    let left = index > 0 && is_python_word(chars[index - 1]);
    let right = index < chars.len() && is_python_word(chars[index]);
    left != right
}

fn is_python_word(ch: char) -> bool {
    if ch == '_' {
        return true;
    }
    // Letters and numbers match Python `\w`. `is_alphanumeric` is wider
    // (marks, symbols, and post-Unicode-14 assignments); those ranges are excluded.
    ch.is_alphanumeric() && !in_ranges(u32::from(ch), NON_WORD_ALNUM_RANGES)
}

/// Python `str.isspace` / regex `\s`.
///
/// Rust [`char::is_whitespace`] omits U+001C..=U+001F, which Python treats as space.
fn is_python_space(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '\u{001C}'..='\u{001F}')
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(is_python_space)
}

fn in_ranges(code: u32, ranges: &[(u32, u32)]) -> bool {
    ranges
        .binary_search_by(|(start, end)| {
            if code < *start {
                Ordering::Greater
            } else if code > *end {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

fn is_python_printable(ch: char) -> bool {
    !in_ranges(u32::from(ch), NONPRINTABLE_RANGES)
}

/// Python `repr` for `str` (prefer single quotes).
fn python_str_repr(text: &str) -> String {
    let use_double = text.contains('\'') && !text.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        let code = u32::from(ch);
        if ch == '\\' {
            out.push_str("\\\\");
        } else if ch == quote {
            out.push('\\');
            out.push(quote);
        } else if ch == '\t' {
            out.push_str("\\t");
        } else if ch == '\n' {
            out.push_str("\\n");
        } else if ch == '\r' {
            out.push_str("\\r");
        } else if code < 32 || code == 0x7F || !is_python_printable(ch) {
            if code < 0x100 {
                push_lower_hex(&mut out, "\\x", code, 2);
            } else if code < 0x10000 {
                push_lower_hex(&mut out, "\\u", code, 4);
            } else {
                push_lower_hex(&mut out, "\\U", code, 8);
            }
        } else {
            out.push(ch);
        }
    }
    out.push(quote);
    out
}

fn push_lower_hex(out: &mut String, prefix: &str, code: u32, width: usize) {
    out.push_str(prefix);
    let digits = format!("{code:x}");
    let pad = width.saturating_sub(digits.len());
    for _ in 0..pad {
        out.push('0');
    }
    out.push_str(&digits);
}

fn walk(
    val: &Evidence,
    context: &str,
    seen: &mut Vec<*const EvidenceKind>,
) -> Result<(), FindingError> {
    match &*val.kind {
        EvidenceKind::Str(text) => enforce_content_free_text(text, context),
        // Scalars are not inspected. `int` / `bool` / `None` stay distinct for readers.
        EvidenceKind::Ignored
        | EvidenceKind::Int(_)
        | EvidenceKind::Bool(_)
        | EvidenceKind::NoneValue
        | EvidenceKind::Bytes(_) => Ok(()),
        EvidenceKind::Map(entries) => {
            let copied = {
                let borrowed = entries.borrow();
                borrowed.clone()
            };
            with_identity(val, context, seen, |seen| walk_map(&copied, context, seen))
        }
        EvidenceKind::List(items) => {
            let copied = {
                let borrowed = items.borrow();
                borrowed.clone()
            };
            with_identity(val, context, seen, |seen| {
                walk_sequence(&copied, context, seen, false)
            })
        }
        EvidenceKind::Tuple(items) => with_identity(val, context, seen, |seen| {
            walk_sequence(items, context, seen, false)
        }),
        EvidenceKind::Set(items) | EvidenceKind::FrozenSet(items) => {
            with_identity(val, context, seen, |seen| {
                walk_sequence(items, context, seen, true)
            })
        }
    }
}

fn with_identity(
    val: &Evidence,
    context: &str,
    seen: &mut Vec<*const EvidenceKind>,
    body: impl FnOnce(&mut Vec<*const EvidenceKind>) -> Result<(), FindingError>,
) -> Result<(), FindingError> {
    let id = Rc::as_ptr(&val.kind);
    if seen.contains(&id) {
        return Err(forbidden(format!(
            "Cyclic reference detected in evidence: {context}"
        )));
    }
    seen.push(id);
    let result = body(seen);
    if let Some(pos) = seen.iter().rposition(|item| *item == id) {
        seen.remove(pos);
    }
    result
}

fn walk_map(
    entries: &[(EvidenceKey, Evidence)],
    context: &str,
    seen: &mut Vec<*const EvidenceKind>,
) -> Result<(), FindingError> {
    for (key, child) in entries {
        match key {
            EvidenceKey::NonString => {
                return Err(forbidden(format!(
                    "{context} keys must be non-empty strings"
                )));
            }
            EvidenceKey::Text(text) => {
                if python_strip(text).is_empty() {
                    return Err(forbidden(format!(
                        "{context} keys must be non-empty strings"
                    )));
                }
                let key_context = format!("{context} key {}", python_str_repr(text));
                enforce_content_free_text(text, &key_context)?;
                let child_context = format!("{context}[{}]", python_str_repr(text));
                walk(child, &child_context, seen)?;
            }
        }
    }
    Ok(())
}

fn walk_sequence(
    items: &[Evidence],
    context: &str,
    seen: &mut Vec<*const EvidenceKind>,
    sort_set: bool,
) -> Result<(), FindingError> {
    let sorted;
    let ordered: &[Evidence] = if sort_set {
        sorted = sorted_set_items(items);
        &sorted
    } else {
        items
    };
    for (idx, item) in ordered.iter().enumerate() {
        let child_context = format!("{context}[{idx}]");
        walk(item, &child_context, seen)?;
    }
    Ok(())
}

fn sorted_set_items(items: &[Evidence]) -> Vec<Evidence> {
    let mut indexed: Vec<(usize, Evidence)> = items.iter().cloned().enumerate().collect();
    indexed.sort_by(|left, right| {
        set_sort_key(&left.1)
            .cmp(&set_sort_key(&right.1))
            .then(left.0.cmp(&right.0))
    });
    indexed.into_iter().map(|(_, item)| item).collect()
}

fn set_sort_key(item: &Evidence) -> (u8, String) {
    match &*item.kind {
        EvidenceKind::Str(text) => (0, text.clone()),
        EvidenceKind::Ignored
        | EvidenceKind::Int(_)
        | EvidenceKind::Bool(_)
        | EvidenceKind::NoneValue
        | EvidenceKind::Bytes(_) => (1, String::new()),
        EvidenceKind::Map(_) => (2, String::new()),
        EvidenceKind::List(_) => (3, String::new()),
        EvidenceKind::Tuple(_) => (4, String::new()),
        EvidenceKind::Set(_) => (5, String::new()),
        EvidenceKind::FrozenSet(_) => (6, String::new()),
    }
}

/// `Finding.related_ids` uniques the raw values (`set`), then this port walks
/// strings in code-point order and other hashable items in input order.
///
/// Python set iteration is not stable, so the first rejected item can differ.
/// Uniqueness is on the raw values: `" a "` and `"a"` both remain, and the
/// sorted tuple can contain duplicates. Items are not uniqued again after strip.
pub const RELATED_IDS_SET_ORDER_DEVIATION: &str = "Finding.related_ids uniques raw values with set equality, then walks strings in code-point order before other hashable items in input order. Python set order is not stable, so the first rejected item can differ. Values are not uniqued after strip, so ' a ' and 'a' can both remain";

/// `Finding.from_dict` raises `KeyError`, `ValueError`, or `TypeError` before
/// `__post_init__`. Rust returns [`FindingError`] and does not panic.
pub const FROM_DICT_EXCEPTION_DEVIATION: &str = "Finding.from_dict raises KeyError for a missing code, severity, repairability, message, fingerprint, or source.path; ValueError from Severity() or Repairability() on a bad enum value; and TypeError from tuple(related_ids) when related_ids is not iterable. Those happen before __post_init__. Rust returns FindingError and does not panic";

/// `Finding.variant` is `typing.cast`. A non-string value is returned as-is.
/// Rust returns [`FindingError`] instead of that raw value.
pub const VARIANT_CAST_DEVIATION: &str = "Finding.variant uses typing.cast and returns a non-string evidence value unchanged; Rust returns FindingError instead of that raw value";

/// `sort_findings` only sees [`Finding`] values. Python can raise `TypeError`
/// while ordering a non-Finding. Rust does not panic to imitate that.
pub const SORT_FINDINGS_TYPE_DEVIATION: &str = "sort_findings only represents Finding values. Python may raise TypeError while ordering a non-Finding; Rust does not panic to imitate that";

/// Python `==` compares every dataclass field. Ordering uses the sort key.
/// Rust [`Eq`] stays structural and [`Ord`] uses the sort key, so they disagree
/// when only a non-key field differs (for example `message_template`).
pub const FINDING_EQ_ORD_DEVIATION: &str = "Python Finding equality is dataclass field equality, while ordering uses the sort key. Rust Eq stays structural and Ord uses the sort key";

const FINGERPRINT_ERROR_PREFIX: &str =
    "Finding.fingerprint must be a 16-character lowercase hex string matching ^[0-9a-f]{16}$, got ";

/// Python object passed into [`Finding::try_new`].
///
/// Wrong types stay representable so the `isinstance` branches can fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    None,
    Severity(Severity),
    Repairability(Repairability),
    Source(SourceRef),
    List(Vec<PyValue>),
    Tuple(Vec<PyValue>),
    Set(Vec<PyValue>),
    FrozenSet(Vec<PyValue>),
    Map(Vec<(PyValue, PyValue)>),
}

impl PyValue {
    pub fn string(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn int(value: i64) -> Self {
        Self::Int(value)
    }

    pub fn bool_value(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    pub fn list(items: Vec<PyValue>) -> Self {
        Self::List(items)
    }

    pub fn tuple(items: Vec<PyValue>) -> Self {
        Self::Tuple(items)
    }

    pub fn set(items: Vec<PyValue>) -> Self {
        Self::Set(items)
    }

    pub fn map(entries: Vec<(PyValue, PyValue)>) -> Self {
        Self::Map(entries)
    }

    pub fn severity(value: Severity) -> Self {
        Self::Severity(value)
    }

    pub fn repairability(value: Repairability) -> Self {
        Self::Repairability(value)
    }

    pub fn source(value: SourceRef) -> Self {
        Self::Source(value)
    }
}

/// One JSON-like value in [`Finding::to_dict`] / [`Finding::from_dict`].
///
/// Map entries keep input order. This is not a `HashMap` or a `BTreeMap`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DictValue {
    Str(String),
    Int(i64),
    Bool(bool),
    None,
    Bytes(Vec<u8>),
    List(Vec<DictValue>),
    Tuple(Vec<DictValue>),
    Set(Vec<DictValue>),
    FrozenSet(Vec<DictValue>),
    Map(Vec<(String, DictValue)>),
}

/// Total order of a [`Finding`] (FR-094). Field order is the comparison order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FindingSortKey {
    pub path: String,
    pub line: i64,
    pub ordinal: i64,
    pub severity_rank: i64,
    pub code: String,
    pub record_id: String,
    pub fingerprint: String,
    pub related_ids: Vec<String>,
    pub message: String,
    pub repairability: String,
}

/// Fields for [`Finding::try_new`], including values Python would reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingInput {
    pub code: PyValue,
    pub severity: PyValue,
    pub repairability: PyValue,
    pub message: PyValue,
    pub source: PyValue,
    pub related_ids: PyValue,
    pub fingerprint: PyValue,
    pub schema_version: PyValue,
    pub message_template: PyValue,
    pub evidence: PyValue,
}

/// Immutable finding envelope capturing an integrity defect.
///
/// Ordering is [`finding_sort_key`] (FR-094). [`Eq`] compares the stored fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    code: String,
    severity: Severity,
    repairability: Repairability,
    message: String,
    source: SourceRef,
    related_ids: Vec<String>,
    fingerprint: String,
    schema_version: String,
    message_template: Option<String>,
    evidence: Option<Evidence>,
}

impl Finding {
    /// Validate in the pinned `__post_init__` order and store the normalized form.
    pub fn try_new(input: FindingInput) -> Result<Self, FindingError> {
        let FindingInput {
            code,
            severity,
            repairability,
            message,
            source,
            related_ids,
            fingerprint,
            schema_version,
            message_template,
            evidence,
        } = input;

        let code = match &code {
            PyValue::Str(text) if is_valid_code(text) => text.clone(),
            other => return Err(invalid_code(other)),
        };
        let severity = match &severity {
            PyValue::Severity(value) => *value,
            other => {
                return Err(FindingError::new(format!(
                    "Finding.severity must be a Severity enum, got {}",
                    python_repr(other)
                )));
            }
        };
        let repairability = match &repairability {
            PyValue::Repairability(value) => *value,
            other => {
                return Err(FindingError::new(format!(
                    "Finding.repairability must be a Repairability enum, got {}",
                    python_repr(other)
                )));
            }
        };
        let message = match &message {
            PyValue::Str(text) if !python_strip(text).is_empty() => text.clone(),
            other => {
                return Err(FindingError::new(format!(
                    "Finding.message must be a non-empty string, got {}",
                    python_type_name(other)
                )));
            }
        };
        let length = message.chars().count();
        if length > max_message_chars() {
            return Err(FindingError::new(format!(
                "Finding.message exceeds maximum length of {MAX_MESSAGE_LENGTH} characters (length: {length})"
            )));
        }
        enforce_content_free_text(&message, "Finding.message")?;

        let source = match source {
            PyValue::Source(source) => source,
            other => {
                return Err(FindingError::new(format!(
                    "Finding.source must be a SourceRef, got {}",
                    python_type_name(&other)
                )));
            }
        };

        let fingerprint = match &fingerprint {
            PyValue::Str(text) if is_lower_hex_fingerprint(text) => text.clone(),
            other => {
                let mut rendered = FINGERPRINT_ERROR_PREFIX.to_owned();
                rendered.push_str(&python_repr(other));
                return Err(FindingError::new(rendered));
            }
        };

        let schema_version = match &schema_version {
            PyValue::Str(text) if text == SCHEMA_VERSION => text.clone(),
            other => {
                return Err(FindingError::new(format!(
                    "Finding.schema_version must be '{SCHEMA_VERSION}', got {}",
                    python_repr(other)
                )));
            }
        };

        let message_template = match &message_template {
            PyValue::None => None,
            PyValue::Str(text) if !python_strip(text).is_empty() => {
                enforce_content_free_text(text, "Finding.message_template")?;
                Some(text.clone())
            }
            other => {
                return Err(FindingError::new(format!(
                    "Finding.message_template must be a non-empty string or None, got {}",
                    python_type_name(other)
                )));
            }
        };

        let related_ids = normalize_related_ids(&related_ids)?;
        let evidence = normalize_evidence(&evidence)?;

        Ok(Self {
            code,
            severity,
            repairability,
            message,
            source,
            related_ids,
            fingerprint,
            schema_version,
            message_template,
            evidence,
        })
    }

    /// Reconstruct a finding from [`Self::to_dict`] order.
    ///
    /// Missing keys and bad enum strings return [`FindingError`]. See
    /// [`FROM_DICT_EXCEPTION_DEVIATION`].
    pub fn from_dict(entries: &[(&str, DictValue)]) -> Result<Self, FindingError> {
        let source_entries = match lookup(entries, "source") {
            Some(DictValue::Map(map)) => map.as_slice(),
            _ => {
                return Err(FindingError::new(
                    "Finding.from_dict requires a 'source' mapping".to_owned(),
                ));
            }
        };
        let code = dict_to_py(require(entries, "code")?);
        let severity = PyValue::Severity(parse_severity(require(entries, "severity")?)?);
        let repairability =
            PyValue::Repairability(parse_repairability(require(entries, "repairability")?)?);
        let message = dict_to_py(require(entries, "message")?);
        let source = PyValue::Source(source_from_dict(source_entries)?);
        let related_ids = related_from_dict(lookup(entries, "related_ids"))?;
        let fingerprint = dict_to_py(require(entries, "fingerprint")?);
        let schema_version = match lookup(entries, "schema_version") {
            None => PyValue::string(SCHEMA_VERSION),
            Some(value) => dict_to_py(value),
        };
        let message_template = match lookup(entries, "message_template") {
            None | Some(DictValue::None) => PyValue::None,
            Some(value) => dict_to_py(value),
        };
        let evidence = match lookup(entries, "evidence") {
            None | Some(DictValue::None) => PyValue::None,
            Some(value) => dict_to_py(value),
        };
        Self::try_new(FindingInput {
            code,
            severity,
            repairability,
            message,
            source,
            related_ids,
            fingerprint,
            schema_version,
            message_template,
            evidence,
        })
    }

    /// Canonical dictionary. Keys follow the Python literal, not alphabetical order.
    ///
    /// `message_template` and `evidence` are omitted when `None`. Evidence keys
    /// keep input order.
    pub fn to_dict(&self) -> Vec<(&'static str, DictValue)> {
        let mut entries = vec![
            (
                "schema_version",
                DictValue::Str(self.schema_version.clone()),
            ),
            ("code", DictValue::Str(self.code.clone())),
            (
                "severity",
                DictValue::Str(self.severity.as_str().to_owned()),
            ),
            (
                "repairability",
                DictValue::Str(self.repairability.as_str().to_owned()),
            ),
            ("message", DictValue::Str(self.message.clone())),
            ("source", source_to_dict(&self.source)),
            (
                "related_ids",
                DictValue::List(
                    self.related_ids
                        .iter()
                        .cloned()
                        .map(DictValue::Str)
                        .collect(),
                ),
            ),
            ("fingerprint", DictValue::Str(self.fingerprint.clone())),
        ];
        if let Some(template) = &self.message_template {
            entries.push(("message_template", DictValue::Str(template.clone())));
        }
        if let Some(evidence) = &self.evidence {
            entries.push(("evidence", evidence_to_dict(evidence)));
        }
        entries
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn repairability(&self) -> Repairability {
        self.repairability
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn source(&self) -> &SourceRef {
        &self.source
    }

    pub fn related_ids(&self) -> &[String] {
        &self.related_ids
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn message_template(&self) -> Option<&str> {
        self.message_template.as_deref()
    }

    pub fn evidence(&self) -> Option<&Evidence> {
        self.evidence.as_ref()
    }

    /// `evidence["variant"]` when that value is a string.
    ///
    /// A missing key yields `Ok(None)`. A non-string yields [`FindingError`];
    /// see [`VARIANT_CAST_DEVIATION`].
    pub fn variant(&self) -> Result<Option<String>, FindingError> {
        let Some(evidence) = &self.evidence else {
            return Ok(None);
        };
        match evidence.variant_lookup() {
            VariantLookup::Absent => Ok(None),
            VariantLookup::Text(text) => Ok(Some(text)),
            VariantLookup::NotString(rendered) => Err(FindingError::new(format!(
                "Finding.variant is not a string; Python cast returns the raw value {rendered}"
            ))),
        }
    }
}

impl PartialOrd for Finding {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Finding {
    fn cmp(&self, other: &Self) -> Ordering {
        finding_sort_key(self).cmp(&finding_sort_key(other))
    }
}

/// Pure sort key. See [`FINDING_EQ_ORD_DEVIATION`] for how this differs from [`Eq`].
pub fn finding_sort_key(finding: &Finding) -> FindingSortKey {
    let ordinal = finding
        .evidence
        .as_ref()
        .map(Evidence::record_ordinal)
        .unwrap_or(-1);
    FindingSortKey {
        path: finding.source.path().replace('\\', "/"),
        line: finding.source.line().unwrap_or(-1),
        ordinal,
        severity_rank: severity_rank(finding.severity),
        code: finding.code.clone(),
        record_id: finding.source.record_id().unwrap_or("").to_owned(),
        fingerprint: finding.fingerprint.clone(),
        related_ids: finding.related_ids.clone(),
        message: finding.message.clone(),
        repairability: finding.repairability.as_str().to_owned(),
    }
}

/// Return a new vec sorted by [`finding_sort_key`]. The input slice is not modified.
///
/// The sort is stable. See [`SORT_FINDINGS_TYPE_DEVIATION`].
#[must_use]
pub fn sort_findings(findings: &[Finding]) -> Vec<Finding> {
    let mut ordered = findings.to_vec();
    ordered.sort();
    ordered
}

enum VariantLookup {
    Absent,
    Text(String),
    NotString(String),
}

impl Evidence {
    fn map_entries(&self) -> Option<Vec<(EvidenceKey, Evidence)>> {
        match &*self.kind {
            EvidenceKind::Map(entries) => Some(entries.borrow().clone()),
            _ => None,
        }
    }

    /// Python: `int` and not `bool`, and `>= 0`. Otherwise `-1`.
    fn record_ordinal(&self) -> i64 {
        let Some(entries) = self.map_entries() else {
            return -1;
        };
        let mut found = None;
        for (key, value) in entries {
            if let EvidenceKey::Text(text) = key {
                if text == "record_ordinal" {
                    found = Some(value);
                }
            }
        }
        match found.as_ref().map(|value| &*value.kind) {
            Some(EvidenceKind::Int(ordinal)) if *ordinal >= 0 => *ordinal,
            _ => -1,
        }
    }

    fn variant_lookup(&self) -> VariantLookup {
        let Some(entries) = self.map_entries() else {
            return VariantLookup::Absent;
        };
        let mut found = None;
        for (key, value) in entries {
            if let EvidenceKey::Text(text) = key {
                if text == "variant" {
                    found = Some(value);
                }
            }
        }
        match found {
            None => VariantLookup::Absent,
            Some(value) => match &*value.kind {
                EvidenceKind::Str(text) => VariantLookup::Text(text.clone()),
                _ => VariantLookup::NotString(evidence_repr(&value)),
            },
        }
    }
}

impl PartialEq for Evidence {
    fn eq(&self, other: &Self) -> bool {
        let mut stack = Vec::new();
        evidence_eq(self, other, &mut stack)
    }
}

impl Eq for Evidence {}

fn evidence_eq(
    left: &Evidence,
    right: &Evidence,
    stack: &mut Vec<(*const EvidenceKind, *const EvidenceKind)>,
) -> bool {
    let left_ptr = Rc::as_ptr(&left.kind);
    let right_ptr = Rc::as_ptr(&right.kind);
    if left_ptr == right_ptr {
        return true;
    }
    if stack
        .iter()
        .any(|(seen_left, seen_right)| *seen_left == left_ptr && *seen_right == right_ptr)
    {
        return true;
    }
    stack.push((left_ptr, right_ptr));
    let equal = evidence_kind_eq(&left.kind, &right.kind, stack);
    let _ = stack.pop();
    equal
}

fn evidence_kind_eq(
    left: &EvidenceKind,
    right: &EvidenceKind,
    stack: &mut Vec<(*const EvidenceKind, *const EvidenceKind)>,
) -> bool {
    match (left, right) {
        (EvidenceKind::Str(left), EvidenceKind::Str(right)) => left == right,
        (EvidenceKind::Int(left), EvidenceKind::Int(right)) => left == right,
        (EvidenceKind::Bool(left), EvidenceKind::Bool(right)) => left == right,
        (EvidenceKind::Bytes(left), EvidenceKind::Bytes(right)) => left == right,
        (EvidenceKind::NoneValue, EvidenceKind::NoneValue)
        | (EvidenceKind::Ignored, EvidenceKind::Ignored) => true,
        (EvidenceKind::Map(left), EvidenceKind::Map(right)) => {
            let left_entries = left.borrow().clone();
            let right_entries = right.borrow().clone();
            left_entries.len() == right_entries.len()
                && left_entries
                    .iter()
                    .zip(right_entries.iter())
                    .all(|(left_entry, right_entry)| {
                        left_entry.0 == right_entry.0
                            && evidence_eq(&left_entry.1, &right_entry.1, stack)
                    })
        }
        (EvidenceKind::List(left), EvidenceKind::List(right)) => {
            let left_items = left.borrow().clone();
            let right_items = right.borrow().clone();
            evidence_slice_eq(&left_items, &right_items, stack)
        }
        (EvidenceKind::Tuple(left), EvidenceKind::Tuple(right))
        | (EvidenceKind::Set(left), EvidenceKind::Set(right))
        | (EvidenceKind::FrozenSet(left), EvidenceKind::FrozenSet(right)) => {
            evidence_slice_eq(left, right, stack)
        }
        _ => false,
    }
}

fn evidence_slice_eq(
    left: &[Evidence],
    right: &[Evidence],
    stack: &mut Vec<(*const EvidenceKind, *const EvidenceKind)>,
) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left_item, right_item)| evidence_eq(left_item, right_item, stack))
}

fn severity_rank(severity: Severity) -> i64 {
    for (kind, rank) in SEVERITY_ORDER {
        if kind == severity {
            return rank;
        }
    }
    match severity {
        Severity::Fatal => 0,
        Severity::Error => 1,
        Severity::Warning => 2,
        Severity::Info => 3,
    }
}

fn max_message_chars() -> usize {
    match usize::try_from(MAX_MESSAGE_LENGTH) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    }
}

fn is_lower_hex_fingerprint(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 16
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn invalid_code(value: &PyValue) -> FindingError {
    FindingError::new(format!(
        "Finding.code must be a registered detector code, got {}. Must be one of {}",
        python_repr(value),
        registered_codes_repr()
    ))
}

fn registered_codes_repr() -> String {
    let mut codes = ALL_CODES.to_vec();
    codes.sort_unstable();
    let mut out = String::from("[");
    for (index, code) in codes.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(code));
    }
    out.push(']');
    out
}

fn python_type_name(value: &PyValue) -> &'static str {
    match value {
        PyValue::Str(_) => "str",
        PyValue::Int(_) => "int",
        PyValue::Bool(_) => "bool",
        PyValue::Bytes(_) => "bytes",
        PyValue::None => "NoneType",
        PyValue::Severity(_) => "Severity",
        PyValue::Repairability(_) => "Repairability",
        PyValue::Source(_) => "SourceRef",
        PyValue::List(_) => "list",
        PyValue::Tuple(_) => "tuple",
        PyValue::Set(_) => "set",
        PyValue::FrozenSet(_) => "frozenset",
        PyValue::Map(_) => "dict",
    }
}

fn python_repr(value: &PyValue) -> String {
    python_repr_depth(value, 0)
}

fn python_repr_depth(value: &PyValue, depth: usize) -> String {
    if depth >= 6 {
        return "...".to_owned();
    }
    match value {
        PyValue::Str(text) => python_str_repr(text),
        PyValue::Int(number) => number.to_string(),
        PyValue::Bool(true) => "True".to_owned(),
        PyValue::Bool(false) => "False".to_owned(),
        PyValue::Bytes(bytes) => python_bytes_repr(bytes),
        PyValue::None => "None".to_owned(),
        PyValue::Severity(severity) => severity_member_repr(*severity),
        PyValue::Repairability(repairability) => repairability_member_repr(*repairability),
        PyValue::Source(source) => source_member_repr(source),
        PyValue::List(items) => sequence_repr("[", "]", items, depth, false),
        PyValue::Tuple(items) => sequence_repr("(", ")", items, depth, true),
        PyValue::Set(items) => braced_repr("set", items, depth),
        PyValue::FrozenSet(items) => braced_repr("frozenset", items, depth),
        PyValue::Map(entries) => map_repr(entries, depth),
    }
}

fn sequence_repr(open: &str, close: &str, items: &[PyValue], depth: usize, tuple: bool) -> String {
    let mut out = String::from(open);
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_repr_depth(item, depth + 1));
    }
    if tuple && items.len() == 1 {
        out.push(',');
    }
    out.push_str(close);
    out
}

fn braced_repr(empty_name: &str, items: &[PyValue], depth: usize) -> String {
    if items.is_empty() {
        return format!("{empty_name}()");
    }
    let mut rendered: Vec<String> = items
        .iter()
        .map(|item| python_repr_depth(item, depth + 1))
        .collect();
    rendered.sort();
    format!("{{{}}}", rendered.join(", "))
}

fn map_repr(entries: &[(PyValue, PyValue)], depth: usize) -> String {
    if entries.is_empty() {
        return "{}".to_owned();
    }
    let mut out = String::from("{");
    for (index, (key, value)) in entries.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_repr_depth(key, depth + 1));
        out.push_str(": ");
        out.push_str(&python_repr_depth(value, depth + 1));
    }
    out.push('}');
    out
}

fn python_bytes_repr(bytes: &[u8]) -> String {
    let mut decoded = String::new();
    for byte in bytes {
        decoded.push(char::from(*byte));
    }
    let use_double = decoded.contains('\'') && !decoded.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::from("b");
    out.push(quote);
    for byte in bytes {
        match *byte {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\'' if !use_double => out.push_str("\\'"),
            b'"' if use_double => out.push_str("\\\""),
            32..=126 => out.push(char::from(*byte)),
            other => {
                out.push_str("\\x");
                out.push(HEX_DIGITS[usize::from(other >> 4)]);
                out.push(HEX_DIGITS[usize::from(other & 0x0f)]);
            }
        }
    }
    out.push(quote);
    out
}

const HEX_DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

fn severity_member_repr(severity: Severity) -> String {
    let name = match severity {
        Severity::Fatal => "FATAL",
        Severity::Error => "ERROR",
        Severity::Warning => "WARNING",
        Severity::Info => "INFO",
    };
    format!("<Severity.{name}: '{}'>", severity.as_str())
}

fn repairability_member_repr(repairability: Repairability) -> String {
    let name = match repairability {
        Repairability::Deterministic => "DETERMINISTIC",
        Repairability::LossyExplicit => "LOSSY_EXPLICIT",
        Repairability::Manual => "MANUAL",
        Repairability::Unsupported => "UNSUPPORTED",
    };
    format!("<Repairability.{name}: '{}'>", repairability.as_str())
}

fn source_member_repr(source: &SourceRef) -> String {
    let line = match source.line() {
        Some(value) => value.to_string(),
        None => "None".to_owned(),
    };
    let record_id = match source.record_id() {
        Some(value) => python_str_repr(value),
        None => "None".to_owned(),
    };
    format!(
        "SourceRef(path={}, line={line}, record_id={record_id})",
        python_str_repr(source.path())
    )
}

fn normalize_related_ids(value: &PyValue) -> Result<Vec<String>, FindingError> {
    let items = related_items(value)?;
    for item in &items {
        if let Some(type_name) = unhashable_type_name(item) {
            return Err(FindingError::new(format!(
                "Finding.related_ids item is not hashable (Python raises TypeError: unhashable type: '{type_name}')"
            )));
        }
    }
    let unique = dedupe_raw(&items);
    let mut strings = Vec::new();
    let mut others = Vec::new();
    for item in &unique {
        if matches!(item, PyValue::Str(_)) {
            strings.push(item);
        } else {
            others.push(item);
        }
    }
    strings.sort_by(|left, right| match (left, right) {
        (PyValue::Str(left_text), PyValue::Str(right_text)) => left_text.cmp(right_text),
        _ => Ordering::Equal,
    });
    let mut cleaned = Vec::new();
    for item in strings.into_iter().chain(others) {
        match item {
            PyValue::Str(text) if !python_strip(text).is_empty() => {
                let stripped = python_strip(text).to_owned();
                enforce_content_free_text(&stripped, "Finding.related_ids")?;
                cleaned.push(stripped);
            }
            other => {
                return Err(FindingError::new(format!(
                    "Finding.related_ids items must be non-empty strings, got {}",
                    python_repr(other)
                )));
            }
        }
    }
    cleaned.sort();
    Ok(cleaned)
}

fn related_items(value: &PyValue) -> Result<Vec<PyValue>, FindingError> {
    match value {
        PyValue::List(items)
        | PyValue::Tuple(items)
        | PyValue::Set(items)
        | PyValue::FrozenSet(items) => Ok(items.clone()),
        PyValue::Map(entries) => Ok(entries.iter().map(|(key, _)| key.clone()).collect()),
        other => Err(FindingError::new(format!(
            "Finding.related_ids must be an iterable of strings, got {}",
            python_type_name(other)
        ))),
    }
}

fn unhashable_type_name(value: &PyValue) -> Option<&'static str> {
    match value {
        PyValue::List(_) => Some("list"),
        PyValue::Map(_) => Some("dict"),
        PyValue::Set(_) => Some("set"),
        PyValue::Tuple(items) | PyValue::FrozenSet(items) => {
            items.iter().find_map(unhashable_type_name)
        }
        PyValue::Str(_)
        | PyValue::Int(_)
        | PyValue::Bool(_)
        | PyValue::Bytes(_)
        | PyValue::None
        | PyValue::Severity(_)
        | PyValue::Repairability(_)
        | PyValue::Source(_) => None,
    }
}

fn dedupe_raw(items: &[PyValue]) -> Vec<PyValue> {
    let mut unique = Vec::new();
    for item in items {
        if unique.iter().any(|existing| py_eq(existing, item)) {
            continue;
        }
        unique.push(item.clone());
    }
    unique
}

fn py_eq(left: &PyValue, right: &PyValue) -> bool {
    match (left, right) {
        (PyValue::Str(left), PyValue::Str(right)) => left == right,
        (PyValue::Int(left), PyValue::Int(right)) => left == right,
        (PyValue::Bool(left), PyValue::Bool(right)) => left == right,
        (PyValue::Bool(true), PyValue::Int(1)) | (PyValue::Int(1), PyValue::Bool(true)) => true,
        (PyValue::Bool(false), PyValue::Int(0)) | (PyValue::Int(0), PyValue::Bool(false)) => true,
        (PyValue::None, PyValue::None) => true,
        (PyValue::Bytes(left), PyValue::Bytes(right)) => left == right,
        (PyValue::Severity(left), PyValue::Severity(right)) => left == right,
        (PyValue::Repairability(left), PyValue::Repairability(right)) => left == right,
        (PyValue::Source(left), PyValue::Source(right)) => left == right,
        (PyValue::Tuple(left), PyValue::Tuple(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(item, other)| py_eq(item, other))
        }
        (PyValue::FrozenSet(left), PyValue::FrozenSet(right)) => frozenset_eq(left, right),
        _ => false,
    }
}

fn frozenset_eq(left: &[PyValue], right: &[PyValue]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|item| right.iter().any(|other| py_eq(item, other)))
}

fn normalize_evidence(value: &PyValue) -> Result<Option<Evidence>, FindingError> {
    match value {
        PyValue::None => Ok(None),
        PyValue::Map(entries) => Ok(Some(evidence_from_py_map(entries)?)),
        other => Err(FindingError::new(format!(
            "Finding.evidence must be a mapping or None, got {}",
            python_type_name(other)
        ))),
    }
}

fn evidence_from_py_map(entries: &[(PyValue, PyValue)]) -> Result<Evidence, FindingError> {
    let mut stored = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let PyValue::Str(text) = key else {
            return Err(FindingError::new(
                "Finding.evidence keys must be non-empty strings".to_owned(),
            ));
        };
        if python_strip(text).is_empty() {
            return Err(FindingError::new(
                "Finding.evidence keys must be non-empty strings".to_owned(),
            ));
        }
        let key_repr = python_str_repr(text);
        enforce_content_free_text(text, &format!("Finding.evidence key {key_repr}"))?;
        let child = py_to_evidence(value);
        enforce_content_free_evidence_recursive(
            &child,
            &format!("Finding.evidence value for {key_repr}"),
        )?;
        stored.push((EvidenceKey::text(text.clone()), child));
    }
    Ok(Evidence::map(stored))
}

fn py_to_evidence(value: &PyValue) -> Evidence {
    match value {
        PyValue::Str(text) => Evidence::string(text.clone()),
        PyValue::Int(number) => Evidence::int(*number),
        PyValue::Bool(flag) => Evidence::bool_value(*flag),
        PyValue::None => Evidence::none_value(),
        PyValue::Bytes(bytes) => Evidence::bytes(bytes.clone()),
        PyValue::List(items) => Evidence::list(items.iter().map(py_to_evidence).collect()),
        PyValue::Tuple(items) => Evidence::tuple(items.iter().map(py_to_evidence).collect()),
        PyValue::Set(items) => Evidence::set(items.iter().map(py_to_evidence).collect()),
        PyValue::FrozenSet(items) => {
            Evidence::frozenset(items.iter().map(py_to_evidence).collect())
        }
        PyValue::Map(entries) => {
            let mapped = entries
                .iter()
                .map(|(key, child)| {
                    let evidence_key = match key {
                        PyValue::Str(text) => EvidenceKey::text(text.clone()),
                        _ => EvidenceKey::NonString,
                    };
                    (evidence_key, py_to_evidence(child))
                })
                .collect();
            Evidence::map(mapped)
        }
        PyValue::Severity(_) | PyValue::Repairability(_) | PyValue::Source(_) => {
            Evidence::ignored()
        }
    }
}

fn evidence_repr(value: &Evidence) -> String {
    evidence_repr_depth(value, 0)
}

fn evidence_repr_depth(value: &Evidence, depth: usize) -> String {
    if depth >= 6 {
        return "...".to_owned();
    }
    match &*value.kind {
        EvidenceKind::Str(text) => python_str_repr(text),
        EvidenceKind::Int(number) => number.to_string(),
        EvidenceKind::Bool(true) => "True".to_owned(),
        EvidenceKind::Bool(false) => "False".to_owned(),
        EvidenceKind::NoneValue => "None".to_owned(),
        EvidenceKind::Bytes(bytes) => python_bytes_repr(bytes),
        EvidenceKind::Ignored => "<ignored>".to_owned(),
        EvidenceKind::List(items) => {
            let cloned = items.borrow().clone();
            evidence_sequence_repr("[", "]", &cloned, depth, false)
        }
        EvidenceKind::Tuple(items) => evidence_sequence_repr("(", ")", items, depth, true),
        EvidenceKind::Set(items) => evidence_braced_repr(items, depth),
        EvidenceKind::FrozenSet(items) => evidence_braced_repr(items, depth),
        EvidenceKind::Map(entries) => {
            let cloned = entries.borrow().clone();
            if cloned.is_empty() {
                return "{}".to_owned();
            }
            let mut out = String::from("{");
            for (index, (key, child)) in cloned.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                match key {
                    EvidenceKey::Text(text) => out.push_str(&python_str_repr(text)),
                    EvidenceKey::NonString => out.push_str("<non-string>"),
                }
                out.push_str(": ");
                out.push_str(&evidence_repr_depth(child, depth + 1));
            }
            out.push('}');
            out
        }
    }
}

fn evidence_sequence_repr(
    open: &str,
    close: &str,
    items: &[Evidence],
    depth: usize,
    tuple: bool,
) -> String {
    let mut out = String::from(open);
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&evidence_repr_depth(item, depth + 1));
    }
    if tuple && items.len() == 1 {
        out.push(',');
    }
    out.push_str(close);
    out
}

fn evidence_braced_repr(items: &[Evidence], depth: usize) -> String {
    if items.is_empty() {
        return "set()".to_owned();
    }
    let mut rendered: Vec<String> = items
        .iter()
        .map(|item| evidence_repr_depth(item, depth + 1))
        .collect();
    rendered.sort();
    format!("{{{}}}", rendered.join(", "))
}

fn evidence_to_dict(value: &Evidence) -> DictValue {
    evidence_to_dict_depth(value, 0)
}

fn evidence_to_dict_depth(value: &Evidence, depth: usize) -> DictValue {
    if depth > 32 {
        return DictValue::None;
    }
    match &*value.kind {
        EvidenceKind::Str(text) => DictValue::Str(text.clone()),
        EvidenceKind::Int(number) => DictValue::Int(*number),
        EvidenceKind::Bool(flag) => DictValue::Bool(*flag),
        EvidenceKind::NoneValue | EvidenceKind::Ignored => DictValue::None,
        EvidenceKind::Bytes(bytes) => DictValue::Bytes(bytes.clone()),
        EvidenceKind::List(items) => {
            let cloned = items.borrow().clone();
            DictValue::List(
                cloned
                    .iter()
                    .map(|item| evidence_to_dict_depth(item, depth + 1))
                    .collect(),
            )
        }
        EvidenceKind::Tuple(items) => DictValue::Tuple(
            items
                .iter()
                .map(|item| evidence_to_dict_depth(item, depth + 1))
                .collect(),
        ),
        EvidenceKind::Set(items) => DictValue::Set(
            items
                .iter()
                .map(|item| evidence_to_dict_depth(item, depth + 1))
                .collect(),
        ),
        EvidenceKind::FrozenSet(items) => DictValue::FrozenSet(
            items
                .iter()
                .map(|item| evidence_to_dict_depth(item, depth + 1))
                .collect(),
        ),
        EvidenceKind::Map(entries) => {
            let cloned = entries.borrow().clone();
            DictValue::Map(
                cloned
                    .iter()
                    .map(|(key, child)| {
                        let name = match key {
                            EvidenceKey::Text(text) => text.clone(),
                            EvidenceKey::NonString => "<non-string>".to_owned(),
                        };
                        (name, evidence_to_dict_depth(child, depth + 1))
                    })
                    .collect(),
            )
        }
    }
}

fn source_to_dict(source: &SourceRef) -> DictValue {
    DictValue::Map(vec![
        ("path".to_owned(), DictValue::Str(source.path().to_owned())),
        (
            "line".to_owned(),
            match source.line() {
                Some(line) => DictValue::Int(line),
                None => DictValue::None,
            },
        ),
        (
            "record_id".to_owned(),
            match source.record_id() {
                Some(record_id) => DictValue::Str(record_id.to_owned()),
                None => DictValue::None,
            },
        ),
    ])
}

fn dict_to_py(value: &DictValue) -> PyValue {
    match value {
        DictValue::Str(text) => PyValue::string(text.clone()),
        DictValue::Int(number) => PyValue::int(*number),
        DictValue::Bool(flag) => PyValue::bool_value(*flag),
        DictValue::None => PyValue::None,
        DictValue::Bytes(bytes) => PyValue::bytes(bytes.clone()),
        DictValue::List(items) => PyValue::List(items.iter().map(dict_to_py).collect()),
        DictValue::Tuple(items) => PyValue::Tuple(items.iter().map(dict_to_py).collect()),
        DictValue::Set(items) => PyValue::Set(items.iter().map(dict_to_py).collect()),
        DictValue::FrozenSet(items) => PyValue::FrozenSet(items.iter().map(dict_to_py).collect()),
        DictValue::Map(entries) => PyValue::Map(
            entries
                .iter()
                .map(|(key, child)| (PyValue::string(key.clone()), dict_to_py(child)))
                .collect(),
        ),
    }
}

fn lookup<'a, K: AsRef<str>>(entries: &'a [(K, DictValue)], key: &str) -> Option<&'a DictValue> {
    entries
        .iter()
        .rev()
        .find(|(entry_key, _)| entry_key.as_ref() == key)
        .map(|(_, value)| value)
}

fn require<'a, K: AsRef<str>>(
    entries: &'a [(K, DictValue)],
    key: &str,
) -> Result<&'a DictValue, FindingError> {
    lookup(entries, key).ok_or_else(|| missing_key(key))
}

fn missing_key(key: &str) -> FindingError {
    FindingError::new(format!(
        "missing required key {} (Python raises KeyError)",
        python_str_repr(key)
    ))
}

fn invalid_enum(kind: &str, value: &DictValue) -> FindingError {
    FindingError::new(format!(
        "{} is not a valid {kind} (Python raises ValueError)",
        python_repr(&dict_to_py(value))
    ))
}

fn parse_severity(value: &DictValue) -> Result<Severity, FindingError> {
    match value {
        DictValue::Str(text) => Severity::parse(text).map_err(|_| invalid_enum("Severity", value)),
        _ => Err(invalid_enum("Severity", value)),
    }
}

fn parse_repairability(value: &DictValue) -> Result<Repairability, FindingError> {
    match value {
        DictValue::Str(text) => {
            Repairability::parse(text).map_err(|_| invalid_enum("Repairability", value))
        }
        _ => Err(invalid_enum("Repairability", value)),
    }
}

fn source_from_dict(entries: &[(String, DictValue)]) -> Result<SourceRef, FindingError> {
    let path = match lookup(entries, "path") {
        Some(DictValue::Str(text)) => text.clone(),
        Some(other) => {
            return Err(FindingError::new(format!(
                "SourceRef.path must be a non-empty string, got {}",
                python_repr(&dict_to_py(other))
            )));
        }
        None => return Err(missing_key("path")),
    };
    let line = match lookup(entries, "line") {
        None | Some(DictValue::None) => None,
        Some(DictValue::Int(value)) => Some(SourceLine::Int(*value)),
        Some(DictValue::Bool(value)) => Some(SourceLine::Bool(*value)),
        Some(other) => {
            return Err(FindingError::new(format!(
                "SourceRef.line must be a positive integer or None, got {}",
                python_repr(&dict_to_py(other))
            )));
        }
    };
    let record_id = match lookup(entries, "record_id") {
        None | Some(DictValue::None) => None,
        Some(DictValue::Str(text)) => Some(text.clone()),
        Some(other) => {
            return Err(FindingError::new(format!(
                "SourceRef.record_id must be non-empty string or None, got {}",
                python_repr(&dict_to_py(other))
            )));
        }
    };
    SourceRef::try_new(&path, line, record_id.as_deref())
}

fn related_from_dict(value: Option<&DictValue>) -> Result<PyValue, FindingError> {
    let Some(value) = value else {
        return Ok(PyValue::tuple(Vec::new()));
    };
    match value {
        DictValue::List(items) => Ok(PyValue::List(items.iter().map(dict_to_py).collect())),
        DictValue::Tuple(items) => Ok(PyValue::Tuple(items.iter().map(dict_to_py).collect())),
        DictValue::Set(items) => Ok(PyValue::Set(items.iter().map(dict_to_py).collect())),
        DictValue::FrozenSet(items) => {
            Ok(PyValue::FrozenSet(items.iter().map(dict_to_py).collect()))
        }
        DictValue::Str(text) => Ok(PyValue::Tuple(
            text.chars().map(|ch| PyValue::string(ch.to_string())).collect(),
        )),
        DictValue::Bytes(bytes) => Ok(PyValue::Tuple(
            bytes
                .iter()
                .map(|byte| PyValue::int(i64::from(*byte)))
                .collect(),
        )),
        DictValue::Map(entries) => Ok(PyValue::List(
            entries
                .iter()
                .map(|(key, _)| PyValue::string(key.clone()))
                .collect(),
        )),
        other => Err(FindingError::new(format!(
            "Finding.from_dict related_ids is not iterable (Python raises TypeError: '{}' object is not iterable)",
            python_type_name(&dict_to_py(other))
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        enforce_content_free_evidence_recursive, enforce_content_free_text, python_str_repr,
        Evidence, EvidenceKey, SourceLine, SourceRef, ALLOWED_TEMPLATE_VARS,
        CONTENT_REJECT_PATTERN, CONTROL_CHAR_PATTERN, CREDENTIAL_ASSIGN_PATTERN,
        DANGEROUS_UNICODE_CATEGORIES, DEFAULT_TEXT_CONTEXT, EMAIL_PATTERN, FINGERPRINT_PATTERN,
        MAX_MESSAGE_LENGTH, SCHEMA_VERSION, SET_ITERATION_DEVIATION, SEVERITY_ORDER,
        TRUNCATION_MARKER, UNCOVERED_DANGEROUS_CODE_POINTS,
    };
    use crate::codes::Severity;
    use std::error::Error;

    fn reject(text: &str, expected: &str) {
        let err = enforce_content_free_text(text, DEFAULT_TEXT_CONTEXT).unwrap_err();
        assert_eq!(err.to_string(), expected);
        assert_eq!(err.code(), "FINDING");
        assert!(err.source().is_none());
    }

    fn accept(text: &str) {
        enforce_content_free_text(text, DEFAULT_TEXT_CONTEXT).unwrap();
    }

    #[test]
    fn module_constants_match_the_pin() {
        assert_eq!(SCHEMA_VERSION, "sesslint.finding/v1");
        assert_eq!(ALLOWED_TEMPLATE_VARS, ["line", "record_id"]);
        assert_eq!(MAX_MESSAGE_LENGTH, 500);
        assert_eq!(TRUNCATION_MARKER, "... [truncated]");
        assert_eq!(
            SEVERITY_ORDER,
            [
                (Severity::Fatal, 0),
                (Severity::Error, 1),
                (Severity::Warning, 2),
                (Severity::Info, 3),
            ]
        );
        assert_eq!(FINGERPRINT_PATTERN, r"^[0-9a-f]{16}$");
        assert_eq!(DANGEROUS_UNICODE_CATEGORIES, ["Cc", "Cf", "Zl", "Zp"]);
        assert!(CONTENT_REJECT_PATTERN.starts_with(CONTROL_CHAR_PATTERN));
        assert!(CONTENT_REJECT_PATTERN.contains(EMAIL_PATTERN));
        assert!(
            CONTENT_REJECT_PATTERN.contains(CREDENTIAL_ASSIGN_PATTERN.trim_start_matches("(?i)"))
        );
        assert_eq!(UNCOVERED_DANGEROUS_CODE_POINTS.len(), 0);
        assert!(SET_ITERATION_DEVIATION.contains("set"));
    }

    #[test]
    fn python_repr_prefers_single_quotes() {
        assert_eq!(python_str_repr(""), "''");
        assert_eq!(python_str_repr("a'b"), "\"a'b\"");
        assert_eq!(python_str_repr("a\"b"), "'a\"b'");
        assert_eq!(python_str_repr("a'\"b"), "'a\\'\"b'");
        assert_eq!(python_str_repr("\n\t\r\u{007f}"), "'\\n\\t\\r\\x7f'");
        assert_eq!(python_str_repr("\u{00a0}\u{200b}"), "'\\xa0\\u200b'");
        assert_eq!(python_str_repr("\u{0378}"), "'\\u0378'");
        assert_eq!(python_str_repr("é😀"), "'é😀'");
    }

    #[test]
    fn clean_ascii_and_ordinary_letters_pass() {
        accept("Clean coordinate reference: record-1234");
        accept("café résumé");
        accept("caf\u{0301}");
        accept("éuser@example.com");
        accept("user@example.comé");
        accept("ésk-0123456789abcdef");
        accept("Bearer abcdefghi");
        accept("Bearer abcdefghi.");
        accept("sk-0123456789abcde");
        accept("-----BEGIN KEY-----");
        accept("-----begin test key-----");
        accept("my_token=example-value");
        accept("password=");
        accept("");
    }

    #[test]
    fn pinned_pattern_edges_match_python() {
        reject(
            "user@mail.example.com",
            "Forbidden content-bearing pattern (e.g., email/PII) in text: 'user@mail.example.com'",
        );
        reject(
            "a@b.co",
            "Forbidden content-bearing pattern (e.g., email/PII) in text: 'a@b.co'",
        );
        reject(
            "a@b..com",
            "Forbidden content-bearing pattern (e.g., email/PII) in text: 'a@b..com'",
        );
        reject(
            ".user@example.com",
            "Forbidden content-bearing pattern (e.g., email/PII) in text: '.user@example.com'",
        );
        reject(
            "user@example.com.",
            "Forbidden content-bearing pattern (e.g., email/PII) in text: 'user@example.com.'",
        );
        reject(
            "first.last+tag@example.com",
            "Forbidden content-bearing pattern (e.g., email/PII) in text: 'first.last+tag@example.com'",
        );
        accept("a@b.c");
        accept("user@127.0.0.1");
        accept("user@ex\u{00e4}mple.com");
        accept("not-an-email");
        accept("bearer abcdefghij");
        accept("SK-0123456789abcdef");
        accept("xBearer abcdefghij");
        accept("api-key=example");
        reject(
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "Forbidden credential pattern (private key) in text: '-----BEGIN OPENSSH PRIVATE KEY-----'",
        );
        reject(
            "gho_0123456789abcdef",
            "Forbidden credential pattern (API key) in text: 'gho_0123456789abcdef'",
        );
        reject(
            "glpat-0123456789abcdef",
            "Forbidden credential pattern (API key) in text: 'glpat-0123456789abcdef'",
        );
        reject(
            "slack_token_0123456789abcdef",
            "Forbidden credential pattern (API key) in text: 'slack_token_0123456789abcdef'",
        );
        reject(
            "api_key=example",
            "Forbidden credential pattern (credential assignment) in text: 'api_key=example'",
        );
        reject(
            "token:abc",
            "Forbidden credential pattern (credential assignment) in text: 'token:abc'",
        );
    }

    #[test]
    fn control_characters_win_over_later_patterns() {
        reject(
            "\nuser@example.com",
            "Forbidden control or newline characters in text: '\\nuser@example.com'",
        );
        reject(
            "Line with \t tab",
            "Forbidden control or newline characters in text: 'Line with \\t tab'",
        );
        reject(
            "a\u{007f}b",
            "Forbidden control or newline characters in text: 'a\\x7fb'",
        );
        reject(
            "\n\u{200b}",
            "Forbidden control or newline characters in text: '\\n\\u200b'",
        );
        let err = enforce_content_free_text("\n", "field").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Forbidden control or newline characters in field: '\\n'"
        );
    }

    #[test]
    fn unicode_categories_reject_known_controls_not_letters() {
        reject(
            "Text\u{0085}with NEL",
            "Forbidden Unicode control/formatting character U+0085 in text: 'Text\\x85with NEL'",
        );
        reject(
            "Text\u{2028}x",
            "Forbidden Unicode control/formatting character U+2028 in text: 'Text\\u2028x'",
        );
        reject(
            "Text\u{2029}x",
            "Forbidden Unicode control/formatting character U+2029 in text: 'Text\\u2029x'",
        );
        reject(
            "Hidden\u{200b}payload",
            "Forbidden Unicode control/formatting character U+200B in text: 'Hidden\\u200bpayload'",
        );
        reject(
            "clean\u{200b}user@example.com",
            "Forbidden Unicode control/formatting character U+200B in text: 'clean\\u200buser@example.com'",
        );
        reject(
            "\u{2028}\u{200b}",
            "Forbidden Unicode control/formatting character U+2028 in text: '\\u2028\\u200b'",
        );
        reject(
            "BOM\u{feff}payload",
            "Forbidden Unicode control/formatting character U+FEFF in text: 'BOM\\ufeffpayload'",
        );
        reject(
            "Bidi\u{202e}override",
            "Forbidden Unicode control/formatting character U+202E in text: 'Bidi\\u202eoverride'",
        );
        reject(
            "mark\u{00ad}here",
            "Forbidden Unicode control/formatting character U+00AD in text: 'mark\\xadhere'",
        );
        accept("letter \u{00e9} only");
    }

    #[test]
    fn credential_patterns_keep_python_precedence() {
        reject(
            "résumé user@example.com",
            "Forbidden content-bearing pattern (e.g., email/PII) in text: 'résumé user@example.com'",
        );
        reject(
            "user@example.com\u{0301}",
            "Forbidden content-bearing pattern (e.g., email/PII) in text: 'user@example.com\u{0301}'",
        );
        reject(
            "user@example.com -----BEGIN TEST KEY-----",
            "Forbidden content-bearing pattern (e.g., email/PII) in text: 'user@example.com -----BEGIN TEST KEY-----'",
        );
        reject(
            "-----BEGIN TEST KEY----- Bearer abcdefghij",
            "Forbidden credential pattern (private key) in text: '-----BEGIN TEST KEY----- Bearer abcdefghij'",
        );
        reject(
            "-----BEGIN  KEY-----",
            "Forbidden credential pattern (private key) in text: '-----BEGIN  KEY-----'",
        );
        reject(
            "Bearer abcdefghij sk-0123456789abcdef",
            "Forbidden credential pattern (bearer token) in text: 'Bearer abcdefghij sk-0123456789abcdef'",
        );
        reject(
            "Bearer abcdefghij.",
            "Forbidden credential pattern (bearer token) in text: 'Bearer abcdefghij.'",
        );
        reject(
            "Bearer\u{00a0}abcdefghij",
            "Forbidden credential pattern (bearer token) in text: 'Bearer\\xa0abcdefghij'",
        );
        reject(
            "sk-0123456789abcdef token = example-value",
            "Forbidden credential pattern (API key) in text: 'sk-0123456789abcdef token = example-value'",
        );
        reject(
            "ghp_0123456789abcdef",
            "Forbidden credential pattern (API key) in text: 'ghp_0123456789abcdef'",
        );
        reject(
            "token = example-value",
            "Forbidden credential pattern (credential assignment) in text: 'token = example-value'",
        );
        reject(
            "TOKEN=example-value",
            "Forbidden credential pattern (credential assignment) in text: 'TOKEN=example-value'",
        );
        reject(
            "ap\u{0131}_key = marker",
            "Forbidden credential pattern (credential assignment) in text: 'ap\u{0131}_key = marker'",
        );
        reject(
            "\u{017f}ecret = marker",
            "Forbidden credential pattern (credential assignment) in text: '\u{017f}ecret = marker'",
        );
        reject(
            "to\u{212a}en = example",
            "Forbidden credential pattern (credential assignment) in text: 'to\u{212a}en = example'",
        );
        reject(
            "secret:\u{00a0}value",
            "Forbidden credential pattern (credential assignment) in text: 'secret:\\xa0value'",
        );
    }

    #[test]
    fn source_ref_normalizes_and_rejects_in_order() {
        let source = SourceRef::try_new(
            "  a\\b\\c.jsonl  ",
            Some(SourceLine::Int(2)),
            Some("  rec  "),
        )
        .unwrap();
        assert_eq!(source.path(), "a/b/c.jsonl");
        assert_eq!(source.line(), Some(2));
        assert_eq!(source.record_id(), Some("rec"));

        let spaced = SourceRef::try_new("\u{00a0}a\\b\u{00a0}", None, Some("  a\\b  ")).unwrap();
        assert_eq!(spaced.path(), "a/b");
        assert_eq!(spaced.line(), None);
        assert_eq!(spaced.record_id(), Some("a\\b"));

        let blank = SourceRef::try_new("\u{001c}", Some(SourceLine::Int(0)), None).unwrap_err();
        assert_eq!(
            blank.to_string(),
            "SourceRef.path must be a non-empty string, got '\\x1c'"
        );
        let spaces = SourceRef::try_new("   ", None, None).unwrap_err();
        assert_eq!(
            spaces.to_string(),
            "SourceRef.path must be a non-empty string, got '   '"
        );
        let email =
            SourceRef::try_new("  user@example.com  ", Some(SourceLine::Int(0)), None).unwrap_err();
        assert_eq!(
            email.to_string(),
            "Forbidden content-bearing pattern (e.g., email/PII) in SourceRef.path: 'user@example.com'"
        );
        let line = SourceRef::try_new("a.jsonl", Some(SourceLine::Int(0)), Some("")).unwrap_err();
        assert_eq!(
            line.to_string(),
            "SourceRef.line must be a positive integer or None, got 0"
        );
        let negative = SourceRef::try_new("a.jsonl", Some(SourceLine::Int(-1)), None).unwrap_err();
        assert_eq!(
            negative.to_string(),
            "SourceRef.line must be a positive integer or None, got -1"
        );
        let yes = SourceRef::try_new("a.jsonl", Some(SourceLine::Bool(true)), None).unwrap_err();
        assert_eq!(
            yes.to_string(),
            "SourceRef.line must be a positive integer or None, got True"
        );
        let no = SourceRef::try_new("a.jsonl", Some(SourceLine::Bool(false)), None).unwrap_err();
        assert_eq!(
            no.to_string(),
            "SourceRef.line must be a positive integer or None, got False"
        );
        let record =
            SourceRef::try_new("a.jsonl", Some(SourceLine::Int(1)), Some("   ")).unwrap_err();
        assert_eq!(
            record.to_string(),
            "SourceRef.record_id must be non-empty string or None, got '   '"
        );
        let record_email =
            SourceRef::try_new("a.jsonl", None, Some("  user@example.com  ")).unwrap_err();
        assert_eq!(
            record_email.to_string(),
            "Forbidden content-bearing pattern (e.g., email/PII) in SourceRef.record_id: 'user@example.com'"
        );
    }

    #[test]
    fn evidence_walks_maps_and_sequences_in_order() {
        let clean = Evidence::map(vec![(
            EvidenceKey::text("trace"),
            Evidence::list(vec![
                Evidence::string("span_1"),
                Evidence::ignored(),
                Evidence::tuple(vec![Evidence::string("clean_val")]),
            ]),
        )]);
        enforce_content_free_evidence_recursive(&clean, "evidence").unwrap();

        let nested = Evidence::map(vec![(
            EvidenceKey::text("metadata"),
            Evidence::map(vec![(
                EvidenceKey::text("author"),
                Evidence::string("user@example.com"),
            )]),
        )]);
        let err = enforce_content_free_evidence_recursive(&nested, "evidence").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Forbidden content-bearing pattern (e.g., email/PII) in evidence['metadata']['author']: 'user@example.com'"
        );

        let ordered = Evidence::map(vec![
            (EvidenceKey::text("b"), Evidence::string("user@example.com")),
            (EvidenceKey::text("a\nb"), Evidence::string("x")),
        ]);
        let err = enforce_content_free_evidence_recursive(&ordered, "evidence").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Forbidden content-bearing pattern (e.g., email/PII) in evidence['b']: 'user@example.com'"
        );

        let quoted = Evidence::map(vec![(
            EvidenceKey::text("a'b"),
            Evidence::string("user@example.com"),
        )]);
        let err = enforce_content_free_evidence_recursive(&quoted, "evidence").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Forbidden content-bearing pattern (e.g., email/PII) in evidence[\"a'b\"]: 'user@example.com'"
        );

        for key in ["", "   ", "\n", "\u{001c}", "\u{00a0}"] {
            let bad = Evidence::map(vec![(EvidenceKey::text(key), Evidence::string("ok"))]);
            let err = enforce_content_free_evidence_recursive(&bad, "evidence").unwrap_err();
            assert_eq!(err.to_string(), "evidence keys must be non-empty strings");
        }
        let non_string = Evidence::map(vec![(EvidenceKey::NonString, Evidence::string("ok"))]);
        let err = enforce_content_free_evidence_recursive(&non_string, "evidence").unwrap_err();
        assert_eq!(err.to_string(), "evidence keys must be non-empty strings");

        let key_control = Evidence::map(vec![(EvidenceKey::text("a\nb"), Evidence::string("x"))]);
        let err = enforce_content_free_evidence_recursive(&key_control, "evidence").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Forbidden control or newline characters in evidence key 'a\\nb': 'a\\nb'"
        );

        let list = Evidence::list(vec![
            Evidence::ignored(),
            Evidence::string("user@example.com"),
        ]);
        let err = enforce_content_free_evidence_recursive(&list, "evidence").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Forbidden content-bearing pattern (e.g., email/PII) in evidence[1]: 'user@example.com'"
        );
    }

    #[test]
    fn evidence_cycles_and_shared_nodes() {
        let map = Evidence::map(vec![(EvidenceKey::text("tag"), Evidence::string("root"))]);
        assert!(map.push_map_entry(EvidenceKey::text("self"), map.clone()));
        let err = enforce_content_free_evidence_recursive(&map, "evidence").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cyclic reference detected in evidence: evidence['self']"
        );

        let inner = Evidence::map(vec![(EvidenceKey::text("tag"), Evidence::string("root"))]);
        assert!(inner.push_map_entry(EvidenceKey::text("self"), inner.clone()));
        let outer = Evidence::map(vec![(EvidenceKey::text("cycle"), inner)]);
        let err = enforce_content_free_evidence_recursive(&outer, "evidence").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cyclic reference detected in evidence: evidence['cycle']['self']"
        );

        let list = Evidence::list(vec![Evidence::string("item")]);
        assert!(list.push_list_item(list.clone()));
        let err = enforce_content_free_evidence_recursive(&list, "evidence").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cyclic reference detected in evidence: evidence[1]"
        );

        let shared = Evidence::map(vec![(EvidenceKey::text("a"), Evidence::string("ok"))]);
        let dag = Evidence::map(vec![
            (EvidenceKey::text("x"), shared.clone()),
            (EvidenceKey::text("y"), shared),
        ]);
        enforce_content_free_evidence_recursive(&dag, "evidence").unwrap();
    }

    #[test]
    fn sets_walk_strings_in_sorted_order() {
        let forward = Evidence::set(vec![
            Evidence::string("b@example.com"),
            Evidence::string("a@example.com"),
        ]);
        let reverse = Evidence::frozenset(vec![
            Evidence::string("a@example.com"),
            Evidence::string("b@example.com"),
        ]);
        for value in [forward, reverse] {
            let err = enforce_content_free_evidence_recursive(&value, "evidence").unwrap_err();
            assert_eq!(
                err.to_string(),
                "Forbidden content-bearing pattern (e.g., email/PII) in evidence[0]: 'a@example.com'"
            );
        }
        let mixed = Evidence::set(vec![
            Evidence::ignored(),
            Evidence::string("b@example.com"),
            Evidence::string("a@example.com"),
        ]);
        let err = enforce_content_free_evidence_recursive(&mixed, "evidence").unwrap_err();
        assert_eq!(
            err.to_string(),
            "Forbidden content-bearing pattern (e.g., email/PII) in evidence[0]: 'a@example.com'"
        );
    }
}

#[cfg(test)]
mod finding_port {
    use super::{
        finding_sort_key, python_strip, sort_findings, DictValue, Finding, FindingInput, PyValue,
        SourceLine, SourceRef, FINDING_EQ_ORD_DEVIATION, FROM_DICT_EXCEPTION_DEVIATION,
        RELATED_IDS_SET_ORDER_DEVIATION, SCHEMA_VERSION, SEVERITY_ORDER,
        SORT_FINDINGS_TYPE_DEVIATION, VARIANT_CAST_DEVIATION,
    };
    use crate::codes::{Repairability, Severity, ALL_CODES};
    use std::cmp::Ordering;
    use std::error::Error;

    fn source(path: &str, line: Option<i64>, record_id: Option<&str>) -> SourceRef {
        let line = line.map(SourceLine::Int);
        SourceRef::try_new(path, line, record_id).unwrap()
    }

    fn base() -> FindingInput {
        FindingInput {
            code: PyValue::string("SL001"),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic marker"),
            source: PyValue::source(source("a.jsonl", Some(1), None)),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence: PyValue::None,
        }
    }

    fn built(input: FindingInput) -> Finding {
        Finding::try_new(input).unwrap()
    }

    fn err(input: FindingInput) -> String {
        let error = Finding::try_new(input).unwrap_err();
        assert_eq!(error.code(), "FINDING");
        assert!(error.source().is_none());
        error.to_string()
    }

    fn strings(items: &[&str]) -> PyValue {
        PyValue::list(items.iter().copied().map(PyValue::string).collect())
    }

    #[test]
    fn happy_path_round_trip_preserves_python_field_order() {
        let mut input = base();
        input.message = PyValue::string("  synthetic marker  ");
        input.message_template = PyValue::string("  synthetic template  ");
        input.related_ids = strings(&["evt-2", "evt-1", "evt-1"]);
        input.source = PyValue::source(source("a.jsonl", Some(2), Some("rec-1")));
        input.evidence = PyValue::map(vec![
            (PyValue::string("b"), PyValue::string("beta")),
            (PyValue::string("a"), PyValue::string("alpha")),
            (
                PyValue::string("variant"),
                PyValue::string("synthetic-variant"),
            ),
            (PyValue::string("record_ordinal"), PyValue::int(3)),
        ]);
        let finding = built(input);
        assert_eq!(finding.message(), "  synthetic marker  ");
        assert_eq!(finding.message_template(), Some("  synthetic template  "));
        assert_eq!(
            finding.related_ids(),
            ["evt-1".to_owned(), "evt-2".to_owned()]
        );
        assert_eq!(finding.schema_version(), SCHEMA_VERSION);
        assert_eq!(
            finding.variant().unwrap(),
            Some("synthetic-variant".to_owned())
        );
        assert_eq!(finding_sort_key(&finding).ordinal, 3);

        let dict = finding.to_dict();
        let keys: Vec<&str> = dict.iter().map(|(key, _)| *key).collect();
        assert_eq!(
            keys,
            [
                "schema_version",
                "code",
                "severity",
                "repairability",
                "message",
                "source",
                "related_ids",
                "fingerprint",
                "message_template",
                "evidence",
            ]
        );
        let DictValue::Map(source_entries) = &dict[5].1 else {
            panic!("source must be a mapping");
        };
        assert_eq!(
            source_entries
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            ["path", "line", "record_id"]
        );
        assert_eq!(dict[2].1, DictValue::Str("error".to_owned()));
        assert_eq!(dict[3].1, DictValue::Str("manual".to_owned()));
        let DictValue::Map(evidence) = &dict[9].1 else {
            panic!("evidence must be a mapping");
        };
        assert_eq!(
            evidence
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            ["b", "a", "variant", "record_ordinal"]
        );
        let again = Finding::from_dict(&dict).unwrap();
        assert_eq!(again, finding);
    }

    #[test]
    fn validation_follows_post_init_order() {
        let mut input = base();
        input.code = PyValue::string("NOPE");
        input.severity = PyValue::string("error");
        input.message = PyValue::string("");
        let message = err(input);
        assert!(message.starts_with(
            "Finding.code must be a registered detector code, got 'NOPE'. Must be one of "
        ));
        assert!(message.contains("['SL001', 'SL002'"));
        assert!(message.contains("', '"));
        assert!(message.ends_with("'SL402']"));
        assert!(!message.contains('"'));
        let mut codes = ALL_CODES.to_vec();
        let declaration = codes.clone();
        codes.sort_unstable();
        assert_eq!(codes, declaration);
        assert!(message.contains("'SL001', 'SL002', 'SL003'"));

        let mut input = base();
        input.code = PyValue::int(3);
        assert!(err(input).contains("got 3. Must be one of ['SL001'"));

        let mut input = base();
        input.code = PyValue::string("");
        assert!(err(input).contains("got ''. Must be one of "));

        let mut input = base();
        input.severity = PyValue::string("error");
        input.repairability = PyValue::int(1);
        assert_eq!(
            err(input),
            "Finding.severity must be a Severity enum, got 'error'"
        );

        let mut input = base();
        input.severity = PyValue::repairability(Repairability::Manual);
        assert_eq!(
            err(input),
            "Finding.severity must be a Severity enum, got <Repairability.MANUAL: 'manual'>"
        );

        let mut input = base();
        input.repairability = PyValue::string("manual");
        assert_eq!(
            err(input),
            "Finding.repairability must be a Repairability enum, got 'manual'"
        );

        let mut input = base();
        input.message = PyValue::int(4);
        assert_eq!(
            err(input),
            "Finding.message must be a non-empty string, got int"
        );
        let mut input = base();
        input.message = PyValue::None;
        assert_eq!(
            err(input),
            "Finding.message must be a non-empty string, got NoneType"
        );
        let mut input = base();
        input.message = PyValue::bool_value(true);
        assert_eq!(
            err(input),
            "Finding.message must be a non-empty string, got bool"
        );
        for blank in ["", "   ", &" ".repeat(501)] {
            let mut input = base();
            input.message = PyValue::string(blank);
            assert_eq!(
                err(input),
                "Finding.message must be a non-empty string, got str"
            );
        }

        let mut input = base();
        input.message = PyValue::string("x".repeat(501));
        assert_eq!(
            err(input),
            "Finding.message exceeds maximum length of 500 characters (length: 501)"
        );
        let wide = "é".repeat(501);
        assert_eq!(wide.len(), 1002);
        let mut input = base();
        input.message = PyValue::string(wide);
        assert_eq!(
            err(input),
            "Finding.message exceeds maximum length of 500 characters (length: 501)"
        );
        let mut input = base();
        input.message = PyValue::string(format!("\n{}", "x".repeat(500)));
        assert_eq!(
            err(input),
            "Finding.message exceeds maximum length of 500 characters (length: 501)"
        );
        let mut input = base();
        input.message = PyValue::string("x".repeat(500));
        assert_eq!(built(input).message().chars().count(), 500);
        let mut input = base();
        input.message = PyValue::string("é".repeat(500));
        assert_eq!(built(input).message().chars().count(), 500);

        let mut input = base();
        input.message = PyValue::string("\nx");
        assert_eq!(
            err(input),
            "Forbidden control or newline characters in Finding.message: '\\nx'"
        );
        let mut input = base();
        input.message = PyValue::string("user@example.com");
        assert_eq!(
            err(input),
            "Forbidden content-bearing pattern (e.g., email/PII) in Finding.message: 'user@example.com'"
        );

        let mut input = base();
        input.source = PyValue::string("a.jsonl");
        assert_eq!(err(input), "Finding.source must be a SourceRef, got str");

        for (fingerprint, rendered) in [
            ("0123456789ABCDEF", "'0123456789ABCDEF'"),
            ("0123456789abcde", "'0123456789abcde'"),
            ("0123456789abcdef0", "'0123456789abcdef0'"),
            ("", "''"),
        ] {
            let mut input = base();
            input.fingerprint = PyValue::string(fingerprint);
            assert_eq!(
                err(input),
                format!(
                    "Finding.fingerprint must be a 16-character lowercase hex string matching ^[0-9a-f]{{16}}$, got {rendered}"
                )
            );
        }
        let mut input = base();
        input.fingerprint = PyValue::int(123);
        assert_eq!(
            err(input),
            "Finding.fingerprint must be a 16-character lowercase hex string matching ^[0-9a-f]{16}$, got 123"
        );
        let mut input = base();
        input.fingerprint = PyValue::bytes(b"0123456789abcdef".to_vec());
        assert_eq!(
            err(input),
            "Finding.fingerprint must be a 16-character lowercase hex string matching ^[0-9a-f]{16}$, got b'0123456789abcdef'"
        );

        let mut input = base();
        input.schema_version = PyValue::string("other");
        assert_eq!(
            err(input),
            "Finding.schema_version must be 'sesslint.finding/v1', got 'other'"
        );
        let mut input = base();
        input.schema_version = PyValue::int(1);
        assert_eq!(
            err(input),
            "Finding.schema_version must be 'sesslint.finding/v1', got 1"
        );

        let mut input = base();
        input.message_template = PyValue::int(8);
        assert_eq!(
            err(input),
            "Finding.message_template must be a non-empty string or None, got int"
        );
        for blank in ["", "   "] {
            let mut input = base();
            input.message_template = PyValue::string(blank);
            assert_eq!(
                err(input),
                "Finding.message_template must be a non-empty string or None, got str"
            );
        }
        let mut input = base();
        input.message_template = PyValue::string("user@example.com");
        assert_eq!(
            err(input),
            "Forbidden content-bearing pattern (e.g., email/PII) in Finding.message_template: 'user@example.com'"
        );

        let mut input = base();
        input.related_ids = PyValue::string("abc");
        assert_eq!(
            err(input),
            "Finding.related_ids must be an iterable of strings, got str"
        );
        let mut input = base();
        input.related_ids = PyValue::bytes(b"ab".to_vec());
        assert_eq!(
            err(input),
            "Finding.related_ids must be an iterable of strings, got bytes"
        );
        let mut input = base();
        input.related_ids = PyValue::int(9);
        assert_eq!(
            err(input),
            "Finding.related_ids must be an iterable of strings, got int"
        );
        let mut input = base();
        input.related_ids = strings(&[""]);
        assert_eq!(
            err(input),
            "Finding.related_ids items must be non-empty strings, got ''"
        );
        let mut input = base();
        input.related_ids = strings(&["   "]);
        assert_eq!(
            err(input),
            "Finding.related_ids items must be non-empty strings, got '   '"
        );
        let mut input = base();
        input.related_ids = PyValue::list(vec![PyValue::string(""), PyValue::int(1)]);
        assert_eq!(
            err(input),
            "Finding.related_ids items must be non-empty strings, got ''"
        );
        let mut input = base();
        input.related_ids =
            PyValue::list(vec![PyValue::string("user@example.com"), PyValue::int(1)]);
        assert_eq!(
            err(input),
            "Forbidden content-bearing pattern (e.g., email/PII) in Finding.related_ids: 'user@example.com'"
        );
        assert!(RELATED_IDS_SET_ORDER_DEVIATION.contains("set"));
        let mut input = base();
        input.related_ids = PyValue::list(vec![PyValue::bool_value(true), PyValue::int(1)]);
        assert_eq!(
            err(input),
            "Finding.related_ids items must be non-empty strings, got True"
        );
        let mut input = base();
        input.related_ids = PyValue::list(vec![PyValue::int(1), PyValue::bool_value(true)]);
        assert_eq!(
            err(input),
            "Finding.related_ids items must be non-empty strings, got 1"
        );
        let mut input = base();
        input.related_ids = strings(&[" a ", "a"]);
        assert_eq!(built(input).related_ids(), ["a".to_owned(), "a".to_owned()]);
        let mut input = base();
        input.related_ids = PyValue::list(vec![PyValue::list(Vec::new())]);
        assert_eq!(
            err(input),
            "Finding.related_ids item is not hashable (Python raises TypeError: unhashable type: 'list')"
        );

        let mut input = base();
        input.evidence = PyValue::list(Vec::new());
        assert_eq!(
            err(input),
            "Finding.evidence must be a mapping or None, got list"
        );
        for key in ["", "   ", "\n"] {
            let mut input = base();
            input.evidence = PyValue::map(vec![(PyValue::string(key), PyValue::string("ok"))]);
            assert_eq!(
                err(input),
                "Finding.evidence keys must be non-empty strings"
            );
        }
        let mut input = base();
        input.evidence = PyValue::map(vec![(PyValue::int(1), PyValue::string("ok"))]);
        assert_eq!(
            err(input),
            "Finding.evidence keys must be non-empty strings"
        );
        let mut input = base();
        input.evidence = PyValue::map(vec![(PyValue::string("a\nb"), PyValue::string("ok"))]);
        assert_eq!(
            err(input),
            "Forbidden control or newline characters in Finding.evidence key 'a\\nb': 'a\\nb'"
        );
        let mut input = base();
        input.evidence = PyValue::map(vec![(
            PyValue::string("rows"),
            PyValue::list(vec![PyValue::string("user@example.com")]),
        )]);
        assert_eq!(
            err(input),
            "Forbidden content-bearing pattern (e.g., email/PII) in Finding.evidence value for 'rows'[0]: 'user@example.com'"
        );
    }

    #[test]
    fn variant_absent_string_and_non_string() {
        let finding = built(base());
        assert_eq!(finding.variant().unwrap(), None);

        let mut input = base();
        input.evidence = PyValue::map(vec![(PyValue::string("other"), PyValue::int(1))]);
        assert_eq!(built(input).variant().unwrap(), None);

        let mut input = base();
        input.evidence = PyValue::map(vec![(PyValue::string("variant"), PyValue::int(4))]);
        let message = err_variant(input);
        assert_eq!(
            message,
            "Finding.variant is not a string; Python cast returns the raw value 4"
        );
        let mut input = base();
        input.evidence = PyValue::map(vec![(
            PyValue::string("variant"),
            PyValue::bool_value(false),
        )]);
        assert_eq!(
            err_variant(input),
            "Finding.variant is not a string; Python cast returns the raw value False"
        );
        assert!(VARIANT_CAST_DEVIATION.contains("cast"));
    }

    fn err_variant(input: FindingInput) -> String {
        built(input).variant().unwrap_err().to_string()
    }

    #[test]
    fn from_dict_uses_defaults_and_reports_python_exceptions() {
        assert!(FROM_DICT_EXCEPTION_DEVIATION.contains("KeyError"));
        assert!(FROM_DICT_EXCEPTION_DEVIATION.contains("ValueError"));
        let source_only = [(
            "source",
            DictValue::Map(vec![(
                "path".to_owned(),
                DictValue::Str("a.jsonl".to_owned()),
            )]),
        )];
        assert_eq!(
            Finding::from_dict(&[]).unwrap_err().to_string(),
            "Finding.from_dict requires a 'source' mapping"
        );
        assert_eq!(
            Finding::from_dict(&[("source", DictValue::Str("a.jsonl".to_owned()))])
                .unwrap_err()
                .to_string(),
            "Finding.from_dict requires a 'source' mapping"
        );
        assert_eq!(
            Finding::from_dict(&source_only).unwrap_err().to_string(),
            "missing required key 'code' (Python raises KeyError)"
        );

        let mut entries = required_entries();
        entries.retain(|(key, _)| *key != "severity");
        assert_eq!(
            Finding::from_dict(&entries).unwrap_err().to_string(),
            "missing required key 'severity' (Python raises KeyError)"
        );

        let mut entries = required_entries();
        replace(&mut entries, "severity", DictValue::Str("nope".to_owned()));
        entries.retain(|(key, _)| *key != "message");
        assert_eq!(
            Finding::from_dict(&entries).unwrap_err().to_string(),
            "'nope' is not a valid Severity (Python raises ValueError)"
        );
        let mut entries = required_entries();
        replace(&mut entries, "severity", DictValue::Int(1));
        assert_eq!(
            Finding::from_dict(&entries).unwrap_err().to_string(),
            "1 is not a valid Severity (Python raises ValueError)"
        );
        let mut entries = required_entries();
        replace(
            &mut entries,
            "repairability",
            DictValue::Str("nope".to_owned()),
        );
        assert_eq!(
            Finding::from_dict(&entries).unwrap_err().to_string(),
            "'nope' is not a valid Repairability (Python raises ValueError)"
        );

        let mut entries = required_entries();
        entries.retain(|(key, _)| *key != "message");
        assert_eq!(
            Finding::from_dict(&entries).unwrap_err().to_string(),
            "missing required key 'message' (Python raises KeyError)"
        );
        let mut entries = required_entries();
        entries.retain(|(key, _)| *key != "fingerprint");
        replace(
            &mut entries,
            "source",
            DictValue::Map(vec![
                ("path".to_owned(), DictValue::Str("a.jsonl".to_owned())),
                ("line".to_owned(), DictValue::Int(0)),
            ]),
        );
        assert_eq!(
            Finding::from_dict(&entries).unwrap_err().to_string(),
            "SourceRef.line must be a positive integer or None, got 0"
        );
        let mut entries = required_entries();
        entries.retain(|(key, _)| *key != "fingerprint");
        entries.push(("related_ids", DictValue::None));
        assert_eq!(
            Finding::from_dict(&entries).unwrap_err().to_string(),
            "Finding.from_dict related_ids is not iterable (Python raises TypeError: 'NoneType' object is not iterable)"
        );
        let mut entries = required_entries();
        entries.retain(|(key, _)| *key != "fingerprint");
        assert_eq!(
            Finding::from_dict(&entries).unwrap_err().to_string(),
            "missing required key 'fingerprint' (Python raises KeyError)"
        );
        let mut entries = required_entries();
        entries.push(("related_ids", DictValue::Bytes(b"ab".to_vec())));
        assert_eq!(
            Finding::from_dict(&entries).unwrap_err().to_string(),
            "Finding.related_ids items must be non-empty strings, got 97"
        );

        let finding = Finding::from_dict(&required_entries()).unwrap();
        assert!(finding.related_ids().is_empty());
        assert_eq!(finding.schema_version(), SCHEMA_VERSION);
        assert_eq!(finding.message_template(), None);
        assert!(finding.evidence().is_none());
        assert_eq!(finding.source().line(), None);
        assert_eq!(finding.source().record_id(), None);
        assert_eq!(finding.source().path(), "a.jsonl");

        let mut entries = required_entries();
        entries.push(("related_ids", DictValue::Str("ba".to_owned())));
        assert_eq!(
            Finding::from_dict(&entries).unwrap().related_ids(),
            ["a".to_owned(), "b".to_owned()]
        );
    }

    fn required_entries() -> Vec<(&'static str, DictValue)> {
        vec![
            ("code", DictValue::Str("SL001".to_owned())),
            ("severity", DictValue::Str("error".to_owned())),
            ("repairability", DictValue::Str("manual".to_owned())),
            ("message", DictValue::Str("synthetic marker".to_owned())),
            (
                "source",
                DictValue::Map(vec![(
                    "path".to_owned(),
                    DictValue::Str("a.jsonl".to_owned()),
                )]),
            ),
            ("fingerprint", DictValue::Str("0123456789abcdef".to_owned())),
        ]
    }

    fn replace(entries: &mut [(&str, DictValue)], key: &str, value: DictValue) {
        for (entry_key, entry_value) in entries {
            if *entry_key == key {
                *entry_value = value;
                return;
            }
        }
        panic!("missing test key");
    }

    #[test]
    fn sort_order_is_total_and_stable() {
        assert!(SORT_FINDINGS_TYPE_DEVIATION.contains("TypeError"));
        let late = built({
            let mut input = base();
            input.source = PyValue::source(source("c.jsonl", Some(1), None));
            input
        });
        let mid = built({
            let mut input = base();
            input.source = PyValue::source(source(r"b\z.jsonl", Some(1), None));
            input
        });
        let early = built(base());
        assert_eq!(mid.source().path(), "b/z.jsonl");
        assert_eq!(finding_sort_key(&mid).path, "b/z.jsonl");
        let sorted = sort_findings(&[late.clone(), mid.clone(), early.clone()]);
        assert_eq!(
            sorted
                .iter()
                .map(|finding| finding.source().path())
                .collect::<Vec<_>>(),
            ["a.jsonl", "b/z.jsonl", "c.jsonl"]
        );

        let none_line = built({
            let mut input = base();
            input.source = PyValue::source(source("a.jsonl", None, None));
            input
        });
        let line_one = built(base());
        assert_eq!(finding_sort_key(&none_line).line, -1);
        assert!(finding_sort_key(&none_line).line < 0);
        assert!(sort_findings(&[line_one, none_line.clone()])[0] == none_line);

        let tagged = |template: &str, evidence: PyValue| {
            let mut input = base();
            input.message_template = PyValue::string(template);
            input.evidence = evidence;
            built(input)
        };
        let ordinal =
            |value: PyValue| PyValue::map(vec![(PyValue::string("record_ordinal"), value)]);
        let one = tagged("one", ordinal(PyValue::int(1)));
        let zero = tagged("zero", ordinal(PyValue::int(0)));
        let yes = tagged("yes", ordinal(PyValue::bool_value(true)));
        let neg = tagged("neg", ordinal(PyValue::int(-5)));
        let none = tagged("none", PyValue::None);
        let no = tagged("no", ordinal(PyValue::bool_value(false)));
        let text = tagged("text", ordinal(PyValue::string("1")));
        assert_eq!(finding_sort_key(&yes).ordinal, -1);
        assert_eq!(finding_sort_key(&no).ordinal, -1);
        assert_eq!(finding_sort_key(&neg).ordinal, -1);
        assert_eq!(finding_sort_key(&text).ordinal, -1);
        assert_eq!(finding_sort_key(&zero).ordinal, 0);
        let order = sort_findings(&[one, zero, yes, neg, none]);
        assert_eq!(
            order
                .iter()
                .map(|finding| finding.message_template().unwrap())
                .collect::<Vec<_>>(),
            ["yes", "neg", "none", "zero", "one"]
        );

        let mut severities = Vec::new();
        for severity in [
            Severity::Info,
            Severity::Warning,
            Severity::Error,
            Severity::Fatal,
        ] {
            let mut input = base();
            input.severity = PyValue::severity(severity);
            severities.push(built(input));
        }
        let sorted = sort_findings(&severities);
        assert_eq!(
            sorted
                .iter()
                .map(|finding| finding.severity())
                .collect::<Vec<_>>(),
            [
                Severity::Fatal,
                Severity::Error,
                Severity::Warning,
                Severity::Info,
            ]
        );
        for (severity, rank) in SEVERITY_ORDER {
            let mut input = base();
            input.severity = PyValue::severity(severity);
            assert_eq!(finding_sort_key(&built(input)).severity_rank, rank);
        }

        let mut alpha = base();
        alpha.message_template = PyValue::string("alpha marker");
        let mut beta = base();
        beta.message_template = PyValue::string("beta marker");
        let alpha = built(alpha);
        let beta = built(beta);
        assert_ne!(alpha, beta);
        assert_eq!(alpha.cmp(&beta), Ordering::Equal);
        assert!(FINDING_EQ_ORD_DEVIATION.contains("sort key"));
        let stable = sort_findings(&[beta.clone(), alpha.clone()]);
        assert_eq!(stable[0].message_template(), Some("beta marker"));
        assert_eq!(stable[1].message_template(), Some("alpha marker"));

        let mut second = base();
        second.fingerprint = PyValue::string("0123456789abcdee");
        let mut first = base();
        first.fingerprint = PyValue::string("0123456789abcdde");
        let pair = sort_findings(&[built(second), built(first)]);
        assert_eq!(pair[0].fingerprint(), "0123456789abcdde");
        assert!(pair[0] < pair[1]);
        assert!(pair[1] >= pair[0]);
    }

    #[test]
    fn line_separator_only_message_does_not_pass() {
        let text = "\u{2028}\u{2029}";
        let mut input = base();
        input.message = PyValue::string(text);
        let result = Finding::try_new(input);
        if python_strip(text).is_empty() {
            assert_eq!(
                result.unwrap_err().to_string(),
                "Finding.message must be a non-empty string, got str"
            );
        } else {
            panic!("U+2028/U+2029 were not stripped; record the strip gap without changing python_strip");
        }
    }
}
