//! Persisted-secret-shape gate, placeholder checks, and SL009 tracker
//! (transcript-hygiene T-01).
//!
//! Port of `src/sesslint/checks/hygiene.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! The gate is a strict superset of the family patterns: a miss skips the
//! family scan, and a hit cannot drop a real family match. Scans walk bytes.
//! There is no `regex` dependency. [`SECRET_FAMILY_IDS`] are the names on
//! `model::secret_families::SECRET_FAMILIES`, in that order.
//!
//! [`SecretScanTracker`] buffers records and scans a window only when
//! [`gate_maybe_contains_secret`] accepts the joined bytes. Match digests are
//! lowercase hex SHA-256 from the `sha2` crate, of the matched bytes only.
//! Those bytes are not retained. [`SecretScanTracker::into_findings`] calls
//! [`make_finding`] with the fingerprint omitted once a hit exists and returns
//! the fingerprint codec error. It does not invent a fingerprint and does not
//! hash the finding.
//!
//! `_GENERIC_ASSIGNMENT_LOWER` is not copied. Generic assignment uses
//! [`model::secret_families::SECRET_FAMILIES`] search on the ASCII-lowered
//! shadow. A byte slice is the record; there is no `memoryview`.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use model::codes::{Repairability, Severity, SL009};
use model::errors::FindingError;
use model::finding::{make_finding, Finding, MakeFindingInput, PyValue, SourceLine, SourceRef};
use model::secret_families::{FAMILY_LITERALS, SECRET_FAMILIES};
use sha2::{Digest, Sha256};

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
/// Per-(record, family) aggregation: count, distinct digest strings, and the
/// longest matched length. Digests are lowercase hex SHA-256 strings. The
/// secret bytes are not stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HitAgg {
    /// Python: `count`. A Python `int`, stored as `i64`.
    pub count: i64,
    /// Python: `digests`. Distinct digest strings. Insertion order is not kept.
    pub digests: BTreeSet<String>,
    /// Python: `max_len`. A Python `int`, stored as `i64`.
    pub max_len: i64,
}

impl HitAgg {
    fn observe(&mut self, secret: &[u8]) {
        self.count = self.count.saturating_add(1);
        self.digests.insert(match_sha256_hex(secret));
        let len = i64::try_from(secret.len()).unwrap_or(i64::MAX);
        if len > self.max_len {
            self.max_len = len;
        }
    }
}

/// Python message template. `{line}` comes from the source line.
const MSG_SL009: &str = "Persisted secret-shaped material in record on line {line}";

const TELEGRAM_BOT_TOKEN: &str = "telegram-bot-token";
const GENERIC_ASSIGNMENT: &str = "generic-credential-assignment";

/// Failure from [`SecretScanTracker::into_findings`]. [`Display`] is the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HygieneError {
    Finding(FindingError),
}

impl HygieneError {
    /// Message text, without a code prefix.
    pub fn message(&self) -> &str {
        match self {
            Self::Finding(error) => error.message(),
        }
    }
}

impl fmt::Display for HygieneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for HygieneError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
        }
    }
}

impl From<FindingError> for HygieneError {
    fn from(error: FindingError) -> Self {
        Self::Finding(error)
    }
}

/// One capped SL009 row, before [`make_finding`].
///
/// `line_number` is the sort key and the source line. It is not an evidence
/// key. Absent coordinates stay [`None`] and are omitted from [`Self::evidence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretEvidenceRow {
    /// Source line. `None` sorts as `-1`.
    pub line_number: Option<i64>,
    /// Record ordinal. `None` sorts as `-1` and is omitted from evidence.
    pub record_ordinal: Option<i64>,
    /// Record start. Omitted from evidence when absent.
    pub byte_offset: Option<i64>,
    /// Record end, exclusive. Omitted from evidence when absent.
    pub byte_end: Option<i64>,
    /// Family id.
    pub family: &'static str,
    /// Exact hit count, including hits past the digest cap.
    pub occurrence_count: i64,
    /// Sorted distinct digests, cut at [`MAX_DIGESTS_PER_FINDING`].
    pub match_sha256: Vec<String>,
    /// Longest secret length. Exact, not capped.
    pub match_len: i64,
    /// Digest set longer than 16, or the last emitted row when any row was cut.
    pub truncated: bool,
    /// Suppressed finding count, only on the last emitted row.
    pub overflow: Option<i64>,
}

impl SecretEvidenceRow {
    /// Evidence map in pin insertion order. No secret bytes.
    pub fn evidence(&self) -> PyValue {
        let mut entries = vec![
            (
                PyValue::string("secret_family"),
                PyValue::string(self.family),
            ),
            (
                PyValue::string("occurrence_count"),
                PyValue::int(self.occurrence_count),
            ),
            (
                PyValue::string("match_sha256"),
                PyValue::list(
                    self.match_sha256
                        .iter()
                        .cloned()
                        .map(PyValue::string)
                        .collect(),
                ),
            ),
            (PyValue::string("match_len"), PyValue::int(self.match_len)),
            (
                PyValue::string("secret_family_set"),
                PyValue::int(SECRET_FAMILY_SET_VERSION),
            ),
        ];
        if let Some(ordinal) = self.record_ordinal {
            entries.push((PyValue::string("record_ordinal"), PyValue::int(ordinal)));
        }
        if let Some(offset) = self.byte_offset {
            entries.push((PyValue::string("byte_offset"), PyValue::int(offset)));
        }
        if let Some(end) = self.byte_end {
            entries.push((PyValue::string("byte_end"), PyValue::int(end)));
        }
        if self.truncated {
            entries.push((PyValue::string("truncated"), PyValue::bool_value(true)));
        }
        if let Some(overflow) = self.overflow {
            entries.push((PyValue::string("overflow"), PyValue::int(overflow)));
        }
        PyValue::map(entries)
    }
}

/// Python: `_HitKey` without the map. `(ordinal, line, offset, end, family)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct HitKey {
    record_ordinal: Option<i64>,
    line_number: Option<i64>,
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
    family: &'static str,
}

struct PendingRecord {
    raw: Vec<u8>,
    line_number: Option<i64>,
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
    record_ordinal: Option<i64>,
}

/// Python: `SecretScanTracker`.
///
/// Records stay buffered until [`GATE_WINDOW_BYTES`] or [`Self::into_findings`].
/// A gate miss drops the window without a family scan.
#[derive(Default)]
pub struct SecretScanTracker {
    hits: BTreeMap<HitKey, HitAgg>,
    /// First-seen order. Sort ties keep this order.
    hit_order: Vec<HitKey>,
    pending: Vec<PendingRecord>,
    pending_bytes: usize,
}

impl SecretScanTracker {
    /// Empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Python: `SecretScanTracker.feed`.
    ///
    /// Empty input is ignored. Otherwise the record is appended and its length
    /// is added to the pending byte count. At [`GATE_WINDOW_BYTES`] the window
    /// is flushed, including the record that crossed the threshold.
    pub fn feed(
        &mut self,
        raw_bytes: &[u8],
        line_number: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
        record_ordinal: Option<i64>,
    ) {
        if raw_bytes.is_empty() {
            return;
        }
        let len = raw_bytes.len();
        self.pending.push(PendingRecord {
            raw: raw_bytes.to_vec(),
            line_number,
            byte_offset,
            byte_end,
            record_ordinal,
        });
        self.pending_bytes = self.pending_bytes.saturating_add(len);
        if self.pending_bytes >= GATE_WINDOW_BYTES {
            self.flush_pending();
        }
    }

    /// Python: `SecretScanTracker.feed_blob`.
    ///
    /// Split on `\n` and keep the newline with the line. Lines start at 1.
    /// `byte_offset` and `byte_end` cover each slice. `record_ordinal` is
    /// absent. A blob that does not end in `\n` does not gain one.
    pub fn feed_blob(&mut self, data: &[u8]) {
        let mut offset = 0usize;
        let mut line_number = 0i64;
        while offset < data.len() {
            line_number = line_number.saturating_add(1);
            let end = match data[offset..].iter().position(|byte| *byte == b'\n') {
                Some(index) => offset
                    .checked_add(index)
                    .and_then(|at| at.checked_add(1))
                    .map(|value| value.min(data.len()))
                    .unwrap_or(data.len()),
                None => data.len(),
            };
            if end <= offset {
                break;
            }
            let Some(slice) = data.get(offset..end) else {
                break;
            };
            self.feed(
                slice,
                Some(line_number),
                usize_to_i64(offset),
                usize_to_i64(end),
                None,
            );
            offset = end;
        }
    }

    /// Flush, then return capped rows. Does not call [`make_finding`].
    pub fn evidence_rows(&mut self) -> Vec<SecretEvidenceRow> {
        self.flush_pending();
        secret_evidence_rows(&self.hit_order, &self.hits)
    }

    /// Python: `SecretScanTracker.into_findings`.
    ///
    /// No hits returns an empty list and does not call [`make_finding`].
    /// A hit calls [`make_finding`] with the fingerprint omitted. That codec
    /// error is propagated. Source construction errors are propagated too.
    pub fn into_findings(&mut self, path_str: &str) -> Result<Vec<Finding>, HygieneError> {
        self.flush_pending();
        let rows = secret_evidence_rows(&self.hit_order, &self.hits);
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let source = SourceRef::try_new(path_str, row.line_number.map(SourceLine::Int), None)?;
            out.push(make_finding(&MakeFindingInput {
                code: PyValue::string(SL009),
                severity: PyValue::severity(Severity::Warning),
                repairability: PyValue::repairability(Repairability::Manual),
                message_template: PyValue::string(MSG_SL009),
                template_args: PyValue::None,
                source: PyValue::source(source),
                related_ids: PyValue::tuple(Vec::new()),
                evidence: row.evidence(),
                fingerprint: PyValue::None,
                adapter_id: None,
                adapter_version: None,
                profile_id: None,
                profile_version: None,
                ordinal: None,
                context: None,
            })?);
        }
        Ok(out)
    }

    fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        if !gate_maybe_contains_secret(&joined_window(&pending)) {
            return;
        }
        for record in &pending {
            if !line_gate_maybe_contains_secret(&record.raw) {
                continue;
            }
            self.scan_record(
                &record.raw,
                record.line_number,
                record.byte_offset,
                record.byte_end,
                record.record_ordinal,
            );
        }
    }

    fn scan_record(
        &mut self,
        raw: &[u8],
        line_number: Option<i64>,
        byte_offset: Option<i64>,
        byte_end: Option<i64>,
        record_ordinal: Option<i64>,
    ) {
        let shadow = json_escape_boundary_shadow(raw);
        let mut lowered_shadow: Option<Vec<u8>> = None;
        for family in SECRET_FAMILIES {
            if let Some(anchors) = literals_for(family.name) {
                let anchor_bytes: &[u8] = if is_casefolded_family(family.name) {
                    lowered_shadow.get_or_insert_with(|| shadow.to_ascii_lowercase())
                } else {
                    raw
                };
                let anchored = anchors
                    .iter()
                    .any(|anchor| find_from(anchor_bytes, anchor, 0).is_some());
                if !anchored {
                    continue;
                }
            }
            if family.name == TELEGRAM_BOT_TOKEN && !gate_token_tail_present(raw) {
                continue;
            }
            let generic = family.name == GENERIC_ASSIGNMENT;
            let lowered_generic;
            let haystack: &[u8] = if generic {
                lowered_generic = shadow.to_ascii_lowercase();
                &lowered_generic
            } else {
                shadow.as_ref()
            };
            for (start, end) in nonoverlapping_spans(haystack, family.search, !generic) {
                let Some(secret) = raw.get(start..end) else {
                    continue;
                };
                if generic && looks_like_placeholder(secret) {
                    continue;
                }
                self.observe_hit(
                    HitKey {
                        record_ordinal,
                        line_number,
                        byte_offset,
                        byte_end,
                        family: family.name,
                    },
                    secret,
                );
            }
        }
    }

    fn observe_hit(&mut self, key: HitKey, secret: &[u8]) {
        if let Some(agg) = self.hits.get_mut(&key) {
            agg.observe(secret);
            return;
        }
        let mut agg = HitAgg::default();
        agg.observe(secret);
        self.hit_order.push(key);
        self.hits.insert(key, agg);
    }

    #[cfg(test)]
    fn pending_is_empty(&self) -> bool {
        self.pending.is_empty() && self.pending_bytes == 0
    }
}

/// Pure projection of aggregated hits. Does not flush and does not call
/// [`make_finding`].
fn secret_evidence_rows(
    order: &[HitKey],
    hits: &BTreeMap<HitKey, HitAgg>,
) -> Vec<SecretEvidenceRow> {
    let mut keys = order.to_vec();
    keys.sort_by(|left, right| {
        (
            left.line_number.unwrap_or(-1),
            left.record_ordinal.unwrap_or(-1),
            left.family,
        )
            .cmp(&(
                right.line_number.unwrap_or(-1),
                right.record_ordinal.unwrap_or(-1),
                right.family,
            ))
    });
    let limit = i64_to_usize(MAX_SECRET_FINDINGS_PER_FILE);
    let suppressed = keys.len().saturating_sub(limit);
    let emitted = keys.len().min(limit);
    let last = emitted.saturating_sub(1);
    let digest_limit = i64_to_usize(MAX_DIGESTS_PER_FINDING);
    let mut rows = Vec::with_capacity(emitted);
    for (index, key) in keys.iter().take(emitted).enumerate() {
        let Some(agg) = hits.get(key) else {
            continue;
        };
        let on_last = emitted > 0 && index == last && suppressed > 0;
        rows.push(SecretEvidenceRow {
            line_number: key.line_number,
            record_ordinal: key.record_ordinal,
            byte_offset: key.byte_offset,
            byte_end: key.byte_end,
            family: key.family,
            occurrence_count: agg.count,
            match_sha256: agg.digests.iter().take(digest_limit).cloned().collect(),
            match_len: agg.max_len,
            truncated: agg.digests.len() > digest_limit || on_last,
            overflow: on_last.then(|| usize_to_i64(suppressed).unwrap_or(i64::MAX)),
        });
    }
    rows
}

fn joined_window(pending: &[PendingRecord]) -> Vec<u8> {
    let mut joined = Vec::new();
    for (index, record) in pending.iter().enumerate() {
        if index > 0 {
            joined.push(b'\n');
        }
        joined.extend_from_slice(&record.raw);
    }
    joined
}

fn literals_for(name: &str) -> Option<&'static [&'static [u8]]> {
    for &(family, literals) in FAMILY_LITERALS {
        if family == name {
            return Some(literals);
        }
    }
    None
}

fn is_casefolded_family(name: &str) -> bool {
    CASEFOLDED_FAMILY_LITERALS.contains(&name)
}

/// Leftmost non-overlapping spans, resuming at each match end.
///
/// `search` sees a suffix. Families other than generic assignment also require
/// the byte before the suffix, when there is one, to sit outside [`TOKEN_BYTES`].
/// A match reported at the cut that fails that check is skipped by one byte,
/// which is the searcher's own retry. Generic assignment has no lookbehind.
fn nonoverlapping_spans(
    haystack: &[u8],
    search: fn(&[u8]) -> Option<(usize, usize)>,
    boundary: bool,
) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut from = 0usize;
    while from <= haystack.len() {
        let Some(slice) = haystack.get(from..) else {
            break;
        };
        let Some((start, end)) = search(slice) else {
            break;
        };
        if start > slice.len() || end > slice.len() || end < start {
            break;
        }
        if boundary && start == 0 && from > 0 && !predecessor_allows_family(haystack, from) {
            let Some(next) = from.checked_add(1) else {
                break;
            };
            from = next;
            continue;
        }
        if end == start {
            let Some(next) = from.checked_add(1) else {
                break;
            };
            from = next;
            continue;
        }
        let Some(abs_start) = from.checked_add(start) else {
            break;
        };
        let Some(abs_end) = from.checked_add(end) else {
            break;
        };
        if abs_end > haystack.len() || abs_end <= from {
            break;
        }
        spans.push((abs_start, abs_end));
        from = abs_end;
    }
    spans
}

fn predecessor_allows_family(haystack: &[u8], index: usize) -> bool {
    if index == 0 {
        return true;
    }
    match haystack.get(index - 1) {
        Some(byte) => !is_token_byte(*byte),
        None => true,
    }
}

/// Lowercase hex SHA-256 of `secret`. The only hash in this module.
fn match_sha256_hex(secret: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(secret);
    let mut out = String::with_capacity(digest.len().saturating_mul(2));
    for byte in digest {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        out.push(char::from(HEX[high]));
        out.push(char::from(HEX[low]));
    }
    out
}

fn usize_to_i64(value: usize) -> Option<i64> {
    i64::try_from(value).ok()
}

fn i64_to_usize(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        gate_maybe_contains_secret, json_escape_boundary_shadow, kw_assignment_present,
        line_gate_maybe_contains_secret, looks_like_placeholder, match_sha256_hex,
        secret_evidence_rows, short_prefix_present, HitAgg, HitKey, HygieneError,
        SecretScanTracker, CASEFOLDED_FAMILY_LITERALS, CASEFOLDED_GATE_LITERALS, GATE_KEYWORDS,
        GATE_KW_MID, GATE_KW_SEP, GATE_LITERALS, GATE_SHORT_PREFIXES, GATE_WINDOW_BYTES,
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
        let banned = [concat!("re", ".compile"), concat!("regex", "::")];
        for needle in banned {
            assert!(!src.contains(needle), "{needle}");
        }
    }

    fn openai(fill: u8, body: usize) -> Vec<u8> {
        let mut raw = b"sk-".to_vec();
        raw.extend(std::iter::repeat_n(fill, body));
        raw
    }

    fn bearer() -> Vec<u8> {
        let mut raw = b"Bearer ".to_vec();
        raw.extend(std::iter::repeat_n(b'd', 16));
        raw
    }

    fn telegram() -> Vec<u8> {
        let mut raw = b"12345678:".to_vec();
        raw.extend(std::iter::repeat_n(b'a', 35));
        raw
    }

    fn pem_header() -> Vec<u8> {
        let mut raw = b"-----BEGIN ".to_vec();
        raw.extend_from_slice(b"PRIVATE ");
        raw.extend_from_slice(b"KEY-----");
        raw
    }

    fn assignment(value: &[u8]) -> Vec<u8> {
        let mut raw = b"token: ".to_vec();
        raw.extend_from_slice(value);
        raw
    }

    fn assert_codec(err: &HygieneError) {
        assert_eq!(
            err.to_string(),
            model::finding::FINGERPRINT_CODEC_UNAVAILABLE
        );
        assert_eq!(err.message(), model::finding::FINGERPRINT_CODEC_UNAVAILABLE);
    }

    fn evidence_keys(row: &super::SecretEvidenceRow) -> Vec<String> {
        let model::finding::PyValue::Map(entries) = row.evidence() else {
            return Vec::new();
        };
        entries
            .iter()
            .map(|(key, _)| match key {
                model::finding::PyValue::Str(text) => text.clone(),
                _ => String::new(),
            })
            .collect()
    }

    fn digest_list(row: &super::SecretEvidenceRow) -> Vec<String> {
        let model::finding::PyValue::Map(entries) = row.evidence() else {
            return Vec::new();
        };
        for (key, value) in entries {
            let model::finding::PyValue::Str(name) = key else {
                continue;
            };
            if name != "match_sha256" {
                continue;
            }
            let model::finding::PyValue::List(items) = value else {
                return Vec::new();
            };
            return items
                .iter()
                .map(|item| match item {
                    model::finding::PyValue::Str(text) => text.clone(),
                    _ => String::new(),
                })
                .collect();
        }
        Vec::new()
    }

    #[test]
    fn match_digest_is_lowercase_sha256_hex() {
        assert_eq!(match_sha256_hex(b"").len(), 64);
        assert_eq!(
            match_sha256_hex(b"a"),
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
        );
        assert!(match_sha256_hex(b"a")
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }

    #[test]
    fn empty_feed_and_gate_miss_emit_nothing() {
        let mut tracker = SecretScanTracker::new();
        tracker.feed(b"", Some(1), Some(0), Some(0), Some(0));
        tracker.feed(b"nothing here", Some(1), None, None, None);
        tracker.feed_blob(b"");
        assert!(!tracker.pending_is_empty());
        assert!(tracker.evidence_rows().is_empty());
        assert!(tracker.pending_is_empty());
        let findings = tracker.into_findings("synth.jsonl").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn window_at_the_gate_flushes_and_a_later_secret_survives() {
        let mut quiet = SecretScanTracker::new();
        quiet.feed(
            &vec![b'z'; GATE_WINDOW_BYTES - 1],
            Some(1),
            None,
            None,
            None,
        );
        assert!(!quiet.pending_is_empty());
        quiet.feed(b"z", Some(2), None, None, None);
        assert!(quiet.pending_is_empty());
        assert!(quiet.evidence_rows().is_empty());

        let token = openai(b'q', 20);
        let pad = GATE_WINDOW_BYTES - token.len() - 1;
        let mut big = vec![b'z'; pad];
        big.push(b' ');
        big.extend_from_slice(&token);
        assert_eq!(big.len(), GATE_WINDOW_BYTES);
        let mut tracker = SecretScanTracker::new();
        tracker.feed(
            &big,
            Some(4),
            Some(0),
            Some(i64::try_from(big.len()).unwrap()),
            Some(7),
        );
        assert!(tracker.pending_is_empty());
        tracker.feed(b"later", Some(5), None, None, None);
        let rows = tracker.evidence_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].family, "openai-api-key");
        assert_eq!(rows[0].line_number, Some(4));
        assert_eq!(rows[0].record_ordinal, Some(7));
        assert_eq!(rows[0].occurrence_count, 1);
        assert_eq!(rows[0].match_len, i64::try_from(token.len()).unwrap());
        assert_eq!(rows[0].match_sha256, vec![match_sha256_hex(&token)]);
        assert!(!rows[0].truncated);
        assert_eq!(rows[0].overflow, None);
    }

    #[test]
    fn line_gate_skips_a_clean_record_in_a_hot_window() {
        let token = openai(b'm', 20);
        let mut tracker = SecretScanTracker::new();
        tracker.feed(b"clean line", Some(1), Some(0), Some(10), Some(0));
        tracker.feed(&token, Some(2), Some(11), Some(40), Some(1));
        let rows = tracker.evidence_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].line_number, Some(2));
        assert_eq!(rows[0].record_ordinal, Some(1));
        assert_eq!(rows[0].byte_offset, Some(11));
        assert_eq!(rows[0].byte_end, Some(40));
        assert_eq!(
            evidence_keys(&rows[0]),
            [
                "secret_family",
                "occurrence_count",
                "match_sha256",
                "match_len",
                "secret_family_set",
                "record_ordinal",
                "byte_offset",
                "byte_end",
            ]
        );
        assert_eq!(digest_list(&rows[0]), rows[0].match_sha256);
    }

    #[test]
    fn split_token_is_not_a_hit_and_a_boundary_miss_is_not_a_hit() {
        let token = openai(b'b', 20);
        let (left, right) = token.split_at(2);
        let mut split = SecretScanTracker::new();
        split.feed(left, Some(1), None, None, Some(0));
        split.feed(right, Some(2), None, None, Some(1));
        assert!(split.evidence_rows().is_empty());

        let mut glued = b"x".to_vec();
        glued.extend_from_slice(&token);
        let mut tracker = SecretScanTracker::new();
        tracker.feed(&glued, Some(1), None, None, None);
        assert!(tracker.evidence_rows().is_empty());
    }

    #[test]
    fn json_escape_shadow_exposes_a_token_the_raw_boundary_hides() {
        let token = openai(b'a', 20);
        let mut raw = b"x\\n".to_vec();
        raw.extend_from_slice(&token);
        let mut tracker = SecretScanTracker::new();
        tracker.feed(&raw, Some(1), None, None, None);
        let rows = tracker.evidence_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].match_sha256, vec![match_sha256_hex(&token)]);
        assert_eq!(rows[0].match_len, i64::try_from(token.len()).unwrap());
        assert_ne!(rows[0].match_sha256, vec![match_sha256_hex(&raw)]);
    }

    #[test]
    fn placeholder_values_are_skipped_and_case_is_preserved() {
        let mut skipped = SecretScanTracker::new();
        skipped.feed(&assignment(b"password"), Some(1), None, None, None);
        skipped.feed(&assignment(b"PASSWORD"), Some(2), None, None, None);
        skipped.feed(&assignment(b"xxxxxxxx"), Some(3), None, None, None);
        skipped.feed(b"token: your-secret-value", Some(4), None, None, None);
        assert!(skipped.evidence_rows().is_empty());

        let raw = b"TOKEN: AbcdEfgh".to_vec();
        let mut tracker = SecretScanTracker::new();
        tracker.feed(&raw, Some(8), None, None, None);
        let rows = tracker.evidence_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].family, "generic-credential-assignment");
        assert_eq!(rows[0].match_sha256, vec![match_sha256_hex(b"AbcdEfgh")]);
        assert_ne!(rows[0].match_sha256, vec![match_sha256_hex(b"abcdefgh")]);
        assert_eq!(rows[0].match_len, 8);
        assert_eq!(
            evidence_keys(&rows[0]),
            [
                "secret_family",
                "occurrence_count",
                "match_sha256",
                "match_len",
                "secret_family_set",
            ]
        );
    }

    #[test]
    fn one_record_aggregates_count_length_and_sorted_digests() {
        let short = openai(b'a', 20);
        let long = openai(b'b', 25);
        let mut raw = short.clone();
        raw.push(b' ');
        raw.extend_from_slice(&long);
        raw.extend_from_slice(b" token: real-value token: other-value");
        let mut tracker = SecretScanTracker::new();
        tracker.feed(&raw, Some(3), Some(1), Some(2), Some(4));
        let rows = tracker.evidence_rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].family, "generic-credential-assignment");
        assert_eq!(rows[1].family, "openai-api-key");
        assert_eq!(rows[1].occurrence_count, 2);
        assert_eq!(rows[1].match_len, i64::try_from(long.len()).unwrap());
        let mut digests = vec![match_sha256_hex(&short), match_sha256_hex(&long)];
        digests.sort();
        assert_eq!(rows[1].match_sha256, digests);
        assert_eq!(rows[0].occurrence_count, 2);
        assert_eq!(rows[0].match_len, 11);
        let mut generic = vec![
            match_sha256_hex(b"real-value"),
            match_sha256_hex(b"other-value"),
        ];
        generic.sort();
        assert_eq!(rows[0].match_sha256, generic);
    }

    #[test]
    fn families_sort_by_line_then_ordinal_then_name() {
        let mut tracker = SecretScanTracker::new();
        tracker.feed(&openai(b'c', 20), Some(2), Some(9), Some(10), None);
        tracker.feed(&bearer(), None, Some(1), Some(2), Some(9));
        tracker.feed(&assignment(b"real-value"), Some(1), None, None, None);
        tracker.feed(&telegram(), Some(1), Some(3), Some(4), Some(2));
        tracker.feed(&pem_header(), Some(1), Some(5), Some(6), Some(0));
        let rows = tracker.evidence_rows();
        let order: Vec<_> = rows
            .iter()
            .map(|row| (row.line_number, row.record_ordinal, row.family))
            .collect();
        assert_eq!(
            order,
            [
                (None, Some(9), "bearer-token"),
                (Some(1), None, "generic-credential-assignment"),
                (Some(1), Some(0), "private-key-block"),
                (Some(1), Some(2), "telegram-bot-token"),
                (Some(2), None, "openai-api-key"),
            ]
        );
        assert_eq!(rows[2].match_sha256, vec![match_sha256_hex(&pem_header())]);
        assert_eq!(rows[3].match_sha256, vec![match_sha256_hex(&telegram())]);
    }

    #[test]
    fn equal_sort_keys_keep_insertion_order() {
        let first = openai(b'a', 20);
        let second = openai(b'b', 20);
        let mut tracker = SecretScanTracker::new();
        tracker.feed(&first, Some(1), Some(50), Some(80), Some(3));
        tracker.feed(&second, Some(1), Some(1), Some(30), Some(3));
        let rows = tracker.evidence_rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].byte_offset, Some(50));
        assert_eq!(rows[1].byte_offset, Some(1));
        assert_eq!(rows[0].match_sha256, vec![match_sha256_hex(&first)]);
        assert_eq!(rows[1].match_sha256, vec![match_sha256_hex(&second)]);
    }

    #[test]
    fn digest_cap_keeps_exact_count_and_length() {
        let mut raw = Vec::new();
        let mut digests = Vec::new();
        for fill in b'a'..=b'q' {
            if !raw.is_empty() {
                raw.push(b' ');
            }
            let token = openai(fill, 20);
            digests.push(match_sha256_hex(&token));
            raw.extend_from_slice(&token);
        }
        digests.sort();
        let mut tracker = SecretScanTracker::new();
        tracker.feed(&raw, Some(1), None, None, None);
        let rows = tracker.evidence_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].occurrence_count, 17);
        assert_eq!(
            rows[0].match_len,
            i64::try_from(openai(b'a', 20).len()).unwrap()
        );
        assert_eq!(rows[0].match_sha256, digests[..16].to_vec());
        assert!(rows[0].truncated);
        assert_eq!(rows[0].overflow, None);
        assert_eq!(digest_list(&rows[0]).len(), 16);
        let model::finding::PyValue::Map(entries) = rows[0].evidence() else {
            panic!("evidence map");
        };
        assert!(entries.iter().any(|(key, value)| {
            matches!(
                (key, value),
                (
                    model::finding::PyValue::Str(name),
                    model::finding::PyValue::Bool(true)
                ) if name == "truncated"
            )
        }));
    }

    #[test]
    fn finding_cap_sets_overflow_on_the_last_emitted_row() {
        let token = openai(b'z', 20);
        let mut tracker = SecretScanTracker::new();
        for line in 1..=65 {
            tracker.feed(&token, Some(line), None, None, None);
        }
        let rows = tracker.evidence_rows();
        assert_eq!(rows.len(), 64);
        assert_eq!(rows[0].line_number, Some(1));
        assert!(!rows[0].truncated);
        assert_eq!(rows[0].overflow, None);
        assert_eq!(rows[0].occurrence_count, 1);
        assert_eq!(rows[63].line_number, Some(64));
        assert!(rows[63].truncated);
        assert_eq!(rows[63].overflow, Some(1));
        assert_eq!(rows[63].occurrence_count, 1);
        let keys = evidence_keys(&rows[63]);
        assert_eq!(
            keys[keys.len() - 2..],
            ["truncated".to_owned(), "overflow".to_owned()]
        );
    }

    #[test]
    fn feed_blob_keeps_newlines_and_omits_the_ordinal() {
        let token = openai(b'c', 20);
        let mut blob = b"head\n".to_vec();
        let offset = blob.len();
        blob.extend_from_slice(&token);
        blob.push(b'\n');
        let end = blob.len();
        blob.extend_from_slice(b"tail");
        let mut tracker = SecretScanTracker::new();
        tracker.feed_blob(&blob);
        let rows = tracker.evidence_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].line_number, Some(2));
        assert_eq!(rows[0].byte_offset, i64::try_from(offset).ok());
        assert_eq!(rows[0].byte_end, i64::try_from(end).ok());
        assert_eq!(rows[0].record_ordinal, None);
        assert_eq!(rows[0].match_len, i64::try_from(token.len()).unwrap());
        assert!(!evidence_keys(&rows[0])
            .iter()
            .any(|key| key == "record_ordinal"));
        let err = tracker.into_findings("synth.jsonl").unwrap_err();
        assert_codec(&err);
        assert_eq!(tracker.evidence_rows().len(), 1);
    }

    #[test]
    fn colon_tail_without_a_telegram_body_is_not_a_finding() {
        let mut raw = b":".to_vec();
        raw.extend(std::iter::repeat_n(b'a', 35));
        let mut tracker = SecretScanTracker::new();
        tracker.feed(&raw, Some(1), None, None, None);
        assert!(tracker.evidence_rows().is_empty());
        let findings = tracker.into_findings("synth.jsonl").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn into_findings_propagates_the_codec_error_and_source_errors() {
        let token = openai(b'd', 20);
        let mut tracker = SecretScanTracker::new();
        tracker.feed(&token, Some(3), Some(0), Some(8), Some(1));
        let err = tracker.into_findings("synth.jsonl").unwrap_err();
        assert_codec(&err);
        let secret = String::from_utf8_lossy(&token);
        assert!(!err.to_string().contains(secret.as_ref()));
        let mut again = SecretScanTracker::new();
        again.feed(&token, Some(3), None, None, None);
        let source_err = again.into_findings("  ").unwrap_err();
        assert_ne!(
            source_err.to_string(),
            model::finding::FINGERPRINT_CODEC_UNAVAILABLE
        );
        assert!(!source_err.to_string().contains(secret.as_ref()));
        let mut missing_line = SecretScanTracker::new();
        missing_line.feed(&token, None, None, None, None);
        assert_codec(&missing_line.into_findings("synth.jsonl").unwrap_err());
    }

    #[test]
    fn pure_projection_caps_without_make_finding() {
        let mut hits = std::collections::BTreeMap::new();
        let mut order = Vec::new();
        let late = HitKey {
            record_ordinal: None,
            line_number: Some(2),
            byte_offset: None,
            byte_end: None,
            family: "openai-api-key",
        };
        let early = HitKey {
            record_ordinal: Some(1),
            line_number: Some(1),
            byte_offset: Some(4),
            byte_end: None,
            family: "bearer-token",
        };
        order.push(late);
        order.push(early);
        let mut many = HitAgg::default();
        for index in 0..20 {
            many.digests.insert(format!("{index:02}"));
            many.count += 1;
            many.max_len = 30;
        }
        hits.insert(late, many);
        let mut one = HitAgg::default();
        one.observe(b"bearer-body-bytes");
        hits.insert(early, one);
        let rows = secret_evidence_rows(&order, &hits);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].family, "bearer-token");
        assert_eq!(rows[0].byte_offset, Some(4));
        assert_eq!(rows[0].byte_end, None);
        assert!(!evidence_keys(&rows[0]).iter().any(|key| key == "byte_end"));
        assert_eq!(rows[1].family, "openai-api-key");
        assert_eq!(rows[1].occurrence_count, 20);
        assert_eq!(rows[1].match_len, 30);
        assert_eq!(rows[1].match_sha256.len(), 16);
        assert_eq!(rows[1].match_sha256[0], "00");
        assert!(rows[1].truncated);
        assert_eq!(rows[1].overflow, None);
        assert!(!rows[0].truncated);
    }
}
