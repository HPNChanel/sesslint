//! Collision-proof synthetic event ID generation and collision guard.
//!
//! Port of `src/sesslint/adapters/synthetic.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–192.
//!
//! Reserved namespace format:
//!     sesslint:synthetic:<adapter>:<ordinal>:<8-hex-hash>
//!
//! Where:
//!     <adapter>: Adapter identifier (e.g. 'claude_code', 'openai_agents')
//!     <ordinal>: Sequence ordinal of the event within the session
//!     <8-hex-hash>: First 8 hex characters of SHA-256 over:
//!                   `{source_hint}:{ordinal}:{payload_len}`
//!
//! Gaps vs Python (recorded, not papered over):
//! - `source_hint.encode("utf-8", errors="replace")` can replace a lone
//!   surrogate. A Rust `&str` cannot contain one, so this port hashes the
//!   UTF-8 bytes as they stand.
//! - Python `str.isdigit` and default `re` `\\d` accept Unicode decimal
//!   digits (category Nd). This port accepts ASCII `0-9` only.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use model::errors::AdapterError;
use sha2::{Digest, Sha256};

/// Python: `SYNTHETIC_ID_PREFIX`.
pub const SYNTHETIC_ID_PREFIX: &str = "sesslint:synthetic:";

const SESSION_EVENT_UNAVAILABLE: &str = "sesslint.canonical.SessionEvent is not available";

/// Python `__all__`, in that order.
pub const ALL: [&str; 4] = [
    "SYNTHETIC_ID_PREFIX",
    "SyntheticIdCollisionGuard",
    "is_synthetic_id",
    "synthetic_event_id",
];

/// Late import of unported `sesslint.canonical.SessionEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckEventError {
    Unsupported,
}

impl CheckEventError {
    pub fn message(self) -> &'static str {
        SESSION_EVENT_UNAVAILABLE
    }
}

impl fmt::Display for CheckEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for CheckEventError {}

/// Generate a collision-resistant synthetic event ID in the reserved namespace.
///
/// Python: `synthetic_event_id(adapter, ordinal, *, source_hint="", payload_len=0)`.
/// Negative `ordinal` / `payload_len` are stringified; they are not rejected.
pub fn synthetic_event_id(
    adapter: &str,
    ordinal: i64,
    source_hint: &str,
    payload_len: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_hint.as_bytes());
    hasher.update(b":");
    hasher.update(ordinal.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(payload_len.to_string().as_bytes());
    let digest = hex_lower(hasher.finalize().as_slice());
    let digest8 = &digest[..digest.len().min(8)];
    format!("{SYNTHETIC_ID_PREFIX}{adapter}:{ordinal}:{digest8}")
}

/// Return true if `event_id` is in the sesslint synthetic namespace.
pub fn is_synthetic_id(event_id: &str) -> bool {
    event_id.starts_with(SYNTHETIC_ID_PREFIX)
}

/// Advance a colliding synthetic ID to the next ordinal or numeric suffix.
///
/// Python: `_advance_synthetic_id`.
pub fn advance_synthetic_id(candidate_id: &str) -> String {
    if candidate_id.starts_with(SYNTHETIC_ID_PREFIX) {
        let parts: Vec<&str> = candidate_id.split(':').collect();
        if parts.len() == 5 && is_ascii_digits(parts[3]) {
            let adapter = parts[2];
            let ordinal = ascii_int_plus_one(parts[3]);
            let digest = parts[4];
            return format!("{SYNTHETIC_ID_PREFIX}{adapter}:{ordinal}:{digest}");
        }
    }

    if let Some((stem, counter)) = split_underscore_ascii_digits(candidate_id) {
        let next = ascii_int_plus_one(counter);
        return format!("{stem}_{next}");
    }
    format!("{candidate_id}_1")
}

/// Tracks real versus synthetic IDs per session load (FR-083).
#[derive(Debug, Clone, Default)]
pub struct SyntheticIdCollisionGuard {
    seen_real_ids: BTreeSet<String>,
    seen_synthetic_ids: BTreeSet<String>,
}

impl SyntheticIdCollisionGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Python: `seen_real_ids` frozenset snapshot.
    pub fn seen_real_ids(&self) -> &BTreeSet<String> {
        &self.seen_real_ids
    }

    /// Python: `seen_synthetic_ids` frozenset snapshot.
    pub fn seen_synthetic_ids(&self) -> &BTreeSet<String> {
        &self.seen_synthetic_ids
    }

    /// Register a vendor-provided real ID.
    pub fn register_real(&mut self, real_id: &str) -> Result<String, AdapterError> {
        if self.seen_synthetic_ids.contains(real_id) {
            return Err(AdapterError::new(format!(
                "Synthetic ID collision: real ID {} collides with a previously generated synthetic ID",
                python_str_repr(real_id)
            )));
        }
        self.seen_real_ids.insert(real_id.to_string());
        Ok(real_id.to_string())
    }

    /// Register a generated synthetic ID.
    pub fn register_synthetic(&mut self, synthetic_id: &str) -> Result<String, AdapterError> {
        if self.seen_real_ids.contains(synthetic_id) {
            return Err(AdapterError::new(format!(
                "Synthetic ID collision: synthetic ID {} collides with a previously seen real ID",
                python_str_repr(synthetic_id)
            )));
        }
        self.seen_synthetic_ids.insert(synthetic_id.to_string());
        Ok(synthetic_id.to_string())
    }

    /// Register an event ID as either real or synthetic.
    pub fn register(&mut self, event_id: &str, is_synthetic: bool) -> Result<String, AdapterError> {
        if is_synthetic {
            self.register_synthetic(event_id)
        } else {
            self.register_real(event_id)
        }
    }

    /// Python `check_event`. `SessionEvent` is not ported, so this takes no
    /// event and does not register a guessed id.
    pub fn check_event(&self) -> Result<(), CheckEventError> {
        let _observed = self.seen_real_ids.len() + self.seen_synthetic_ids.len();
        Err(CheckEventError::Unsupported)
    }

    /// Assert that no real ID equals any synthetic ID in this load.
    pub fn assert_no_collision(&self) -> Result<(), AdapterError> {
        let mut collision = self.seen_real_ids.intersection(&self.seen_synthetic_ids);
        if let Some(colliding) = collision.next() {
            return Err(AdapterError::new(format!(
                "Synthetic ID collision: ID {} exists in both real and synthetic namespaces",
                python_str_repr(colliding)
            )));
        }
        Ok(())
    }
}

/// ASCII-only stand-in for Python `str.isdigit` (Unicode Nd is a recorded gap).
fn is_ascii_digits(value: &str) -> bool {
    !value.is_empty() && value.as_bytes().iter().all(u8::is_ascii_digit)
}

/// Hand-written `r"^(.*)_(\d+)$"` with ASCII `\\d` (Python default `\\d` is Nd).
fn split_underscore_ascii_digits(candidate_id: &str) -> Option<(&str, &str)> {
    let (stem, counter) = candidate_id.rsplit_once('_')?;
    if is_ascii_digits(counter) {
        Some((stem, counter))
    } else {
        None
    }
}

/// Python `str(int(digits) + 1)` for a non-empty ASCII digit string.
fn ascii_int_plus_one(digits: &str) -> String {
    let stripped = digits.trim_start_matches('0');
    let body = if stripped.is_empty() { "0" } else { stripped };
    increment_ascii_digits(body)
}

fn increment_ascii_digits(digits: &str) -> String {
    let mut bytes = digits.as_bytes().to_vec();
    let mut index = bytes.len();
    let mut carry = true;
    while carry && index > 0 {
        index -= 1;
        if bytes[index] == b'9' {
            bytes[index] = b'0';
        } else {
            bytes[index] += 1;
            carry = false;
        }
    }
    let mut out = String::new();
    if carry {
        out.push('1');
    }
    for byte in bytes {
        out.push(char::from(byte));
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Python `repr(str)` with single quotes.
fn python_str_repr(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::{
        advance_synthetic_id, is_synthetic_id, python_str_repr, synthetic_event_id,
        CheckEventError, SyntheticIdCollisionGuard, ALL, SESSION_EVENT_UNAVAILABLE,
        SYNTHETIC_ID_PREFIX,
    };

    const SYNTH_A: &str = "sesslint:synthetic:adapter:0:12345678";
    const SYNTH_B: &str = "sesslint:synthetic:adapter:1:87654321";
    const SYNTH_CLAUDE: &str = "sesslint:synthetic:claude_code:0:deadbeef";
    const SYNTH_OPENAI: &str = "sesslint:synthetic:openai_agents:1:cafebabe";
    const SYNTH_COLLIDE_LO: &str = "sesslint:synthetic:a:0:aaaaaaaa";
    const SYNTH_COLLIDE_HI: &str = "sesslint:synthetic:z:0:bbbbbbbb";

    #[test]
    fn synthetic_event_id_matches_pinned_sha256() {
        let id = synthetic_event_id("claude_code", 42, "synthetic-hint", 128);
        assert_eq!(id, "sesslint:synthetic:claude_code:42:0e21956c");
        assert!(is_synthetic_id(&id));
    }

    #[test]
    fn synthetic_event_id_defaults_and_negative_ordinal() {
        assert_eq!(
            synthetic_event_id("test", 0, "", 0),
            "sesslint:synthetic:test:0:1d770858"
        );
        assert_eq!(
            synthetic_event_id("test", -3, "synthetic-hint", 0),
            "sesslint:synthetic:test:-3:f5a7161d"
        );
    }

    #[test]
    fn synthetic_event_id_unicode_hint_and_large_ints() {
        assert_eq!(
            synthetic_event_id("test", 10, "synthetic-hint-日本語", 1024),
            "sesslint:synthetic:test:10:1b303bbb"
        );
        assert_eq!(
            synthetic_event_id("test", 10_000_000, "synthetic-stream", 50_000_000),
            "sesslint:synthetic:test:10000000:04c14450"
        );
    }

    #[test]
    fn synthetic_event_id_is_deterministic_and_sensitive() {
        let base = synthetic_event_id("adapter_a", 0, "synthetic-file", 100);
        assert_eq!(
            base,
            synthetic_event_id("adapter_a", 0, "synthetic-file", 100)
        );
        assert_ne!(
            base,
            synthetic_event_id("adapter_b", 0, "synthetic-file", 100)
        );
        assert_ne!(
            base,
            synthetic_event_id("adapter_a", 1, "synthetic-file", 100)
        );
        assert_ne!(
            base,
            synthetic_event_id("adapter_a", 0, "synthetic-other", 100)
        );
        assert_ne!(
            base,
            synthetic_event_id("adapter_a", 0, "synthetic-file", 101)
        );
    }

    #[test]
    fn is_synthetic_id_prefix_only() {
        assert!(is_synthetic_id(&format!("{SYNTHETIC_ID_PREFIX}any:1:abc")));
        assert!(is_synthetic_id(SYNTHETIC_ID_PREFIX));
        assert!(!is_synthetic_id("sesslint:synthetic"));
        assert!(!is_synthetic_id("sesslint:synthetic-x:0:abcd1234"));
        assert!(!is_synthetic_id(""));
    }

    #[test]
    fn advance_reserved_namespace_increments_ordinal_keeps_digest() {
        let candidate = format!("{SYNTHETIC_ID_PREFIX}adapter_test:3:12345678");
        assert_eq!(
            advance_synthetic_id(&candidate),
            format!("{SYNTHETIC_ID_PREFIX}adapter_test:4:12345678")
        );
        assert_eq!(
            advance_synthetic_id("sesslint:synthetic:adapter:08:deadbeef"),
            "sesslint:synthetic:adapter:9:deadbeef"
        );
    }

    #[test]
    fn advance_negative_reserved_ordinal_is_not_isdigit() {
        let candidate = "sesslint:synthetic:test:-1:deadbeef";
        assert_eq!(
            advance_synthetic_id(candidate),
            "sesslint:synthetic:test:-1:deadbeef_1"
        );
    }

    #[test]
    fn advance_suffix_and_bare() {
        assert_eq!(advance_synthetic_id("rec_item_call_2"), "rec_item_call_3");
        assert_eq!(advance_synthetic_id("rec_item_text"), "rec_item_text_1");
        assert_eq!(advance_synthetic_id("foo_00"), "foo_1");
        assert_eq!(advance_synthetic_id("foo_9"), "foo_10");
        assert_eq!(advance_synthetic_id("_1"), "_2");
    }

    #[test]
    fn advance_vulgar_fraction_is_not_a_digit() {
        let candidate = "item_\u{00bd}";
        assert_eq!(advance_synthetic_id(candidate), "item_\u{00bd}_1");
    }

    #[test]
    fn advance_non_ascii_nd_digit_is_recorded_gap() {
        let reserved = "sesslint:synthetic:adapter:\u{0661}:deadbeef";
        assert_eq!(
            advance_synthetic_id(reserved),
            "sesslint:synthetic:adapter:\u{0661}:deadbeef_1"
        );
        assert_eq!(advance_synthetic_id("item_\u{0661}"), "item_\u{0661}_1");
    }

    #[test]
    fn collision_guard_clean_operation() {
        let mut guard = SyntheticIdCollisionGuard::new();
        assert_eq!(guard.register_real(SYNTH_A).unwrap(), SYNTH_A);
        guard.register_real(SYNTH_B).unwrap();
        guard.register_synthetic(SYNTH_CLAUDE).unwrap();
        guard.register_synthetic(SYNTH_OPENAI).unwrap();
        assert!(guard.seen_real_ids().contains(SYNTH_A));
        assert!(guard.seen_real_ids().contains(SYNTH_B));
        assert!(guard.seen_synthetic_ids().contains(SYNTH_CLAUDE));
        guard.register_real(SYNTH_A).unwrap();
        guard.register_synthetic(SYNTH_CLAUDE).unwrap();
        guard.assert_no_collision().unwrap();
    }

    #[test]
    fn register_synthetic_collides_with_prior_real() {
        let mut guard = SyntheticIdCollisionGuard::new();
        guard.register_real(SYNTH_CLAUDE).unwrap();
        let err = guard.register_synthetic(SYNTH_CLAUDE).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Synthetic ID collision: synthetic ID {} collides with a previously seen real ID",
                python_str_repr(SYNTH_CLAUDE)
            )
        );
    }

    #[test]
    fn register_real_collides_with_prior_synthetic() {
        let mut guard = SyntheticIdCollisionGuard::new();
        guard.register_synthetic(SYNTH_OPENAI).unwrap();
        let err = guard.register_real(SYNTH_OPENAI).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Synthetic ID collision: real ID {} collides with a previously generated synthetic ID",
                python_str_repr(SYNTH_OPENAI)
            )
        );
    }

    #[test]
    fn register_dispatches_on_is_synthetic_flag() {
        let mut guard = SyntheticIdCollisionGuard::new();
        guard.register(SYNTH_A, false).unwrap();
        guard.register(SYNTH_B, true).unwrap();
        assert!(guard.seen_real_ids().contains(SYNTH_A));
        assert!(guard.seen_synthetic_ids().contains(SYNTH_B));
        let err = guard.register(SYNTH_A, true).unwrap_err();
        assert!(err.to_string().contains("synthetic ID"));
    }

    #[test]
    fn assert_no_collision_reports_sorted_first_id() {
        let mut guard = SyntheticIdCollisionGuard::new();
        guard.seen_real_ids.insert(SYNTH_COLLIDE_HI.to_string());
        guard.seen_real_ids.insert(SYNTH_COLLIDE_LO.to_string());
        guard
            .seen_synthetic_ids
            .insert(SYNTH_COLLIDE_HI.to_string());
        guard
            .seen_synthetic_ids
            .insert(SYNTH_COLLIDE_LO.to_string());
        let err = guard.assert_no_collision().unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Synthetic ID collision: ID {} exists in both real and synthetic namespaces",
                python_str_repr(SYNTH_COLLIDE_LO)
            )
        );
    }

    #[test]
    fn check_event_fails_closed_without_session_event() {
        let mut guard = SyntheticIdCollisionGuard::new();
        let err = guard.check_event().unwrap_err();
        assert_eq!(err, CheckEventError::Unsupported);
        assert_eq!(err.to_string(), SESSION_EVENT_UNAVAILABLE);
        assert_eq!(err.message(), SESSION_EVENT_UNAVAILABLE);
        assert!(guard.seen_real_ids().is_empty());
        assert!(guard.seen_synthetic_ids().is_empty());
        guard.register_synthetic(SYNTH_A).unwrap();
        assert_eq!(
            guard.check_event().unwrap_err().to_string(),
            SESSION_EVENT_UNAVAILABLE
        );
        assert_eq!(guard.seen_synthetic_ids().len(), 1);
        assert!(guard.seen_real_ids().is_empty());
    }

    #[test]
    fn all_matches_python_export_order() {
        assert_eq!(
            ALL,
            [
                "SYNTHETIC_ID_PREFIX",
                "SyntheticIdCollisionGuard",
                "is_synthetic_id",
                "synthetic_event_id",
            ]
        );
    }
}
