//! Structured progress events and cooperative cancellation for long-running
//! operations (DW-T-13).
//!
//! Long-running API calls (directory scans, single-file checks, repair) accept an
//! optional `progress_cb` callback receiving frozen [`ProgressEvent`] records and
//! an optional [`CancellationToken`] checked at existing loop boundaries.
//!
//! Contract (FR-081 applies to progress too):
//!
//! - Events carry counters and coordinates only — a phase name, completed/total
//!   counts, and an optional basename or step identifier. Record content is never
//!   emitted.
//! - Progress emission never affects output bytes or finding order; events are
//!   emitted in a deterministic sequence for a deterministic input.
//! - Cancellation is cooperative: [`CancellationToken::throw_if_cancelled`]
//!   returns [`OperationCancelled`], which propagates through the same cleanup
//!   paths as `KeyboardInterrupt` (no partial outputs, source immutable). CLI
//!   exit semantics are unchanged — a cancelled CLI operation still exits 130
//!   via the existing interrupt handling.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// JSON-safe value in a [`ProgressEvent::to_dict`] map (`str` or `int` only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProgressValue {
    Integer(i64),
    String(String),
}

/// A single structured progress emission.
///
/// Attributes:
/// - `phase`: Stable phase identifier, e.g. `"scan"`, `"check:load"`,
///   `"repair:execute"`.
/// - `completed`: Units of work finished within `phase` (1-based count of
///   completed items; phase-start emissions use the count completed so far).
/// - `total`: Total units for `phase` when known upfront, else `None`.
/// - `item`: Optional current-item coordinate — a basename or step identifier
///   only, never a full path or record content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressEvent {
    phase: String,
    completed: i64,
    total: Option<i64>,
    item: Option<String>,
}

impl ProgressEvent {
    /// Construct a frozen progress event.
    pub fn new(
        phase: impl Into<String>,
        completed: i64,
        total: Option<i64>,
        item: Option<String>,
    ) -> Self {
        Self {
            phase: phase.into(),
            completed,
            total,
            item,
        }
    }

    pub fn phase(&self) -> &str {
        &self.phase
    }

    pub fn completed(&self) -> i64 {
        self.completed
    }

    pub fn total(&self) -> Option<i64> {
        self.total
    }

    pub fn item(&self) -> Option<&str> {
        self.item.as_deref()
    }

    /// Return a deterministic dict form (sorted keys, JSON-safe values).
    ///
    /// Optional `total` / `item` are omitted when `None`, matching Python
    /// `is not None` (so `total=0` and `item=""` are present).
    pub fn to_dict(&self) -> BTreeMap<&'static str, ProgressValue> {
        let mut map = BTreeMap::new();
        map.insert("completed", ProgressValue::Integer(self.completed));
        if let Some(item) = &self.item {
            map.insert("item", ProgressValue::String(item.clone()));
        }
        map.insert("phase", ProgressValue::String(self.phase.clone()));
        if let Some(total) = self.total {
            map.insert("total", ProgressValue::Integer(total));
        }
        map
    }

    /// `json.dumps(self.to_dict(), sort_keys=True)` — default Python separators
    /// and `ensure_ascii=True` escapes. Keys are sorted via [`BTreeMap`].
    pub fn to_json(&self) -> String {
        let dict = self.to_dict();
        let mut out = String::from("{");
        let mut first = true;
        for (key, value) in &dict {
            if !first {
                out.push_str(", ");
            }
            first = false;
            out.push('"');
            out.push_str(key);
            out.push_str("\": ");
            match value {
                ProgressValue::Integer(number) => out.push_str(&number.to_string()),
                ProgressValue::String(text) => push_json_string(&mut out, text),
            }
        }
        out.push('}');
        out
    }
}

/// Raised at cooperative cancellation boundaries when the token is set.
///
/// Propagates like `KeyboardInterrupt` with respect to cleanup guarantees:
/// callers must not leave partial outputs behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationCancelled;

impl OperationCancelled {
    pub const MESSAGE: &'static str = "operation cancelled";
}

impl fmt::Display for OperationCancelled {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::MESSAGE)
    }
}

impl Error for OperationCancelled {}

/// Cooperative cancellation token checked at loop boundaries.
///
/// Thread-safe: [`CancellationToken::cancel`] may be called from any thread
/// (e.g. a UI callback) while the operation runs on another.
#[derive(Clone, Debug)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cancellation; the next boundary check raises.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// True after [`CancellationToken::cancel`] has been called.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Return [`OperationCancelled`] if cancellation was requested.
    pub fn throw_if_cancelled(&self) -> Result<(), OperationCancelled> {
        if self.flag.load(Ordering::SeqCst) {
            Err(OperationCancelled)
        } else {
            Ok(())
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Callback receiving a frozen [`ProgressEvent`].
pub type ProgressCallback = dyn Fn(&ProgressEvent);

/// Invoke `cb` with `event` when a callback is attached.
///
/// Centralized so call sites stay uniform; a `None` callback is the
/// zero-cost default path.
pub fn emit<F>(cb: Option<&F>, event: &ProgressEvent)
where
    F: Fn(&ProgressEvent) + ?Sized,
{
    if let Some(callback) = cb {
        callback(event);
    }
}

/// Return [`OperationCancelled`] when `token` is set and cancelled.
pub fn check_token(token: Option<&CancellationToken>) -> Result<(), OperationCancelled> {
    if let Some(token) = token {
        token.throw_if_cancelled()
    } else {
        Ok(())
    }
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => {
                let code = c as u32;
                if code < 0x20 {
                    push_unicode_escape(out, code);
                } else if code >= 0x80 {
                    if code <= 0xFFFF {
                        push_unicode_escape(out, code);
                    } else {
                        let payload = code - 0x1_0000;
                        let high = 0xD800 + (payload >> 10);
                        let low = 0xDC00 + (payload & 0x3FF);
                        push_unicode_escape(out, high);
                        push_unicode_escape(out, low);
                    }
                } else {
                    out.push(c);
                }
            }
        }
    }
    out.push('"');
}

fn push_unicode_escape(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(char::from(HEX[((code >> 12) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 8) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 4) & 0xF) as usize]));
    out.push(char::from(HEX[(code & 0xF) as usize]));
}

#[cfg(test)]
mod tests {
    use super::{
        check_token, emit, CancellationToken, OperationCancelled, ProgressCallback, ProgressEvent,
        ProgressValue,
    };
    use std::cell::RefCell;
    use std::sync::Mutex;

    const SYNTHETIC_PHASE: &str = "scan";
    const SYNTHETIC_ITEM: &str = "a.jsonl";

    fn full_event() -> ProgressEvent {
        ProgressEvent::new(
            SYNTHETIC_PHASE,
            3,
            Some(7),
            Some(SYNTHETIC_ITEM.to_string()),
        )
    }

    #[test]
    fn to_dict_happy_path_shape_matches_python() {
        let event = full_event();
        let dict = event.to_dict();
        let keys: Vec<&str> = dict.keys().copied().collect();
        assert_eq!(keys, vec!["completed", "item", "phase", "total"]);
        assert_eq!(dict.get("completed"), Some(&ProgressValue::Integer(3)));
        assert_eq!(
            dict.get("item"),
            Some(&ProgressValue::String(SYNTHETIC_ITEM.to_string()))
        );
        assert_eq!(
            dict.get("phase"),
            Some(&ProgressValue::String(SYNTHETIC_PHASE.to_string()))
        );
        assert_eq!(dict.get("total"), Some(&ProgressValue::Integer(7)));
    }

    #[test]
    fn to_dict_omits_none_total_and_item() {
        let event = ProgressEvent::new(SYNTHETIC_PHASE, 1, None, None);
        let dict = event.to_dict();
        let keys: Vec<&str> = dict.keys().copied().collect();
        assert_eq!(keys, vec!["completed", "phase"]);
        assert!(!dict.contains_key("item"));
        assert!(!dict.contains_key("total"));
    }

    #[test]
    fn to_dict_keeps_zero_total_and_empty_item() {
        let event = ProgressEvent::new(SYNTHETIC_PHASE, -1, Some(0), Some(String::new()));
        let dict = event.to_dict();
        let keys: Vec<&str> = dict.keys().copied().collect();
        assert_eq!(keys, vec!["completed", "item", "phase", "total"]);
        assert_eq!(dict.get("completed"), Some(&ProgressValue::Integer(-1)));
        assert_eq!(
            dict.get("item"),
            Some(&ProgressValue::String(String::new()))
        );
        assert_eq!(dict.get("total"), Some(&ProgressValue::Integer(0)));
    }

    #[test]
    fn to_json_keys_are_sorted_python_dumps() {
        let event = full_event();
        assert_eq!(
            event.to_json(),
            r#"{"completed": 3, "item": "a.jsonl", "phase": "scan", "total": 7}"#
        );
        let sparse = ProgressEvent::new(SYNTHETIC_PHASE, 1, None, None);
        assert_eq!(sparse.to_json(), r#"{"completed": 1, "phase": "scan"}"#);
        let zero = ProgressEvent::new(SYNTHETIC_PHASE, -1, Some(0), Some(String::new()));
        assert_eq!(
            zero.to_json(),
            r#"{"completed": -1, "item": "", "phase": "scan", "total": 0}"#
        );
    }

    #[test]
    fn to_json_escapes_like_python_ensure_ascii() {
        let quote = ProgressEvent::new(SYNTHETIC_PHASE, 1, None, Some("a\"b\\c".to_string()));
        assert_eq!(
            quote.to_json(),
            r#"{"completed": 1, "item": "a\"b\\c", "phase": "scan"}"#
        );
        let controls = ProgressEvent::new(
            SYNTHETIC_PHASE,
            1,
            None,
            Some("\u{00}\u{08}\n\t".to_string()),
        );
        assert_eq!(
            controls.to_json(),
            r#"{"completed": 1, "item": "\u0000\b\n\t", "phase": "scan"}"#
        );
        let latin = ProgressEvent::new(SYNTHETIC_PHASE, 1, None, Some("café".to_string()));
        assert_eq!(
            latin.to_json(),
            r#"{"completed": 1, "item": "caf\u00e9", "phase": "scan"}"#
        );
        let emoji = ProgressEvent::new(SYNTHETIC_PHASE, 1, None, Some("😀".to_string()));
        assert_eq!(
            emoji.to_json(),
            r#"{"completed": 1, "item": "\ud83d\ude00", "phase": "scan"}"#
        );
    }

    #[test]
    fn events_carry_counters_and_coordinates_only() {
        let event = full_event();
        for (key, value) in event.to_dict() {
            assert!(
                matches!(key, "phase" | "completed" | "total" | "item"),
                "unexpected progress key {key}"
            );
            match value {
                ProgressValue::Integer(_) | ProgressValue::String(_) => {}
            }
        }
        let json = event.to_json();
        assert!(!json.contains("payload"));
        assert!(!json.contains("transcript"));
        assert!(!json.contains('/'));
        assert!(!json.contains('\\') || json.contains("jsonl"));
    }

    #[test]
    fn emit_none_is_a_noop() {
        let event = full_event();
        let before = event.clone();
        emit::<ProgressCallback>(None, &event);
        assert_eq!(event, before);
    }

    #[test]
    fn emit_invokes_callback_in_call_order() {
        let events = [
            ProgressEvent::new("check:detect", 1, Some(4), Some("canonical.json".into())),
            ProgressEvent::new("check:load", 2, Some(4), Some("canonical.json".into())),
            ProgressEvent::new("check:analyze", 3, Some(4), Some("canonical.json".into())),
            ProgressEvent::new("check:report", 4, Some(4), Some("canonical.json".into())),
        ];
        let seen: RefCell<Vec<ProgressEvent>> = RefCell::new(Vec::new());
        let callback = |event: &ProgressEvent| seen.borrow_mut().push(event.clone());
        for event in &events {
            emit(Some(&callback), event);
        }
        assert_eq!(seen.into_inner(), events);
        assert_eq!(
            events.iter().map(ProgressEvent::phase).collect::<Vec<_>>(),
            vec![
                "check:detect",
                "check:load",
                "check:analyze",
                "check:report"
            ]
        );
        assert_eq!(
            events
                .iter()
                .map(ProgressEvent::completed)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
    }

    #[test]
    fn check_token_none_and_live_token_succeed() {
        assert!(check_token(None).is_ok());
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        assert!(token.throw_if_cancelled().is_ok());
        assert!(check_token(Some(&token)).is_ok());
    }

    #[test]
    fn throw_if_cancelled_returns_operation_cancelled() {
        let token = CancellationToken::new();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
        let error = token.throw_if_cancelled().expect_err("cancelled token");
        assert_eq!(error.to_string(), OperationCancelled::MESSAGE);
        assert_eq!(error.to_string(), "operation cancelled");
        let check = check_token(Some(&token)).expect_err("check_token cancelled");
        assert_eq!(check, OperationCancelled);
    }

    #[test]
    fn cancellation_does_not_mutate_events() {
        let event = full_event();
        let snapshot = event.clone();
        let token = CancellationToken::new();
        token.cancel();
        let _ = check_token(Some(&token));
        emit::<ProgressCallback>(None, &event);
        assert_eq!(event, snapshot);
        assert_eq!(event.to_json(), snapshot.to_json());
    }

    #[test]
    fn cloned_token_shares_cancel_state() {
        let token = CancellationToken::new();
        let clone = token.clone();
        clone.cancel();
        assert!(token.is_cancelled());
        assert!(clone.throw_if_cancelled().is_err());
    }

    #[test]
    fn cancel_from_another_thread_is_visible() {
        let token = CancellationToken::new();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                token.cancel();
            });
        });
        assert!(token.is_cancelled());
        assert_eq!(
            token.throw_if_cancelled().unwrap_err().to_string(),
            "operation cancelled"
        );
    }

    #[test]
    fn emit_from_threads_preserves_push_order_when_serialized() {
        let events = [
            ProgressEvent::new("scan", 1, None, Some("one.jsonl".into())),
            ProgressEvent::new("scan", 2, None, Some("two.jsonl".into())),
        ];
        let seen = Mutex::new(Vec::new());
        let callback = |event: &ProgressEvent| seen.lock().expect("test mutex").push(event.clone());
        for event in &events {
            emit(Some(&callback), event);
        }
        assert_eq!(*seen.lock().expect("test mutex"), events);
    }
}
