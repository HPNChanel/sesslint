//! Codex rollout prefix constants.
//!
//! Port of `src/sesslint/adapters/codex_rollout.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–317.
//! Stops before the loader. No session is loaded here.
//!
//! [`_safe_type_value`] is Python `_safe_type_value`. It calls
//! [`crate::safe_value::safe_type_value`] and does not shape values itself.
//! [`PyValue::Bool`] is a bool.
//!
//! [`_TIMESTAMP_ISO_REGEX`] keeps the pin pattern text. This module does not
//! compile that pattern. There is no `regex` crate and no `serde_json`.
//! This slice does not hash.
//!
//! Gaps vs Python (recorded, not papered over):
//! - The pin binds `_TIMESTAMP_ISO_REGEX` with `re.compile`. This port stores
//!   the pattern `&str`.

use crate::safe_value::{safe_type_value, PyValue};

/// Python: `SQLITE_MAGIC`. The pin bytes, including the trailing NUL.
pub const SQLITE_MAGIC: &[u8] = b"SQLite format 3\x00";

/// Python: `SUPPORTED_CODEX_ROLLOUT_VERSIONS`, in pin literal order.
pub const SUPPORTED_CODEX_ROLLOUT_VERSIONS: [&str; 4] = ["1", "1.0", "1.0.0", "codex-rollout-v1"];

/// Python: `ENVELOPE_OPAQUE_TYPES`, in pin literal order.
///
/// Envelope types that carry run or telemetry metadata. `session_meta` is
/// also a durable envelope type.
pub const ENVELOPE_OPAQUE_TYPES: [&str; 7] = [
    "session_meta",
    "event_msg",
    "turn_context",
    "world_state",
    "inter_agent_communication_metadata",
    "token_usage_record",
    "retained_context",
];

/// Python: `DURABLE_ENVELOPE_TYPES`, in pin literal order.
///
/// Envelope families the rollout writer persists as thread history.
pub const DURABLE_ENVELOPE_TYPES: [&str; 3] = ["session_meta", "response_item", "compacted"];

/// Python: `RESPONSE_ITEM_TYPE_MAP`. Each row is `(payload type, actor, kind)`.
///
/// The pin literal stores `message` as `assistant` / `message`. Role
/// disambiguation is outside this slice.
pub const RESPONSE_ITEM_TYPE_MAP: [(&str, &str, &str); 9] = [
    ("message", "assistant", "message"),
    ("agent_message", "assistant", "message"),
    ("reasoning", "assistant", "opaque"),
    ("function_call", "assistant", "tool_call"),
    ("custom_tool_call", "assistant", "tool_call"),
    ("tool_search_call", "assistant", "tool_call"),
    ("function_call_output", "tool", "tool_result"),
    ("custom_tool_call_output", "tool", "tool_result"),
    ("tool_search_output", "tool", "tool_result"),
];

/// Python: `GUARDIAN_SNAPSHOT_ITEM_CAP`.
///
/// Bound on the structural projection of a compacted record's
/// `guardian_history`. The cap is 512 items.
pub const GUARDIAN_SNAPSHOT_ITEM_CAP: usize = 512;

/// Python: `_GUARDIAN_ID_MAX`. Maximum length of a projected guardian id.
pub const _GUARDIAN_ID_MAX: usize = 256;

/// Python: `KNOWN_ENVELOPE_KEYS`, in pin literal order.
pub const KNOWN_ENVELOPE_KEYS: [&str; 11] = [
    "timestamp",
    "ts",
    "created_at",
    "type",
    "ordinal",
    "payload",
    "rollout_version",
    "format_version",
    "schema_version",
    "export_version",
    "version",
];

/// Python: `KNOWN_PAYLOAD_KEYS`, in pin literal order.
pub const KNOWN_PAYLOAD_KEYS: [&str; 93] = [
    "type",
    "id",
    "role",
    "phase",
    "content",
    "author",
    "recipient",
    "name",
    "namespace",
    "arguments",
    "args",
    "input",
    "output",
    "call_id",
    "tool_call_id",
    "status",
    "summary",
    "encrypted_content",
    "internal_chat_message_metadata_passthrough",
    // session_meta
    "session_id",
    "cli_version",
    "model_provider",
    "originator",
    "source",
    "thread_source",
    "history_mode",
    "context_window",
    "base_instructions",
    "cwd",
    "timestamp",
    "git",
    "agent_nickname",
    "agent_path",
    "agent_role",
    "forked_from_id",
    "multi_agent_version",
    "parent_thread_id",
    "subagent_history_start_ordinal",
    // turn_context / world_state
    "turn_id",
    "approval_policy",
    "approvals_reviewer",
    "collaboration_mode",
    "comp_hash",
    "current_date",
    "effort",
    "model",
    "permission_profile",
    "personality",
    "realtime_active",
    "sandbox_policy",
    "timezone",
    "workspace_roots",
    "full",
    "state",
    // event_msg payloads
    "started_at",
    "started_at_ms",
    "completed_at",
    "completed_at_ms",
    "duration_ms",
    "reason",
    "last_agent_message",
    "time_to_first_token_ms",
    "collaboration_mode_kind",
    "model_context_window",
    "thread_id",
    "item",
    "info",
    "rate_limits",
    "thread_settings",
    // compacted
    "message",
    "first_window_id",
    "previous_window_id",
    "window_id",
    "window_number",
    "replacement_history",
    "guardian_history",
    // inter_agent_communication_metadata
    "trigger_turn",
    // version markers honored when present
    "rollout_version",
    "format_version",
    "schema_version",
    "export_version",
    "version",
    "is_error",
    "error",
    "result",
    "metadata",
    // token_usage_record
    "response_id",
    "root_turn_id",
    "thread_token_usage",
    "turn_token_usage",
    "usage",
    // tool_search_call / tool_search_output
    "execution",
    "tools",
];

/// Python: `CRITICAL_KEYS`, in pin literal order.
pub const CRITICAL_KEYS: [&str; 6] = [
    "type",
    "parent_id",
    "prev_id",
    "call_id",
    "tool_call_id",
    "unknown_critical_field",
];

/// Python: `_TIMESTAMP_ISO_REGEX`.
///
/// The pin source
/// `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$`.
/// Stored as text. This module does not compile it.
pub const _TIMESTAMP_ISO_REGEX: &str =
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$";

/// Return a safe type and size descriptor without leaking field content (FR-081, FR-082).
///
/// Python: `_safe_type_value`. Calls [`crate::safe_value::safe_type_value`]
/// and does not shape the value itself.
#[must_use]
pub fn _safe_type_value(val: PyValue<'_>) -> String {
    safe_type_value(val)
}

#[cfg(test)]
mod tests {
    use super::{
        _safe_type_value, CRITICAL_KEYS, DURABLE_ENVELOPE_TYPES, ENVELOPE_OPAQUE_TYPES,
        GUARDIAN_SNAPSHOT_ITEM_CAP, KNOWN_ENVELOPE_KEYS, KNOWN_PAYLOAD_KEYS,
        RESPONSE_ITEM_TYPE_MAP, SQLITE_MAGIC, SUPPORTED_CODEX_ROLLOUT_VERSIONS, _GUARDIAN_ID_MAX,
        _TIMESTAMP_ISO_REGEX,
    };
    use crate::safe_value::{safe_type_value, PyValue};

    #[test]
    fn sqlite_magic_is_the_pin_bytes() {
        assert_eq!(SQLITE_MAGIC, b"SQLite format 3\x00");
        assert_eq!(SQLITE_MAGIC.len(), 16);
        assert_eq!(SQLITE_MAGIC.last().copied(), Some(0));
    }

    #[test]
    fn version_and_envelope_sets_keep_pin_order() {
        assert_eq!(
            SUPPORTED_CODEX_ROLLOUT_VERSIONS,
            ["1", "1.0", "1.0.0", "codex-rollout-v1"]
        );
        assert_eq!(
            ENVELOPE_OPAQUE_TYPES,
            [
                "session_meta",
                "event_msg",
                "turn_context",
                "world_state",
                "inter_agent_communication_metadata",
                "token_usage_record",
                "retained_context",
            ]
        );
        assert_eq!(
            DURABLE_ENVELOPE_TYPES,
            ["session_meta", "response_item", "compacted"]
        );
        assert_eq!(GUARDIAN_SNAPSHOT_ITEM_CAP, 512);
        assert_eq!(_GUARDIAN_ID_MAX, 256);
    }

    #[test]
    fn response_item_type_map_keeps_pin_pairs() {
        assert_eq!(
            RESPONSE_ITEM_TYPE_MAP,
            [
                ("message", "assistant", "message"),
                ("agent_message", "assistant", "message"),
                ("reasoning", "assistant", "opaque"),
                ("function_call", "assistant", "tool_call"),
                ("custom_tool_call", "assistant", "tool_call"),
                ("tool_search_call", "assistant", "tool_call"),
                ("function_call_output", "tool", "tool_result"),
                ("custom_tool_call_output", "tool", "tool_result"),
                ("tool_search_output", "tool", "tool_result"),
            ]
        );
    }

    #[test]
    fn known_envelope_and_critical_keys_keep_pin_order() {
        assert_eq!(
            KNOWN_ENVELOPE_KEYS,
            [
                "timestamp",
                "ts",
                "created_at",
                "type",
                "ordinal",
                "payload",
                "rollout_version",
                "format_version",
                "schema_version",
                "export_version",
                "version",
            ]
        );
        assert_eq!(
            CRITICAL_KEYS,
            [
                "type",
                "parent_id",
                "prev_id",
                "call_id",
                "tool_call_id",
                "unknown_critical_field",
            ]
        );
    }

    const PIN_KNOWN_PAYLOAD_KEYS: [&str; 93] = [
        "type",
        "id",
        "role",
        "phase",
        "content",
        "author",
        "recipient",
        "name",
        "namespace",
        "arguments",
        "args",
        "input",
        "output",
        "call_id",
        "tool_call_id",
        "status",
        "summary",
        "encrypted_content",
        "internal_chat_message_metadata_passthrough",
        "session_id",
        "cli_version",
        "model_provider",
        "originator",
        "source",
        "thread_source",
        "history_mode",
        "context_window",
        "base_instructions",
        "cwd",
        "timestamp",
        "git",
        "agent_nickname",
        "agent_path",
        "agent_role",
        "forked_from_id",
        "multi_agent_version",
        "parent_thread_id",
        "subagent_history_start_ordinal",
        "turn_id",
        "approval_policy",
        "approvals_reviewer",
        "collaboration_mode",
        "comp_hash",
        "current_date",
        "effort",
        "model",
        "permission_profile",
        "personality",
        "realtime_active",
        "sandbox_policy",
        "timezone",
        "workspace_roots",
        "full",
        "state",
        "started_at",
        "started_at_ms",
        "completed_at",
        "completed_at_ms",
        "duration_ms",
        "reason",
        "last_agent_message",
        "time_to_first_token_ms",
        "collaboration_mode_kind",
        "model_context_window",
        "thread_id",
        "item",
        "info",
        "rate_limits",
        "thread_settings",
        "message",
        "first_window_id",
        "previous_window_id",
        "window_id",
        "window_number",
        "replacement_history",
        "guardian_history",
        "trigger_turn",
        "rollout_version",
        "format_version",
        "schema_version",
        "export_version",
        "version",
        "is_error",
        "error",
        "result",
        "metadata",
        "response_id",
        "root_turn_id",
        "thread_token_usage",
        "turn_token_usage",
        "usage",
        "execution",
        "tools",
    ];

    #[test]
    fn known_payload_keys_keep_pin_order() {
        assert_eq!(KNOWN_PAYLOAD_KEYS, PIN_KNOWN_PAYLOAD_KEYS);
    }

    #[test]
    fn timestamp_pattern_stays_source_text() {
        assert_eq!(
            _TIMESTAMP_ISO_REGEX,
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$"
        );
    }

    #[test]
    fn safe_type_value_delegates_and_bool_is_not_an_int() {
        let samples = [
            PyValue::Str("synthetic-field"),
            PyValue::Bytes(4),
            PyValue::List(2),
            PyValue::Dict(1),
            PyValue::Set(0),
            PyValue::Tuple(3),
            PyValue::None,
            PyValue::Int,
            PyValue::Float,
            PyValue::Bool,
            PyValue::Other("SyntheticType"),
        ];
        for sample in samples {
            assert_eq!(_safe_type_value(sample), safe_type_value(sample));
        }
        assert_eq!(_safe_type_value(PyValue::Bool), "<bool>");
        assert_eq!(_safe_type_value(PyValue::Int), "<int>");
        assert_ne!(
            _safe_type_value(PyValue::Bool),
            _safe_type_value(PyValue::Int)
        );
        let shaped = _safe_type_value(PyValue::Str("synthetic-field"));
        assert_eq!(shaped, "<str:len=15>");
        assert!(!shaped.contains("synthetic"));
    }
}
