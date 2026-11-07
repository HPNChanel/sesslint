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

// Codex rollout detection and the pure record checks.
// Port of `src/sesslint/adapters/codex_rollout.py`
// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 320–542.
// Stops before `_process_rollout_record`. No session is loaded here.
//
// Gaps vs Python (recorded, not papered over):
// - `detect_codex_rollout` searches substrings. It does not parse JSON, compile
//   `_TIMESTAMP_ISO_REGEX`, or use `serde_json`.
// - `_normalize_timestamp` hand-walks that pattern with ASCII `0-9` only. A
//   Unicode decimal digit (category Nd, such as U+0661) is not a match.
//   `str.strip` uses the explicit space list below, not a Unicode database.
// - `bool` is not an `int`. `_check_version` does not take the `str` / `int` /
//   `float` arm for `True` or `False`. Dict copies do not collapse `True`
//   with `1` or `1.0`.
// - `_check_version` and `_emit_sl302` call `make_finding` with the fingerprint
//   omitted. That returns `sesslint.determinism.canonical_json_bytes is not
//   available`. The error is propagated. The finding is not appended. This
//   file does not hash a fingerprint preimage.
// - A string tool input stops at `sesslint.io._STRICT_JSON_DECODER.decode`.
//   It does not fall through to `{"value": <original str>}`.
// - `byte_end - byte_offset` is passed to `synthetic_event_id` only when the
//   difference fits in `i64`. `MetaValue::Int` is `i64`. Coordinate `bool`
//   values are not representable on those `Option<i64>` parameters.
// - ASCII filenames match `str.lower`. A few non-ASCII case folds differ.

use std::error::Error;
use std::fmt;

use model::codes::{Repairability, Severity, SL301, SL302};
use model::errors::{AdapterError, FindingError};
use model::finding::{
    make_finding, Finding, MakeFindingInput, PyValue as FindingValue, SourceLine, SourceRef,
    FINGERPRINT_CODEC_UNAVAILABLE,
};

use crate::openai_agents::{
    normalize_version, MapKey, MapValue, MetaValue, SourceMetadata, STRICT_JSON_DECODE_UNAVAILABLE,
};
use crate::safe_value::safe_discriminator;
use crate::synthetic::{synthetic_event_id, SyntheticIdCollisionGuard};

const DETECT_PREFIX_BYTES: usize = 4096;

const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

const EPOCH_TIMESTAMP: &str = "1970-01-01T00:00:00Z";

const UNSUPPORTED_VERSION_TEMPLATE: &str =
    "Unsupported format version on line {line} for record {record_id}";

const UNKNOWN_CRITICAL_TEMPLATE: &str =
    "Unknown critical record on line {line} for record {record_id}";

const INVALID_VERSION_TYPE: &str = "<invalid_version_type>";

const SPAN_OUTSIDE_I64: &str = "byte_end - byte_offset is outside i64";

const ENVELOPE_VERSION_KEYS: [&str; 5] = [
    "rollout_version",
    "format_version",
    "schema_version",
    "export_version",
    "version",
];

const PAYLOAD_VERSION_KEYS: [&str; 4] = [
    "rollout_version",
    "format_version",
    "schema_version",
    "export_version",
];

/// Failure from [`_check_version`].
///
/// Display is the inner message. [`CheckVersionError::Finding`] is the
/// omitted-fingerprint seam, or an earlier [`SourceRef`] rejection.
/// [`CheckVersionError::Collision`] is `register_synthetic`.
/// [`CheckVersionError::Span`] is a payload length that does not fit in `i64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckVersionError {
    /// `byte_end - byte_offset` does not fit in `i64`.
    Span,
    /// The minted id collided with a real id.
    Collision(AdapterError),
    /// [`SourceRef`] or [`make_finding`] failed.
    Finding(FindingError),
}

impl CheckVersionError {
    /// The Python exception text, or the missing-codec seam.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Span => SPAN_OUTSIDE_I64,
            Self::Collision(error) => error.message(),
            Self::Finding(error) => error.message(),
        }
    }
}

impl fmt::Display for CheckVersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for CheckVersionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Collision(error) => Some(error),
            Self::Finding(error) => Some(error),
            Self::Span => None,
        }
    }
}

/// Failure from [`_tool_input_payload`].
///
/// Display is the message only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolInputError {
    /// `list(mapping.items())` raises.
    Items,
    /// The strict JSON decoder is not in this crate.
    Unavailable,
}

impl ToolInputError {
    /// Stable text for this arm.
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::Items => "list(mapping.items()) raises",
            Self::Unavailable => STRICT_JSON_DECODE_UNAVAILABLE,
        }
    }
}

impl fmt::Display for ToolInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ToolInputError {}

/// Text passed to the SL301 evidence builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionText<'a> {
    /// Stripped `str` of a `str`, `int`, or `float`. `bool` is not one of these.
    Scalar(&'a str),
    /// The pin literal `<invalid_version_type>`. `safe_discriminator` is not called.
    InvalidType,
}

/// Heuristic confidence that `first_bytes` is a Codex rollout JSONL file.
///
/// Python: `detect_codex_rollout`. Returns `0.0`, `0.3`, `0.8`, or `1.0`.
/// Only `.jsonl` and `.json` are considered, after `str.lower`. Empty bytes
/// are `0.0`. A [`SQLITE_MAGIC`] prefix is `0.0`. One leading UTF-8 BOM is
/// removed, then the first 4096 bytes are decoded with U+FFFD replacement.
///
/// Signals, searched as substrings: `"session_meta"` +4, `"response_item"` +4,
/// `"ordinal"` together with `"payload"` +2, `"turn_context"` or
/// `"world_state"` +2, `"event_msg"` +1, `"custom_tool_call"` or
/// `"function_call_output"` +2, `"compacted"` +1, and a filename that starts
/// with `rollout-` +2. At least 6 is `1.0`, at least 3 is `0.8`, at least 1
/// is `0.3`, otherwise `0.0`.
#[must_use]
pub fn detect_codex_rollout(first_bytes: &[u8], filename: &str) -> f64 {
    let fn_lower = filename.to_lowercase();
    if !fn_lower.ends_with(".jsonl") && !fn_lower.ends_with(".json") {
        return 0.0;
    }
    if first_bytes.is_empty() {
        return 0.0;
    }
    if first_bytes.starts_with(SQLITE_MAGIC) {
        return 0.0;
    }
    let data = match first_bytes.strip_prefix(UTF8_BOM) {
        Some(rest) => rest,
        None => first_bytes,
    };
    let prefix = match data.get(..DETECT_PREFIX_BYTES) {
        Some(head) => head,
        None => data,
    };
    let decoded = String::from_utf8_lossy(prefix);
    score_codex_signals(codex_signal_count(&decoded, &fn_lower))
}

/// Ensure a timestamp matches [`_TIMESTAMP_ISO_REGEX`], or return the epoch.
///
/// Python: `_normalize_timestamp`. A non-string, or a string that is empty
/// after stripping, is `1970-01-01T00:00:00Z`. A matching string is returned
/// without the surrounding whitespace. The walk accepts ASCII digits only.
/// Naive timestamps match and stay. The calendar is not checked.
#[must_use]
pub fn _normalize_timestamp(raw_ts: PyValue<'_>) -> String {
    let PyValue::Str(text) = raw_ts else {
        return EPOCH_TIMESTAMP.to_owned();
    };
    let val = python_strip(text);
    if val.is_empty() || walk_timestamp(val.as_bytes()).is_none() {
        return EPOCH_TIMESTAMP.to_owned();
    }
    val.to_owned()
}

/// Evaluate one rollout format version and stop an unsupported value at the codec.
///
/// Python: `_check_version`. [`MetaValue::Null`] returns `seen_version_sl301`
/// and does not mint an id or write `version_raw`. Otherwise a missing
/// `rec_id` calls [`synthetic_event_id`] with adapter `codex_rollout` and,
/// when `guard` is present, `register_synthetic`. That error is returned
/// before coordinates, `version_raw`, or [`make_finding`].
///
/// A `str`, `int`, or `float` is rendered with `str`, stripped, stored with
/// [`SourceMetadata::set_attribute`], then passed to [`normalize_version`].
/// `bool` is not an `int` and does not take this arm. A supported normalized
/// text does not call [`make_finding`]. An unsupported text with the seen
/// flag false calls [`make_finding`] with [`FindingValue::None`] as the
/// fingerprint. The [`FindingError`] is returned. The finding is not appended
/// and this function does not return true on that arm. When the flag is
/// already true, the raw text is still stored and the result is true.
///
/// Any other type does not store `version_raw`. The same omitted fingerprint
/// is used, with evidence `version_raw` equal to `<invalid_version_type>`.
/// [`safe_discriminator`] is not called for that arm. When the seen flag is
/// already true, the result is true and [`make_finding`] is not called.
/// `findings` is not extended.
///
/// # Errors
///
/// [`CheckVersionError::Span`] when `byte_end - byte_offset` does not fit in
/// `i64`. [`CheckVersionError::Collision`] from `register_synthetic`.
/// [`CheckVersionError::Finding`] from [`SourceRef`] or [`make_finding`].
/// After the other checks, that display is
/// `sesslint.determinism.canonical_json_bytes is not available`.
#[allow(clippy::too_many_arguments)]
#[must_use = "the seen flag or the fingerprint seam is the result"]
pub fn _check_version(
    version_candidate: &MetaValue,
    path_str: &str,
    line_number: i64,
    rec_id: Option<&str>,
    findings: &[Finding],
    source_metadata: &mut SourceMetadata,
    seen_version_sl301: bool,
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
    record_ordinal: Option<i64>,
    guard: Option<&mut SyntheticIdCollisionGuard>,
) -> Result<bool, CheckVersionError> {
    let _unchanged = findings.len();
    if matches!(version_candidate, MetaValue::Null) {
        return Ok(seen_version_sl301);
    }
    let rec_id_str = match rec_id {
        Some(record_id) => record_id.to_owned(),
        None => {
            let minted = minted_record_id(path_str, byte_offset, byte_end, record_ordinal)?;
            if let Some(guard) = guard {
                guard
                    .register_synthetic(&minted)
                    .map_err(CheckVersionError::Collision)?;
            }
            minted
        }
    };
    let coordinates = coordinate_entries(byte_offset, byte_end, record_ordinal);
    if let Some(rendered) = version_scalar_text(version_candidate) {
        let version_raw = python_strip(&rendered).to_owned();
        source_metadata.set_attribute("version_raw", MetaValue::Str(version_raw.clone()));
        let version_norm = normalize_version(&version_raw);
        if !supported_version(&version_norm) && !seen_version_sl301 {
            let evidence = version_evidence(VersionText::Scalar(&version_raw), &coordinates);
            return Err(refuse_version(path_str, line_number, &rec_id_str, evidence));
        }
    } else if !seen_version_sl301 {
        let evidence = version_evidence(VersionText::InvalidType, &coordinates);
        return Err(refuse_version(path_str, line_number, &rec_id_str, evidence));
    }
    Ok(seen_version_sl301)
}

/// Emit one bounded SL302 unknown-critical-record finding, then stop at the codec.
///
/// Python: `_emit_sl302`. [`safe_discriminator`] shapes `type_value`. Evidence
/// order is `field_path`, `type_value`, `record_id`, then `coord_ev`, then
/// `type_truncated` when the discriminator truncated. An existing key keeps
/// its position and takes the later value. `type_truncated` is `True`, which
/// is a `bool`.
///
/// [`make_finding`] is called with [`SL302`], severity error, repairability
/// manual, and the fingerprint omitted. The [`FindingError`] is returned.
/// `findings` is not extended.
///
/// # Errors
///
/// [`FindingError`] from [`SourceRef`] or [`make_finding`]. After a valid
/// source, the display is
/// `sesslint.determinism.canonical_json_bytes is not available`.
#[must_use = "the fingerprint seam is the result"]
pub fn _emit_sl302(
    path_str: &str,
    line_number: i64,
    rec_id: &str,
    field_path: &str,
    type_value: &MetaValue,
    coord_ev: &[(&str, FindingValue)],
    findings: &[Finding],
) -> Result<(), FindingError> {
    let _unchanged = findings.len();
    let evidence = sl302_evidence(field_path, type_value, rec_id, coord_ev);
    let source = SourceRef::try_new(path_str, Some(SourceLine::Int(line_number)), Some(rec_id))?;
    Err(omitted_fingerprint(
        SL302,
        Severity::Error,
        Repairability::Manual,
        UNKNOWN_CRITICAL_TEMPLATE,
        source,
        evidence,
    ))
}

/// Normalize a tool input into a canonical payload.
///
/// Python: `_tool_input_payload`. `None` is `{}`. A mapping is `dict(raw)`.
/// `bool` is not collapsed with `int` or `float` when equal keys are folded.
/// Every other non-string is `{"value": raw_input}`.
///
/// A `str` does not fall through. The strict decoder is required, so this
/// returns [`ToolInputError::Unavailable`] and does not wrap the original text.
///
/// # Errors
///
/// [`ToolInputError::Items`] when `items()` raises.
/// [`ToolInputError::Unavailable`] when `raw_input` is a `str`.
#[must_use = "the copied payload or the decoder seam is the result"]
pub fn _tool_input_payload(raw_input: &MetaValue) -> Result<MetaValue, ToolInputError> {
    if matches!(raw_input, MetaValue::Null) {
        return Ok(MetaValue::Map(MapValue::new(Vec::new())));
    }
    if matches!(raw_input, MetaValue::Str(_)) {
        return Err(ToolInputError::Unavailable);
    }
    if let MetaValue::Map(map) = raw_input {
        return Ok(MetaValue::Map(copied_mapping(map)?));
    }
    Ok(wrapped_value(raw_input))
}

/// Return the key path that supplied the version candidate.
///
/// Python: `_version_field_name`. Envelope keys are walked first, including
/// `version`, then payload keys. The payload walk does not include `version`.
/// The last duplicate `str` key wins, matching `dict.get`. A truthy value
/// selects that key. `False`, `0`, `0.0`, `""`, and empty containers are not
/// selected.
/// `True` is truthy and is not an `int`. A non-mapping payload is skipped.
/// The fallback is `version`.
///
/// This function does not call [`make_finding`].
#[must_use]
pub fn _version_field_name(envelope: &MapValue, payload: &MetaValue) -> String {
    for key in ENVELOPE_VERSION_KEYS {
        if last_string_value(envelope, key).is_some_and(is_truthy) {
            return key.to_owned();
        }
    }
    if let MetaValue::Map(map) = payload {
        for key in PAYLOAD_VERSION_KEYS {
            if last_string_value(map, key).is_some_and(is_truthy) {
                return format!("payload.{key}");
            }
        }
    }
    "version".to_owned()
}

fn score_codex_signals(signals: u32) -> f64 {
    if signals >= 6 {
        1.0
    } else if signals >= 3 {
        0.8
    } else if signals >= 1 {
        0.3
    } else {
        0.0
    }
}

fn codex_signal_count(decoded: &str, fn_lower: &str) -> u32 {
    let mut signals = 0u32;
    if decoded.contains("\"session_meta\"") {
        signals += 4;
    }
    if decoded.contains("\"response_item\"") {
        signals += 4;
    }
    if decoded.contains("\"ordinal\"") && decoded.contains("\"payload\"") {
        signals += 2;
    }
    if decoded.contains("\"turn_context\"") || decoded.contains("\"world_state\"") {
        signals += 2;
    }
    if decoded.contains("\"event_msg\"") {
        signals += 1;
    }
    if decoded.contains("\"custom_tool_call\"") || decoded.contains("\"function_call_output\"") {
        signals += 2;
    }
    if decoded.contains("\"compacted\"") {
        signals += 1;
    }
    if fn_lower.starts_with("rollout-") {
        signals += 2;
    }
    signals
}

/// `_TIMESTAMP_ISO_REGEX` with ASCII digits.
///
/// `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$`
fn walk_timestamp(bytes: &[u8]) -> Option<()> {
    let mut index = 0usize;
    eat_digits(bytes, &mut index, 4)?;
    eat_byte(bytes, &mut index, b'-')?;
    eat_digits(bytes, &mut index, 2)?;
    eat_byte(bytes, &mut index, b'-')?;
    eat_digits(bytes, &mut index, 2)?;
    eat_byte(bytes, &mut index, b'T')?;
    eat_digits(bytes, &mut index, 2)?;
    eat_byte(bytes, &mut index, b':')?;
    eat_digits(bytes, &mut index, 2)?;
    eat_byte(bytes, &mut index, b':')?;
    eat_digits(bytes, &mut index, 2)?;
    if bytes.get(index).copied() == Some(b'.') {
        bump(&mut index)?;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            bump(&mut index)?;
        }
        if index == start {
            return None;
        }
    }
    match bytes.get(index).copied() {
        None => Some(()),
        Some(b'Z') => {
            bump(&mut index)?;
            end_of(bytes, index)
        }
        Some(b'+' | b'-') => {
            bump(&mut index)?;
            eat_digits(bytes, &mut index, 2)?;
            eat_byte(bytes, &mut index, b':')?;
            eat_digits(bytes, &mut index, 2)?;
            end_of(bytes, index)
        }
        Some(_) => None,
    }
}

fn end_of(bytes: &[u8], index: usize) -> Option<()> {
    if index == bytes.len() {
        Some(())
    } else {
        None
    }
}

fn eat_digits(bytes: &[u8], index: &mut usize, count: usize) -> Option<()> {
    for _ in 0..count {
        let byte = bytes.get(*index).copied()?;
        if !byte.is_ascii_digit() {
            return None;
        }
        bump(index)?;
    }
    Some(())
}

fn eat_byte(bytes: &[u8], index: &mut usize, expected: u8) -> Option<()> {
    if bytes.get(*index).copied() != Some(expected) {
        return None;
    }
    bump(index)
}

fn bump(index: &mut usize) -> Option<()> {
    *index = index.checked_add(1)?;
    Some(())
}

fn python_strip(text: &str) -> &str {
    let mut start = 0usize;
    for ch in text.chars() {
        if !is_python_space(ch) {
            break;
        }
        start = match start.checked_add(ch.len_utf8()) {
            Some(next) => next,
            None => return "",
        };
    }
    let Some(tail) = text.get(start..) else {
        return "";
    };
    let mut end = tail.len();
    for ch in tail.chars().rev() {
        if !is_python_space(ch) {
            break;
        }
        end = match end.checked_sub(ch.len_utf8()) {
            Some(next) => next,
            None => return "",
        };
    }
    tail.get(..end).unwrap_or_default()
}

/// Python `str.strip` whitespace, written out. This is not a Unicode database.
fn is_python_space(ch: char) -> bool {
    matches!(
        u32::from(ch),
        0x0009
            | 0x000A
            | 0x000B
            | 0x000C
            | 0x000D
            | 0x001C
            | 0x001D
            | 0x001E
            | 0x001F
            | 0x0020
            | 0x0085
            | 0x00A0
            | 0x1680
            | 0x2000..=0x200A
            | 0x2028
            | 0x2029
            | 0x202F
            | 0x205F
            | 0x3000
    )
}

fn minted_record_id(
    path_str: &str,
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
    record_ordinal: Option<i64>,
) -> Result<String, CheckVersionError> {
    let ordinal = record_ordinal.unwrap_or(0);
    let payload_len = match (byte_offset, byte_end) {
        (Some(start), Some(end)) => i64_span(start, end)?,
        _ => 0,
    };
    Ok(synthetic_event_id(
        "codex_rollout",
        ordinal,
        path_str,
        payload_len,
    ))
}

fn i64_span(start: i64, end: i64) -> Result<i64, CheckVersionError> {
    let wide = i128::from(end) - i128::from(start);
    i64::try_from(wide).map_err(|_| CheckVersionError::Span)
}

fn supported_version(normalized: &str) -> bool {
    SUPPORTED_CODEX_ROLLOUT_VERSIONS.contains(&normalized)
}

fn version_scalar_text(value: &MetaValue) -> Option<String> {
    match value {
        MetaValue::Str(text) => Some(text.clone()),
        MetaValue::Int(number) => Some(number.to_string()),
        MetaValue::Float(bits) => Some(python_float_str(f64::from_bits(*bits))),
        MetaValue::Bool(_)
        | MetaValue::Null
        | MetaValue::Bytes(_)
        | MetaValue::List(_)
        | MetaValue::Tuple(_)
        | MetaValue::Map(_)
        | MetaValue::Set(_)
        | MetaValue::Object(_) => None,
    }
}

fn coordinate_entries(
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
    record_ordinal: Option<i64>,
) -> Vec<(String, FindingValue)> {
    let mut entries = Vec::new();
    if let Some(offset) = byte_offset {
        entries.push(("byte_offset".to_owned(), FindingValue::int(offset)));
    }
    if let Some(end) = byte_end {
        entries.push(("byte_end".to_owned(), FindingValue::int(end)));
    }
    if let Some(ordinal) = record_ordinal {
        entries.push(("record_ordinal".to_owned(), FindingValue::int(ordinal)));
    }
    entries
}

fn version_evidence(
    version_raw: VersionText<'_>,
    coord: &[(String, FindingValue)],
) -> FindingValue {
    let raw = match version_raw {
        VersionText::Scalar(text) => {
            let (safe_version, _truncated) = safe_discriminator(PyValue::Str(text));
            safe_version
        }
        VersionText::InvalidType => INVALID_VERSION_TYPE.to_owned(),
    };
    let mut entries = Vec::new();
    put_entry(&mut entries, "version_raw", FindingValue::string(raw));
    put_entry(
        &mut entries,
        "supported_set",
        supported_set_tuple(),
    );
    for (key, value) in coord {
        put_entry(&mut entries, key, value.clone());
    }
    FindingValue::map(entries)
}

fn supported_set_tuple() -> FindingValue {
    let mut versions = SUPPORTED_CODEX_ROLLOUT_VERSIONS;
    versions.sort_unstable();
    FindingValue::tuple(versions.into_iter().map(FindingValue::string).collect())
}

fn sl302_evidence(
    field_path: &str,
    type_value: &MetaValue,
    rec_id: &str,
    coord_ev: &[(&str, FindingValue)],
) -> FindingValue {
    let (safe_val, truncated) = safe_discriminator(discriminator_input(type_value));
    let mut entries = Vec::new();
    put_entry(
        &mut entries,
        "field_path",
        FindingValue::string(field_path),
    );
    put_entry(&mut entries, "type_value", FindingValue::string(safe_val));
    put_entry(&mut entries, "record_id", FindingValue::string(rec_id));
    for (key, value) in coord_ev {
        put_entry(&mut entries, key, value.clone());
    }
    if truncated {
        put_entry(
            &mut entries,
            "type_truncated",
            FindingValue::bool_value(true),
        );
    }
    FindingValue::map(entries)
}

fn put_entry(entries: &mut Vec<(FindingValue, FindingValue)>, key: &str, value: FindingValue) {
    if let Some(slot) = entries.iter_mut().find(|(existing, _)| match existing {
        FindingValue::Str(text) => text == key,
        _ => false,
    }) {
        slot.1 = value;
        return;
    }
    entries.push((FindingValue::string(key), value));
}

fn discriminator_input(value: &MetaValue) -> PyValue<'_> {
    match value {
        MetaValue::Null => PyValue::None,
        MetaValue::Bool(_) => PyValue::Bool,
        MetaValue::Int(_) => PyValue::Int,
        MetaValue::Float(_) => PyValue::Float,
        MetaValue::Str(text) => PyValue::Str(text),
        MetaValue::Bytes(len) => PyValue::Bytes(*len),
        MetaValue::List(items) => PyValue::List(items.len()),
        MetaValue::Tuple(items) => PyValue::Tuple(items.len()),
        MetaValue::Map(map) => PyValue::Dict(map.entries.len()),
        MetaValue::Set(len) => PyValue::Set(*len),
        MetaValue::Object(obj) => PyValue::Other(obj.type_name.as_str()),
    }
}

fn refuse_version(
    path_str: &str,
    line_number: i64,
    record_id: &str,
    evidence: FindingValue,
) -> CheckVersionError {
    let source = match SourceRef::try_new(
        path_str,
        Some(SourceLine::Int(line_number)),
        Some(record_id),
    ) {
        Ok(source) => source,
        Err(error) => return CheckVersionError::Finding(error),
    };
    CheckVersionError::Finding(omitted_fingerprint(
        SL301,
        Severity::Error,
        Repairability::Unsupported,
        UNSUPPORTED_VERSION_TEMPLATE,
        source,
        evidence,
    ))
}

fn omitted_fingerprint(
    code: &str,
    severity: Severity,
    repairability: Repairability,
    message_template: &str,
    source: SourceRef,
    evidence: FindingValue,
) -> FindingError {
    match make_finding(&MakeFindingInput {
        code: FindingValue::string(code),
        severity: FindingValue::severity(severity),
        repairability: FindingValue::repairability(repairability),
        message_template: FindingValue::string(message_template),
        template_args: FindingValue::None,
        source: FindingValue::source(source),
        related_ids: FindingValue::tuple(Vec::new()),
        evidence,
        fingerprint: FindingValue::None,
        adapter_id: None,
        adapter_version: None,
        profile_id: None,
        profile_version: None,
        ordinal: None,
        context: None,
    }) {
        Err(error) => error,
        Ok(_finding) => FindingError::new(FINGERPRINT_CODEC_UNAVAILABLE),
    }
}

fn copied_mapping(map: &MapValue) -> Result<MapValue, ToolInputError> {
    if map.items_raise {
        return Err(ToolInputError::Items);
    }
    let mut entries = Vec::new();
    for (key, value) in &map.entries {
        if let Some(slot) = entries
            .iter_mut()
            .find(|(existing, _)| same_map_key(existing, key))
        {
            slot.1 = value.clone();
        } else {
            entries.push((key.clone(), value.clone()));
        }
    }
    Ok(MapValue::new(entries))
}

fn same_map_key(left: &MapKey, right: &MapKey) -> bool {
    match (left, right) {
        (MapKey::Str(left_text), MapKey::Str(right_text)) => left_text == right_text,
        (MapKey::Rendered(left_text), MapKey::Rendered(right_text)) => left_text == right_text,
        (MapKey::Bool(left_flag), MapKey::Bool(right_flag)) => left_flag == right_flag,
        (MapKey::Null, MapKey::Null) => true,
        (MapKey::Int(left_number), MapKey::Int(right_number)) => left_number == right_number,
        (MapKey::Float(left_bits), MapKey::Float(right_bits)) => {
            float_keys_equal(*left_bits, *right_bits)
        }
        (MapKey::Int(number), MapKey::Float(bits)) | (MapKey::Float(bits), MapKey::Int(number)) => {
            float_equals_int(*bits, *number)
        }
        (MapKey::Bool(_), MapKey::Int(_) | MapKey::Float(_))
        | (MapKey::Int(_) | MapKey::Float(_), MapKey::Bool(_)) => false,
        _ => false,
    }
}

fn float_keys_equal(left: u64, right: u64) -> bool {
    let left_value = f64::from_bits(left);
    let right_value = f64::from_bits(right);
    if left_value.is_nan() || right_value.is_nan() {
        return false;
    }
    left_value == right_value
}

fn float_equals_int(bits: u64, number: i64) -> bool {
    f64::from_bits(bits) == integer_as_float(number)
}

fn integer_as_float(number: i64) -> f64 {
    // Python `int == float` converts the integer. `i64` to `f64` is that conversion.
    #[allow(clippy::cast_precision_loss)]
    let converted = number as f64;
    converted
}

fn wrapped_value(value: &MetaValue) -> MetaValue {
    MetaValue::Map(MapValue::new(vec![(
        MapKey::Str("value".to_owned()),
        value.clone(),
    )]))
}

fn last_string_value<'a>(map: &'a MapValue, key: &str) -> Option<&'a MetaValue> {
    map.entries
        .iter()
        .rev()
        .find(|(name, _)| matches!(name, MapKey::Str(text) if text == key))
        .map(|(_, value)| value)
}

fn is_truthy(value: &MetaValue) -> bool {
    match value {
        MetaValue::Null => false,
        MetaValue::Bool(flag) => *flag,
        MetaValue::Int(number) => *number != 0,
        MetaValue::Float(bits) => float_truthy(*bits),
        MetaValue::Str(text) => !text.is_empty(),
        MetaValue::Bytes(len) | MetaValue::Set(len) => *len != 0,
        MetaValue::List(items) | MetaValue::Tuple(items) => !items.is_empty(),
        MetaValue::Map(map) => !map.entries.is_empty(),
        MetaValue::Object(_) => true,
    }
}

fn float_truthy(bits: u64) -> bool {
    const SIGN: u64 = 1_u64 << 63;
    bits & !SIGN != 0
}

fn python_float_str(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_negative() {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        };
    }
    let bits = value.to_bits();
    if bits == 0 {
        return "0.0".to_owned();
    }
    if bits == (1_u64 << 63) {
        return "-0.0".to_owned();
    }
    let debug = format!("{value:?}");
    let Some((mantissa, exponent)) = split_exponent(&debug) else {
        if debug.contains('.') {
            return debug;
        }
        return format!("{debug}.0");
    };
    let (sign, digits) = if let Some(rest) = exponent.strip_prefix('+') {
        ('+', rest)
    } else if let Some(rest) = exponent.strip_prefix('-') {
        ('-', rest)
    } else {
        ('+', exponent)
    };
    if digits.len() >= 2 {
        format!("{mantissa}e{sign}{digits}")
    } else {
        format!("{mantissa}e{sign}0{digits}")
    }
}

fn split_exponent(text: &str) -> Option<(&str, &str)> {
    let index = text.find(['e', 'E'])?;
    Some((&text[..index], &text[index + 1..]))
}

#[cfg(test)]
mod rollout_record_tests {
    use super::{
        _check_version, _emit_sl302, _normalize_timestamp, _tool_input_payload,
        _version_field_name, detect_codex_rollout, sl302_evidence, supported_set_tuple,
        version_evidence, CheckVersionError, ToolInputError, VersionText, SQLITE_MAGIC,
        _TIMESTAMP_ISO_REGEX,
    };
    use crate::openai_agents::{
        normalize_version, AttrObject, MapKey, MapValue, MetaValue, SourceMetadata,
        STRICT_JSON_DECODE_UNAVAILABLE,
    };
    use crate::safe_value::{safe_discriminator, PyValue};
    use crate::synthetic::{synthetic_event_id, SyntheticIdCollisionGuard};
    use model::codes::{Repairability, Severity};
    use model::finding::{
        Finding, FindingInput, SourceLine, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE, SCHEMA_VERSION,
    };
    use model::finding::PyValue as FindingValue;

    fn stored_raw(meta: &SourceMetadata) -> Option<&str> {
        match meta.get("version_raw") {
            Some(MetaValue::Str(text)) => Some(text.as_str()),
            Some(_) => panic!("version_raw is not a str"),
            None => None,
        }
    }

    fn sample_finding() -> Finding {
        let source = SourceRef::try_new("a.jsonl", Some(SourceLine::Int(1)), None).expect("source");
        Finding::try_new(FindingInput {
            code: FindingValue::string("SL001"),
            severity: FindingValue::severity(Severity::Error),
            repairability: FindingValue::repairability(Repairability::Manual),
            message: FindingValue::string("synthetic marker"),
            source: FindingValue::source(source),
            related_ids: FindingValue::tuple(Vec::new()),
            fingerprint: FindingValue::string("0123456789abcdef"),
            schema_version: FindingValue::string(SCHEMA_VERSION),
            message_template: FindingValue::None,
            evidence: FindingValue::None,
        })
        .expect("finding")
    }

    fn field(key: &str, value: FindingValue) -> (FindingValue, FindingValue) {
        (FindingValue::string(key), value)
    }

    #[test]
    fn detect_rejects_the_wrong_suffix_empty_bytes_and_sqlite_magic() {
        let marked = b"\"session_meta\"";
        assert_eq!(detect_codex_rollout(marked, "session.txt"), 0.0);
        assert_eq!(detect_codex_rollout(marked, "rollout-abc.sqlite"), 0.0);
        assert_eq!(detect_codex_rollout(marked, "notes.jsonl.bak"), 0.0);
        assert_eq!(detect_codex_rollout(marked, "rollout-json"), 0.0);
        assert_eq!(detect_codex_rollout(b"", "rollout-x.jsonl"), 0.0);
        assert_eq!(detect_codex_rollout(b"", "a.json"), 0.0);
        assert_eq!(detect_codex_rollout(SQLITE_MAGIC, "rollout-x.jsonl"), 0.0);
        let mut prefixed = SQLITE_MAGIC.to_vec();
        prefixed.extend_from_slice(marked);
        assert_eq!(detect_codex_rollout(&prefixed, "rollout-x.jsonl"), 0.0);
        assert_eq!(
            detect_codex_rollout(b"SQLite format 3", "rollout-x.jsonl"),
            0.3
        );
    }

    #[test]
    fn detect_scores_substrings_without_parsing_json() {
        assert_eq!(detect_codex_rollout(b"\"session_meta\"", "a.JSONL"), 0.8);
        assert_eq!(detect_codex_rollout(b"\"session_meta\"", "a.Json"), 0.8);
        assert_eq!(
            detect_codex_rollout(b"\"session_meta\"", "rollout-a.jsonl"),
            1.0
        );
        assert_eq!(
            detect_codex_rollout(b"\"session_meta\"\"response_item\"", "session.json"),
            1.0
        );
        assert_eq!(
            detect_codex_rollout(b"\"session_meta\"\"event_msg\"", "a.json"),
            0.8
        );
        assert_eq!(detect_codex_rollout(b"\"ordinal\"", "a.jsonl"), 0.0);
        assert_eq!(detect_codex_rollout(b"\"payload\"", "a.jsonl"), 0.0);
        assert_eq!(
            detect_codex_rollout(b"\"ordinal\" \"payload\"", "x.jsonl"),
            0.3
        );
        assert_eq!(detect_codex_rollout(b"\"turn_context\"", "a.jsonl"), 0.3);
        assert_eq!(
            detect_codex_rollout(b"\"turn_context\"\"world_state\"", "a.jsonl"),
            0.3
        );
        assert_eq!(detect_codex_rollout(b"\"event_msg\"", "a.jsonl"), 0.3);
        assert_eq!(detect_codex_rollout(b"\"compacted\"", "a.jsonl"), 0.3);
        assert_eq!(
            detect_codex_rollout(b"\"event_msg\"\"compacted\"", "a.jsonl"),
            0.3
        );
        assert_eq!(
            detect_codex_rollout(b"\"event_msg\"\"compacted\"", "rollout-a.jsonl"),
            0.8
        );
        assert_eq!(detect_codex_rollout(b"\"custom_tool_call\"", "a.jsonl"), 0.3);
        assert_eq!(
            detect_codex_rollout(b"\"function_call_output\"", "a.jsonl"),
            0.3
        );
        assert_eq!(
            detect_codex_rollout(b"\"custom_tool_call\"\"function_call_output\"", "a.jsonl"),
            0.3
        );
        assert_eq!(
            detect_codex_rollout(b"\"custom_tool_call\"\"event_msg\"", "a.jsonl"),
            0.8
        );
        assert_eq!(
            detect_codex_rollout(b"\"turn_context\"\"compacted\"", "a.jsonl"),
            0.8
        );
        assert_eq!(detect_codex_rollout(b"session_meta response_item", "a.jsonl"), 0.0);
        assert_eq!(detect_codex_rollout(b"SESSION_META", "a.jsonl"), 0.0);
        assert_eq!(
            detect_codex_rollout(b"{\"type\": \"session_meta\"", "a.jsonl"),
            0.8
        );
        assert_eq!(detect_codex_rollout(b"{}", "Rollout-1.Jsonl"), 0.3);
        assert_eq!(detect_codex_rollout(b"\"event_msg\"", "dir/rollout-a.jsonl"), 0.3);
        assert_eq!(detect_codex_rollout(b"hello", "a.jsonl"), 0.0);
    }

    #[test]
    fn detect_strips_one_bom_and_reads_only_4096_bytes() {
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(b"\"response_item\"");
        assert_eq!(detect_codex_rollout(&bom, "a.json"), 0.8);

        let mut bom_sqlite = vec![0xef, 0xbb, 0xbf];
        bom_sqlite.extend_from_slice(SQLITE_MAGIC);
        assert_eq!(detect_codex_rollout(&bom_sqlite, "a.jsonl"), 0.0);
        assert_eq!(detect_codex_rollout(&bom_sqlite, "rollout-a.jsonl"), 0.3);

        let mut late = vec![b'x'; 4096];
        late.extend_from_slice(b"\"session_meta\"");
        assert_eq!(detect_codex_rollout(&late, "a.jsonl"), 0.0);

        let mut inside = vec![b'x'; 4096 - 14];
        inside.extend_from_slice(b"\"session_meta\"");
        assert_eq!(inside.len(), 4096);
        assert_eq!(detect_codex_rollout(&inside, "a.jsonl"), 0.8);

        let mut bom_window = vec![0xef, 0xbb, 0xbf];
        bom_window.extend(std::iter::repeat_n(b'x', 4096));
        bom_window.extend_from_slice(b"\"session_meta\"");
        assert_eq!(detect_codex_rollout(&bom_window, "a.jsonl"), 0.0);

        let mut broken = vec![0xff, 0xfe];
        broken.extend_from_slice(b"\"compacted\"");
        assert_eq!(detect_codex_rollout(&broken, "a.jsonl"), 0.3);
    }

    #[test]
    fn normalize_timestamp_walks_ascii_digits_and_epochs_the_rest() {
        assert_eq!(
            _TIMESTAMP_ISO_REGEX,
            r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$"
        );
        let kept = [
            "2020-01-01T00:00:00Z",
            "2020-13-40T99:99:99",
            "2020-01-01T00:00:00.123456789+05:30",
            "2020-01-01T00:00:00-00:00",
            "2020-01-01T00:00:00.0",
            "2020-01-01T00:00:00",
            "1970-01-01T00:00:00Z",
            "2020-01-01T00:00:00.12Z",
        ];
        for raw in kept {
            assert_eq!(_normalize_timestamp(PyValue::Str(raw)), raw, "{raw}");
        }
        assert_eq!(
            _normalize_timestamp(PyValue::Str("  2020-01-01T00:00:00Z  ")),
            "2020-01-01T00:00:00Z"
        );
        assert_eq!(
            _normalize_timestamp(PyValue::Str("\n2020-01-01T00:00:00Z\n")),
            "2020-01-01T00:00:00Z"
        );
        assert_eq!(
            _normalize_timestamp(PyValue::Str("\u{00a0}2020-01-01T00:00:00-00:00")),
            "2020-01-01T00:00:00-00:00"
        );
        assert_eq!(
            _normalize_timestamp(PyValue::Str("\u{2003}2020-01-01T00:00:00Z\u{2003}")),
            "2020-01-01T00:00:00Z"
        );
        let arabic_one = '\u{0661}';
        let year = format!("202{arabic_one}-01-01T00:00:00Z");
        assert_eq!(
            _normalize_timestamp(PyValue::Str(&year)),
            "1970-01-01T00:00:00Z"
        );
        let fraction = format!("2020-01-01T00:00:00.{arabic_one}");
        assert_eq!(
            _normalize_timestamp(PyValue::Str(&fraction)),
            "1970-01-01T00:00:00Z"
        );
        for raw in [
            "nope",
            "True",
            "2020-01-01T00:00:00z",
            "2020-01-01T00:00:00.Z",
            "2020-01-01T00:00:00+0000",
            "2020-01-01 00:00:00Z",
            "2020-01-01t00:00:00Z",
            "",
            "   ",
            "2020-01-01T00:00:00.",
            "2020-01-01T00:00:00+5:30",
            "2020-01-01T00:00:00Z\nextra",
        ] {
            assert_eq!(
                _normalize_timestamp(PyValue::Str(raw)),
                "1970-01-01T00:00:00Z",
                "{raw}"
            );
        }
        for sample in [
            PyValue::None,
            PyValue::Int,
            PyValue::Bool,
            PyValue::Float,
            PyValue::List(0),
            PyValue::Bytes(0),
            PyValue::Dict(0),
        ] {
            assert_eq!(_normalize_timestamp(sample), "1970-01-01T00:00:00Z");
        }
        assert_eq!(_normalize_timestamp(PyValue::Bool), "1970-01-01T00:00:00Z");
        assert_eq!(_normalize_timestamp(PyValue::Int), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn version_evidence_sorts_the_supported_set_and_keeps_bool_invalid() {
        assert_eq!(
            supported_set_tuple(),
            FindingValue::tuple(
                ["1", "1.0", "1.0.0", "codex-rollout-v1"]
                    .into_iter()
                    .map(FindingValue::string)
                    .collect()
            )
        );
        let coords = vec![
            ("byte_offset".to_owned(), FindingValue::int(1)),
            ("byte_end".to_owned(), FindingValue::int(2)),
            ("record_ordinal".to_owned(), FindingValue::int(0)),
        ];
        assert_eq!(
            version_evidence(VersionText::Scalar("99.0.0"), &coords),
            FindingValue::map(vec![
                field("version_raw", FindingValue::string("99.0.0")),
                field("supported_set", supported_set_tuple()),
                field("byte_offset", FindingValue::int(1)),
                field("byte_end", FindingValue::int(2)),
                field("record_ordinal", FindingValue::int(0)),
            ])
        );
        let (shape, truncated) = safe_discriminator(PyValue::Str("has space"));
        assert!(truncated);
        assert_eq!(shape, "<str:len=9>");
        assert_eq!(
            version_evidence(VersionText::Scalar("has space"), &[]),
            FindingValue::map(vec![
                field("version_raw", FindingValue::string("<str:len=9>")),
                field("supported_set", supported_set_tuple()),
            ])
        );
        let invalid = version_evidence(VersionText::InvalidType, &[]);
        assert_eq!(
            invalid,
            FindingValue::map(vec![
                field(
                    "version_raw",
                    FindingValue::string("<invalid_version_type>")
                ),
                field("supported_set", supported_set_tuple()),
            ])
        );
        let rendered = format!("{invalid:?}");
        assert!(!rendered.contains("True"));
        assert!(!rendered.contains("False"));
    }

    #[test]
    fn supported_versions_store_raw_text_and_skip_make_finding() {
        let kept = sample_finding();
        let findings = [kept.clone()];
        for version in ["1", "1.0", "1.0.0", "codex-rollout-v1"] {
            let mut meta = SourceMetadata::new();
            let flag = _check_version(
                &MetaValue::Str(version.to_owned()),
                "session.jsonl",
                0,
                Some("evt"),
                &findings,
                &mut meta,
                false,
                None,
                None,
                None,
                None,
            )
            .expect("supported");
            assert!(!flag);
            assert_eq!(stored_raw(&meta), Some(version));
            assert_eq!(findings[0], kept);
        }
        let mut marked = SourceMetadata::new();
        let flag = _check_version(
            &MetaValue::Str("  V1.0.0 \n".to_owned()),
            "session.jsonl",
            4,
            Some("evt"),
            &[],
            &mut marked,
            false,
            None,
            None,
            None,
            None,
        )
        .expect("marked");
        assert!(!flag);
        assert_eq!(stored_raw(&marked), Some("V1.0.0"));
        assert_eq!(normalize_version("V1.0.0"), "1.0.0");

        let mut upper = SourceMetadata::new();
        let flag = _check_version(
            &MetaValue::Str("CODEX-ROLLOUT-V1".to_owned()),
            "session.jsonl",
            1,
            Some("evt"),
            &[],
            &mut upper,
            true,
            None,
            None,
            None,
            None,
        )
        .expect("upper");
        assert!(flag);
        assert_eq!(stored_raw(&upper), Some("CODEX-ROLLOUT-V1"));

        let mut number = SourceMetadata::new();
        let flag = _check_version(
            &MetaValue::Int(1),
            "session.jsonl",
            1,
            Some("evt"),
            &[],
            &mut number,
            false,
            None,
            None,
            None,
            None,
        )
        .expect("int");
        assert!(!flag);
        assert_eq!(stored_raw(&number), Some("1"));

        let mut one = SourceMetadata::new();
        let flag = _check_version(
            &MetaValue::float(1.0),
            "session.jsonl",
            1,
            Some("evt"),
            &[],
            &mut one,
            false,
            None,
            None,
            None,
            None,
        )
        .expect("float");
        assert!(!flag);
        assert_eq!(stored_raw(&one), Some("1.0"));
    }

    #[test]
    fn none_candidate_does_not_mint_or_store() {
        let id = synthetic_event_id("codex_rollout", 0, "session.jsonl", 0);
        let mut guard = SyntheticIdCollisionGuard::new();
        guard.register_real(&id).expect("real");
        let mut meta =
            SourceMetadata::from_entries([("version_raw", MetaValue::Str("keep".to_owned()))]);
        let unseen = _check_version(
            &MetaValue::Null,
            "session.jsonl",
            1,
            None,
            &[],
            &mut meta,
            false,
            Some(i64::MIN),
            Some(i64::MAX),
            None,
            Some(&mut guard),
        )
        .expect("none");
        assert!(!unseen);
        assert_eq!(stored_raw(&meta), Some("keep"));
        assert!(guard.seen_synthetic_ids().is_empty());
    }

    #[test]
    fn bool_is_not_an_int_and_stops_at_the_codec() {
        let kept = sample_finding();
        let findings = [kept.clone()];
        for sample in [MetaValue::Bool(true), MetaValue::Bool(false)] {
            let mut meta = SourceMetadata::new();
            let err = _check_version(
                &sample,
                "session.jsonl",
                2,
                Some("evt"),
                &findings,
                &mut meta,
                false,
                Some(4),
                Some(9),
                Some(0),
                None,
            )
            .expect_err("bool");
            assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
            assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
            assert!(matches!(err, CheckVersionError::Finding(_)));
            assert_eq!(stored_raw(&meta), None);
            assert_eq!(findings[0], kept);
        }

        let mut zero = SourceMetadata::new();
        let err = _check_version(
            &MetaValue::Int(0),
            "session.jsonl",
            2,
            Some("evt"),
            &[],
            &mut zero,
            false,
            None,
            None,
            None,
            None,
        )
        .expect_err("zero");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(stored_raw(&zero), Some("0"));

        let mut negative = SourceMetadata::new();
        let err = _check_version(
            &MetaValue::float(-0.0),
            "session.jsonl",
            2,
            Some("evt"),
            &[],
            &mut negative,
            false,
            None,
            None,
            None,
            None,
        )
        .expect_err("negzero");
        assert_eq!(stored_raw(&negative), Some("-0.0"));
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
    }

    #[test]
    fn other_invalid_types_do_not_store_raw_or_append() {
        let samples = [
            MetaValue::Bytes(2),
            MetaValue::List(vec![MetaValue::Int(1)]),
            MetaValue::Tuple(vec![MetaValue::Bool(true)]),
            MetaValue::Map(MapValue::new(vec![(
                MapKey::Str("bad".to_owned()),
                MetaValue::Str("type".to_owned()),
            )])),
            MetaValue::Set(1),
            MetaValue::Object(Box::new(AttrObject::new("SyntheticType"))),
        ];
        for sample in &samples {
            let mut meta = SourceMetadata::new();
            let err = _check_version(
                sample,
                "session.jsonl",
                3,
                Some("evt"),
                &[],
                &mut meta,
                false,
                None,
                None,
                None,
                None,
            )
            .expect_err("invalid");
            assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
            assert_eq!(stored_raw(&meta), None);
        }
    }

    #[test]
    fn unsupported_scalar_mints_registers_and_stops_before_append() {
        let mut meta = SourceMetadata::new();
        let mut guard = SyntheticIdCollisionGuard::new();
        let err = _check_version(
            &MetaValue::Str("  V99 ".to_owned()),
            "session.jsonl",
            3,
            None,
            &[],
            &mut meta,
            false,
            Some(4),
            Some(9),
            Some(2),
            Some(&mut guard),
        )
        .expect_err("unsupported");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(stored_raw(&meta), Some("V99"));
        assert_eq!(normalize_version("V99"), "99");
        let expected = synthetic_event_id("codex_rollout", 2, "session.jsonl", 5);
        assert!(guard.seen_synthetic_ids().contains(&expected));
        assert_eq!(guard.seen_synthetic_ids().len(), 1);
    }

    #[test]
    fn seen_unsupported_scalar_stores_raw_and_skips_make_finding() {
        let mut meta = SourceMetadata::new();
        let mut guard = SyntheticIdCollisionGuard::new();
        let flag = _check_version(
            &MetaValue::Str("99".to_owned()),
            "session.jsonl",
            1,
            None,
            &[],
            &mut meta,
            true,
            None,
            None,
            None,
            Some(&mut guard),
        )
        .expect("seen");
        assert!(flag);
        assert_eq!(stored_raw(&meta), Some("99"));
        assert_eq!(guard.seen_synthetic_ids().len(), 1);

        let mut flagged = SourceMetadata::new();
        let flag = _check_version(
            &MetaValue::Bool(true),
            "session.jsonl",
            1,
            Some("evt"),
            &[],
            &mut flagged,
            true,
            None,
            None,
            None,
            None,
        )
        .expect("seen bool");
        assert!(flag);
        assert_eq!(stored_raw(&flagged), None);
    }

    #[test]
    fn empty_string_is_a_scalar_and_a_bad_line_is_not_the_codec() {
        let mut meta = SourceMetadata::new();
        let err = _check_version(
            &MetaValue::Str("   ".to_owned()),
            "session.jsonl",
            1,
            Some("evt"),
            &[],
            &mut meta,
            false,
            None,
            None,
            None,
            None,
        )
        .expect_err("blank");
        assert_eq!(stored_raw(&meta), Some(""));
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);

        let mut lined = SourceMetadata::new();
        let err = _check_version(
            &MetaValue::Str("99".to_owned()),
            "session.jsonl",
            0,
            Some("evt"),
            &[],
            &mut lined,
            false,
            None,
            None,
            None,
            None,
        )
        .expect_err("line");
        assert_eq!(stored_raw(&lined), Some("99"));
        assert_ne!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(err.to_string().contains("SourceRef.line"));

        let mut blank_bool = SourceMetadata::new();
        let err = _check_version(
            &MetaValue::Bool(false),
            "",
            1,
            Some("evt"),
            &[],
            &mut blank_bool,
            false,
            None,
            None,
            None,
            None,
        )
        .expect_err("path");
        assert_eq!(stored_raw(&blank_bool), None);
        assert_ne!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(err.to_string().contains("SourceRef.path"));
    }

    #[test]
    fn span_and_collision_happen_before_version_raw() {
        let mut meta = SourceMetadata::new();
        let mut guard = SyntheticIdCollisionGuard::new();
        let err = _check_version(
            &MetaValue::Str("99".to_owned()),
            "session.jsonl",
            1,
            None,
            &[],
            &mut meta,
            false,
            Some(i64::MIN),
            Some(i64::MAX),
            Some(1),
            Some(&mut guard),
        )
        .expect_err("span");
        assert_eq!(err, CheckVersionError::Span);
        assert_eq!(err.to_string(), "byte_end - byte_offset is outside i64");
        assert_eq!(stored_raw(&meta), None);
        assert!(guard.seen_synthetic_ids().is_empty());

        let mut kept = SourceMetadata::new();
        let mut idle = SyntheticIdCollisionGuard::new();
        let flag = _check_version(
            &MetaValue::Str("1".to_owned()),
            "session.jsonl",
            1,
            Some("evt"),
            &[],
            &mut kept,
            false,
            Some(i64::MIN),
            Some(i64::MAX),
            None,
            Some(&mut idle),
        )
        .expect("explicit id");
        assert!(!flag);
        assert_eq!(stored_raw(&kept), Some("1"));
        assert!(idle.seen_synthetic_ids().is_empty());

        let id = synthetic_event_id("codex_rollout", 4, "session.jsonl", 5);
        let mut colliding = SyntheticIdCollisionGuard::new();
        colliding.register_real(&id).expect("real");
        let mut missed = SourceMetadata::new();
        let err = _check_version(
            &MetaValue::Str("99".to_owned()),
            "session.jsonl",
            1,
            None,
            &[],
            &mut missed,
            false,
            Some(10),
            Some(15),
            Some(4),
            Some(&mut colliding),
        )
        .expect_err("collision");
        assert!(matches!(err, CheckVersionError::Collision(_)));
        assert!(err.to_string().contains("Synthetic ID collision"));
        assert_ne!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(stored_raw(&missed), None);
        assert!(colliding.seen_synthetic_ids().is_empty());

        let mut negative = SourceMetadata::new();
        let mut guard = SyntheticIdCollisionGuard::new();
        let err = _check_version(
            &MetaValue::Str("99".to_owned()),
            "session.jsonl",
            1,
            None,
            &[],
            &mut negative,
            false,
            Some(10),
            Some(3),
            None,
            Some(&mut guard),
        )
        .expect_err("negative span");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        let expected = synthetic_event_id("codex_rollout", 0, "session.jsonl", -7);
        assert!(guard.seen_synthetic_ids().contains(&expected));
    }

    #[test]
    fn sl302_evidence_keeps_bool_apart_from_int() {
        assert_eq!(
            sl302_evidence("type", &MetaValue::Bool(true), "evt", &[]),
            FindingValue::map(vec![
                field("field_path", FindingValue::string("type")),
                field("type_value", FindingValue::string("<bool>")),
                field("record_id", FindingValue::string("evt")),
                field("type_truncated", FindingValue::bool_value(true)),
            ])
        );
        let bool_evidence = sl302_evidence("type", &MetaValue::Bool(false), "evt", &[]);
        let int_evidence = sl302_evidence("type", &MetaValue::Int(1), "evt", &[]);
        assert_ne!(bool_evidence, int_evidence);
        assert_eq!(
            int_evidence,
            FindingValue::map(vec![
                field("field_path", FindingValue::string("type")),
                field("type_value", FindingValue::string("<int>")),
                field("record_id", FindingValue::string("evt")),
                field("type_truncated", FindingValue::bool_value(true)),
            ])
        );
        assert_eq!(
            sl302_evidence(
                "payload.type",
                &MetaValue::Str("weird_item".to_owned()),
                "evt",
                &[
                    ("byte_offset", FindingValue::int(0)),
                    ("record_ordinal", FindingValue::int(3)),
                ],
            ),
            FindingValue::map(vec![
                field("field_path", FindingValue::string("payload.type")),
                field("type_value", FindingValue::string("weird_item")),
                field("record_id", FindingValue::string("evt")),
                field("byte_offset", FindingValue::int(0)),
                field("record_ordinal", FindingValue::int(3)),
            ])
        );
        assert_eq!(
            sl302_evidence(
                "type",
                &MetaValue::Bool(true),
                "evt",
                &[
                    ("field_path", FindingValue::string("other")),
                    ("type_truncated", FindingValue::bool_value(false)),
                ],
            ),
            FindingValue::map(vec![
                field("field_path", FindingValue::string("other")),
                field("type_value", FindingValue::string("<bool>")),
                field("record_id", FindingValue::string("evt")),
                field("type_truncated", FindingValue::bool_value(true)),
            ])
        );
    }

    #[test]
    fn emit_sl302_stops_at_the_codec_and_does_not_append() {
        let kept = sample_finding();
        let findings = [kept.clone()];
        let err = _emit_sl302(
            "session.jsonl",
            2,
            "evt",
            "type",
            &MetaValue::Bool(true),
            &[("record_ordinal", FindingValue::int(0))],
            &findings,
        )
        .expect_err("codec");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.message(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(findings[0], kept);

        let err = _emit_sl302(
            "session.jsonl",
            0,
            "evt",
            "type",
            &MetaValue::Str("weird_item".to_owned()),
            &[],
            &[],
        )
        .expect_err("line");
        assert_ne!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(err.to_string().contains("SourceRef.line"));

        let err = _emit_sl302(
            "session.jsonl",
            1,
            "  ",
            "payload.type",
            &MetaValue::Str("weird_item".to_owned()),
            &[],
            &[],
        )
        .expect_err("record");
        assert!(err.to_string().contains("record_id"));
        assert_ne!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
    }

    #[test]
    fn tool_input_stops_on_strings_and_keeps_bool_apart_from_int() {
        assert_eq!(
            _tool_input_payload(&MetaValue::Null).expect("none"),
            MetaValue::Map(MapValue::new(Vec::new()))
        );
        assert_eq!(
            _tool_input_payload(&MetaValue::Map(MapValue::new(Vec::new()))).expect("empty"),
            MetaValue::Map(MapValue::new(Vec::new()))
        );
        for sample in ["", "{}", "[]", "1", "true", "\"x\"", "not json"] {
            let err = _tool_input_payload(&MetaValue::Str(sample.to_owned())).expect_err("str");
            assert_eq!(err, ToolInputError::Unavailable);
            assert_eq!(
                err.to_string(),
                "sesslint.io._STRICT_JSON_DECODER.decode is not available"
            );
            assert_eq!(err.to_string(), STRICT_JSON_DECODE_UNAVAILABLE);
        }
        let raw = MetaValue::List(vec![MetaValue::Bool(true), MetaValue::Int(1)]);
        assert_eq!(
            _tool_input_payload(&raw).expect("list"),
            wrapped_expect(&raw)
        );
        assert_eq!(
            _tool_input_payload(&MetaValue::Bool(false)).expect("bool"),
            wrapped_expect(&MetaValue::Bool(false))
        );
        assert_eq!(
            _tool_input_payload(&MetaValue::Bytes(0)).expect("bytes"),
            wrapped_expect(&MetaValue::Bytes(0))
        );
        let raising = MetaValue::Map(MapValue::raising(vec![]));
        let err = _tool_input_payload(&raising).expect_err("items");
        assert_eq!(err, ToolInputError::Items);
        assert_eq!(err.to_string(), "list(mapping.items()) raises");
        assert_ne!(err.to_string(), STRICT_JSON_DECODE_UNAVAILABLE);

        let folded = MetaValue::Map(MapValue::new(vec![
            (MapKey::Str("a".to_owned()), MetaValue::Int(1)),
            (MapKey::Str("a".to_owned()), MetaValue::Int(2)),
            (MapKey::Int(1), MetaValue::Str("int".to_owned())),
            (MapKey::float(1.0), MetaValue::Str("float".to_owned())),
            (MapKey::Bool(true), MetaValue::Str("bool".to_owned())),
        ]));
        assert_eq!(
            _tool_input_payload(&folded).expect("copy"),
            MetaValue::Map(MapValue::new(vec![
                (MapKey::Str("a".to_owned()), MetaValue::Int(2)),
                (MapKey::Int(1), MetaValue::Str("float".to_owned())),
                (MapKey::Bool(true), MetaValue::Str("bool".to_owned())),
            ]))
        );
    }

    fn wrapped_expect(value: &MetaValue) -> MetaValue {
        MetaValue::Map(MapValue::new(vec![(
            MapKey::Str("value".to_owned()),
            value.clone(),
        )]))
    }

    #[test]
    fn version_field_follows_the_or_chain_and_skips_payload_version() {
        assert_eq!(
            _version_field_name(&MapValue::new(vec![]), &MetaValue::Null),
            "version"
        );
        let both = MapValue::new(vec![
            (
                MapKey::Str("version".to_owned()),
                MetaValue::Str("1".to_owned()),
            ),
            (
                MapKey::Str("format_version".to_owned()),
                MetaValue::Str("2".to_owned()),
            ),
        ]);
        let payload = MetaValue::Map(MapValue::new(vec![(
            MapKey::Str("rollout_version".to_owned()),
            MetaValue::Str("9".to_owned()),
        )]));
        assert_eq!(_version_field_name(&both, &payload), "format_version");

        let rollout = MapValue::new(vec![
            (
                MapKey::Str("rollout_version".to_owned()),
                MetaValue::Str("1".to_owned()),
            ),
            (
                MapKey::Str("version".to_owned()),
                MetaValue::Str("2".to_owned()),
            ),
        ]);
        assert_eq!(_version_field_name(&rollout, &MetaValue::Null), "rollout_version");

        let falsy = MapValue::new(vec![
            (MapKey::Str("rollout_version".to_owned()), MetaValue::Str(String::new())),
            (MapKey::Str("format_version".to_owned()), MetaValue::Int(0)),
            (MapKey::Str("schema_version".to_owned()), MetaValue::Bool(false)),
            (MapKey::Str("export_version".to_owned()), MetaValue::float(0.0)),
            (MapKey::Str("version".to_owned()), MetaValue::List(vec![])),
        ]);
        assert_eq!(_version_field_name(&falsy, &payload), "payload.rollout_version");

        let payload_version = MetaValue::Map(MapValue::new(vec![(
            MapKey::Str("version".to_owned()),
            MetaValue::Str("9".to_owned()),
        )]));
        assert_eq!(
            _version_field_name(&MapValue::new(vec![]), &payload_version),
            "version"
        );
        for skipped in [
            MetaValue::Null,
            MetaValue::Bool(true),
            MetaValue::Str("1".to_owned()),
            MetaValue::List(vec![MetaValue::Str("rollout_version".to_owned())]),
        ] {
            assert_eq!(_version_field_name(&MapValue::new(vec![]), &skipped), "version");
        }

        let truthy_bool = MapValue::new(vec![(
            MapKey::Str("export_version".to_owned()),
            MetaValue::Bool(true),
        )]);
        assert_eq!(_version_field_name(&truthy_bool, &payload), "export_version");
        let truthy_int = MapValue::new(vec![(
            MapKey::Str("schema_version".to_owned()),
            MetaValue::Int(1),
        )]);
        assert_eq!(_version_field_name(&truthy_int, &MetaValue::Null), "schema_version");

        let last_empty = MapValue::new(vec![
            (MapKey::Str("version".to_owned()), MetaValue::Str("1".to_owned())),
            (MapKey::Str("version".to_owned()), MetaValue::Str(String::new())),
        ]);
        assert_eq!(
            _version_field_name(&last_empty, &payload),
            "payload.rollout_version"
        );
        let last_present = MapValue::new(vec![
            (MapKey::Str("version".to_owned()), MetaValue::Str(String::new())),
            (MapKey::Str("version".to_owned()), MetaValue::Str("1".to_owned())),
        ]);
        assert_eq!(_version_field_name(&last_present, &payload), "version");

        let ignored = MapValue::new(vec![
            (MapKey::Int(1), MetaValue::Str("nope".to_owned())),
            (
                MapKey::Rendered("rollout_version".to_owned()),
                MetaValue::Str("nope".to_owned()),
            ),
            (
                MapKey::Str("format_version".to_owned()),
                MetaValue::Str("yes".to_owned()),
            ),
        ]);
        assert_eq!(_version_field_name(&ignored, &MetaValue::Null), "format_version");

        let raising = MapValue::raising(vec![(
            MapKey::Str("rollout_version".to_owned()),
            MetaValue::Str("1".to_owned()),
        )]);
        assert_eq!(_version_field_name(&raising, &MetaValue::Null), "rollout_version");

        let spaces = MapValue::new(vec![(
            MapKey::Str("version".to_owned()),
            MetaValue::Str(" ".to_owned()),
        )]);
        assert_eq!(_version_field_name(&spaces, &payload), "version");
        let half = MapValue::new(vec![(
            MapKey::Str("format_version".to_owned()),
            MetaValue::float(0.5),
        )]);
        assert_eq!(_version_field_name(&half, &MetaValue::Null), "format_version");
        let nested = MapValue::new(vec![(
            MapKey::Str("schema_version".to_owned()),
            MetaValue::Map(MapValue::new(vec![(
                MapKey::Str("k".to_owned()),
                MetaValue::Int(1),
            )])),
        )]);
        assert_eq!(_version_field_name(&nested, &MetaValue::Null), "schema_version");
        let empty_map = MapValue::new(vec![(
            MapKey::Str("schema_version".to_owned()),
            MetaValue::Map(MapValue::new(vec![])),
        )]);
        assert_eq!(_version_field_name(&empty_map, &payload), "payload.rollout_version");
    }
}
