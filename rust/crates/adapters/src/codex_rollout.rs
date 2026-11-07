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

// Port of `src/sesslint/adapters/codex_rollout.py`
// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 545–1126.
// `_process_rollout_record` only. `_process_jsonl_line` starts at line 1129.
//
// Gaps vs Python (recorded, not papered over):
// - The first `canonical_bytes(envelope)` failure sets the synthetic payload
//   length to 0 and continues. A successful encoding whose length does not
//   fit in `i64` is [`ProcessRolloutRecordError::CanonicalLen`].
// - [`compute_content_hash`] is called before [`SessionEvent`] is built. Its
//   Display is `sesslint._canonical_codec.payload_content_hash is not available`.
//   No digest is invented.
// - The later `canonical_bytes` that would build `source_record_hash` is not
//   caught. Its Display is
//   `sesslint._canonical_codec.canonical_json_bytes is not available`.
//   No sha256 is invented. The event is not appended. `check_event` is not
//   called on that arm.
// - [`_check_version`], [`_emit_sl302`], and
//   [`UnknownMetadataTracker::findings`] stop at the omitted fingerprint.
//   That error is propagated. A finding is not appended, and an event is not
//   appended after it. This file does not hash a fingerprint.
// - A string tool input stays at
//   `sesslint.io._STRICT_JSON_DECODER.decode is not available`.
// - `bool` is not an `int`. Ordinal continuity, the returned envelope
//   ordinal, usage counters, context pressure, and
//   `subagent_history_start_ordinal` exclude `bool`.
// - `str()` of a list, tuple, dict, bytes, set, or other object is
//   [`ProcessRolloutRecordError::Unrendered`].
// - `byte_end - byte_offset` is stored only when the difference fits in
//   `i64`. `len(guardian_history)` that does not fit is
//   [`ProcessRolloutRecordError::Count`].
// - A non-`str` mapping key stops with
//   [`ProcessRolloutRecordError::KeyOrder`] before a finding is emitted.

use std::collections::BTreeMap;

use model::canonical::{
    canonical_bytes, compute_content_hash, CanonicalUnavailable, Payload, SessionEvent,
    MUTATING_TOOL_NAMES, READ_ONLY_TOOL_NAMES,
};

use crate::drift::DriftTracker;
use crate::links::{extract_links, Link, ObjectValue};
use crate::metadata::{has_semantic_fields, MetadataKey, MetadataValue, UnknownMetadataTracker};
use crate::openai_agents::STR_UNRENDERED;
use crate::synthetic::CheckEventError;

const EVENTS_LEN_OUTSIDE_I64: &str = "len(events) does not fit in i64";

const CANONICAL_LEN_OUTSIDE_I64: &str = "canonical byte length does not fit in i64";

const KEY_ORDER_UNSUPPORTED: &str = "sorted() cannot order these key types";

const GUARDIAN_LEN_OUTSIDE_I64: &str = "len(guardian_history) does not fit in i64";

const LINK_SHAPE: &str = "links entry is missing kind or target";

/// Failure from [`_process_rollout_record`].
///
/// [`Display`] is the inner message. [`Self::ContentHash`] is
/// [`compute_content_hash`]. [`Self::RecordHash`] is the uncaught
/// `canonical_bytes` call that would have built `source_record_hash`.
/// Neither arm appends a finding or an event. [`Self::RecordHash`] does not
/// call `check_event`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessRolloutRecordError {
    /// `len(events)` does not fit in `i64`.
    SeqIndex,
    /// A successful canonical encoding whose length does not fit in `i64`.
    CanonicalLen,
    /// `str()` is not available for this value.
    Unrendered,
    /// `register_real` or `register_synthetic`.
    Collision(AdapterError),
    /// [`_check_version`] failed.
    Version(CheckVersionError),
    /// [`_emit_sl302`] or [`UnknownMetadataTracker::findings`] failed.
    Finding(FindingError),
    /// [`_tool_input_payload`] failed, or `items()` raised.
    ToolInput(ToolInputError),
    /// `sorted()` cannot order these keys. `bool` is not an `int`.
    KeyOrder,
    /// `len(guardian_history)` does not fit in `i64`.
    Count,
    /// An existing `links` entry is not a `{kind, target}` dict.
    LinkShape,
    /// [`compute_content_hash`] failed. [`SessionEvent`] was not built.
    ContentHash(CanonicalUnavailable),
    /// `canonical_bytes` for `source_record_hash` failed.
    RecordHash(CanonicalUnavailable),
    /// `check_event` failed after a record hash was actually produced.
    CheckEvent(CheckEventError),
}

impl ProcessRolloutRecordError {
    /// The Python exception text, or the missing-codec seam.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::SeqIndex => EVENTS_LEN_OUTSIDE_I64,
            Self::CanonicalLen => CANONICAL_LEN_OUTSIDE_I64,
            Self::Unrendered => STR_UNRENDERED,
            Self::Collision(error) => error.message(),
            Self::Version(error) => error.message(),
            Self::Finding(error) => error.message(),
            Self::ToolInput(error) => error.message(),
            Self::KeyOrder => KEY_ORDER_UNSUPPORTED,
            Self::Count => GUARDIAN_LEN_OUTSIDE_I64,
            Self::LinkShape => LINK_SHAPE,
            Self::ContentHash(error) | Self::RecordHash(error) => error.message(),
            Self::CheckEvent(error) => error.message(),
        }
    }
}

impl fmt::Display for ProcessRolloutRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ProcessRolloutRecordError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Collision(error) => Some(error),
            Self::Version(error) => Some(error),
            Self::Finding(error) => Some(error),
            Self::ToolInput(error) => Some(error),
            Self::ContentHash(error) | Self::RecordHash(error) => Some(error),
            Self::CheckEvent(error) => Some(error),
            Self::SeqIndex
            | Self::CanonicalLen
            | Self::Unrendered
            | Self::KeyOrder
            | Self::Count
            | Self::LinkShape => None,
        }
    }
}

struct RecordLoc<'a> {
    path_str: &'a str,
    line_number: i64,
    rec_id: &'a str,
    coord: &'a [(&'static str, FindingValue)],
}

struct ProjectCtx<'a> {
    loc: &'a RecordLoc<'a>,
    findings: &'a mut Vec<Finding>,
    source_metadata: &'a mut SourceMetadata,
    unknown_metadata: Option<&'a mut UnknownMetadataTracker>,
}

struct Projection {
    actor: String,
    kind: String,
    correlation_id: Option<String>,
    execution_state: Option<String>,
    side_effects: Option<String>,
    payload: MapValue,
    codex: MapValue,
    extra: MapValue,
}

impl Projection {
    fn new(codex: MapValue) -> Self {
        Self {
            actor: "system".to_owned(),
            kind: "unknown".to_owned(),
            correlation_id: None,
            execution_state: None,
            side_effects: None,
            payload: MapValue::new(Vec::new()),
            codex,
            extra: MapValue::new(Vec::new()),
        }
    }
}

struct FinishInput {
    seq_index: i64,
    line_number: i64,
    seen: bool,
    ordinal_out: Option<i64>,
    ts: String,
    parent_id: Option<String>,
    original_id: Option<String>,
    rec_id: String,
    projected: Projection,
}

struct GuardianMark {
    items: MetaValue,
    total: i64,
    truncated: bool,
}

/// Canonicalize one rollout envelope and stop at the content-hash seam.
///
/// Python: `_process_rollout_record`. The first [`canonical_bytes`] call is
/// caught: a failure uses payload length 0 and the function continues. A
/// real id is `payload.id` after `str` and `str.strip` when that text is
/// non-empty. Otherwise [`synthetic_event_id`] uses adapter `codex_rollout`,
/// `record_ordinal` or `len(events)`, and that length.
///
/// [`_check_version`], [`_emit_sl302`], [`_tool_input_payload`],
/// [`_normalize_timestamp`], and [`_version_field_name`] are the existing
/// helpers. Their errors are returned. A finding is not appended, and an
/// event is not appended after those errors. No fingerprint is hashed here.
///
/// `bool` is not an `int`. A boolean envelope ordinal does not have to equal
/// the previous ordinal plus one, and it is not returned as the envelope
/// ordinal. The same exclusion applies to usage counters, context pressure,
/// and `subagent_history_start_ordinal`.
///
/// [`compute_content_hash`] runs before [`SessionEvent`] is built. Its
/// Display is `sesslint._canonical_codec.payload_content_hash is not available`.
/// The later [`canonical_bytes`] call that builds `source_record_hash` is not
/// caught. Its Display is
/// `sesslint._canonical_codec.canonical_json_bytes is not available`. That arm
/// does not invent a sha256, does not append the event, and does not call
/// `check_event`.
///
/// # Errors
///
/// A sequence length or canonical length outside `i64`, an unrenderable
/// `str()`, a guard collision, [`_check_version`], [`_emit_sl302`],
/// [`_tool_input_payload`], unordered keys, a guardian length outside `i64`,
/// a malformed links entry, the content-hash seam, or the record-hash seam.
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
#[must_use = "the codec seam or the seen flag is the result"]
pub fn _process_rollout_record(
    envelope: &MapValue,
    line_number: i64,
    path_str: &str,
    events: &mut Vec<SessionEvent>,
    findings: &mut Vec<Finding>,
    source_metadata: &mut SourceMetadata,
    seen_version_sl301: bool,
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
    record_ordinal: Option<i64>,
    mut guard: Option<&mut SyntheticIdCollisionGuard>,
    last_event_id: Option<&str>,
    last_envelope_ordinal: Option<i64>,
    gap_after_drop: bool,
    mut drift: Option<&mut DriftTracker>,
    unknown_metadata: Option<&mut UnknownMetadataTracker>,
) -> Result<(bool, Option<i64>), ProcessRolloutRecordError> {
    let seq_index = i64::try_from(events.len()).map_err(|_| ProcessRolloutRecordError::SeqIndex)?;
    let payload_len = canonical_payload_len(envelope)?;
    let env_type = owned_present(envelope, "type");
    let payload = owned_present(envelope, "payload");
    let (rec_id, original_id) = record_identity(
        &payload,
        seq_index,
        record_ordinal,
        path_str,
        payload_len,
        guard.as_deref_mut(),
    )?;
    if let Some(tracker) = drift.as_deref_mut() {
        observe_envelope(
            tracker,
            &env_type,
            line_number,
            &rec_id,
            record_ordinal,
            byte_offset,
            byte_end,
        );
    }
    let candidate = version_candidate(envelope, &payload);
    let seen = _check_version(
        &candidate,
        path_str,
        line_number,
        Some(&rec_id),
        findings,
        source_metadata,
        seen_version_sl301,
        byte_offset,
        byte_end,
        record_ordinal,
        guard.as_deref_mut(),
    )
    .map_err(ProcessRolloutRecordError::Version)?;
    note_drift_version(
        drift,
        seen,
        &candidate,
        envelope,
        &payload,
        line_number,
        &rec_id,
        record_ordinal,
        byte_offset,
        byte_end,
    );
    if let MetaValue::Map(map) = &payload {
        append_links(source_metadata, map, &rec_id, line_number)?;
    }
    append_record_size(source_metadata, byte_offset, byte_end);
    let coord = coordinate_pairs(byte_offset, byte_end, record_ordinal);
    let loc = RecordLoc {
        path_str,
        line_number,
        rec_id: &rec_id,
        coord: &coord,
    };
    let ordinal_value = owned_present(envelope, "ordinal");
    let mut projected = Projection::new(initial_codex(&env_type, &ordinal_value));
    {
        let mut ctx = ProjectCtx {
            loc: &loc,
            findings,
            source_metadata,
            unknown_metadata,
        };
        dispatch_envelope(&mut ctx, &mut projected, envelope, &env_type, &payload)?;
    }
    reject_unknown_critical(envelope, KNOWN_ENVELOPE_KEYS.as_slice(), &loc, findings)?;
    reject_payload_critical(&payload, &loc, findings)?;
    finish_record(
        events,
        guard,
        envelope,
        FinishInput {
            seq_index,
            line_number,
            seen,
            ordinal_out: envelope_ordinal(&ordinal_value),
            ts: record_timestamp(envelope),
            parent_id: contiguous_parent(
                last_event_id,
                gap_after_drop,
                last_envelope_ordinal,
                &ordinal_value,
            ),
            original_id,
            rec_id,
            projected,
        },
    )
}

fn canonical_payload_len(envelope: &MapValue) -> Result<i64, ProcessRolloutRecordError> {
    match canonical_bytes(envelope) {
        Err(_unavailable) => Ok(0),
        Ok(bytes) => i64::try_from(bytes.len()).map_err(|_| ProcessRolloutRecordError::CanonicalLen),
    }
}

/// `source_record_hash` from the uncaught [`canonical_bytes`] call.
///
/// Both arms return [`ProcessRolloutRecordError::RecordHash`]. The Display is
/// `sesslint._canonical_codec.canonical_json_bytes is not available`. The
/// bytes are not passed to sha256.
fn source_record_hash(envelope: &MapValue) -> Result<String, ProcessRolloutRecordError> {
    match canonical_bytes(envelope) {
        Err(error) => Err(ProcessRolloutRecordError::RecordHash(error)),
        Ok(_bytes) => Err(ProcessRolloutRecordError::RecordHash(
            CanonicalUnavailable::canonical_json_bytes(),
        )),
    }
}

fn finish_record(
    events: &mut Vec<SessionEvent>,
    guard: Option<&mut SyntheticIdCollisionGuard>,
    envelope: &MapValue,
    input: FinishInput,
) -> Result<(bool, Option<i64>), ProcessRolloutRecordError> {
    let FinishInput {
        seq_index,
        line_number,
        seen,
        ordinal_out,
        ts,
        parent_id,
        original_id,
        rec_id,
        projected,
    } = input;
    let Projection {
        actor,
        kind,
        correlation_id,
        execution_state,
        side_effects,
        payload,
        codex,
        mut extra,
    } = projected;
    push_entry(&mut extra, "codex", MetaValue::Map(codex));
    let payload_node = meta_to_payload(&MetaValue::Map(payload))?;
    let content_hash = match compute_content_hash(&payload_node) {
        Err(error) => return Err(ProcessRolloutRecordError::ContentHash(error)),
        Ok(digest) => digest,
    };
    let record_hash = source_record_hash(envelope)?;
    let extra_node = meta_to_payload(&MetaValue::Map(extra))?;
    let mut event = SessionEvent::new(rec_id, parent_id, seq_index, ts, actor, kind);
    event.payload = payload_node;
    event.content_hash = Some(content_hash);
    event.correlation_id = correlation_id;
    event.execution_state = execution_state;
    event.source_line = Some(line_number);
    event.source_record_hash = Some(record_hash);
    event.original_id = original_id;
    event.source_adapter = Some("codex-rollout".to_owned());
    event.side_effects = side_effects;
    event.extra_fields = extra_node;
    events.push(event);
    if let Some(guard) = guard {
        guard
            .check_event()
            .map_err(ProcessRolloutRecordError::CheckEvent)?;
    }
    Ok((seen, ordinal_out))
}

fn record_identity(
    payload: &MetaValue,
    seq_index: i64,
    record_ordinal: Option<i64>,
    path_str: &str,
    payload_len: i64,
    guard: Option<&mut SyntheticIdCollisionGuard>,
) -> Result<(String, Option<String>), ProcessRolloutRecordError> {
    if let Some(real_id) = real_payload_id(payload)? {
        if let Some(guard) = guard {
            guard
                .register_real(&real_id)
                .map_err(ProcessRolloutRecordError::Collision)?;
        }
        return Ok((real_id.clone(), Some(real_id)));
    }
    let ordinal = record_ordinal.unwrap_or(seq_index);
    let minted = synthetic_event_id("codex_rollout", ordinal, path_str, payload_len);
    if let Some(guard) = guard {
        guard
            .register_synthetic(&minted)
            .map_err(ProcessRolloutRecordError::Collision)?;
    }
    Ok((minted, None))
}

fn real_payload_id(payload: &MetaValue) -> Result<Option<String>, ProcessRolloutRecordError> {
    let MetaValue::Map(map) = payload else {
        return Ok(None);
    };
    let Some(raw) = present(map, "id") else {
        return Ok(None);
    };
    let rendered = meta_str(raw)?;
    let stripped = python_strip(&rendered);
    if stripped.is_empty() {
        Ok(None)
    } else {
        Ok(Some(stripped.to_owned()))
    }
}

fn observe_envelope(
    drift: &mut DriftTracker,
    env_type: &MetaValue,
    line: i64,
    record_id: &str,
    record_ordinal: Option<i64>,
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
) {
    let raw = match env_type {
        MetaValue::Str(text) => PyValue::Str(text),
        _ => PyValue::None,
    };
    drift.observe_signature(
        raw,
        Some(line),
        Some(record_id),
        record_ordinal,
        byte_offset,
        byte_end,
    );
}

fn version_candidate(envelope: &MapValue, payload: &MetaValue) -> MetaValue {
    if let Some(value) = or_chain(envelope, ENVELOPE_VERSION_KEYS.as_slice()) {
        return value.clone();
    }
    if let MetaValue::Map(map) = payload {
        if let Some(value) = or_chain(map, PAYLOAD_VERSION_KEYS.as_slice()) {
            return value.clone();
        }
    }
    MetaValue::Null
}

/// Python `or` across `dict.get`. A missing key is `None` and replaces a
/// previous falsy operand. `None` is not a stored falsy value.
fn or_chain<'a>(map: &'a MapValue, keys: &[&str]) -> Option<&'a MetaValue> {
    let mut current: Option<&'a MetaValue> = None;
    for key in keys {
        if current.is_some_and(is_truthy) {
            break;
        }
        current = last_string_value(map, key);
    }
    match current {
        Some(MetaValue::Null) | None => None,
        Some(value) => Some(value),
    }
}

#[allow(clippy::too_many_arguments)] // same coordinate list as observe_version
fn note_drift_version(
    drift: Option<&mut DriftTracker>,
    seen: bool,
    candidate: &MetaValue,
    envelope: &MapValue,
    payload: &MetaValue,
    line: i64,
    record_id: &str,
    record_ordinal: Option<i64>,
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
) {
    let Some(drift) = drift else {
        return;
    };
    if seen {
        drift.note_unsupported_version();
        return;
    }
    let Some(rendered) = version_scalar_text(candidate) else {
        return;
    };
    let normalized = normalize_version(python_strip(&rendered));
    let field = _version_field_name(envelope, payload);
    drift.observe_version(
        &normalized,
        supported_version(&normalized),
        &field,
        Some(line),
        Some(record_id),
        record_ordinal,
        byte_offset,
        byte_end,
    );
}

fn append_links(
    source_metadata: &mut SourceMetadata,
    payload: &MapValue,
    record_id: &str,
    line: i64,
) -> Result<(), ProcessRolloutRecordError> {
    let existing = match source_metadata.get("links") {
        Some(MetaValue::List(items)) => items.clone(),
        _ => return Ok(()),
    };
    let mut links = Vec::with_capacity(existing.len());
    for item in &existing {
        links.push(link_from_meta(item)?);
    }
    extract_links(
        &payload_objects(payload),
        &mut links,
        Some(record_id),
        Some(line),
    );
    let stored = links.into_iter().map(link_to_meta).collect();
    source_metadata.insert("links", MetaValue::List(stored));
    Ok(())
}

fn link_from_meta(value: &MetaValue) -> Result<Link, ProcessRolloutRecordError> {
    let MetaValue::Map(map) = value else {
        return Err(ProcessRolloutRecordError::LinkShape);
    };
    let Some(kind) = cloned_str(present(map, "kind")) else {
        return Err(ProcessRolloutRecordError::LinkShape);
    };
    let Some(target) = cloned_str(present(map, "target")) else {
        return Err(ProcessRolloutRecordError::LinkShape);
    };
    let record_id = match present(map, "record_id") {
        Some(MetaValue::Str(text)) => Some(text.clone()),
        None => None,
        Some(_) => return Err(ProcessRolloutRecordError::LinkShape),
    };
    let line = match present(map, "line") {
        Some(MetaValue::Int(number)) => Some(*number),
        None => None,
        Some(_) => return Err(ProcessRolloutRecordError::LinkShape),
    };
    Ok(Link {
        kind,
        target,
        record_id,
        line,
    })
}

fn link_to_meta(link: Link) -> MetaValue {
    MetaValue::Map(map_value([
        ("kind", MetaValue::Str(link.kind)),
        ("target", MetaValue::Str(link.target)),
        (
            "record_id",
            match link.record_id {
                Some(text) => MetaValue::Str(text),
                None => MetaValue::Null,
            },
        ),
        (
            "line",
            match link.line {
                Some(number) => MetaValue::Int(number),
                None => MetaValue::Null,
            },
        ),
    ]))
}

fn payload_objects(map: &MapValue) -> BTreeMap<String, ObjectValue> {
    let mut objects = BTreeMap::new();
    for (key, value) in &map.entries {
        let MapKey::Str(text) = key else {
            continue;
        };
        objects.insert(text.clone(), object_value(value));
    }
    objects
}

fn object_value(value: &MetaValue) -> ObjectValue {
    match value {
        MetaValue::Str(text) => ObjectValue::Str(text.clone()),
        MetaValue::Int(number) => ObjectValue::Int(*number),
        MetaValue::Bool(flag) => ObjectValue::Bool(*flag),
        _ => ObjectValue::Other,
    }
}

fn append_record_size(source_metadata: &mut SourceMetadata, start: Option<i64>, end: Option<i64>) {
    let (Some(start), Some(end)) = (start, end) else {
        return;
    };
    if end < start {
        return;
    }
    let Some(size) = end.checked_sub(start) else {
        return;
    };
    let Some(MetaValue::List(items)) = source_metadata.get_mut("record_sizes") else {
        return;
    };
    items.push(MetaValue::Int(size));
}

fn dispatch_envelope(
    ctx: &mut ProjectCtx<'_>,
    projected: &mut Projection,
    envelope: &MapValue,
    env_type: &MetaValue,
    payload: &MetaValue,
) -> Result<(), ProcessRolloutRecordError> {
    match env_type {
        MetaValue::Str(text) if text == "response_item" => {
            project_response_item(ctx, projected, payload)
        }
        MetaValue::Str(text) if text == "compacted" => project_compacted(projected, payload),
        MetaValue::Str(text) if ENVELOPE_OPAQUE_TYPES.contains(&text.as_str()) => {
            project_opaque(ctx, projected, text, payload)
        }
        MetaValue::Str(text) if !text.is_empty() && !envelope_is_semantic(envelope) => {
            note_unknown(ctx, text)?;
            projected.actor = "system".to_owned();
            projected.kind = "opaque".to_owned();
            projected.payload = map_value([("type", MetaValue::Str(text.clone()))]);
            Ok(())
        }
        other => {
            emit_at(ctx.loc, "type", other, ctx.findings)?;
            projected.actor = "system".to_owned();
            projected.kind = "unknown".to_owned();
            projected.payload = map_value([("type", MetaValue::Str(type_label(other)?))]);
            Ok(())
        }
    }
}

fn project_response_item(
    ctx: &mut ProjectCtx<'_>,
    projected: &mut Projection,
    payload: &MetaValue,
) -> Result<(), ProcessRolloutRecordError> {
    let MetaValue::Map(payload_map) = payload else {
        emit_at(ctx.loc, "payload", payload, ctx.findings)?;
        projected.payload = map_value([("type", MetaValue::Str("<invalid>".to_owned()))]);
        return Ok(());
    };
    let item_type = owned_present(payload_map, "type");
    if let MetaValue::Str(text) = &item_type {
        push_entry(
            &mut projected.codex,
            "item_type",
            MetaValue::Str(text.clone()),
        );
        if text == "reasoning" {
            mark_reasoning(&mut projected.codex, payload_map);
        }
    }
    classify_item(ctx, projected, payload_map, &item_type)?;
    match projected.kind.as_str() {
        "message" => project_message(payload_map, &item_type, projected)?,
        "tool_call" => project_tool_call(payload_map, ctx.loc.rec_id, projected)?,
        "tool_result" => project_tool_result(payload_map, projected)?,
        "opaque" => {
            let label = match &item_type {
                MetaValue::Str(text) => text.clone(),
                other => meta_str(other)?,
            };
            projected.payload = map_value([("type", MetaValue::Str(label))]);
        }
        _ => {}
    }
    Ok(())
}

fn classify_item(
    ctx: &mut ProjectCtx<'_>,
    projected: &mut Projection,
    payload: &MapValue,
    item_type: &MetaValue,
) -> Result<(), ProcessRolloutRecordError> {
    if let Some((actor, kind)) = mapped_item(item_type) {
        projected.actor = actor.to_owned();
        projected.kind = kind.to_owned();
        return Ok(());
    }
    if let MetaValue::Str(text) = item_type {
        if !text.is_empty() && !map_is_semantic(payload) {
            projected.actor = "system".to_owned();
            projected.kind = "opaque".to_owned();
            note_unknown(ctx, text)?;
            projected.payload = map_value([("type", MetaValue::Str(text.clone()))]);
            return Ok(());
        }
    }
    emit_at(ctx.loc, "type", item_type, ctx.findings)?;
    projected.payload = map_value([("type", MetaValue::Str(type_label(item_type)?))]);
    Ok(())
}

fn mapped_item(item_type: &MetaValue) -> Option<(&'static str, &'static str)> {
    let MetaValue::Str(text) = item_type else {
        return None;
    };
    RESPONSE_ITEM_TYPE_MAP
        .iter()
        .find(|(name, _, _)| *name == text)
        .map(|(_, actor, kind)| (*actor, *kind))
}

fn project_message(
    payload: &MapValue,
    item_type: &MetaValue,
    projected: &mut Projection,
) -> Result<(), ProcessRolloutRecordError> {
    assign_message_actor(payload, item_type, &mut projected.actor);
    let mut out = map_value([
        ("content", owned_present(payload, "content")),
        ("role", MetaValue::Str(projected.actor.clone())),
    ]);
    if let Some(phase) = present(payload, "phase") {
        push_entry(&mut out, "phase", phase.clone());
    }
    if is_text(item_type, "agent_message") {
        if let Some(author) = present(payload, "author") {
            push_entry(&mut out, "author", MetaValue::Str(meta_str(author)?));
        }
        if let Some(recipient) = present(payload, "recipient") {
            push_entry(&mut out, "recipient", MetaValue::Str(meta_str(recipient)?));
        }
    }
    projected.payload = out;
    Ok(())
}

fn assign_message_actor(payload: &MapValue, item_type: &MetaValue, actor: &mut String) {
    if is_text(item_type, "agent_message") {
        *actor = "assistant".to_owned();
        return;
    }
    match present(payload, "role") {
        Some(MetaValue::Str(role)) if role == "user" => *actor = "user".to_owned(),
        Some(MetaValue::Str(role)) if role == "assistant" => *actor = "assistant".to_owned(),
        Some(MetaValue::Str(role)) if role == "developer" => *actor = "system".to_owned(),
        Some(_) => *actor = "system".to_owned(),
        None => {}
    }
}

fn project_tool_call(
    payload: &MapValue,
    rec_id: &str,
    projected: &mut Projection,
) -> Result<(), ProcessRolloutRecordError> {
    let raw = call_raw(payload);
    let call_id = match raw {
        Some(value) => meta_str(value)?,
        None => rec_id.to_owned(),
    };
    projected.correlation_id = Some(call_id.clone());
    push_entry(&mut projected.codex, "call_id", declared_call_id(raw));
    let tool_name = tool_name_of(payload)?;
    let absent = MetaValue::Null;
    let raw_input = first_present(payload, &["arguments", "args", "input"]).unwrap_or(&absent);
    let input = _tool_input_payload(raw_input).map_err(ProcessRolloutRecordError::ToolInput)?;
    projected.payload = map_value([
        ("call_id", MetaValue::Str(call_id.clone())),
        ("input", input),
        ("name", MetaValue::Str(tool_name.clone())),
        ("tool_name", MetaValue::Str(tool_name.clone())),
        ("tool_use_id", MetaValue::Str(call_id)),
    ]);
    if let Some(status) = present(payload, "status") {
        projected.execution_state = Some(execution_state_of(&meta_str(status)?));
    }
    projected.side_effects = Some(side_effects_for(&tool_name).to_owned());
    Ok(())
}

fn project_tool_result(
    payload: &MapValue,
    projected: &mut Projection,
) -> Result<(), ProcessRolloutRecordError> {
    let raw = call_raw(payload);
    let call_id = match raw {
        Some(value) => meta_str(value)?,
        None => String::new(),
    };
    projected.correlation_id = if call_id.is_empty() {
        None
    } else {
        Some(call_id.clone())
    };
    push_entry(&mut projected.codex, "call_id", declared_call_id(raw));
    let content = match first_present(payload, &["output", "content", "result", "tools"]) {
        Some(value) => value.clone(),
        None => MetaValue::Str(String::new()),
    };
    let is_err = error_flag(payload);
    projected.payload = map_value([
        ("call_id", MetaValue::Str(call_id.clone())),
        ("content", content),
        ("is_error", MetaValue::Bool(is_err)),
        ("tool_use_id", MetaValue::Str(call_id)),
    ]);
    projected.execution_state = Some(if is_err { "failure" } else { "success" }.to_owned());
    projected.side_effects = Some("none".to_owned());
    Ok(())
}

fn project_compacted(
    projected: &mut Projection,
    payload: &MetaValue,
) -> Result<(), ProcessRolloutRecordError> {
    projected.actor = "system".to_owned();
    projected.kind = "compaction_boundary".to_owned();
    let MetaValue::Map(payload_map) = payload else {
        projected.payload = map_value([("summary", MetaValue::Str(String::new()))]);
        return Ok(());
    };
    let summary = match present(payload_map, "message").or_else(|| present(payload_map, "summary"))
    {
        Some(raw) => meta_str(raw)?,
        None => String::new(),
    };
    let mut out = map_value([("summary", MetaValue::Str(summary))]);
    for key in [
        "window_id",
        "window_number",
        "first_window_id",
        "previous_window_id",
    ] {
        if let Some(value) = present(payload_map, key) {
            push_entry(&mut out, key, value.clone());
        }
    }
    projected.payload = out;
    if let Some(mark) = guardian_mark(present(payload_map, "guardian_history"))? {
        push_entry(&mut projected.codex, "guardian_items", mark.items);
        push_entry(
            &mut projected.codex,
            "guardian_items_total",
            MetaValue::Int(mark.total),
        );
        if mark.truncated {
            push_entry(
                &mut projected.codex,
                "guardian_items_truncated",
                MetaValue::Bool(true),
            );
        }
    }
    Ok(())
}

fn project_opaque(
    ctx: &mut ProjectCtx<'_>,
    projected: &mut Projection,
    env_type: &str,
    payload: &MetaValue,
) -> Result<(), ProcessRolloutRecordError> {
    projected.actor = "system".to_owned();
    projected.kind = "opaque".to_owned();
    projected.payload = map_value([("type", MetaValue::Str(env_type.to_owned()))]);
    let MetaValue::Map(payload_map) = payload else {
        return Ok(());
    };
    if env_type == "token_usage_record" {
        if let Some(slot) = usage_slot(payload_map)? {
            push_entry(&mut projected.extra, "usage", MetaValue::Map(slot));
        }
    }
    if env_type == "session_meta" {
        apply_session_meta(ctx.source_metadata, payload_map, projected)?;
    } else if env_type == "retained_context" {
        apply_retained(payload_map, &mut projected.payload);
    } else if env_type == "turn_context" {
        apply_turn(payload_map, &mut projected.payload)?;
    } else if env_type == "event_msg" {
        apply_event_msg(payload_map, projected)?;
    }
    Ok(())
}

fn apply_session_meta(
    source_metadata: &mut SourceMetadata,
    payload: &MapValue,
    projected: &mut Projection,
) -> Result<(), ProcessRolloutRecordError> {
    let mut meta = MapValue::new(Vec::new());
    for key in ["session_id", "cli_version", "model_provider", "originator"] {
        if let Some(value) = present(payload, key) {
            push_entry(&mut meta, key, value.clone());
        }
    }
    source_metadata.set_attribute("session_meta", MetaValue::Map(meta));
    if let Some(session_id) = present(payload, "session_id") {
        push_entry(
            &mut projected.payload,
            "session_id",
            MetaValue::Str(meta_str(session_id)?),
        );
    }
    if source_metadata.get("session_id").is_none() {
        if let Some(stored) = thread_session_id(payload)? {
            source_metadata.insert("session_id", MetaValue::Str(stored));
        }
    }
    if let Some(number) = subagent_ordinal(payload) {
        push_entry(
            &mut projected.codex,
            "subagent_history_start_ordinal",
            MetaValue::Int(number),
        );
    }
    Ok(())
}

fn thread_session_id(payload: &MapValue) -> Result<Option<String>, ProcessRolloutRecordError> {
    if let Some(raw) = present(payload, "id") {
        if let Some(text) = str_or_int(raw) {
            let stripped = python_strip(&text);
            if !stripped.is_empty() {
                return Ok(Some(stripped.to_owned()));
            }
        }
    }
    if let Some(raw) = present(payload, "session_id") {
        return Ok(Some(python_strip(&meta_str(raw)?).to_owned()));
    }
    Ok(None)
}

/// `str` or `int`, with `bool` excluded.
fn str_or_int(value: &MetaValue) -> Option<String> {
    match value {
        MetaValue::Str(text) => Some(text.clone()),
        MetaValue::Int(number) => Some(number.to_string()),
        _ => None,
    }
}

/// Inherited-prefix ordinal. `bool` is not an `int`.
fn subagent_ordinal(payload: &MapValue) -> Option<i64> {
    match present(payload, "subagent_history_start_ordinal") {
        Some(MetaValue::Int(number)) => Some(*number),
        _ => None,
    }
}

fn apply_retained(payload: &MapValue, out_payload: &mut MapValue) {
    if let Some(text) = cloned_str(present(payload, "type")) {
        push_entry(out_payload, "subtype", MetaValue::Str(text));
    }
    if let Some(text) = cloned_str(present(payload, "turn_id")) {
        push_entry(out_payload, "turn_id", MetaValue::Str(text));
    }
}

fn apply_turn(
    payload: &MapValue,
    out_payload: &mut MapValue,
) -> Result<(), ProcessRolloutRecordError> {
    if let Some(raw) = present(payload, "turn_id") {
        push_entry(out_payload, "turn_id", MetaValue::Str(meta_str(raw)?));
    }
    Ok(())
}

fn apply_event_msg(
    payload: &MapValue,
    projected: &mut Projection,
) -> Result<(), ProcessRolloutRecordError> {
    if let Some(raw) = present(payload, "type") {
        push_entry(
            &mut projected.payload,
            "subtype",
            MetaValue::Str(meta_str(raw)?),
        );
    }
    if let Some(raw) = present(payload, "turn_id") {
        push_entry(
            &mut projected.payload,
            "turn_id",
            MetaValue::Str(meta_str(raw)?),
        );
    }
    if is_text_at(payload, "type", "token_count") {
        if let Some(pressure) = context_pressure(payload) {
            push_entry(
                &mut projected.codex,
                "context_pressure",
                MetaValue::Map(pressure),
            );
        }
    }
    Ok(())
}

fn usage_slot(payload: &MapValue) -> Result<Option<MapValue>, ProcessRolloutRecordError> {
    let Some(contribution_raw) = present(payload, "usage") else {
        return Ok(None);
    };
    let mut slot = MapValue::new(Vec::new());
    if let MetaValue::Map(map) = contribution_raw {
        push_entry(
            &mut slot,
            "contribution",
            MetaValue::Map(int_counter_map(map)?),
        );
    }
    if let Some(MetaValue::Map(map)) = present(payload, "thread_token_usage") {
        push_entry(&mut slot, "cumulative", MetaValue::Map(int_counter_map(map)?));
    }
    if slot.entries.is_empty() {
        Ok(None)
    } else {
        Ok(Some(slot))
    }
}

/// Integer counters. `bool` values are skipped. A `bool` key is not an `int` key.
fn int_counter_map(map: &MapValue) -> Result<MapValue, ProcessRolloutRecordError> {
    if map.items_raise {
        return Err(ProcessRolloutRecordError::ToolInput(ToolInputError::Items));
    }
    let mut entries = Vec::new();
    for (key, value) in &map.entries {
        let MetaValue::Int(number) = value else {
            continue;
        };
        let text = key.text();
        if let Some((_, stored)) = entries.iter_mut().find(|(name, _)| name == &text) {
            *stored = *number;
        } else {
            entries.push((text, *number));
        }
    }
    Ok(MapValue::new(
        entries
            .into_iter()
            .map(|(key, number)| (MapKey::Str(key), MetaValue::Int(number)))
            .collect(),
    ))
}

/// Occupancy and window. Each must be an `int`. `bool` is excluded.
fn context_pressure(payload: &MapValue) -> Option<MapValue> {
    let MetaValue::Map(info) = present(payload, "info")? else {
        return None;
    };
    let occupancy = match present(info, "last_token_usage") {
        Some(MetaValue::Map(usage)) => match present(usage, "input_tokens") {
            Some(MetaValue::Int(number)) => Some(*number),
            _ => None,
        },
        _ => None,
    };
    let window = match present(info, "model_context_window") {
        Some(MetaValue::Int(number)) => Some(*number),
        _ => None,
    };
    match (occupancy, window) {
        (Some(occupancy), Some(window)) => Some(map_value([
            ("occupancy", MetaValue::Int(occupancy)),
            ("window", MetaValue::Int(window)),
        ])),
        _ => None,
    }
}

fn guardian_mark(
    history: Option<&MetaValue>,
) -> Result<Option<GuardianMark>, ProcessRolloutRecordError> {
    let Some(MetaValue::List(items)) = history else {
        return Ok(None);
    };
    let mut projected = Vec::new();
    for item in items.iter().take(GUARDIAN_SNAPSHOT_ITEM_CAP) {
        let MetaValue::Map(map) = item else {
            continue;
        };
        projected.push(MetaValue::Map(map_value([
            ("id", bounded_text(present(map, "id"), _GUARDIAN_ID_MAX)),
            ("type", bounded_text(present(map, "type"), 64)),
            (
                "call_id",
                bounded_text(present(map, "call_id"), _GUARDIAN_ID_MAX),
            ),
        ])));
    }
    let total = i64::try_from(items.len()).map_err(|_| ProcessRolloutRecordError::Count)?;
    Ok(Some(GuardianMark {
        items: MetaValue::List(projected),
        total,
        truncated: items.len() > GUARDIAN_SNAPSHOT_ITEM_CAP,
    }))
}

fn bounded_text(value: Option<&MetaValue>, max: usize) -> MetaValue {
    match value {
        Some(MetaValue::Str(text)) if text.chars().count() <= max => MetaValue::Str(text.clone()),
        _ => MetaValue::Null,
    }
}

fn mark_reasoning(codex: &mut MapValue, payload: &MapValue) {
    let encrypted = has_key(payload, "encrypted_content");
    push_entry(
        codex,
        "has_encrypted_content",
        MetaValue::Bool(encrypted),
    );
    let shape = if !has_key(payload, "content") {
        "absent"
    } else {
        match last_string_value(payload, "content") {
            Some(MetaValue::Null) | None => "null",
            Some(MetaValue::List(_)) => "array",
            _ => "other",
        }
    };
    push_entry(
        codex,
        "reasoning_content_shape",
        MetaValue::Str(shape.to_owned()),
    );
}

fn reject_payload_critical(
    payload: &MetaValue,
    loc: &RecordLoc<'_>,
    findings: &[Finding],
) -> Result<(), ProcessRolloutRecordError> {
    let MetaValue::Map(map) = payload else {
        return Ok(());
    };
    reject_unknown_critical(map, KNOWN_PAYLOAD_KEYS.as_slice(), loc, findings)
}

fn reject_unknown_critical(
    map: &MapValue,
    known: &[&str],
    loc: &RecordLoc<'_>,
    findings: &[Finding],
) -> Result<(), ProcessRolloutRecordError> {
    for key in sorted_string_keys(map)? {
        if !is_unknown_critical(&key, known) {
            continue;
        }
        let absent = MetaValue::Null;
        let value = last_string_value(map, &key).unwrap_or(&absent);
        emit_at(loc, &key, value, findings)?;
        break;
    }
    Ok(())
}

fn sorted_string_keys(map: &MapValue) -> Result<Vec<String>, ProcessRolloutRecordError> {
    let mut keys = Vec::new();
    for (key, _) in &map.entries {
        let MapKey::Str(text) = key else {
            return Err(ProcessRolloutRecordError::KeyOrder);
        };
        if !keys.iter().any(|existing| existing == text) {
            keys.push(text.clone());
        }
    }
    keys.sort_unstable();
    Ok(keys)
}

fn is_unknown_critical(key: &str, known: &[&str]) -> bool {
    if known.contains(&key) {
        return false;
    }
    CRITICAL_KEYS.contains(&key)
        || key.starts_with("critical_")
        || key.starts_with("unknown_critical")
}

fn note_unknown(ctx: &mut ProjectCtx<'_>, raw_type: &str) -> Result<(), ProcessRolloutRecordError> {
    if let Some(tracker) = ctx.unknown_metadata.as_deref_mut() {
        tracker.note(raw_type, ctx.loc.line_number);
        return Ok(());
    }
    let mut tracker = UnknownMetadataTracker::new();
    tracker.note(raw_type, ctx.loc.line_number);
    let extra = tracker
        .findings(ctx.loc.path_str)
        .map_err(ProcessRolloutRecordError::Finding)?;
    ctx.findings.extend(extra);
    Ok(())
}

fn emit_at(
    loc: &RecordLoc<'_>,
    field_path: &str,
    type_value: &MetaValue,
    findings: &[Finding],
) -> Result<(), ProcessRolloutRecordError> {
    _emit_sl302(
        loc.path_str,
        loc.line_number,
        loc.rec_id,
        field_path,
        type_value,
        loc.coord,
        findings,
    )
    .map_err(ProcessRolloutRecordError::Finding)
}

/// Parent id when continuity is provable.
///
/// `bool` is not an `int`, so a boolean ordinal does not have to equal
/// `previous + 1`.
fn contiguous_parent(
    last_event_id: Option<&str>,
    gap_after_drop: bool,
    last_envelope_ordinal: Option<i64>,
    current: &MetaValue,
) -> Option<String> {
    if !ordinals_contiguous(
        last_event_id.is_some(),
        gap_after_drop,
        last_envelope_ordinal,
        current,
    ) {
        return None;
    }
    last_event_id.map(str::to_owned)
}

fn ordinals_contiguous(
    has_last: bool,
    gap_after_drop: bool,
    last_envelope_ordinal: Option<i64>,
    current: &MetaValue,
) -> bool {
    if !has_last || gap_after_drop {
        return false;
    }
    let Some(previous) = last_envelope_ordinal else {
        return true;
    };
    match current {
        MetaValue::Int(number) => i128::from(*number) == i128::from(previous) + 1,
        MetaValue::Bool(_)
        | MetaValue::Null
        | MetaValue::Float(_)
        | MetaValue::Str(_)
        | MetaValue::Bytes(_)
        | MetaValue::List(_)
        | MetaValue::Tuple(_)
        | MetaValue::Map(_)
        | MetaValue::Set(_)
        | MetaValue::Object(_) => true,
    }
}

/// Returned envelope ordinal. `bool` is not an `int`.
fn envelope_ordinal(value: &MetaValue) -> Option<i64> {
    match value {
        MetaValue::Int(number) => Some(*number),
        MetaValue::Bool(_)
        | MetaValue::Null
        | MetaValue::Float(_)
        | MetaValue::Str(_)
        | MetaValue::Bytes(_)
        | MetaValue::List(_)
        | MetaValue::Tuple(_)
        | MetaValue::Map(_)
        | MetaValue::Set(_)
        | MetaValue::Object(_) => None,
    }
}

fn record_timestamp(envelope: &MapValue) -> String {
    let raw = present(envelope, "timestamp")
        .or_else(|| present(envelope, "ts"))
        .or_else(|| present(envelope, "created_at"));
    match raw {
        Some(value) => _normalize_timestamp(py_of(value)),
        None => _normalize_timestamp(PyValue::None),
    }
}

fn initial_codex(env_type: &MetaValue, ordinal: &MetaValue) -> MapValue {
    map_value([
        ("durable", MetaValue::Bool(is_durable(env_type))),
        (
            "ordinal",
            match ordinal {
                MetaValue::Int(number) => MetaValue::Int(*number),
                _ => MetaValue::Null,
            },
        ),
        (
            "envelope_type",
            match env_type {
                MetaValue::Str(text) => MetaValue::Str(text.clone()),
                _ => MetaValue::Null,
            },
        ),
    ])
}

fn is_durable(env_type: &MetaValue) -> bool {
    match env_type {
        MetaValue::Str(text) => DURABLE_ENVELOPE_TYPES.contains(&text.as_str()),
        _ => false,
    }
}

fn call_raw(payload: &MapValue) -> Option<&MetaValue> {
    present(payload, "call_id").or_else(|| present(payload, "tool_call_id"))
}

fn declared_call_id(raw: Option<&MetaValue>) -> MetaValue {
    match raw {
        Some(MetaValue::Str(text)) if text.chars().count() <= _GUARDIAN_ID_MAX => {
            MetaValue::Str(text.clone())
        }
        _ => MetaValue::Null,
    }
}

fn tool_name_of(payload: &MapValue) -> Result<String, ProcessRolloutRecordError> {
    match present(payload, "name") {
        Some(value) if is_truthy(value) => meta_str(value),
        _ => Ok(String::new()),
    }
}

fn execution_state_of(status: &str) -> String {
    match status {
        "completed" => "success".to_owned(),
        "failed" => "failure".to_owned(),
        _ => "unknown".to_owned(),
    }
}

fn side_effects_for(tool_name: &str) -> &'static str {
    let lower = tool_name.to_lowercase();
    if READ_ONLY_TOOL_NAMES.contains(&lower.as_str()) {
        "none"
    } else if MUTATING_TOOL_NAMES.contains(&lower.as_str()) {
        "possible"
    } else {
        "unknown"
    }
}

fn error_flag(payload: &MapValue) -> bool {
    if let Some(value) = present(payload, "is_error") {
        return is_truthy(value);
    }
    if let Some(value) = present(payload, "error") {
        return is_truthy(value);
    }
    false
}

fn coordinate_pairs(
    byte_offset: Option<i64>,
    byte_end: Option<i64>,
    record_ordinal: Option<i64>,
) -> Vec<(&'static str, FindingValue)> {
    let mut coord = Vec::new();
    if let Some(offset) = byte_offset {
        coord.push(("byte_offset", FindingValue::int(offset)));
    }
    if let Some(end) = byte_end {
        coord.push(("byte_end", FindingValue::int(end)));
    }
    if let Some(ordinal) = record_ordinal {
        coord.push(("record_ordinal", FindingValue::int(ordinal)));
    }
    coord
}

fn present<'a>(map: &'a MapValue, key: &str) -> Option<&'a MetaValue> {
    match last_string_value(map, key) {
        Some(value) if !matches!(value, MetaValue::Null) => Some(value),
        _ => None,
    }
}

fn owned_present(map: &MapValue, key: &str) -> MetaValue {
    present(map, key).cloned().unwrap_or(MetaValue::Null)
}

fn first_present<'a>(map: &'a MapValue, keys: &[&str]) -> Option<&'a MetaValue> {
    keys.iter().find_map(|key| present(map, key))
}

fn has_key(map: &MapValue, key: &str) -> bool {
    map.entries
        .iter()
        .any(|(name, _)| matches!(name, MapKey::Str(text) if text == key))
}

fn is_text(value: &MetaValue, expected: &str) -> bool {
    matches!(value, MetaValue::Str(text) if text == expected)
}

fn is_text_at(map: &MapValue, key: &str, expected: &str) -> bool {
    present(map, key).is_some_and(|value| is_text(value, expected))
}

fn cloned_str(value: Option<&MetaValue>) -> Option<String> {
    match value {
        Some(MetaValue::Str(text)) => Some(text.clone()),
        _ => None,
    }
}

fn type_label(value: &MetaValue) -> Result<String, ProcessRolloutRecordError> {
    if matches!(value, MetaValue::Null) {
        Ok("<missing>".to_owned())
    } else {
        meta_str(value)
    }
}

fn meta_str(value: &MetaValue) -> Result<String, ProcessRolloutRecordError> {
    match value {
        MetaValue::Str(text) => Ok(text.clone()),
        MetaValue::Null => Ok("None".to_owned()),
        MetaValue::Bool(true) => Ok("True".to_owned()),
        MetaValue::Bool(false) => Ok("False".to_owned()),
        MetaValue::Int(number) => Ok(number.to_string()),
        MetaValue::Float(bits) => Ok(python_float_str(f64::from_bits(*bits))),
        MetaValue::List(_)
        | MetaValue::Tuple(_)
        | MetaValue::Map(_)
        | MetaValue::Bytes(_)
        | MetaValue::Set(_)
        | MetaValue::Object(_) => Err(ProcessRolloutRecordError::Unrendered),
    }
}

fn map_value<const N: usize>(entries: [(&str, MetaValue); N]) -> MapValue {
    MapValue::new(
        entries
            .into_iter()
            .map(|(key, value)| (MapKey::Str(key.to_owned()), value))
            .collect(),
    )
}

fn push_entry(map: &mut MapValue, key: &str, value: MetaValue) {
    map.entries
        .push((MapKey::Str(key.to_owned()), value));
}

fn envelope_is_semantic(envelope: &MapValue) -> bool {
    has_semantic_fields(&MetadataValue::Map(metadata_entries(envelope)))
}

fn map_is_semantic(map: &MapValue) -> bool {
    has_semantic_fields(&MetadataValue::Map(metadata_entries(map)))
}

fn metadata_entries(map: &MapValue) -> Vec<(MetadataKey, MetadataValue)> {
    map.entries
        .iter()
        .map(|(key, value)| {
            let name = match key {
                MapKey::Str(text) => MetadataKey::Str(text.clone()),
                _ => MetadataKey::NonStr,
            };
            (name, meta_to_metadata(value))
        })
        .collect()
}

fn meta_to_metadata(value: &MetaValue) -> MetadataValue {
    match value {
        MetaValue::Null => MetadataValue::NoneValue,
        MetaValue::List(items) => {
            MetadataValue::List(items.iter().map(meta_to_metadata).collect())
        }
        MetaValue::Map(map) => MetadataValue::Map(metadata_entries(map)),
        _ => MetadataValue::Scalar,
    }
}

fn meta_to_payload(value: &MetaValue) -> Result<Payload, ProcessRolloutRecordError> {
    match value {
        MetaValue::Null => Ok(Payload::null()),
        MetaValue::Bool(flag) => Ok(Payload::bool_value(*flag)),
        MetaValue::Int(number) => Ok(Payload::int(*number)),
        MetaValue::Float(bits) => Ok(Payload::float(f64::from_bits(*bits))),
        MetaValue::Str(text) => Ok(Payload::string(text.clone())),
        MetaValue::List(items) => {
            let mut converted = Vec::with_capacity(items.len());
            for item in items {
                converted.push(meta_to_payload(item)?);
            }
            Ok(Payload::list(converted))
        }
        MetaValue::Tuple(items) => {
            let mut converted = Vec::with_capacity(items.len());
            for item in items {
                converted.push(meta_to_payload(item)?);
            }
            Ok(Payload::tuple(converted))
        }
        MetaValue::Map(map) => {
            let mut converted = Vec::with_capacity(map.entries.len());
            for (key, item) in &map.entries {
                converted.push((map_key_payload(key), meta_to_payload(item)?));
            }
            Ok(Payload::map(converted))
        }
        MetaValue::Bytes(_) | MetaValue::Set(_) | MetaValue::Object(_) => {
            Err(ProcessRolloutRecordError::Unrendered)
        }
    }
}

fn map_key_payload(key: &MapKey) -> Payload {
    match key {
        MapKey::Str(text) | MapKey::Rendered(text) => Payload::string(text.clone()),
        MapKey::Int(number) => Payload::int(*number),
        MapKey::Bool(flag) => Payload::bool_value(*flag),
        MapKey::Null => Payload::null(),
        MapKey::Float(bits) => Payload::float(f64::from_bits(*bits)),
    }
}

fn py_of(value: &MetaValue) -> PyValue<'_> {
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

/// Synthetic envelopes only. No session payload from a real transcript.
#[cfg(test)]
mod process_rollout_tests {
    use super::{
        _process_rollout_record, canonical_payload_len, context_pressure, contiguous_parent,
        envelope_ordinal, guardian_mark, int_counter_map, ordinals_contiguous, record_timestamp,
        side_effects_for, source_record_hash, subagent_ordinal, ProcessRolloutRecordError,
        ToolInputError,
    };
    use crate::drift::DriftTracker;
    use crate::metadata::UnknownMetadataTracker;
    use crate::openai_agents::{
        MapKey, MapValue, MetaValue, SourceMetadata, STRICT_JSON_DECODE_UNAVAILABLE, STR_UNRENDERED,
    };
    use crate::synthetic::{synthetic_event_id, SyntheticIdCollisionGuard};
    use model::canonical::{
        SessionEvent, CANONICAL_JSON_BYTES_UNAVAILABLE, PAYLOAD_CONTENT_HASH_UNAVAILABLE,
    };
    use model::codes::{Repairability, Severity};
    use model::finding::PyValue as FindingValue;
    use model::finding::{
        Finding, FindingInput, SourceLine, SourceRef, FINGERPRINT_CODEC_UNAVAILABLE, SCHEMA_VERSION,
    };

    const PATH: &str = "synthetic.jsonl";
    const LINE: i64 = 3;
    const EPOCH: &str = "1970-01-01T00:00:00Z";
    const KEPT: &str = "2020-01-01T00:00:00Z";

    struct Bag {
        meta: SourceMetadata,
        events: Vec<SessionEvent>,
        findings: Vec<Finding>,
        guard: SyntheticIdCollisionGuard,
    }

    struct Input<'a> {
        seen: bool,
        start: Option<i64>,
        end: Option<i64>,
        ordinal: Option<i64>,
        last_id: Option<&'a str>,
        last_ordinal: Option<i64>,
        gap: bool,
    }

    fn bag() -> Bag {
        Bag {
            meta: SourceMetadata::new(),
            events: Vec::new(),
            findings: Vec::new(),
            guard: SyntheticIdCollisionGuard::new(),
        }
    }

    fn input() -> Input<'static> {
        Input {
            seen: false,
            start: None,
            end: None,
            ordinal: None,
            last_id: None,
            last_ordinal: None,
            gap: false,
        }
    }

    fn run(
        bag: &mut Bag,
        envelope: &MapValue,
        input: Input<'_>,
        drift: Option<&mut DriftTracker>,
        unknown: Option<&mut UnknownMetadataTracker>,
    ) -> Result<(bool, Option<i64>), ProcessRolloutRecordError> {
        _process_rollout_record(
            envelope,
            LINE,
            PATH,
            &mut bag.events,
            &mut bag.findings,
            &mut bag.meta,
            input.seen,
            input.start,
            input.end,
            input.ordinal,
            Some(&mut bag.guard),
            input.last_id,
            input.last_ordinal,
            input.gap,
            drift,
            unknown,
        )
    }

    fn s(text: &str) -> MetaValue {
        MetaValue::Str(text.to_owned())
    }

    fn kv(key: &str, value: MetaValue) -> (MapKey, MetaValue) {
        (MapKey::Str(key.to_owned()), value)
    }

    fn typed(kind: &str, payload: MapValue) -> MapValue {
        MapValue::new(vec![
            kv("type", s(kind)),
            kv("payload", MetaValue::Map(payload)),
        ])
    }

    fn empty_payload(kind: &str) -> MapValue {
        typed(kind, MapValue::new(vec![]))
    }

    fn marker() -> Finding {
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

    fn hash_seam(err: &ProcessRolloutRecordError) {
        assert!(matches!(err, ProcessRolloutRecordError::ContentHash(_)));
        assert_eq!(err.to_string(), PAYLOAD_CONTENT_HASH_UNAVAILABLE);
        assert!(!err.to_string().contains("sha256"));
        assert_ne!(err.to_string(), CANONICAL_JSON_BYTES_UNAVAILABLE);
        assert_ne!(
            err.to_string(),
            "sesslint.canonical.SessionEvent is not available"
        );
    }

    fn version_seam(err: &ProcessRolloutRecordError) {
        assert!(matches!(err, ProcessRolloutRecordError::Version(_)));
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("sha256"));
    }

    fn finding_seam(err: &ProcessRolloutRecordError) {
        assert!(matches!(err, ProcessRolloutRecordError::Finding(_)));
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(!err.to_string().contains("sha256"));
    }

    fn raw(meta: &SourceMetadata) -> Option<&str> {
        match meta.get("version_raw") {
            Some(MetaValue::Str(text)) => Some(text.as_str()),
            Some(_) => panic!("version_raw is not a str"),
            None => None,
        }
    }

    fn entry<'a>(map: &'a MapValue, key: &str) -> &'a MetaValue {
        map.entries
            .iter()
            .rev()
            .find(|(name, _)| matches!(name, MapKey::Str(text) if text == key))
            .map(|(_, value)| value)
            .expect("entry")
    }

    fn text_at(map: &MapValue, key: &str) -> String {
        match entry(map, key) {
            MetaValue::Str(text) => text.clone(),
            _ => panic!("expected str"),
        }
    }

    fn stored_session(meta: &SourceMetadata) -> String {
        match meta.get("session_id") {
            Some(MetaValue::Str(text)) => text.clone(),
            _ => panic!("session_id"),
        }
    }

    fn sizes(meta: &SourceMetadata) -> Vec<i64> {
        let Some(MetaValue::List(items)) = meta.get("record_sizes") else {
            panic!("record_sizes");
        };
        items
            .iter()
            .map(|item| match item {
                MetaValue::Int(number) => *number,
                _ => panic!("size"),
            })
            .collect()
    }

    #[test]
    fn first_canonical_failure_continues_until_the_content_hash() {
        let envelope = empty_payload("event_msg");
        let mut held = bag();
        let err = run(&mut held, &envelope, input(), None, None).unwrap_err();
        hash_seam(&err);
        assert_eq!(canonical_payload_len(&envelope).expect("len"), 0);
        let expected = synthetic_event_id("codex_rollout", 0, PATH, 0);
        assert!(held.guard.seen_synthetic_ids().contains(&expected));
        assert!(held.events.is_empty());
        assert!(held.findings.is_empty());
    }

    #[test]
    fn source_record_hash_propagates_the_uncaught_codec() {
        let err = source_record_hash(&MapValue::new(vec![])).unwrap_err();
        assert!(matches!(err, ProcessRolloutRecordError::RecordHash(_)));
        assert_eq!(err.to_string(), CANONICAL_JSON_BYTES_UNAVAILABLE);
        assert!(!err.to_string().contains("sha256"));
        assert_ne!(err.to_string(), PAYLOAD_CONTENT_HASH_UNAVAILABLE);
    }

    #[test]
    fn string_tool_input_stays_at_the_strict_decoder() {
        let envelope = typed(
            "response_item",
            MapValue::new(vec![
                kv("type", s("function_call")),
                kv("name", s("read")),
                kv("arguments", s("{}")),
            ]),
        );
        let mut held = bag();
        let err = run(&mut held, &envelope, input(), None, None).unwrap_err();
        assert!(matches!(
            err,
            ProcessRolloutRecordError::ToolInput(ToolInputError::Unavailable)
        ));
        assert_eq!(err.to_string(), STRICT_JSON_DECODE_UNAVAILABLE);
        assert!(held.events.is_empty());
        assert!(held.findings.is_empty());
    }

    #[test]
    fn bool_tool_input_is_not_sent_to_the_decoder() {
        let envelope = typed(
            "response_item",
            MapValue::new(vec![
                kv("type", s("function_call")),
                kv("name", s("bash")),
                kv("arguments", MetaValue::Bool(true)),
            ]),
        );
        let mut held = bag();
        hash_seam(&run(&mut held, &envelope, input(), None, None).unwrap_err());
        assert!(held.events.is_empty());
        assert!(held.findings.is_empty());
    }

    #[test]
    fn raising_tool_input_stops_before_the_event() {
        let envelope = typed(
            "response_item",
            MapValue::new(vec![
                kv("type", s("function_call")),
                kv("arguments", MetaValue::Map(MapValue::raising(vec![]))),
            ]),
        );
        let mut held = bag();
        let err = run(&mut held, &envelope, input(), None, None).unwrap_err();
        assert!(matches!(
            err,
            ProcessRolloutRecordError::ToolInput(ToolInputError::Items)
        ));
        assert_eq!(err.to_string(), "list(mapping.items()) raises");
        assert!(held.events.is_empty());
        assert!(held.findings.is_empty());
    }

    #[test]
    fn ordinal_continuity_excludes_bool_from_int() {
        let previous = Some(1);
        assert!(ordinals_contiguous(
            true,
            false,
            previous,
            &MetaValue::Bool(true)
        ));
        assert!(ordinals_contiguous(
            true,
            false,
            previous,
            &MetaValue::Bool(false)
        ));
        assert!(ordinals_contiguous(
            true,
            false,
            previous,
            &MetaValue::Int(2)
        ));
        assert!(!ordinals_contiguous(
            true,
            false,
            previous,
            &MetaValue::Int(3)
        ));
        assert!(!ordinals_contiguous(
            true,
            true,
            previous,
            &MetaValue::Int(2)
        ));
        assert!(!ordinals_contiguous(
            false,
            false,
            previous,
            &MetaValue::Int(2)
        ));
        assert!(ordinals_contiguous(
            true,
            false,
            None,
            &MetaValue::Int(9)
        ));
        assert!(ordinals_contiguous(
            true,
            false,
            previous,
            &MetaValue::Str("2".to_owned())
        ));
        assert!(!ordinals_contiguous(
            true,
            false,
            Some(i64::MAX),
            &MetaValue::Int(i64::MAX)
        ));
        assert_eq!(envelope_ordinal(&MetaValue::Bool(true)), None);
        assert_eq!(envelope_ordinal(&MetaValue::Bool(false)), None);
        assert_eq!(envelope_ordinal(&MetaValue::Null), None);
        assert_eq!(envelope_ordinal(&MetaValue::Int(4)), Some(4));
        assert_eq!(
            contiguous_parent(Some("prior"), false, previous, &MetaValue::Bool(true)),
            Some("prior".to_owned())
        );
        assert_eq!(
            contiguous_parent(Some("prior"), false, previous, &MetaValue::Int(4)),
            None
        );
        assert_eq!(
            contiguous_parent(Some("prior"), false, previous, &MetaValue::Int(2)),
            Some("prior".to_owned())
        );
    }

    #[test]
    fn bool_and_max_ordinals_stop_at_the_content_hash() {
        let bool_ordinal = MapValue::new(vec![
            kv("type", s("event_msg")),
            kv("ordinal", MetaValue::Bool(true)),
            kv("payload", MetaValue::Map(MapValue::new(vec![]))),
        ]);
        let mut held = bag();
        let mut options = input();
        options.last_id = Some("prior");
        options.last_ordinal = Some(1);
        hash_seam(&run(&mut held, &bool_ordinal, options, None, None).unwrap_err());
        assert!(held.events.is_empty());

        let max_ordinal = MapValue::new(vec![
            kv("type", s("event_msg")),
            kv("ordinal", MetaValue::Int(i64::MAX)),
            kv("payload", MetaValue::Map(MapValue::new(vec![]))),
        ]);
        let mut again = bag();
        let mut max_options = input();
        max_options.last_id = Some("prior");
        max_options.last_ordinal = Some(i64::MAX);
        hash_seam(&run(&mut again, &max_ordinal, max_options, None, None).unwrap_err());
        assert!(again.events.is_empty());
    }

    #[test]
    fn unsupported_version_stops_before_a_finding_or_a_size() {
        let envelope = MapValue::new(vec![
            kv("type", s("event_msg")),
            kv("rollout_version", s("9")),
            kv("payload", MetaValue::Map(MapValue::new(vec![]))),
        ]);
        let mut held = bag();
        held.findings.push(marker());
        held.meta
            .insert("record_sizes", MetaValue::List(Vec::new()));
        let mut options = input();
        options.start = Some(10);
        options.end = Some(18);
        version_seam(&run(&mut held, &envelope, options, None, None).unwrap_err());
        assert_eq!(raw(&held.meta), Some("9"));
        assert_eq!(held.findings.len(), 1);
        assert!(sizes(&held.meta).is_empty());
        assert!(held.events.is_empty());
    }

    #[test]
    fn seen_version_stores_the_raw_text_and_reaches_the_content_hash() {
        let envelope = MapValue::new(vec![
            kv("type", s("event_msg")),
            kv("rollout_version", s("9")),
            kv("payload", MetaValue::Map(MapValue::new(vec![]))),
        ]);
        let mut held = bag();
        let mut drift = DriftTracker::new("codex-rollout");
        let mut options = input();
        options.seen = true;
        hash_seam(&run(&mut held, &envelope, options, Some(&mut drift), None).unwrap_err());
        assert_eq!(raw(&held.meta), Some("9"));
        assert!(drift.into_findings(PATH).expect("suppressed").is_empty());
        assert!(held.events.is_empty());
        assert!(held.findings.is_empty());
    }

    #[test]
    fn true_version_wins_the_chain_and_is_not_an_int() {
        let envelope = MapValue::new(vec![
            kv("type", s("event_msg")),
            kv("rollout_version", MetaValue::Bool(true)),
            kv("version", s("1")),
            kv("payload", MetaValue::Map(MapValue::new(vec![]))),
        ]);
        let mut held = bag();
        version_seam(&run(&mut held, &envelope, input(), None, None).unwrap_err());
        assert_eq!(raw(&held.meta), None);
        assert!(held.findings.is_empty());
        assert!(held.events.is_empty());
    }

    #[test]
    fn false_version_is_replaced_and_the_payload_marker_is_kept() {
        let envelope = typed(
            "event_msg",
            MapValue::new(vec![kv("rollout_version", s("1"))]),
        );
        let mut entries = envelope.entries;
        entries.insert(1, kv("rollout_version", MetaValue::Bool(false)));
        let envelope = MapValue::new(entries);
        let mut held = bag();
        hash_seam(&run(&mut held, &envelope, input(), None, None).unwrap_err());
        assert_eq!(raw(&held.meta), Some("1"));
        assert!(held.events.is_empty());
    }

    #[test]
    fn payload_version_is_used_when_the_envelope_has_none() {
        let envelope = typed(
            "event_msg",
            MapValue::new(vec![kv("rollout_version", s("1"))]),
        );
        let mut held = bag();
        hash_seam(&run(&mut held, &envelope, input(), None, None).unwrap_err());
        assert_eq!(raw(&held.meta), Some("1"));
        assert!(held.events.is_empty());
    }

    #[test]
    fn unknown_critical_field_does_not_append_a_finding() {
        let envelope = typed(
            "session_meta",
            MapValue::new(vec![
                kv("session_id", s("s")),
                kv("unknown_critical_field", MetaValue::Int(1)),
            ]),
        );
        let mut held = bag();
        held.findings.push(marker());
        finding_seam(&run(&mut held, &envelope, input(), None, None).unwrap_err());
        assert_eq!(held.findings.len(), 1);
        assert!(held.events.is_empty());
        match held.meta.attribute("session_meta").expect("attr") {
            MetaValue::Map(map) => assert_eq!(text_at(map, "session_id"), "s"),
            _ => panic!("session_meta"),
        }
    }

    #[test]
    fn session_meta_keeps_links_sizes_and_the_unstripped_copy() {
        let envelope = typed(
            "session_meta",
            MapValue::new(vec![
                kv("id", s(" thread-1 ")),
                kv("session_id", s(" sess ")),
                kv("cli_version", s("0")),
                kv("parent_thread_id", s(" parent ")),
                kv("subagent_history_start_ordinal", MetaValue::Int(4)),
            ]),
        );
        let mut held = bag();
        held.meta.insert("links", MetaValue::List(Vec::new()));
        held.meta
            .insert("record_sizes", MetaValue::List(Vec::new()));
        let mut options = input();
        options.start = Some(10);
        options.end = Some(18);
        hash_seam(&run(&mut held, &envelope, options, None, None).unwrap_err());
        assert_eq!(stored_session(&held.meta), "thread-1");
        assert!(held.guard.seen_real_ids().contains("thread-1"));
        assert_eq!(sizes(&held.meta), vec![8]);
        match held.meta.attribute("session_meta").expect("attr") {
            MetaValue::Map(map) => {
                assert_eq!(text_at(map, "session_id"), " sess ");
                assert_eq!(text_at(map, "cli_version"), "0");
            }
            _ => panic!("session_meta"),
        }
        let Some(MetaValue::List(links)) = held.meta.get("links") else {
            panic!("links");
        };
        assert_eq!(links.len(), 1);
        let MetaValue::Map(link) = &links[0] else {
            panic!("link");
        };
        assert_eq!(text_at(link, "kind"), "session_ref");
        assert_eq!(text_at(link, "target"), "parent");
        assert_eq!(text_at(link, "record_id"), "thread-1");
        assert_eq!(entry(link, "line"), &MetaValue::Int(LINE));
        assert!(held.events.is_empty());
    }

    #[test]
    fn thread_session_id_excludes_bool_and_keeps_int() {
        let bool_id = typed(
            "session_meta",
            MapValue::new(vec![
                kv("id", MetaValue::Bool(true)),
                kv("session_id", s("sess-9")),
                kv("subagent_history_start_ordinal", MetaValue::Bool(false)),
            ]),
        );
        let mut held = bag();
        hash_seam(&run(&mut held, &bool_id, input(), None, None).unwrap_err());
        assert_eq!(stored_session(&held.meta), "sess-9");
        assert!(held.events.is_empty());

        let int_id = typed(
            "session_meta",
            MapValue::new(vec![
                kv("id", MetaValue::Int(42)),
                kv("session_id", s("other")),
                kv("subagent_history_start_ordinal", MetaValue::Int(4)),
            ]),
        );
        let mut again = bag();
        hash_seam(&run(&mut again, &int_id, input(), None, None).unwrap_err());
        assert_eq!(stored_session(&again.meta), "42");
        assert!(again.guard.seen_real_ids().contains("42"));
        assert!(again.events.is_empty());
    }

    #[test]
    fn parent_thread_link_excludes_bool() {
        let bool_parent = typed(
            "session_meta",
            MapValue::new(vec![kv("parent_thread_id", MetaValue::Bool(true))]),
        );
        let mut held = bag();
        held.meta.insert("links", MetaValue::List(Vec::new()));
        hash_seam(&run(&mut held, &bool_parent, input(), None, None).unwrap_err());
        assert_eq!(held.meta.get("links"), Some(&MetaValue::List(Vec::new())));

        let int_parent = typed(
            "session_meta",
            MapValue::new(vec![kv("parent_thread_id", MetaValue::Int(15))]),
        );
        let mut again = bag();
        again.meta.insert("links", MetaValue::List(Vec::new()));
        hash_seam(&run(&mut again, &int_parent, input(), None, None).unwrap_err());
        let Some(MetaValue::List(links)) = again.meta.get("links") else {
            panic!("links");
        };
        let MetaValue::Map(link) = &links[0] else {
            panic!("link");
        };
        assert_eq!(text_at(link, "target"), "15");
        assert_eq!(text_at(link, "kind"), "session_ref");
        let expected = synthetic_event_id("codex_rollout", 0, PATH, 0);
        assert_eq!(text_at(link, "record_id"), expected);
    }

    #[test]
    fn counters_pressure_guardian_and_side_effects_exclude_bool() {
        let counters = MapValue::new(vec![
            (MapKey::Bool(true), MetaValue::Int(1)),
            (MapKey::Int(1), MetaValue::Int(2)),
            (MapKey::Str("flag".to_owned()), MetaValue::Bool(true)),
            (MapKey::Str("n".to_owned()), MetaValue::Int(3)),
        ]);
        let filtered = int_counter_map(&counters).expect("counters");
        assert_eq!(entry(&filtered, "True"), &MetaValue::Int(1));
        assert_eq!(entry(&filtered, "1"), &MetaValue::Int(2));
        assert_eq!(entry(&filtered, "n"), &MetaValue::Int(3));
        assert_eq!(filtered.entries.len(), 3);

        assert!(context_pressure(&nested_info(MetaValue::Bool(true), MetaValue::Int(8))).is_none());
        let pressure =
            context_pressure(&nested_info(MetaValue::Int(3), MetaValue::Int(8))).expect("pressure");
        assert_eq!(entry(&pressure, "occupancy"), &MetaValue::Int(3));
        assert_eq!(entry(&pressure, "window"), &MetaValue::Int(8));

        assert!(subagent_ordinal(&MapValue::new(vec![kv(
            "subagent_history_start_ordinal",
            MetaValue::Bool(true),
        )]))
        .is_none());
        assert_eq!(
            subagent_ordinal(&MapValue::new(vec![kv(
                "subagent_history_start_ordinal",
                MetaValue::Int(4),
            )])),
            Some(4)
        );
        assert_eq!(side_effects_for("read"), "none");
        assert_eq!(side_effects_for("READ"), "none");
        assert_eq!(side_effects_for("bash"), "possible");
        assert_eq!(side_effects_for("other"), "unknown");
    }

    fn nested_info(tokens: MetaValue, window: MetaValue) -> MapValue {
        MapValue::new(vec![kv(
            "info",
            MetaValue::Map(MapValue::new(vec![
                kv(
                    "last_token_usage",
                    MetaValue::Map(MapValue::new(vec![kv("input_tokens", tokens)])),
                ),
                kv("model_context_window", window),
            ])),
        )])
    }

    #[test]
    fn guardian_mark_skips_non_maps_and_caps_the_list() {
        let bad = MapValue::new(vec![kv("id", MetaValue::Bool(true))]);
        let good = MapValue::new(vec![
            kv("id", s("kept")),
            kv("type", s("tool")),
            kv("call_id", s("c")),
        ]);
        let history = MetaValue::List(vec![
            MetaValue::Int(1),
            MetaValue::Map(bad),
            MetaValue::Map(good),
        ]);
        let mark = guardian_mark(Some(&history)).expect("count").expect("mark");
        assert_eq!(mark.total, 3);
        assert!(!mark.truncated);
        let MetaValue::List(items) = &mark.items else {
            panic!("items");
        };
        assert_eq!(items.len(), 2);
        let MetaValue::Map(first) = &items[0] else {
            panic!("first");
        };
        assert_eq!(entry(first, "id"), &MetaValue::Null);
        let MetaValue::Map(second) = &items[1] else {
            panic!("second");
        };
        assert_eq!(text_at(second, "id"), "kept");

        let long = MetaValue::List(vec![MetaValue::Null; 513]);
        let capped = guardian_mark(Some(&long)).expect("count").expect("mark");
        assert_eq!(capped.total, 513);
        assert!(capped.truncated);
        assert_eq!(capped.items, MetaValue::List(Vec::new()));
    }

    #[test]
    fn token_usage_and_compacted_bools_reach_the_content_hash() {
        let usage = typed(
            "token_usage_record",
            MapValue::new(vec![kv(
                "usage",
                MetaValue::Map(MapValue::new(vec![
                    (MapKey::Bool(true), MetaValue::Int(1)),
                    kv("n", MetaValue::Bool(false)),
                    kv("kept", MetaValue::Int(4)),
                ])),
            )]),
        );
        let mut held = bag();
        hash_seam(&run(&mut held, &usage, input(), None, None).unwrap_err());
        assert!(held.events.is_empty());

        let raising = typed(
            "token_usage_record",
            MapValue::new(vec![kv(
                "usage",
                MetaValue::Map(MapValue::raising(vec![])),
            )]),
        );
        let mut blocked = bag();
        let err = run(&mut blocked, &raising, input(), None, None).unwrap_err();
        assert!(matches!(
            err,
            ProcessRolloutRecordError::ToolInput(ToolInputError::Items)
        ));
        assert!(blocked.events.is_empty());

        let compacted = typed(
            "compacted",
            MapValue::new(vec![kv(
                "guardian_history",
                MetaValue::List(vec![MetaValue::Null; 513]),
            )]),
        );
        let mut again = bag();
        hash_seam(&run(&mut again, &compacted, input(), None, None).unwrap_err());
        assert!(again.events.is_empty());
    }

    #[test]
    fn unknown_item_and_envelope_stop_without_extending_findings() {
        let item = typed(
            "response_item",
            MapValue::new(vec![kv("type", s("widget"))]),
        );
        let mut held = bag();
        held.findings.push(marker());
        finding_seam(&run(&mut held, &item, input(), None, None).unwrap_err());
        assert_eq!(held.findings.len(), 1);
        assert!(held.events.is_empty());

        let mut tracker = UnknownMetadataTracker::new();
        let mut noted = bag();
        hash_seam(&run(&mut noted, &item, input(), None, Some(&mut tracker)).unwrap_err());
        assert!(tracker.findings(PATH).is_err());
        assert_eq!(
            tracker.findings(PATH).unwrap_err().to_string(),
            FINGERPRINT_CODEC_UNAVAILABLE
        );
        assert!(noted.events.is_empty());
        assert!(noted.findings.is_empty());

        let semantic = typed(
            "widget",
            MapValue::new(vec![kv("content", s("synthetic-body"))]),
        );
        let mut semantic_tracker = UnknownMetadataTracker::new();
        let mut semantic_bag = bag();
        finding_seam(
            &run(
                &mut semantic_bag,
                &semantic,
                input(),
                None,
                Some(&mut semantic_tracker),
            )
            .unwrap_err(),
        );
        assert!(semantic_tracker
            .findings(PATH)
            .expect("not noted")
            .is_empty());
        assert!(semantic_bag.events.is_empty());
        assert!(semantic_bag.findings.is_empty());

        let opaque = empty_payload("widget");
        let mut opaque_tracker = UnknownMetadataTracker::new();
        let mut opaque_bag = bag();
        hash_seam(
            &run(
                &mut opaque_bag,
                &opaque,
                input(),
                None,
                Some(&mut opaque_tracker),
            )
            .unwrap_err(),
        );
        assert!(opaque_tracker.findings(PATH).is_err());
        assert!(opaque_bag.events.is_empty());
    }

    #[test]
    fn foreign_signature_and_version_transition_stop_at_the_fingerprint() {
        let summary = empty_payload("summary");
        let mut tracker = UnknownMetadataTracker::new();
        let mut drift = DriftTracker::new("codex-rollout");
        let mut held = bag();
        hash_seam(
            &run(
                &mut held,
                &summary,
                input(),
                Some(&mut drift),
                Some(&mut tracker),
            )
            .unwrap_err(),
        );
        assert_eq!(
            drift.into_findings(PATH).unwrap_err().to_string(),
            FINGERPRINT_CODEC_UNAVAILABLE
        );
        assert!(held.events.is_empty());

        let mut versions = DriftTracker::new("codex-rollout");
        let first = MapValue::new(vec![
            kv("type", s("event_msg")),
            kv("rollout_version", s("1")),
            kv("payload", MetaValue::Map(MapValue::new(vec![]))),
        ]);
        let mut first_bag = bag();
        hash_seam(&run(&mut first_bag, &first, input(), Some(&mut versions), None).unwrap_err());
        assert!(versions.into_findings(PATH).expect("baseline").is_empty());
        let second = MapValue::new(vec![
            kv("type", s("event_msg")),
            kv("rollout_version", s("1.0")),
            kv("payload", MetaValue::Map(MapValue::new(vec![]))),
        ]);
        let mut second_bag = bag();
        hash_seam(&run(&mut second_bag, &second, input(), Some(&mut versions), None).unwrap_err());
        assert_eq!(
            versions.into_findings(PATH).unwrap_err().to_string(),
            FINGERPRINT_CODEC_UNAVAILABLE
        );
        assert!(first_bag.events.is_empty());
        assert!(second_bag.events.is_empty());
    }

    #[test]
    fn real_id_collision_does_not_append_the_event() {
        let envelope = typed(
            "response_item",
            MapValue::new(vec![
                kv("type", s("message")),
                kv("id", s("real-id")),
                kv("role", s("user")),
            ]),
        );
        let mut held = bag();
        held.guard
            .register_synthetic("real-id")
            .expect("synthetic");
        let err = run(&mut held, &envelope, input(), None, None).unwrap_err();
        assert!(matches!(err, ProcessRolloutRecordError::Collision(_)));
        assert!(err.to_string().contains("Synthetic ID collision"));
        assert!(!held.guard.seen_real_ids().contains("real-id"));
        assert!(held.guard.seen_synthetic_ids().contains("real-id"));
        assert!(held.events.is_empty());
        assert!(held.findings.is_empty());
    }

    #[test]
    fn synthetic_ordinal_uses_the_record_ordinal_or_the_event_len() {
        let envelope = empty_payload("event_msg");
        let mut held = bag();
        let mut options = input();
        options.ordinal = Some(4);
        hash_seam(&run(&mut held, &envelope, options, None, None).unwrap_err());
        let used = synthetic_event_id("codex_rollout", 4, PATH, 0);
        let unused = synthetic_event_id("codex_rollout", 0, PATH, 0);
        assert!(held.guard.seen_synthetic_ids().contains(&used));
        assert!(!held.guard.seen_synthetic_ids().contains(&unused));
        assert!(held.events.is_empty());

        let mut prior = bag();
        prior.events.push(SessionEvent::new(
            "a",
            None,
            0,
            EPOCH,
            "system",
            "opaque",
        ));
        prior.events.push(SessionEvent::new(
            "b",
            None,
            1,
            EPOCH,
            "system",
            "opaque",
        ));
        hash_seam(&run(&mut prior, &envelope, input(), None, None).unwrap_err());
        let from_len = synthetic_event_id("codex_rollout", 2, PATH, 0);
        assert!(prior.guard.seen_synthetic_ids().contains(&from_len));
        assert_eq!(prior.events.len(), 2);
    }

    #[test]
    fn a_non_str_key_stops_before_a_finding() {
        let envelope = MapValue::new(vec![
            kv("type", s("event_msg")),
            kv("payload", MetaValue::Map(MapValue::new(vec![]))),
            (MapKey::Int(1), MetaValue::Int(2)),
        ]);
        let mut held = bag();
        let err = run(&mut held, &envelope, input(), None, None).unwrap_err();
        assert!(matches!(err, ProcessRolloutRecordError::KeyOrder));
        assert_eq!(err.to_string(), "sorted() cannot order these key types");
        assert_ne!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(held.events.is_empty());
        assert!(held.findings.is_empty());
    }

    #[test]
    fn record_timestamp_falls_through_null_and_epochs_the_rest() {
        let kept = MapValue::new(vec![kv("timestamp", s(KEPT))]);
        assert_eq!(record_timestamp(&kept), KEPT);
        let nope = MapValue::new(vec![kv("timestamp", s("nope"))]);
        assert_eq!(record_timestamp(&nope), EPOCH);
        let missing = MapValue::new(vec![
            kv("timestamp", MetaValue::Null),
            kv("ts", s(KEPT)),
        ]);
        assert_eq!(record_timestamp(&missing), KEPT);
        let created = MapValue::new(vec![kv("created_at", s(KEPT))]);
        assert_eq!(record_timestamp(&created), KEPT);
        let flag = MapValue::new(vec![
            kv("timestamp", MetaValue::Bool(true)),
            kv("ts", s(KEPT)),
        ]);
        assert_eq!(record_timestamp(&flag), EPOCH);

        let live = MapValue::new(vec![
            kv("type", s("event_msg")),
            kv("timestamp", s("nope")),
            kv("payload", MetaValue::Map(MapValue::new(vec![]))),
        ]);
        let mut held = bag();
        hash_seam(&run(&mut held, &live, input(), None, None).unwrap_err());
        assert!(held.events.is_empty());
    }

    #[test]
    fn message_id_is_real_and_an_invalid_payload_does_not_append() {
        let message = typed(
            "response_item",
            MapValue::new(vec![
                kv("type", s("message")),
                kv("role", s("user")),
                kv("id", s("m1")),
                kv("content", s("synthetic")),
            ]),
        );
        let mut held = bag();
        hash_seam(&run(&mut held, &message, input(), None, None).unwrap_err());
        assert!(held.guard.seen_real_ids().contains("m1"));
        assert!(held.guard.seen_synthetic_ids().is_empty());
        assert!(held.events.is_empty());
        assert!(held.findings.is_empty());

        let invalid = MapValue::new(vec![
            kv("type", s("response_item")),
            kv("payload", MetaValue::Int(1)),
        ]);
        let mut again = bag();
        again.findings.push(marker());
        finding_seam(&run(&mut again, &invalid, input(), None, None).unwrap_err());
        assert_eq!(again.findings.len(), 1);
        assert!(again.events.is_empty());
    }

    #[test]
    fn critical_prefix_and_unrendered_id_stop_before_the_event() {
        let critical = typed(
            "response_item",
            MapValue::new(vec![
                kv("type", s("message")),
                kv("role", s("user")),
                kv("critical_extra", MetaValue::Int(1)),
            ]),
        );
        let mut held = bag();
        finding_seam(&run(&mut held, &critical, input(), None, None).unwrap_err());
        assert!(held.findings.is_empty());
        assert!(held.events.is_empty());

        let unrendered = typed(
            "response_item",
            MapValue::new(vec![
                kv("type", s("message")),
                kv("id", MetaValue::List(Vec::new())),
            ]),
        );
        let mut again = bag();
        let err = run(&mut again, &unrendered, input(), None, None).unwrap_err();
        assert!(matches!(err, ProcessRolloutRecordError::Unrendered));
        assert_eq!(err.to_string(), STR_UNRENDERED);
        assert!(again.events.is_empty());
        assert!(again.findings.is_empty());
    }

    #[test]
    fn record_sizes_append_only_a_fitting_list_span() {
        let envelope = empty_payload("event_msg");
        let mut zero = bag();
        zero.meta
            .insert("record_sizes", MetaValue::List(Vec::new()));
        let mut zero_options = input();
        zero_options.start = Some(4);
        zero_options.end = Some(4);
        hash_seam(&run(&mut zero, &envelope, zero_options, None, None).unwrap_err());
        assert_eq!(sizes(&zero.meta), vec![0]);

        let mut backwards = bag();
        backwards
            .meta
            .insert("record_sizes", MetaValue::List(Vec::new()));
        let mut back_options = input();
        back_options.start = Some(5);
        back_options.end = Some(4);
        hash_seam(&run(&mut backwards, &envelope, back_options, None, None).unwrap_err());
        assert!(sizes(&backwards.meta).is_empty());

        let mut tuple = bag();
        tuple
            .meta
            .insert("record_sizes", MetaValue::Tuple(vec![MetaValue::Int(4)]));
        let mut tuple_options = input();
        tuple_options.start = Some(1);
        tuple_options.end = Some(2);
        hash_seam(&run(&mut tuple, &envelope, tuple_options, None, None).unwrap_err());
        assert_eq!(
            tuple.meta.get("record_sizes"),
            Some(&MetaValue::Tuple(vec![MetaValue::Int(4)]))
        );

        let mut overflow = bag();
        overflow
            .meta
            .insert("record_sizes", MetaValue::List(Vec::new()));
        let mut overflow_options = input();
        overflow_options.start = Some(i64::MIN);
        overflow_options.end = Some(i64::MAX);
        hash_seam(&run(&mut overflow, &envelope, overflow_options, None, None).unwrap_err());
        assert!(sizes(&overflow.meta).is_empty());
        assert!(zero.events.is_empty());
    }

    #[test]
    fn a_malformed_link_stops_before_the_event() {
        let envelope = empty_payload("event_msg");
        let mut held = bag();
        held.meta
            .insert("links", MetaValue::List(vec![MetaValue::Int(1)]));
        held.meta
            .insert("record_sizes", MetaValue::List(Vec::new()));
        let mut options = input();
        options.start = Some(1);
        options.end = Some(2);
        let err = run(&mut held, &envelope, options, None, None).unwrap_err();
        assert!(matches!(err, ProcessRolloutRecordError::LinkShape));
        assert_eq!(err.to_string(), "links entry is missing kind or target");
        assert!(sizes(&held.meta).is_empty());
        assert!(held.events.is_empty());
        assert!(held.findings.is_empty());
    }
}

// Port of `src/sesslint/adapters/codex_rollout.py`
// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1129–1309.
// `_process_jsonl_line` only. `load_codex_rollout` starts at line 1312
// and is not defined here.
//
// Gaps vs Python (recorded, not papered over):
// - A supplied tracker is not `SecretScanTracker`. `feed` is not called.
//   Display is `sesslint.checks.hygiene.SecretScanTracker is not available`
//   before the truncated, NUL, UTF-8, JSON, duplicate, nesting, or record
//   checks. No scan result is invented.
// - [`make_finding`] omits the fingerprint. Display is
//   `sesslint.determinism.canonical_json_bytes is not available`. The
//   finding is not appended. Duplicate-key findings therefore do not
//   continue into [`_process_rollout_record`].
// - A dict that passes those checks calls [`_process_rollout_record`].
//   That function's content-hash Display is
//   `sesslint._canonical_codec.payload_content_hash is not available`.
//   This slice does not hash and does not push an event.
// - JSON is hand-walked. There is no `regex` crate and no `serde_json`.
//   `true` and `false` are bools. An integer outside `i64` is a decode
//   defect, not a bool and not a float.
// - Parser depth above 1000 is the pin's `RecursionError` arm.
//   `limits.max_depth` is the later `check_nesting_depth` arm. A bool is
//   not a container. Duplicate values that `dict` drops stay marked, so
//   the truncated flag can be set without listing those dropped keys.

use model::codes::{SL001, SL002, SL303};
use model::finding::enforce_content_free_text;

const JSONL_SECRET_TRACKER_UNAVAILABLE: &str =
    "sesslint.checks.hygiene.SecretScanTracker is not available";

const JSONL_RECORD_ID_MAX: usize = 200;

const JSONL_RECORD_ID_CONTEXT: &str = "extracted record_id";

const JSONL_NESTING_LIMIT: u32 = 1000;

const JSONL_MAX_DUP_KEYS: usize = 16;

const JSONL_CUT: i64 = -1;

const JSONL_BAD: i64 = -2;

const JSONL_LIMIT_TEMPLATE: &str =
    "Line {line} exceeds maximum line byte limit [detail: LIMIT] for record {record_id}";

const JSONL_NUL_TEMPLATE: &str = "Forbidden NUL byte on line {line} for record {record_id}";

const JSONL_UTF8_TEMPLATE: &str =
    "Invalid UTF-8 encoding on line {line} [detail: ENCODING] for record {record_id}";

const JSONL_NESTING_TEMPLATE: &str =
    "Nesting depth exceeds maximum limit on line {line} [detail: LIMIT] for record {record_id}";

const JSONL_MALFORMED_TEMPLATE: &str = "Malformed record on line {line} for record {record_id}";

const JSONL_TORN_TEMPLATE: &str = "Torn terminal record on line {line} for record {record_id}";

const JSONL_DUP_TEMPLATE: &str = "Duplicate JSON key on line {line} for record {record_id}";

const JSONL_LONE_SURROGATE_WHY: &str = "line {line} contains an invalid Unicode character (lone surrogate, e.g. \\ud800), so it cannot be parsed as a session record. The file was not truncated.";

/// Witness that the caller already holds a `SecretScanTracker`.
///
/// This is not a tracker. It has no `feed` and it stores no scan result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuppliedSecretScanTracker;

/// `max_depth` from a provided `ReaderLimits`.
///
/// The field is an `i64`. A bool is not an int, and a bool cannot be stored
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodexLineLimits {
    /// Python: `ReaderLimits.max_depth`.
    pub max_depth: i64,
}

/// One physical rollout JSONL line.
///
/// Python: `_RawLine`. Coordinates are `i64`. A bool is not an int, so this
/// constructor cannot take one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexRawLine {
    line_number: i64,
    raw_bytes: Vec<u8>,
    truncated_limit: bool,
    byte_offset: i64,
    byte_end: i64,
    record_ordinal: i64,
}

impl CodexRawLine {
    /// Validate coordinates, then store the line.
    ///
    /// # Errors
    ///
    /// `byte_offset < 0`, `byte_end < byte_offset`, or `record_ordinal < 1`.
    pub fn try_new(
        line_number: i64,
        raw_bytes: Vec<u8>,
        truncated_limit: bool,
        byte_offset: i64,
        byte_end: i64,
        record_ordinal: i64,
    ) -> Result<Self, CodexRawLineError> {
        if byte_offset < 0 {
            return Err(CodexRawLineError::new(format!(
                "Invalid byte_offset: {byte_offset} (must be integer >= 0)"
            )));
        }
        if byte_end < byte_offset {
            return Err(CodexRawLineError::new(format!(
                "Invalid byte_end: {byte_end} (must be integer >= byte_offset={byte_offset})"
            )));
        }
        if record_ordinal < 1 {
            return Err(CodexRawLineError::new(format!(
                "Invalid record_ordinal: {record_ordinal} (must be integer >= 1)"
            )));
        }
        Ok(Self {
            line_number,
            raw_bytes,
            truncated_limit,
            byte_offset,
            byte_end,
            record_ordinal,
        })
    }

    /// Python: `line_number`.
    #[must_use]
    pub const fn line_number(&self) -> i64 {
        self.line_number
    }

    /// Python: `raw_bytes`.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Python: `truncated_limit`.
    #[must_use]
    pub const fn truncated_limit(&self) -> bool {
        self.truncated_limit
    }

    /// Python: `byte_offset`.
    #[must_use]
    pub const fn byte_offset(&self) -> i64 {
        self.byte_offset
    }

    /// Python: `byte_end`.
    #[must_use]
    pub const fn byte_end(&self) -> i64 {
        self.byte_end
    }

    /// Python: `record_ordinal`.
    #[must_use]
    pub const fn record_ordinal(&self) -> i64 {
        self.record_ordinal
    }
}

/// `ValueError` from `_RawLine` coordinate checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexRawLineError {
    message: String,
}

impl CodexRawLineError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The Python `ValueError` text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CodexRawLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CodexRawLineError {}

/// Failure from [`_process_jsonl_line`].
///
/// [`Display`] is one seam. A finding is not appended on
/// [`Self::Finding`]. An event is not appended on [`Self::Record`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessJsonlLineError {
    /// [`JSONL_SECRET_TRACKER_UNAVAILABLE`].
    SecretScanTracker,
    /// [`SourceRef`] or [`make_finding`] failed. The finding was not appended.
    Finding(FindingError),
    /// [`_process_rollout_record`] failed. The event was not appended here.
    Record(Box<ProcessRolloutRecordError>),
}

impl ProcessJsonlLineError {
    /// The Python exception text, or the missing-codec seam.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::SecretScanTracker => JSONL_SECRET_TRACKER_UNAVAILABLE,
            Self::Finding(error) => error.message(),
            Self::Record(error) => error.message(),
        }
    }
}

impl fmt::Display for ProcessJsonlLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ProcessJsonlLineError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Finding(error) => Some(error),
            Self::Record(error) => Some(error.as_ref()),
            Self::SecretScanTracker => None,
        }
    }
}

/// Process one rollout JSONL line and stop at the record seam.
///
/// Python: `_process_jsonl_line` lines 1129–1309 at
/// `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`. `load_codex_rollout` is not
/// defined in this slice and does not call this function.
///
/// When `secret_tracker` is [`Some`](Option::Some), the first action would be
/// `secret_tracker.feed(...)`. `SecretScanTracker` is not constructed and no
/// scan result is invented. Display is
/// `sesslint.checks.hygiene.SecretScanTracker is not available`. Events and
/// findings are left untouched. The line is not decoded.
///
/// Otherwise the line is decoded by hand. There is no `serde_json` and no
/// `regex` crate. A bool is not an int: JSON `true` is [`MetaValue::Bool`],
/// and `true` is not `1`.
///
/// Every [`make_finding`] call omits the fingerprint. That returns
/// `sesslint.determinism.canonical_json_bytes is not available`. The finding
/// is not appended.
///
/// A record that reaches [`_process_rollout_record`] returns that function's
/// error. The content-hash arm's Display is
/// `sesslint._canonical_codec.payload_content_hash is not available`. No
/// digest is invented. This function does not push an event.
///
/// # Errors
///
/// The secret-tracker seam, [`SourceRef`], [`make_finding`], or
/// [`_process_rollout_record`].
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
#[must_use = "the codec seam or the seen flag is the result"]
pub fn _process_jsonl_line(
    raw: &CodexRawLine,
    is_terminal: bool,
    path_str: &str,
    limits: CodexLineLimits,
    events: &mut Vec<SessionEvent>,
    findings: &mut Vec<Finding>,
    source_metadata: &mut SourceMetadata,
    seen_version_sl301: bool,
    guard: Option<&mut SyntheticIdCollisionGuard>,
    last_event_id: Option<&str>,
    last_envelope_ordinal: Option<i64>,
    gap_after_drop: bool,
    drift: Option<&mut DriftTracker>,
    secret_tracker: Option<SuppliedSecretScanTracker>,
    unknown_metadata: Option<&mut UnknownMetadataTracker>,
) -> Result<(bool, bool, Option<i64>), ProcessJsonlLineError> {
    if secret_tracker.is_some() {
        return Err(ProcessJsonlLineError::SecretScanTracker);
    }
    if raw.truncated_limit() {
        let rec_id = jsonl_record_id(Some(&jsonl_lossy(raw.raw_bytes())), None);
        return Err(jsonl_plain(
            SL001,
            JSONL_LIMIT_TEMPLATE,
            path_str,
            raw,
            rec_id.as_deref(),
            jsonl_coord_map(raw),
        ));
    }
    if raw.raw_bytes().contains(&0) {
        return Err(jsonl_byte_defect(raw, is_terminal, path_str, JSONL_NUL_TEMPLATE));
    }
    let decoded = match jsonl_strict_text(raw) {
        Ok(text) => text,
        Err(()) => {
            return Err(jsonl_byte_defect(
                raw,
                is_terminal,
                path_str,
                JSONL_UTF8_TEMPLATE,
            ));
        }
    };
    let parsed = match jsonl_parse(&decoded) {
        Ok(value) => value,
        Err(fail) => return Err(jsonl_decode_defect(raw, is_terminal, path_str, &decoded, fail)),
    };
    let (dups, dups_truncated) = jsonl_duplicates(&parsed);
    let value = jsonl_meta(&parsed);
    if let Some(dup) = dups.first() {
        let rec_id = jsonl_mapped_id(&decoded, &value);
        return Err(jsonl_dup_finding(
            raw,
            path_str,
            rec_id.as_deref(),
            dup,
            dups_truncated,
        ));
    }
    let MetaValue::Map(envelope) = value else {
        return Err(jsonl_plain(
            SL001,
            JSONL_MALFORMED_TEMPLATE,
            path_str,
            raw,
            None,
            jsonl_coord_map(raw),
        ));
    };
    if !jsonl_within_depth(&envelope, limits.max_depth) {
        let rec_id = jsonl_record_id(Some(&decoded), Some(&envelope));
        return Err(jsonl_plain(
            SL001,
            JSONL_NESTING_TEMPLATE,
            path_str,
            raw,
            rec_id.as_deref(),
            jsonl_coord_map(raw),
        ));
    }
    let (latch, env_ord) = _process_rollout_record(
        &envelope,
        raw.line_number(),
        path_str,
        events,
        findings,
        source_metadata,
        seen_version_sl301,
        Some(raw.byte_offset()),
        Some(raw.byte_end()),
        Some(raw.record_ordinal()),
        guard,
        last_event_id,
        last_envelope_ordinal,
        gap_after_drop,
        drift,
        unknown_metadata,
    )
    .map_err(|error| ProcessJsonlLineError::Record(Box::new(error)))?;
    Ok((latch, true, env_ord))
}

fn jsonl_byte_defect(
    raw: &CodexRawLine,
    is_terminal: bool,
    path_str: &str,
    template: &str,
) -> ProcessJsonlLineError {
    let code = jsonl_defect_code(raw, is_terminal);
    let rec_id = jsonl_record_id(Some(&jsonl_lossy(raw.raw_bytes())), None);
    jsonl_plain(
        code,
        template,
        path_str,
        raw,
        rec_id.as_deref(),
        jsonl_defect_map(code, raw),
    )
}

fn jsonl_decode_defect(
    raw: &CodexRawLine,
    is_terminal: bool,
    path_str: &str,
    decoded: &str,
    fail: JsonlFail,
) -> ProcessJsonlLineError {
    if matches!(fail, JsonlFail::Nesting) {
        let rec_id = jsonl_record_id(Some(decoded), None);
        return jsonl_plain(
            SL001,
            JSONL_NESTING_TEMPLATE,
            path_str,
            raw,
            rec_id.as_deref(),
            jsonl_coord_map(raw),
        );
    }
    let code = jsonl_defect_code(raw, is_terminal);
    let template = if matches!(fail, JsonlFail::LoneSurrogate) {
        JSONL_LONE_SURROGATE_WHY
    } else if code == SL002 {
        JSONL_TORN_TEMPLATE
    } else {
        JSONL_MALFORMED_TEMPLATE
    };
    let rec_id = jsonl_record_id(Some(decoded), None);
    jsonl_plain(
        code,
        template,
        path_str,
        raw,
        rec_id.as_deref(),
        jsonl_defect_map(code, raw),
    )
}

fn jsonl_plain(
    code: &str,
    template: &str,
    path_str: &str,
    raw: &CodexRawLine,
    record_id: Option<&str>,
    evidence: FindingValue,
) -> ProcessJsonlLineError {
    jsonl_refuse(
        code,
        FindingValue::None,
        FindingValue::None,
        template,
        path_str,
        raw.line_number(),
        record_id,
        evidence,
    )
}

fn jsonl_dup_finding(
    raw: &CodexRawLine,
    path_str: &str,
    record_id: Option<&str>,
    dup: &JsonlDup,
    truncated: bool,
) -> ProcessJsonlLineError {
    let mut entries = vec![
        (
            FindingValue::string("key_path"),
            FindingValue::string(dup.key_path.clone()),
        ),
        (
            FindingValue::string("occurrence_count"),
            FindingValue::int(dup.occurrence_count),
        ),
        (
            FindingValue::string("critical"),
            FindingValue::bool_value(dup.critical),
        ),
        (
            FindingValue::string("record_index"),
            FindingValue::int(raw.record_ordinal()),
        ),
    ];
    if truncated {
        entries.push((
            FindingValue::string("truncated"),
            FindingValue::bool_value(true),
        ));
    }
    let severity = if dup.critical {
        Severity::Error
    } else {
        Severity::Warning
    };
    jsonl_refuse(
        SL303,
        FindingValue::severity(severity),
        FindingValue::repairability(Repairability::Manual),
        JSONL_DUP_TEMPLATE,
        path_str,
        raw.line_number(),
        record_id,
        FindingValue::map(entries),
    )
}

#[allow(clippy::too_many_arguments)] // same finding fields as make_finding
fn jsonl_refuse(
    code: &str,
    severity: FindingValue,
    repairability: FindingValue,
    template: &str,
    path_str: &str,
    line: i64,
    record_id: Option<&str>,
    evidence: FindingValue,
) -> ProcessJsonlLineError {
    let source = match SourceRef::try_new(path_str, Some(SourceLine::Int(line)), record_id) {
        Ok(source) => source,
        Err(error) => return ProcessJsonlLineError::Finding(error),
    };
    match make_finding(&MakeFindingInput {
        code: FindingValue::string(code),
        severity,
        repairability,
        message_template: FindingValue::string(template),
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
        Err(error) => ProcessJsonlLineError::Finding(error),
        Ok(_finding) => {
            ProcessJsonlLineError::Finding(FindingError::new(FINGERPRINT_CODEC_UNAVAILABLE))
        }
    }
}

fn jsonl_coord_entries(raw: &CodexRawLine) -> Vec<(FindingValue, FindingValue)> {
    vec![
        (
            FindingValue::string("byte_offset"),
            FindingValue::int(raw.byte_offset()),
        ),
        (
            FindingValue::string("byte_end"),
            FindingValue::int(raw.byte_end()),
        ),
        (
            FindingValue::string("record_ordinal"),
            FindingValue::int(raw.record_ordinal()),
        ),
    ]
}

fn jsonl_coord_map(raw: &CodexRawLine) -> FindingValue {
    FindingValue::map(jsonl_coord_entries(raw))
}

fn jsonl_defect_map(code: &str, raw: &CodexRawLine) -> FindingValue {
    let mut entries = jsonl_coord_entries(raw);
    if code == SL002 {
        entries.push((
            FindingValue::string("unterminated"),
            FindingValue::bool_value(true),
        ));
    }
    FindingValue::map(entries)
}

fn jsonl_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn jsonl_strict_text(raw: &CodexRawLine) -> Result<String, ()> {
    let mut bytes = raw.raw_bytes();
    if raw.line_number() == 1 {
        bytes = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    Ok(python_strip(text).to_owned())
}

fn jsonl_mapped_id(text: &str, value: &MetaValue) -> Option<String> {
    match value {
        MetaValue::Map(map) => jsonl_record_id(Some(text), Some(map)),
        _ => jsonl_record_id(Some(text), None),
    }
}

fn jsonl_defect_code(raw: &CodexRawLine, is_terminal: bool) -> &'static str {
    if is_terminal && !raw.truncated_limit() && jsonl_line_is_torn(raw.raw_bytes(), raw.line_number() == 1)
    {
        SL002
    } else {
        SL001
    }
}

enum JsonlId {
    Found(String),
    Rejected,
    Miss,
}

fn jsonl_record_id(raw_text: Option<&str>, obj: Option<&MapValue>) -> Option<String> {
    if let Some(map) = obj {
        if let Some(MetaValue::Str(text)) = last_string_value(map, "id") {
            match jsonl_screen_id(text) {
                JsonlId::Found(id) => return Some(id),
                JsonlId::Rejected => return None,
                JsonlId::Miss => {}
            }
        }
    }
    let raw = raw_text?;
    let capture = jsonl_search_id(raw)?;
    match jsonl_screen_id(capture) {
        JsonlId::Found(id) => Some(id),
        JsonlId::Rejected | JsonlId::Miss => None,
    }
}

fn jsonl_screen_id(text: &str) -> JsonlId {
    let stripped = python_strip(text);
    if stripped.is_empty() {
        return JsonlId::Miss;
    }
    let candidate: String = stripped.chars().take(JSONL_RECORD_ID_MAX).collect();
    match enforce_content_free_text(&candidate, JSONL_RECORD_ID_CONTEXT) {
        Ok(()) => JsonlId::Found(candidate),
        Err(_) => JsonlId::Rejected,
    }
}

fn jsonl_search_id(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut start = 0usize;
    while let Some(end) = start.checked_add(4) {
        if end > bytes.len() {
            break;
        }
        if bytes.get(start..end) == Some(b"\"id\"".as_slice()) {
            if let Some(id) = text.get(start..).and_then(jsonl_capture_id) {
                return Some(id);
            }
        }
        start = start.saturating_add(1);
    }
    None
}

fn jsonl_capture_id(text: &str) -> Option<&str> {
    let rest = text.get(4..)?;
    let after_key = jsonl_trim_start(rest);
    let after_colon = after_key.strip_prefix(':')?;
    let content = jsonl_trim_start(after_colon).strip_prefix('"')?;
    let mut count = 0usize;
    let mut end = 0usize;
    for ch in content.chars() {
        if ch == '"' {
            if count == 0 {
                return None;
            }
            return content.get(..end);
        }
        if count == JSONL_RECORD_ID_MAX {
            return None;
        }
        count = count.saturating_add(1);
        end = end.checked_add(ch.len_utf8())?;
    }
    None
}

fn jsonl_trim_start(text: &str) -> &str {
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
    text.get(start..).unwrap_or("")
}

fn jsonl_within_depth(map: &MapValue, max_depth: i64) -> bool {
    let mut stack = vec![(JsonlNode::Map(map), 1i64)];
    while let Some((node, depth)) = stack.pop() {
        if depth > max_depth {
            return false;
        }
        let Some(next) = depth.checked_add(1) else {
            return false;
        };
        match node {
            JsonlNode::Map(current) => {
                for (_, child) in &current.entries {
                    jsonl_push_child(&mut stack, child, next);
                }
            }
            JsonlNode::List(items) => {
                for child in items {
                    jsonl_push_child(&mut stack, child, next);
                }
            }
        }
    }
    true
}

enum JsonlNode<'a> {
    Map(&'a MapValue),
    List(&'a [MetaValue]),
}

fn jsonl_push_child<'a>(stack: &mut Vec<(JsonlNode<'a>, i64)>, child: &'a MetaValue, depth: i64) {
    match child {
        MetaValue::Map(map) => stack.push((JsonlNode::Map(map), depth)),
        MetaValue::List(items) | MetaValue::Tuple(items) => {
            stack.push((JsonlNode::List(items), depth));
        }
        MetaValue::Null
        | MetaValue::Bool(_)
        | MetaValue::Int(_)
        | MetaValue::Float(_)
        | MetaValue::Str(_)
        | MetaValue::Bytes(_)
        | MetaValue::Set(_)
        | MetaValue::Object(_) => {}
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Parsed {
    Null,
    Bool(bool),
    Int(i64),
    Float(u64),
    Str(String),
    Arr(Vec<Parsed>),
    Obj(Vec<(String, Parsed)>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonlFail {
    Syntax,
    Nesting,
    LoneSurrogate,
}

fn jsonl_parse(text: &str) -> Result<Parsed, JsonlFail> {
    if text.starts_with('\u{feff}') {
        return Err(JsonlFail::Syntax);
    }
    let mut parser = JsonlParser::new(text);
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.index != parser.bytes.len() {
        return Err(JsonlFail::Syntax);
    }
    if parser.lone && (text.contains("\\u") || text.contains("\\U")) {
        return Err(JsonlFail::LoneSurrogate);
    }
    Ok(value)
}

struct JsonlParser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    index: usize,
    depth: u32,
    lone: bool,
}

impl<'a> JsonlParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            index: 0,
            depth: 0,
            lone: false,
        }
    }

    fn parse_value(&mut self) -> Result<Parsed, JsonlFail> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Parsed::Str(self.parse_string()?)),
            Some(b't') => self.consume_lit(b"true", Parsed::Bool(true)),
            Some(b'f') => self.consume_lit(b"false", Parsed::Bool(false)),
            Some(b'n') => self.consume_lit(b"null", Parsed::Null),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(JsonlFail::Syntax),
        }
    }

    fn parse_object(&mut self) -> Result<Parsed, JsonlFail> {
        self.bump().ok_or(JsonlFail::Syntax)?;
        self.enter()?;
        self.skip_ws();
        let mut pairs = Vec::new();
        if self.peek() == Some(b'}') {
            self.bump();
            self.leave();
            return Ok(Parsed::Obj(pairs));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(JsonlFail::Syntax);
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(JsonlFail::Syntax);
            }
            let value = self.parse_value()?;
            pairs.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                    self.skip_ws();
                }
                Some(b'}') => {
                    self.bump();
                    self.leave();
                    return Ok(Parsed::Obj(pairs));
                }
                _ => return Err(JsonlFail::Syntax),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Parsed, JsonlFail> {
        self.bump().ok_or(JsonlFail::Syntax)?;
        self.enter()?;
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.bump();
            self.leave();
            return Ok(Parsed::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                    self.skip_ws();
                }
                Some(b']') => {
                    self.bump();
                    self.leave();
                    return Ok(Parsed::Arr(items));
                }
                _ => return Err(JsonlFail::Syntax),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonlFail> {
        self.bump().ok_or(JsonlFail::Syntax)?;
        let mut out = String::new();
        loop {
            let start = self.index;
            while let Some(byte) = self.peek() {
                if byte == b'"' || byte == b'\\' || byte < 0x20 {
                    break;
                }
                self.bump();
            }
            if self.index > start {
                let slice = self.text.get(start..self.index).ok_or(JsonlFail::Syntax)?;
                out.push_str(slice);
            }
            match self.peek() {
                Some(b'"') => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.bump();
                    self.push_escape(&mut out)?;
                }
                _ => return Err(JsonlFail::Syntax),
            }
        }
    }

    fn push_escape(&mut self, out: &mut String) -> Result<(), JsonlFail> {
        match self.bump() {
            Some(b'"') => out.push('"'),
            Some(b'\\') => out.push('\\'),
            Some(b'/') => out.push('/'),
            Some(b'b') => out.push('\u{0008}'),
            Some(b'f') => out.push('\u{000c}'),
            Some(b'n') => out.push('\n'),
            Some(b'r') => out.push('\r'),
            Some(b't') => out.push('\t'),
            Some(b'u') => self.push_unicode(out)?,
            _ => return Err(JsonlFail::Syntax),
        }
        Ok(())
    }

    fn push_unicode(&mut self, out: &mut String) -> Result<(), JsonlFail> {
        let unit = self.read_hex4()?;
        if jsonl_high_surrogate(unit) {
            if self.starts_with(b"\\u") {
                self.bump();
                self.bump();
                let low = self.read_hex4()?;
                if jsonl_low_surrogate(low) {
                    match jsonl_surrogate_pair(unit, low) {
                        Some(ch) => out.push(ch),
                        None => self.lone = true,
                    }
                    return Ok(());
                }
                self.lone = true;
                return self.push_unit(out, low);
            }
            self.lone = true;
            return Ok(());
        }
        if jsonl_low_surrogate(unit) {
            self.lone = true;
            return Ok(());
        }
        self.push_unit(out, unit)
    }

    fn push_unit(&mut self, out: &mut String, unit: u32) -> Result<(), JsonlFail> {
        match char::from_u32(unit) {
            Some(ch) => {
                out.push(ch);
                Ok(())
            }
            None => Err(JsonlFail::Syntax),
        }
    }

    fn read_hex4(&mut self) -> Result<u32, JsonlFail> {
        let mut value = 0u32;
        for _ in 0..4 {
            let Some(byte) = self.bump() else {
                return Err(JsonlFail::Syntax);
            };
            let Some(digit) = jsonl_hex_digit(byte) else {
                return Err(JsonlFail::Syntax);
            };
            value = value
                .checked_mul(16)
                .and_then(|next| next.checked_add(digit))
                .ok_or(JsonlFail::Syntax)?;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Parsed, JsonlFail> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        if !self.consume_int() {
            return Err(JsonlFail::Syntax);
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.bump();
            if !self.consume_digits() {
                return Err(JsonlFail::Syntax);
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if !self.consume_digits() {
                return Err(JsonlFail::Syntax);
            }
        }
        let token = self.text.get(start..self.index).ok_or(JsonlFail::Syntax)?;
        if is_float {
            let value: f64 = token.parse().map_err(|_| JsonlFail::Syntax)?;
            if !value.is_finite() {
                return Err(JsonlFail::Syntax);
            }
            return Ok(Parsed::Float(value.to_bits()));
        }
        let value: i64 = token.parse().map_err(|_| JsonlFail::Syntax)?;
        Ok(Parsed::Int(value))
    }

    fn consume_int(&mut self) -> bool {
        match self.peek() {
            Some(b'0') => {
                self.bump();
                true
            }
            Some(b'1'..=b'9') => self.consume_digits(),
            _ => false,
        }
    }

    fn consume_digits(&mut self) -> bool {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return false;
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        true
    }

    fn consume_lit(&mut self, literal: &[u8], value: Parsed) -> Result<Parsed, JsonlFail> {
        if self.starts_with(literal) {
            self.index = self.index.saturating_add(literal.len());
            Ok(value)
        } else {
            Err(JsonlFail::Syntax)
        }
    }

    fn enter(&mut self) -> Result<(), JsonlFail> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > JSONL_NESTING_LIMIT {
            Err(JsonlFail::Nesting)
        } else {
            Ok(())
        }
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.index = self.index.checked_add(1)?;
        Some(byte)
    }

    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.bytes
            .get(self.index..)
            .is_some_and(|rest| rest.starts_with(prefix))
    }
}

fn jsonl_hex_digit(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte) - u32::from(b'0')),
        b'a'..=b'f' => Some(u32::from(byte) - u32::from(b'a') + 10),
        b'A'..=b'F' => Some(u32::from(byte) - u32::from(b'A') + 10),
        _ => None,
    }
}

fn jsonl_high_surrogate(unit: u32) -> bool {
    (0xD800..=0xDBFF).contains(&unit)
}

fn jsonl_low_surrogate(unit: u32) -> bool {
    (0xDC00..=0xDFFF).contains(&unit)
}

fn jsonl_surrogate_pair(high: u32, low: u32) -> Option<char> {
    let high_off = high.checked_sub(0xD800)?;
    let low_off = low.checked_sub(0xDC00)?;
    let merged = high_off.checked_shl(10)?.checked_add(low_off)?;
    char::from_u32(merged.checked_add(0x1_0000)?)
}

fn jsonl_meta(parsed: &Parsed) -> MetaValue {
    match parsed {
        Parsed::Null => MetaValue::Null,
        Parsed::Bool(flag) => MetaValue::Bool(*flag),
        Parsed::Int(number) => MetaValue::Int(*number),
        Parsed::Float(bits) => MetaValue::Float(*bits),
        Parsed::Str(text) => MetaValue::Str(text.clone()),
        Parsed::Arr(items) => MetaValue::List(items.iter().map(jsonl_meta).collect()),
        Parsed::Obj(pairs) => MetaValue::Map(jsonl_collapse(pairs)),
    }
}

fn jsonl_collapse(pairs: &[(String, Parsed)]) -> MapValue {
    let mut entries = Vec::new();
    for (key, value) in pairs {
        let stored = jsonl_meta(value);
        if let Some(slot) = entries
            .iter_mut()
            .find(|(name, _)| matches!(name, MapKey::Str(text) if text == key))
        {
            slot.1 = stored;
        } else {
            entries.push((MapKey::Str(key.clone()), stored));
        }
    }
    MapValue::new(entries)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JsonlDup {
    key_path: String,
    occurrence_count: i64,
    critical: bool,
}

struct JsonlFrame<'a> {
    node: &'a Parsed,
    path: String,
}

fn jsonl_duplicates(root: &Parsed) -> (Vec<JsonlDup>, bool) {
    let marked = jsonl_count_marked(root);
    let mut dups = Vec::new();
    let mut visited = 0usize;
    let mut stack = vec![JsonlFrame {
        node: root,
        path: String::from("$"),
    }];
    while let Some(frame) = stack.pop() {
        let path = frame.path;
        match frame.node {
            Parsed::Obj(pairs) => {
                let counts = jsonl_dup_counts(pairs);
                if !counts.is_empty() {
                    visited = visited.saturating_add(1);
                    for (key, count) in counts {
                        if dups.len() >= JSONL_MAX_DUP_KEYS {
                            return (dups, true);
                        }
                        dups.push(JsonlDup {
                            key_path: format!("{path}.{key}"),
                            occurrence_count: count,
                            critical: jsonl_critical(&key),
                        });
                    }
                }
                for (key, child) in jsonl_collapsed_refs(pairs).into_iter().rev() {
                    stack.push(JsonlFrame {
                        node: child,
                        path: format!("{path}.{key}"),
                    });
                }
            }
            Parsed::Arr(items) => {
                for (index, child) in items.iter().enumerate().rev() {
                    stack.push(JsonlFrame {
                        node: child,
                        path: format!("{path}[{index}]"),
                    });
                }
            }
            Parsed::Null | Parsed::Bool(_) | Parsed::Int(_) | Parsed::Float(_) | Parsed::Str(_) => {}
        }
    }
    (dups, visited < marked)
}

fn jsonl_critical(key: &str) -> bool {
    CRITICAL_KEYS.contains(&key)
}

fn jsonl_dup_counts(pairs: &[(String, Parsed)]) -> Vec<(String, i64)> {
    let mut counts: Vec<(String, i64)> = Vec::new();
    for (key, _) in pairs {
        if let Some((_, count)) = counts.iter_mut().find(|(name, _)| name == key) {
            *count = count.saturating_add(1);
        } else {
            counts.push((key.clone(), 1));
        }
    }
    counts.retain(|(_, count)| *count > 1);
    counts
}

fn jsonl_collapsed_refs(pairs: &[(String, Parsed)]) -> Vec<(&str, &Parsed)> {
    let mut collapsed: Vec<(&str, &Parsed)> = Vec::new();
    for (key, value) in pairs {
        if let Some((_, slot)) = collapsed.iter_mut().find(|(name, _)| *name == key) {
            *slot = value;
        } else {
            collapsed.push((key, value));
        }
    }
    collapsed
}

fn jsonl_count_marked(root: &Parsed) -> usize {
    let mut total = 0usize;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node {
            Parsed::Obj(pairs) => {
                if pairs.len() != jsonl_collapsed_refs(pairs).len() {
                    total = total.saturating_add(1);
                }
                for (_, child) in pairs {
                    stack.push(child);
                }
            }
            Parsed::Arr(items) => {
                for child in items {
                    stack.push(child);
                }
            }
            Parsed::Null | Parsed::Bool(_) | Parsed::Int(_) | Parsed::Float(_) | Parsed::Str(_) => {}
        }
    }
    total
}

fn jsonl_line_is_torn(line: &[u8], strip_bom: bool) -> bool {
    if line.ends_with(b"\n") {
        return false;
    }
    let mut body = line;
    if strip_bom && body.starts_with(UTF8_BOM) {
        body = &body[UTF8_BOM.len()..];
    }
    body = jsonl_strip_trailing_nuls(body);
    if body.contains(&0) {
        return false;
    }
    let Some(text) = jsonl_torn_text(body) else {
        return false;
    };
    if text.bytes().all(jsonl_json_ws) {
        return true;
    }
    jsonl_cut_object(text)
}

fn jsonl_strip_trailing_nuls(body: &[u8]) -> &[u8] {
    let end = body
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index.saturating_add(1));
    body.get(..end).unwrap_or(body)
}

fn jsonl_torn_text(body: &[u8]) -> Option<&str> {
    match std::str::from_utf8(body) {
        Ok(text) => Some(text),
        Err(err) if err.error_len().is_none() && err.valid_up_to() < body.len() => {
            std::str::from_utf8(body.get(..err.valid_up_to())?).ok()
        }
        Err(_) => None,
    }
}

fn jsonl_json_ws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

#[derive(Clone, Copy)]
enum JsonlExpect {
    Object,
    KeyOrClose,
    Key,
    Colon,
    Value,
    ValueOrClose,
    After,
}

enum JsonlCut {
    Continue { pos: usize, expect: JsonlExpect },
    Stop(bool),
}

fn jsonl_cut_object(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut closers: Vec<u8> = Vec::new();
    let mut expect = JsonlExpect::Object;
    let mut pos = 0usize;
    loop {
        pos = jsonl_skip_json_ws(bytes, pos);
        if pos == bytes.len() {
            return !closers.is_empty();
        }
        match jsonl_cut_step(text, pos, expect, &mut closers) {
            JsonlCut::Continue {
                pos: next,
                expect: next_expect,
            } => {
                pos = next;
                expect = next_expect;
            }
            JsonlCut::Stop(torn) => return torn,
        }
    }
}

fn jsonl_skip_json_ws(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() && jsonl_json_ws(bytes[pos]) {
        pos = pos.saturating_add(1);
    }
    pos
}

fn jsonl_cut_step(
    text: &str,
    pos: usize,
    expect: JsonlExpect,
    closers: &mut Vec<u8>,
) -> JsonlCut {
    let bytes = text.as_bytes();
    let Some(ch) = bytes.get(pos).copied() else {
        return JsonlCut::Stop(false);
    };
    match expect {
        JsonlExpect::Object => {
            if ch != b'{' {
                return JsonlCut::Stop(false);
            }
            closers.push(b'}');
            jsonl_cut_continue(pos.saturating_add(1), JsonlExpect::KeyOrClose)
        }
        JsonlExpect::KeyOrClose => jsonl_cut_key(text, pos, true, closers),
        JsonlExpect::Key => jsonl_cut_key(text, pos, false, closers),
        JsonlExpect::Colon => {
            if ch != b':' {
                return JsonlCut::Stop(false);
            }
            jsonl_cut_continue(pos.saturating_add(1), JsonlExpect::Value)
        }
        JsonlExpect::Value => jsonl_cut_value(text, pos, false, closers),
        JsonlExpect::ValueOrClose => jsonl_cut_value(text, pos, true, closers),
        JsonlExpect::After => jsonl_cut_after(bytes, pos, closers),
    }
}

fn jsonl_cut_continue(pos: usize, expect: JsonlExpect) -> JsonlCut {
    JsonlCut::Continue { pos, expect }
}

fn jsonl_cut_key(text: &str, pos: usize, allow_close: bool, closers: &mut Vec<u8>) -> JsonlCut {
    let Some(ch) = text.as_bytes().get(pos).copied() else {
        return JsonlCut::Stop(false);
    };
    if allow_close && ch == b'}' {
        if closers.pop().is_none() {
            return JsonlCut::Stop(false);
        }
        return jsonl_cut_continue(pos.saturating_add(1), JsonlExpect::After);
    }
    if ch == b'"' {
        return jsonl_cut_token(text, pos, JsonlExpect::Colon, true);
    }
    JsonlCut::Stop(false)
}

fn jsonl_cut_value(text: &str, pos: usize, allow_close: bool, closers: &mut Vec<u8>) -> JsonlCut {
    let Some(ch) = text.as_bytes().get(pos).copied() else {
        return JsonlCut::Stop(false);
    };
    if allow_close && ch == b']' {
        if closers.pop().is_none() {
            return JsonlCut::Stop(false);
        }
        return jsonl_cut_continue(pos.saturating_add(1), JsonlExpect::After);
    }
    if ch == b'{' || ch == b'[' {
        closers.push(if ch == b'{' { b'}' } else { b']' });
        let expect = if ch == b'{' {
            JsonlExpect::KeyOrClose
        } else {
            JsonlExpect::ValueOrClose
        };
        return jsonl_cut_continue(pos.saturating_add(1), expect);
    }
    if ch == b'"' {
        return jsonl_cut_token(text, pos, JsonlExpect::After, true);
    }
    jsonl_cut_token(text, pos, JsonlExpect::After, false)
}

fn jsonl_cut_after(bytes: &[u8], pos: usize, closers: &mut Vec<u8>) -> JsonlCut {
    let Some(closer) = closers.last().copied() else {
        return JsonlCut::Stop(false);
    };
    let Some(ch) = bytes.get(pos).copied() else {
        return JsonlCut::Stop(false);
    };
    if ch == b',' {
        let expect = if closer == b'}' {
            JsonlExpect::Key
        } else {
            JsonlExpect::Value
        };
        return jsonl_cut_continue(pos.saturating_add(1), expect);
    }
    if ch == closer {
        closers.pop();
        return jsonl_cut_continue(pos.saturating_add(1), JsonlExpect::After);
    }
    JsonlCut::Stop(false)
}

fn jsonl_cut_token(text: &str, pos: usize, expect: JsonlExpect, string: bool) -> JsonlCut {
    let Ok(index) = i64::try_from(pos) else {
        return JsonlCut::Stop(false);
    };
    let next = if string {
        jsonl_cut_skip_string(text, index)
    } else {
        jsonl_cut_skip_scalar(text, index)
    };
    if next < 0 {
        return JsonlCut::Stop(next == JSONL_CUT);
    }
    match usize::try_from(next) {
        Ok(advanced) if advanced <= text.len() => jsonl_cut_continue(advanced, expect),
        _ => JsonlCut::Stop(false),
    }
}

fn jsonl_cut_skip_string(text: &str, pos: i64) -> i64 {
    if pos < 0 {
        return JSONL_BAD;
    }
    let Some(start) = usize::try_from(pos).ok().and_then(|value| value.checked_add(1)) else {
        return JSONL_BAD;
    };
    let bytes = text.as_bytes();
    if start > bytes.len() {
        return JSONL_BAD;
    }
    if start == bytes.len() {
        return JSONL_CUT;
    }
    match jsonl_scan_string(bytes, start) {
        JsonlString::Closed(end) => i64::try_from(end).unwrap_or(JSONL_BAD),
        JsonlString::Cut => JSONL_CUT,
        JsonlString::Bad => JSONL_BAD,
    }
}

enum JsonlString {
    Closed(usize),
    Cut,
    Bad,
}

fn jsonl_scan_string(bytes: &[u8], mut index: usize) -> JsonlString {
    loop {
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'"' || byte == b'\\' || byte <= 0x1F {
                break;
            }
            index = index.saturating_add(1);
        }
        if index >= bytes.len() {
            return JsonlString::Cut;
        }
        if bytes[index] == b'"' {
            return JsonlString::Closed(index.saturating_add(1));
        }
        if bytes[index] != b'\\' {
            return JsonlString::Bad;
        }
        let next = index.saturating_add(1);
        if next >= bytes.len() {
            return JsonlString::Cut;
        }
        let Some(escaped) = bytes.get(next).copied() else {
            return JsonlString::Cut;
        };
        if matches!(
            escaped,
            b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
        ) {
            index = next.saturating_add(1);
            continue;
        }
        if escaped == b'u' {
            let hex_at = next.saturating_add(1);
            let hex_end = hex_at.saturating_add(4);
            if hex_end <= bytes.len()
                && bytes
                    .get(hex_at..hex_end)
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
            {
                index = hex_end;
                continue;
            }
        }
        let rest = bytes.get(index..).unwrap_or(&[]);
        if jsonl_partial_escape(rest) {
            return JsonlString::Cut;
        }
        return JsonlString::Bad;
    }
}

fn jsonl_partial_escape(rest: &[u8]) -> bool {
    if rest.first() != Some(&b'\\') {
        return false;
    }
    if rest.len() == 1 {
        return true;
    }
    if rest.get(1) != Some(&b'u') {
        return false;
    }
    let hex = rest.get(2..).unwrap_or(&[]);
    hex.len() <= 3 && hex.iter().all(u8::is_ascii_hexdigit)
}

fn jsonl_cut_skip_scalar(text: &str, pos: i64) -> i64 {
    if pos < 0 {
        return JSONL_BAD;
    }
    let Some(start) = usize::try_from(pos).ok() else {
        return JSONL_CUT;
    };
    let bytes = text.as_bytes();
    if start >= bytes.len() {
        return JSONL_CUT;
    }
    let Some(head) = bytes.get(start).copied() else {
        return JSONL_BAD;
    };
    if jsonl_number_byte(head) {
        return jsonl_skip_number_run(bytes, start);
    }
    jsonl_skip_literal(bytes, start)
}

fn jsonl_number_byte(byte: u8) -> bool {
    matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
}

fn jsonl_skip_number_run(bytes: &[u8], start: usize) -> i64 {
    let mut end = start;
    while end < bytes.len() && bytes.get(end).is_some_and(|byte| jsonl_number_byte(*byte)) {
        end = end.saturating_add(1);
    }
    let Some(run) = bytes.get(start..end) else {
        return JSONL_BAD;
    };
    if end == bytes.len() {
        if jsonl_viable_number(run) {
            JSONL_CUT
        } else {
            JSONL_BAD
        }
    } else if jsonl_complete_number(run) {
        i64::try_from(end).unwrap_or(JSONL_BAD)
    } else {
        JSONL_BAD
    }
}

fn jsonl_skip_literal(bytes: &[u8], start: usize) -> i64 {
    let Some(rest) = bytes.get(start..) else {
        return JSONL_BAD;
    };
    for literal in [b"true".as_slice(), b"false".as_slice(), b"null".as_slice()] {
        if rest.starts_with(literal) {
            return i64::try_from(start.saturating_add(literal.len())).unwrap_or(JSONL_BAD);
        }
        if rest.len() < literal.len() && literal.starts_with(rest) {
            return JSONL_CUT;
        }
    }
    JSONL_BAD
}

fn jsonl_viable_number(run: &[u8]) -> bool {
    let mut index = 0usize;
    if run.first() == Some(&b'-') {
        index = 1;
    }
    if index == run.len() {
        return true;
    }
    jsonl_cut_number_body(run, &mut index) && index == run.len()
}

fn jsonl_cut_number_body(run: &[u8], index: &mut usize) -> bool {
    if !jsonl_cut_integer(run, index) {
        return false;
    }
    if *index == run.len() {
        return true;
    }
    match run.get(*index) {
        Some(b'.') => jsonl_cut_fraction(run, index),
        Some(b'e' | b'E') => jsonl_cut_exponent(run, index),
        _ => false,
    }
}

fn jsonl_cut_fraction(run: &[u8], index: &mut usize) -> bool {
    *index = index.saturating_add(1);
    if *index == run.len() {
        return true;
    }
    if !run.get(*index).is_some_and(u8::is_ascii_digit) {
        return false;
    }
    while run.get(*index).is_some_and(u8::is_ascii_digit) {
        *index = index.saturating_add(1);
    }
    if *index == run.len() {
        return true;
    }
    jsonl_cut_exponent(run, index)
}

fn jsonl_cut_exponent(run: &[u8], index: &mut usize) -> bool {
    if !matches!(run.get(*index), Some(b'e' | b'E')) {
        return false;
    }
    *index = index.saturating_add(1);
    if matches!(run.get(*index), Some(b'+' | b'-')) {
        *index = index.saturating_add(1);
    }
    while run.get(*index).is_some_and(u8::is_ascii_digit) {
        *index = index.saturating_add(1);
    }
    *index == run.len()
}

fn jsonl_cut_integer(run: &[u8], index: &mut usize) -> bool {
    let Some(digit) = run.get(*index) else {
        return false;
    };
    if !digit.is_ascii_digit() {
        return false;
    }
    if *digit == b'0' {
        *index = index.saturating_add(1);
        return true;
    }
    *index = index.saturating_add(1);
    while run.get(*index).is_some_and(u8::is_ascii_digit) {
        *index = index.saturating_add(1);
    }
    true
}

fn jsonl_complete_number(run: &[u8]) -> bool {
    let mut index = 0usize;
    if run.first() == Some(&b'-') {
        index = 1;
    }
    if !jsonl_cut_integer(run, &mut index) {
        return false;
    }
    if run.get(index) == Some(&b'.') {
        let next = index.saturating_add(1);
        if !run.get(next).is_some_and(u8::is_ascii_digit) {
            return false;
        }
        index = next.saturating_add(1);
        while run.get(index).is_some_and(u8::is_ascii_digit) {
            index = index.saturating_add(1);
        }
    }
    if matches!(run.get(index), Some(b'e' | b'E')) {
        index = index.saturating_add(1);
        if matches!(run.get(index), Some(b'+' | b'-')) {
            index = index.saturating_add(1);
        }
        if !run.get(index).is_some_and(u8::is_ascii_digit) {
            return false;
        }
        index = index.saturating_add(1);
        while run.get(index).is_some_and(u8::is_ascii_digit) {
            index = index.saturating_add(1);
        }
    }
    index == run.len()
}

/// Synthetic envelopes only. No session payload from a real transcript.
#[cfg(test)]
mod process_jsonl_line_tests {
    use model::finding::{FindingInput, SCHEMA_VERSION};

    use super::{
        jsonl_defect_code, jsonl_duplicates, jsonl_line_is_torn, jsonl_meta, jsonl_parse,
        jsonl_record_id, last_string_value, _process_jsonl_line, CodexLineLimits, CodexRawLine,
        Finding, FindingValue, JsonlFail, JsonlParser, MetaValue, ProcessJsonlLineError,
        ProcessRolloutRecordError, Repairability, SessionEvent, Severity, SourceLine, SourceMetadata,
        SourceRef, SuppliedSecretScanTracker, SL001, SL002,
    };

    const EVENT: &str = r#"{"type":"event_msg","payload":{}}"#;
    const FINGERPRINT: &str = "sesslint.determinism.canonical_json_bytes is not available";
    const CONTENT_HASH: &str = "sesslint._canonical_codec.payload_content_hash is not available";
    const SECRET: &str = "sesslint.checks.hygiene.SecretScanTracker is not available";

    struct Hold {
        meta: SourceMetadata,
        events: Vec<SessionEvent>,
        findings: Vec<Finding>,
    }

    fn hold() -> Hold {
        Hold {
            meta: SourceMetadata::new(),
            events: vec![SessionEvent::new(
                "seed",
                None,
                0,
                "1970-01-01T00:00:00Z",
                "system",
                "unknown",
            )],
            findings: vec![marker()],
        }
    }

    fn marker() -> Finding {
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

    fn line_at(number: i64, bytes: &[u8], truncated: bool) -> CodexRawLine {
        let end = i64::try_from(bytes.len()).expect("len");
        CodexRawLine::try_new(number, bytes.to_vec(), truncated, 0, end, 1).expect("line")
    }

    fn run(
        held: &mut Hold,
        bytes: &[u8],
        terminal: bool,
        depth: i64,
        secret: Option<SuppliedSecretScanTracker>,
    ) -> Result<(bool, bool, Option<i64>), ProcessJsonlLineError> {
        let raw = line_at(1, bytes, false);
        call(held, &raw, terminal, depth, secret)
    }

    fn call(
        held: &mut Hold,
        raw: &CodexRawLine,
        terminal: bool,
        depth: i64,
        secret: Option<SuppliedSecretScanTracker>,
    ) -> Result<(bool, bool, Option<i64>), ProcessJsonlLineError> {
        _process_jsonl_line(
            raw,
            terminal,
            "synthetic.jsonl",
            CodexLineLimits { max_depth: depth },
            &mut held.events,
            &mut held.findings,
            &mut held.meta,
            false,
            None,
            None,
            None,
            false,
            None,
            secret,
            None,
        )
    }

    fn unchanged(held: &Hold) {
        assert_eq!(held.events.len(), 1);
        assert_eq!(held.events[0].id, "seed");
        assert_eq!(held.findings.len(), 1);
        assert_eq!(held.meta, SourceMetadata::new());
    }

    fn field(text: &str, key: &str) -> MetaValue {
        let parsed = jsonl_parse(text).expect("json");
        let MetaValue::Map(map) = jsonl_meta(&parsed) else {
            panic!("object");
        };
        last_string_value(&map, key).expect("field").clone()
    }

    #[test]
    fn secret_tracker_stops_before_the_record_seam() {
        let mut held = hold();
        let err = run(&mut held, EVENT.as_bytes(), true, 100, Some(SuppliedSecretScanTracker))
            .expect_err("secret");
        assert!(matches!(err, ProcessJsonlLineError::SecretScanTracker));
        assert_eq!(err.to_string(), SECRET);
        assert_eq!(err.message(), SECRET);
        unchanged(&held);

        let mut truncated = hold();
        let raw = line_at(1, EVENT.as_bytes(), true);
        let early = call(
            &mut truncated,
            &raw,
            true,
            100,
            Some(SuppliedSecretScanTracker),
        )
        .expect_err("secret first");
        assert!(matches!(early, ProcessJsonlLineError::SecretScanTracker));
        assert_eq!(early.to_string(), SECRET);
        unchanged(&truncated);
    }

    #[test]
    fn absent_tracker_reaches_the_content_hash_and_appends_nothing() {
        let mut held = hold();
        let err = run(&mut held, EVENT.as_bytes(), true, 100, None).expect_err("hash");
        assert!(matches!(
            err,
            ProcessJsonlLineError::Record(ref error)
                if matches!(error.as_ref(), ProcessRolloutRecordError::ContentHash(_))
        ));
        assert_eq!(err.to_string(), CONTENT_HASH);
        assert_eq!(err.message(), CONTENT_HASH);
        unchanged(&held);

        let mut ordinal = hold();
        let bool_line = br#"{"type":"event_msg","payload":{},"ordinal":true}"#;
        let bool_err = run(&mut ordinal, bool_line, false, 2, None).expect_err("bool ordinal");
        assert_eq!(bool_err.to_string(), CONTENT_HASH);
        unchanged(&ordinal);
        assert_eq!(field(r#"{"ordinal":true}"#, "ordinal"), MetaValue::Bool(true));
        assert_eq!(field(r#"{"ordinal":1}"#, "ordinal"), MetaValue::Int(1));
        assert_eq!(field(r#"{"ordinal":false}"#, "ordinal"), MetaValue::Bool(false));
        assert_eq!(field(r#"{"ordinal":0}"#, "ordinal"), MetaValue::Int(0));
        assert_ne!(
            field(r#"{"ordinal":true}"#, "ordinal"),
            field(r#"{"ordinal":1}"#, "ordinal")
        );
    }

    #[test]
    fn make_finding_stops_without_appending_a_finding() {
        let mut nested = hold();
        let err = run(&mut nested, EVENT.as_bytes(), true, 1, None).expect_err("depth");
        assert!(matches!(err, ProcessJsonlLineError::Finding(_)));
        assert_eq!(err.to_string(), FINGERPRINT);
        unchanged(&nested);

        let mut bad = hold();
        let syntax = run(&mut bad, b"{", true, 100, None).expect_err("torn");
        assert!(matches!(syntax, ProcessJsonlLineError::Finding(_)));
        assert_eq!(syntax.to_string(), FINGERPRINT);
        unchanged(&bad);

        let mut duplicated = hold();
        let dup_line = br#"{"a":1,"a":true}"#;
        let dup = run(&mut duplicated, dup_line, true, 100, None).expect_err("dup");
        assert!(matches!(dup, ProcessJsonlLineError::Finding(_)));
        assert_eq!(dup.to_string(), FINGERPRINT);
        unchanged(&duplicated);
        assert_eq!(field(r#"{"a":1,"a":true}"#, "a"), MetaValue::Bool(true));

        let mut scalar = hold();
        let flag = run(&mut scalar, b"true", true, 100, None).expect_err("bool");
        assert!(matches!(flag, ProcessJsonlLineError::Finding(_)));
        assert_eq!(jsonl_meta(&jsonl_parse("true").expect("true")), MetaValue::Bool(true));
        assert_eq!(jsonl_meta(&jsonl_parse("1").expect("one")), MetaValue::Int(1));
        assert_eq!(jsonl_meta(&jsonl_parse("0").expect("zero")), MetaValue::Int(0));
        assert_eq!(jsonl_meta(&jsonl_parse("false").expect("false")), MetaValue::Bool(false));
        assert!(matches!(
            jsonl_meta(&jsonl_parse("1.0").expect("float")),
            MetaValue::Float(_)
        ));
        unchanged(&scalar);
    }

    #[test]
    fn decode_defects_use_the_fingerprint_seam() {
        let mut nul = hold();
        let nul_err = run(&mut nul, b"{\x00", true, 100, None).expect_err("nul");
        assert!(matches!(nul_err, ProcessJsonlLineError::Finding(_)));
        assert_eq!(nul_err.to_string(), FINGERPRINT);
        unchanged(&nul);

        let mut utf8 = hold();
        let utf8_err = run(&mut utf8, b"\xff", false, 100, None).expect_err("utf8");
        assert_eq!(utf8_err.to_string(), FINGERPRINT);
        unchanged(&utf8);

        let mut lone = hold();
        let lone_line = br#"{"type":"event_msg","payload":{"text":"\ud800"}}"#;
        let lone_err = run(&mut lone, lone_line, true, 100, None).expect_err("surrogate");
        assert!(matches!(lone_err, ProcessJsonlLineError::Finding(_)));
        assert_eq!(lone_err.to_string(), FINGERPRINT);
        unchanged(&lone);
        assert!(matches!(
            jsonl_parse(r#"{"t":"\ud800"}"#),
            Err(JsonlFail::LoneSurrogate)
        ));
        assert!(jsonl_parse(r#"{"t":"\ud800\udc00"}"#).is_ok());

        let mut wide = hold();
        let big = format!("1{}", "0".repeat(40));
        let big_err = run(&mut wide, big.as_bytes(), false, 100, None).expect_err("i64");
        assert!(matches!(big_err, ProcessJsonlLineError::Finding(_)));
        assert!(matches!(jsonl_parse("1e309"), Err(JsonlFail::Syntax)));
        assert!(matches!(jsonl_parse("01"), Err(JsonlFail::Syntax)));
        assert!(matches!(
            jsonl_meta(&jsonl_parse("1e2").expect("float")),
            MetaValue::Float(_)
        ));
        unchanged(&wide);
    }

    #[test]
    fn torn_classification_and_duplicate_order_follow_the_pin() {
        assert!(jsonl_line_is_torn(b"{", false));
        assert!(!jsonl_line_is_torn(b"{}\n", false));
        assert!(!jsonl_line_is_torn(b"{}", false));
        assert!(jsonl_line_is_torn(b"{\"a\":", false));
        assert!(!jsonl_line_is_torn(b"[", false));
        assert!(!jsonl_line_is_torn(b"true", false));
        assert!(jsonl_line_is_torn(b"   ", false));
        assert!(!jsonl_line_is_torn(b"{\n", false));
        assert!(jsonl_line_is_torn(b"{\x00", false));
        assert!(!jsonl_line_is_torn(b"{\x00a", false));
        assert!(!jsonl_line_is_torn(br#"{"a":1}"#, false));

        let open = line_at(1, b"{", false);
        assert_eq!(jsonl_defect_code(&open, true), SL002);
        assert_eq!(jsonl_defect_code(&open, false), SL001);
        let newline = line_at(1, b"{\n", false);
        assert_eq!(jsonl_defect_code(&newline, true), SL001);
        let spaces = line_at(1, b"   ", false);
        assert_eq!(jsonl_defect_code(&spaces, true), SL002);
        let complete = line_at(1, b"{}", false);
        assert_eq!(jsonl_defect_code(&complete, true), SL001);
        let bom = line_at(1, b"\xef\xbb\xbf{", false);
        assert_eq!(jsonl_defect_code(&bom, true), SL002);
        let later = line_at(2, b"\xef\xbb\xbf{", false);
        assert_eq!(jsonl_defect_code(&later, true), SL001);
        let cut = line_at(1, b"{", true);
        assert_eq!(jsonl_defect_code(&cut, true), SL001);

        let simple = jsonl_parse(r#"{"a":1,"a":2}"#).expect("dup");
        let (dups, truncated) = jsonl_duplicates(&simple);
        assert!(!truncated);
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].key_path, "$.a");
        assert_eq!(dups[0].occurrence_count, 2);
        assert!(!dups[0].critical);

        let typed = jsonl_parse(r#"{"type":1,"type":2}"#).expect("type");
        let (typed_dups, typed_truncated) = jsonl_duplicates(&typed);
        assert!(!typed_truncated);
        assert!(typed_dups[0].critical);
        assert_eq!(typed_dups[0].key_path, "$.type");

        let dropped = jsonl_parse(r#"{"a":{"b":1,"b":2},"a":3}"#).expect("drop");
        let (dropped_dups, dropped_truncated) = jsonl_duplicates(&dropped);
        assert!(dropped_truncated);
        assert_eq!(dropped_dups.len(), 1);
        assert_eq!(dropped_dups[0].key_path, "$.a");
        assert_eq!(dropped_dups[0].occurrence_count, 2);

        let nested = jsonl_parse(r#"{"a":{"b":1,"b":2}}"#).expect("nested");
        let (nested_dups, nested_truncated) = jsonl_duplicates(&nested);
        assert!(!nested_truncated);
        assert_eq!(nested_dups[0].key_path, "$.a.b");
        assert_eq!(nested_dups[0].occurrence_count, 2);

        assert_eq!(
            jsonl_record_id(Some(r#"{"id":"evt-1"}"#), None).as_deref(),
            Some("evt-1")
        );
        let parsed = jsonl_parse(r#"{"id":"evt-1"}"#).expect("id");
        let MetaValue::Map(map) = jsonl_meta(&parsed) else {
            panic!("map");
        };
        assert_eq!(jsonl_record_id(Some("nope"), Some(&map)).as_deref(), Some("evt-1"));

        let mut parser = JsonlParser::new("[]");
        for _ in 0..1000 {
            parser.enter().expect("within");
        }
        assert!(matches!(parser.enter(), Err(JsonlFail::Nesting)));
    }

    #[test]
    fn coordinates_reject_a_negative_integer() {
        let offset = CodexRawLine::try_new(1, Vec::new(), false, -1, 0, 1).expect_err("offset");
        assert_eq!(
            offset.to_string(),
            "Invalid byte_offset: -1 (must be integer >= 0)"
        );
        let end = CodexRawLine::try_new(1, Vec::new(), false, 2, 1, 1).expect_err("end");
        assert_eq!(
            end.to_string(),
            "Invalid byte_end: 1 (must be integer >= byte_offset=2)"
        );
        let ordinal = CodexRawLine::try_new(1, Vec::new(), false, 0, 0, 0).expect_err("ordinal");
        assert_eq!(
            ordinal.to_string(),
            "Invalid record_ordinal: 0 (must be integer >= 1)"
        );
    }
}
