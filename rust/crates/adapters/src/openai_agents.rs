//! OpenAI Agents SDK run-state projection, detection, payload assembly, and load gates.
//!
//! Port of `src/sesslint/adapters/openai_agents.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–1201.
//! Stops before `_check_version` (line 1204).
//!
//! Lines 1–313 port [`safe_type_value`] (Python `_safe_type_value`),
//! [`project_run_state`], and [`SourceMetadata`]. [`SourceMetadata`] is the
//! class at line 303. It is not [`crate::canonical::SourceMetadata`].
//!
//! Lines 316–525 port [`EventList`], [`normalize_version`],
//! [`detect_openai_agents`], [`normalize_timestamp`] (Python
//! `_normalize_timestamp`), and [`build_payload`] (Python `_build_payload`).
//! [`EventList`] is the class at line 316. It is not
//! [`crate::canonical::EventList`]. It stores [`SessionEvent`] values from
//! `model` and this module's [`SourceMetadata`].
//!
//! [`safe_type_value`] calls [`crate::safe_value::safe_type_value`]. It does
//! not shape values itself. [`project_run_state`] calls that wrapper and
//! [`crate::safe_value::safe_discriminator`]. [`build_payload`] calls
//! [`crate::safe_value::safe_discriminator`] for a handoff `reason`.
//!
//! [`build_payload`] calls `sesslint.io._STRICT_JSON_DECODER.decode` only when
//! the selected tool-call `args` / `arguments` / `input` value is a `str`.
//! That decoder is not in this crate. The arm returns
//! [`STRICT_JSON_DECODE_UNAVAILABLE`] and does not build a payload. Name and
//! call-id `str()` run first, in pin order, and an unrepresentable value
//! fails before the decoder seam. Other kinds do not call it.
//! [`detect_openai_agents`] does not call it and returns a score.
//! This file does not invent an SL code.
//!
//! [`load_openai_agents`] ports lines 528–670. Bytes use an in-memory stream
//! and the path `<bytes>`. A filesystem path checks existence, then a
//! directory, then the size gate. The first two errors are raised before the
//! file is opened. An `OSError` from the size-gate stat is ignored and the
//! open still runs. A stream uses its `name`, or `<stream>`, and `\` becomes
//! `/` in that path. Exception text keeps `str(Path(...))`. A finding path
//! uses the slash form.
//!
//! The first 16 bytes refuse [`SQLITE_MAGIC`] before any later read. The next
//! read is `max(0, max_file_bytes - 16 + 1)` bytes. A longer buffer is the
//! same size-limit finding as the stat gate. An owned file is closed on every
//! exit from that read, including the size-limit return. A leading UTF-8 BOM
//! is removed, then ASCII whitespace. Empty data returns an empty
//! [`EventList`] and no findings, and does not construct the secret tracker.
//! A non-empty body is classified as a JSON document or JSONL, then stops.
//!
//! `sesslint.checks.hygiene.SecretScanTracker` is not in this crate. Building
//! it is the first missing call. The error display is
//! [`SECRET_SCAN_TRACKER_UNAVAILABLE`]. The JSON and JSONL loaders are not
//! called. No events, SL301, or SL302 are invented. A non-empty document does
//! not return a successful [`EventList`].
//!
//! [`load_openai_agents_json`] ports `_load_openai_agents_json` (lines 673–904).
//! Its first statement is `secret_tracker.feed_blob(data)`. Python scans the
//! whole persisted document before any validation. `feed_blob` is not in
//! this crate. The display is [`SECRET_SCAN_FEED_BLOB_UNAVAILABLE`]. The
//! bytes are not checked for NUL, decoded as UTF-8, parsed as JSON, or walked
//! as items. No [`EventList`] is returned. SL001, SL009, SL301, and SL302 are
//! not produced. [`load_openai_agents`] does not call this function.
//!
//! [`load_openai_agents_jsonl`] ports `_load_openai_agents_jsonl` (lines
//! 907–1016). Before the line loop it builds a
//! [`crate::synthetic::SyntheticIdCollisionGuard`] and a
//! [`crate::drift::DriftTracker`], then `sesslint.io.MalformedTailTracker`.
//! That type is not in this crate. This crate does not depend on scan.
//! The display is [`MALFORMED_TAIL_TRACKER_UNAVAILABLE`]. The bytes are not
//! split. [`process_jsonl_line`] is not called. `feed` is not called. No
//! [`EventList`] is returned. Empty input, whitespace, a NUL byte, and a JSON
//! object all stop at that display. [`load_openai_agents`] and
//! [`load_openai_agents_json`] do not call this function.
//!
//! [`process_jsonl_line`] ports `_process_jsonl_line` (lines 1019–1201).
//! A supplied tracker stops at [`SECRET_SCAN_FEED_UNAVAILABLE`] before the
//! line bytes are read. An absent tracker does not call `feed`. When
//! `record_sizes` is a list, the next step appends `byte_end - byte_offset`.
//! A truncated line, a NUL line, and invalid UTF-8 then stop at
//! [`EXTRACT_RECORD_ID_UNAVAILABLE`], before [`model::finding::make_finding`].
//! A decodable line stops at [`DECODE_JSON_DUPAWARE_UNAVAILABLE`]. JSON is not
//! parsed. SL001, SL002, SL009, and SL011 are not produced. `_check_version`
//! is not ported.
//!
//! `limits is None` uses [`DEFAULT_MAX_FILE_BYTES`] from `src/sesslint/io.py`
//! at this pin (`100 * 1024 * 1024`). A provided integer is that cap.
//! [`MaxFileBytes::Bool`] is not an integer and is not used as `0` or `1`.
//!
//! The size and SQLite gates call [`model::finding::make_finding`] with the
//! fingerprint omitted. That stops at
//! `sesslint.determinism.canonical_json_bytes is not available`. These gates
//! do not return a finding and do not invent a digest. The JSON and JSONL
//! loaders, and [`model::finding::sort_findings`], are not reached.
//!
//! [`detect_openai_agents`] uses the filename, then the bytes: an empty
//! buffer, [`SQLITE_MAGIC`], a leading UTF-8 BOM, the rollout envelope on the
//! first 4096 decoded bytes, then the signal substrings.
//!
//! [`normalize_timestamp`] walks `_TIMESTAMP_ISO_REGEX` by hand. There is no
//! `regex` dependency.
//!
//! [`project_run_state`] keeps the pin order: read `run_state` and
//! `checkpoints`, take `items()` (an exception yields no keys), sort by
//! `str(key)`, project at most 32 keys, then project at most 8 checkpoints.
//!
//! Gaps vs Python (recorded, not papered over):
//! - `SUPPORTED_OPENAI_AGENTS_VERSIONS`, `CRITICAL_KEYS`, `KNOWN_RECORD_KEYS`,
//!   `ITEM_TYPE_MAP`, and `CanonicalEvent` are not read by the functions in
//!   this file. They are not ported. [`build_payload`] does not apply
//!   `ITEM_TYPE_MAP`; `kind` is already classified.
//! - `str.isdigit` accepts Unicode decimal digits (`١`, U+0661) and then
//!   `int` keeps them. A seq string is ASCII `0-9` only here, so U+0661 stays
//!   `None`. Superscripts such as `²` fail `int` in Python and also stay
//!   `None` here.
//! - [`MetaValue::Int`] is `i64`. A larger Python `int` is not that variant.
//!   A digit string that does not fit is [`SeqNumber::Big`].
//! - Float text is Rust `Debug` with Python's exponent sign and two-digit
//!   padding. Locked samples match CPython `str`. Other floats are not claimed.
//! - A truthy checkpoint id whose default `str` cannot pass the discriminator
//!   allowlist (`bytes`, `list`, `tuple`, `dict`, `set`, and a default object
//!   repr all contain a character outside `[A-Za-z0-9_.-]`) is `<redacted>`.
//!   A custom `__str__` that would echo is not representable.
//! - [`MetaValue::Object`] is always truthy. `__bool__` and `__len__` are not
//!   modeled. Attribute reads are pure; the pin calls `getattr` twice for `seq`.
//! - [`MapValue::items_raise`] is the `items()` exception. A `Mapping.get` that
//!   raises is not representable. Custom sequences other than `list` and
//!   `tuple`, including `bytearray`, are not representable.
//! - [`SourceMetadata::attribute`] is `__getattr__` only. Python still resolves
//!   real `dict` methods (`get`, `keys`) before it. A stored key with one of
//!   those names is visible here. `__delitem__`, `pop`, `update`, and iteration
//!   are not ported. Missing `checkpoints` is an attribute error. This class
//!   does not invent an empty list.
//! - A Rust `&str` cannot contain a lone surrogate.
//! - `str.lower` follows Rust Unicode lowercase. A few special cases such as
//!   U+0130 differ from CPython. ASCII filenames and versions match.
//! - `str.isdigit` and default `re` `\d` accept Unicode decimal digits
//!   (category Nd). [`normalize_version`] and [`normalize_timestamp`] accept
//!   ASCII `0-9` only. The timestamp walk does not check the calendar.
//! - Python `re` `$` also matches before one trailing newline.
//!   [`normalize_timestamp`] strips first, and that strip already removes the
//!   newline.
//! - A string tool-call input does not fall through when decode would raise.
//!   The decoder call is required, so [`build_payload`] returns
//!   [`BuildPayloadError::Unavailable`] and not `{"value": <original str>}`.
//! - `str()` of [`MetaValue::Bytes`], [`MetaValue::Set`], or
//!   [`MetaValue::Object`] is not built. Bytes content and set items are not
//!   stored, and a custom `__str__` is not representable.
//!   [`BuildPayloadError::Unrendered`] is that refusal. It is not a payload.
//! - [`EventList`] stores the constructor sequence. The rest of `list` is not
//!   ported. Two default lists do not share one [`SourceMetadata`].
//! - [`load_openai_agents_json`] does not build `SecretScanTracker` and does
//!   not read the document, `path_str`, or `limits`.
//!   [`SuppliedSecretScanTracker`] has no scan state.
//!   [`crate::source::SuppliedReaderLimits`] is the `sesslint.io` limits
//!   witness, unread here.
//! - [`load_openai_agents_jsonl`] builds the collision guard and the drift
//!   tracker, then stops. `MalformedTailTracker` is not built. The buffer is
//!   not split into lines. [`process_jsonl_line`] and `feed` are not called.
//!   The result is not an [`EventList`].
//! - A supplied [`SuppliedSecretScanTracker`] has no `feed`. That path does
//!   not read the line. `record_sizes` grows only when the value is a list.
//!   The appended value is `byte_end - byte_offset` as [`MetaValue::Int`].
//!   A tuple is not a list. A bool coordinate is not representable.
//! - `extract_record_id` and `decode_json_dupaware` are not called. No record
//!   id, fingerprint, or SL001/SL002/SL009/SL011 is produced. Python
//!   `str.strip` runs before the decoder. Strip cannot fail, and the stripped
//!   text is not kept.

use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PrefixComponent};

use model::canonical::SessionEvent;
use model::codes::{Repairability, Severity, SL001};
use model::finding::PyValue as FindingValue;
use model::finding::{make_finding, Finding, MakeFindingInput, SourceLine, SourceRef};

use crate::drift::DriftTracker;
use crate::safe_value::safe_discriminator;
use crate::safe_value::PyValue;
use crate::source::SuppliedReaderLimits;
use crate::synthetic::SyntheticIdCollisionGuard;

/// Python: `MAX_PROJECTED_RUN_STATE_KEYS`.
pub const MAX_PROJECTED_RUN_STATE_KEYS: usize = 32;

/// Python: `MAX_PROJECTED_CHECKPOINTS`.
pub const MAX_PROJECTED_CHECKPOINTS: usize = 8;

/// Python `AttributeError` from [`SourceMetadata::attribute`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataAttributeError {
    message: String,
}

impl MetadataAttributeError {
    fn new(name: &str) -> Self {
        Self {
            message: format!("SourceMetadata has no attribute {}", python_str_repr(name)),
        }
    }

    /// The Python exception text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MetadataAttributeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for MetadataAttributeError {}

/// Python `KeyError` from [`SourceMetadata::item`].
///
/// [`Display`] is `repr(key)`, which is what `str(KeyError(key))` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataKeyError {
    message: String,
}

impl MetadataKeyError {
    fn new(key: &str) -> Self {
        Self {
            message: python_str_repr(key),
        }
    }

    /// The Python exception text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MetadataKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for MetadataKeyError {}

/// Key in a run-state mapping. Sorting and `safe_discriminator` use [`MapKey::text`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapKey {
    /// Python `str`.
    Str(String),
    /// Python `int`. `bool` is [`Self::Bool`].
    Int(i64),
    /// Python `bool`.
    Bool(bool),
    /// Python `None`. `str` is `None`.
    Null,
    /// Python `float`, stored as IEEE bits so `-0.0` and `NaN` stay distinct.
    Float(u64),
    /// `str(key)` for a key this port does not render. Not a `str` key for `.get`.
    Rendered(String),
}

impl MapKey {
    /// Python `float` key.
    #[must_use]
    pub fn float(value: f64) -> Self {
        Self::Float(value.to_bits())
    }

    /// Python `str(key)`.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Str(text) | Self::Rendered(text) => text.clone(),
            Self::Int(number) => number.to_string(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Null => "None".to_owned(),
            Self::Float(bits) => python_float_str(f64::from_bits(*bits)),
        }
    }
}

/// Python mapping used as `run_state` or as a checkpoint record.
///
/// `entries` is `items()` order. This is not a `HashMap`. Equal keys are not
/// collapsed; a real `dict` collapses them before they are stored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapValue {
    /// `items()` pairs. Ignored when [`Self::items_raise`] is set.
    pub entries: Vec<(MapKey, MetaValue)>,
    /// `list(mapping.items())` raises. The key projection is empty.
    pub items_raise: bool,
}

impl MapValue {
    /// Mapping whose `items()` returns `entries`.
    #[must_use]
    pub fn new(entries: Vec<(MapKey, MetaValue)>) -> Self {
        Self {
            entries,
            items_raise: false,
        }
    }

    /// Mapping whose `items()` raises. `get` still sees `entries`.
    #[must_use]
    pub fn raising(entries: Vec<(MapKey, MetaValue)>) -> Self {
        Self {
            entries,
            items_raise: true,
        }
    }
}

/// Value observed by [`project_run_state`] and stored on [`SourceMetadata`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetaValue {
    /// Python `None`.
    Null,
    /// Python `bool`. Not an [`Self::Int`].
    Bool(bool),
    /// Python `int` that fits in `i64`.
    Int(i64),
    /// Python `float`, as IEEE bits.
    Float(u64),
    /// Python `str`.
    Str(String),
    /// Python `bytes`. The length is `len(val)`. Content is not kept.
    Bytes(usize),
    /// Python `list`.
    List(Vec<MetaValue>),
    /// Python `tuple`.
    Tuple(Vec<MetaValue>),
    /// Python `dict` or other `Mapping`.
    Map(MapValue),
    /// Python `set`. `len` only. A set is not a sequence.
    Set(usize),
    /// Not a mapping and not one of the scalars above.
    Object(Box<AttrObject>),
}

impl MetaValue {
    /// Python `float`.
    #[must_use]
    pub fn float(value: f64) -> Self {
        Self::Float(value.to_bits())
    }

    fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

/// Non-mapping object. The pin reads these attributes and no others.
///
/// Missing and `None` are both [`Option::None`], matching `getattr(..., None)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttrObject {
    /// `type(obj).__name__`, used only by [`safe_type_value`].
    pub type_name: String,
    /// Source attribute `run_state`.
    pub run_state: Option<MetaValue>,
    /// Source attribute `checkpoints`.
    pub checkpoints: Option<MetaValue>,
    /// Checkpoint attribute `id`.
    pub id: Option<MetaValue>,
    /// Checkpoint attribute `checkpoint_id`.
    pub checkpoint_id: Option<MetaValue>,
    /// Checkpoint attribute `seq`.
    pub seq: Option<MetaValue>,
    /// Checkpoint attribute `checkpoint_seq`.
    pub checkpoint_seq: Option<MetaValue>,
    /// Checkpoint attribute `hash`.
    pub hash: Option<MetaValue>,
    /// Checkpoint attribute `payload_hash`.
    pub payload_hash: Option<MetaValue>,
    /// Checkpoint attribute `state_hash`.
    pub state_hash: Option<MetaValue>,
    /// Checkpoint attribute `ts`.
    pub ts: Option<MetaValue>,
    /// Checkpoint attribute `created_at`.
    pub created_at: Option<MetaValue>,
}

impl AttrObject {
    /// Object whose attributes are all missing.
    #[must_use]
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            run_state: None,
            checkpoints: None,
            id: None,
            checkpoint_id: None,
            seq: None,
            checkpoint_seq: None,
            hash: None,
            payload_hash: None,
            state_hash: None,
            ts: None,
            created_at: None,
        }
    }

    fn field(&self, name: &str) -> Option<&MetaValue> {
        match name {
            "id" => self.id.as_ref(),
            "checkpoint_id" => self.checkpoint_id.as_ref(),
            "seq" => self.seq.as_ref(),
            "checkpoint_seq" => self.checkpoint_seq.as_ref(),
            "hash" => self.hash.as_ref(),
            "payload_hash" => self.payload_hash.as_ref(),
            "state_hash" => self.state_hash.as_ref(),
            "ts" => self.ts.as_ref(),
            "created_at" => self.created_at.as_ref(),
            _ => None,
        }
    }
}

/// Preserved source provenance and checkpoint evidence.
///
/// Python: `SourceMetadata` at line 303. Insertion order is the order of first
/// insert. Assigning an existing key updates the value and keeps its position.
/// This is a `dict` subclass there. It is not the canonical adapter's metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceMetadata {
    entries: Vec<(String, MetaValue)>,
}

impl SourceMetadata {
    /// Python: `SourceMetadata()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Python `dict` constructed from pairs, in that order.
    #[must_use]
    pub fn from_entries<I, K>(entries: I) -> Self
    where
        I: IntoIterator<Item = (K, MetaValue)>,
        K: Into<String>,
    {
        let mut meta = Self::new();
        for (key, value) in entries {
            meta.insert(key, value);
        }
        meta
    }

    /// Entries in insertion order.
    #[must_use]
    pub fn entries(&self) -> &[(String, MetaValue)] {
        &self.entries
    }

    /// Python `dict.get` without a default. A missing key is `None`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&MetaValue> {
        self.entries
            .iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// Mutable `dict.get` without a default. A missing key is `None`.
    ///
    /// The last inserted entry wins, matching [`Self::get`].
    #[must_use]
    pub fn get_mut(&mut self, key: &str) -> Option<&mut MetaValue> {
        self.entries
            .iter_mut()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// Python `dict.__getitem__`.
    ///
    /// # Errors
    ///
    /// A missing key is [`MetadataKeyError`]. [`Display`] is Python `repr`.
    pub fn item(&self, key: &str) -> Result<&MetaValue, MetadataKeyError> {
        self.entries
            .iter()
            .rev()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
            .ok_or_else(|| MetadataKeyError::new(key))
    }

    /// Python `dict.__setitem__` and [`Self::set_attribute`].
    pub fn insert(&mut self, key: impl Into<String>, value: MetaValue) {
        let key = key.into();
        if let Some(slot) = self.entries.iter_mut().find(|(name, _)| *name == key) {
            slot.1 = value;
            return;
        }
        self.entries.push((key, value));
    }

    /// Python `__getattr__`.
    ///
    /// # Errors
    ///
    /// `SourceMetadata has no attribute {name!r}`.
    pub fn attribute(&self, name: &str) -> Result<&MetaValue, MetadataAttributeError> {
        self.entries
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
            .ok_or_else(|| MetadataAttributeError::new(name))
    }

    /// Python `__setattr__`. Stores `name` as a key.
    pub fn set_attribute(&mut self, name: impl Into<String>, value: MetaValue) {
        self.insert(name, value);
    }
}

/// Input of [`project_run_state`].
#[derive(Debug, Clone, Copy)]
pub enum RunSource<'a> {
    /// Python `None`.
    None,
    /// `isinstance(source, Mapping)`, including [`SourceMetadata`].
    Mapping(&'a SourceMetadata),
    /// Not `None` and not a `Mapping`.
    Object(&'a AttrObject),
}

/// `seq` in one projected checkpoint.
///
/// [`Self::Small`] fits in `i64`. [`Self::Big`] is the canonical decimal of a
/// larger digit string, without a sign and without leading zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeqNumber {
    /// Python `int` in `i64`.
    Small(i64),
    /// Python `int` whose decimal does not fit in `i64`.
    Big(String),
}

impl SeqNumber {
    /// `Some` when the integer fits in `i64`.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Small(number) => Some(*number),
            Self::Big(_) => None,
        }
    }
}

/// One projected checkpoint. Field order matches the pin: hash, id, seq, ts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedCheckpoint {
    /// Safe shape, or the literal `<NoneType>` when the hash is `None`.
    pub hash: String,
    /// Allowlisted id, `""`, `<invalid>`, or `<redacted>`.
    pub id: String,
    /// Parsed `seq`, or `None`.
    pub seq: Option<SeqNumber>,
    /// `bool(ts)`.
    pub ts: bool,
}

/// Counts added only when [`RunProjection::truncated`] is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TruncationTotals {
    /// `len` of the sorted run-state items before the cap.
    pub total_keys: usize,
    /// `len` of the checkpoint sequence before the cap.
    pub total_checkpoints: usize,
    /// `max(0, total_keys - 32)`.
    pub truncated_keys: usize,
    /// `max(0, total_checkpoints - 8)`.
    pub truncated_checkpoints: usize,
}

/// Return value of [`project_run_state`].
///
/// `shapes` is insertion order, which is the sorted key order. `totals` is
/// `None` when `truncated` is false. Python omits those four keys then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunProjection {
    /// Projected checkpoints, at most [`MAX_PROJECTED_CHECKPOINTS`].
    pub checkpoints: Vec<ProjectedCheckpoint>,
    /// Projected key names, at most [`MAX_PROJECTED_RUN_STATE_KEYS`].
    pub keys: Vec<String>,
    /// `(safe key, shape)` in the same order as [`Self::keys`].
    pub shapes: Vec<(String, String)>,
    /// Either cap was exceeded.
    pub truncated: bool,
    /// Present only when [`Self::truncated`] is true.
    pub totals: Option<TruncationTotals>,
}

impl RunProjection {
    /// Shape stored for `key`, if that safe key was projected.
    #[must_use]
    pub fn shape(&self, key: &str) -> Option<&str> {
        self.shapes
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, shape)| shape.as_str())
    }
}

/// Safe type and size descriptor.
///
/// Python: `_safe_type_value`. Delegates to
/// [`crate::safe_value::safe_type_value`].
#[must_use]
pub fn safe_type_value(val: PyValue<'_>) -> String {
    crate::safe_value::safe_type_value(val)
}

/// Redact runtime state and checkpoints to a content-free structural projection.
///
/// Python: `project_run_state`. At most 32 keys and 8 checkpoints. Values are
/// safe shapes. Keys go through [`safe_discriminator`]. Checkpoint ids that
/// do not echo are `<redacted>`.
#[must_use]
pub fn project_run_state(source: RunSource<'_>) -> RunProjection {
    let (run_state, checkpoints) = source_fields(source);
    let (keys, shapes, total_keys, keys_truncated) = project_keys(run_map(run_state));
    let checkpoint_list = checkpoint_items(checkpoints);
    let total_checkpoints = checkpoint_list.len();
    let checkpoints_truncated = total_checkpoints > MAX_PROJECTED_CHECKPOINTS;
    let projected = checkpoint_list
        .iter()
        .take(MAX_PROJECTED_CHECKPOINTS)
        .map(project_checkpoint)
        .collect();
    let truncated = keys_truncated || checkpoints_truncated;
    RunProjection {
        checkpoints: projected,
        keys,
        shapes,
        truncated,
        totals: truncation(truncated, total_keys, total_checkpoints),
    }
}

fn source_fields<'a>(source: RunSource<'a>) -> (Option<&'a MetaValue>, Option<&'a MetaValue>) {
    match source {
        RunSource::None => (None, None),
        RunSource::Mapping(meta) => (meta.get("run_state"), meta.get("checkpoints")),
        RunSource::Object(obj) => (obj.run_state.as_ref(), obj.checkpoints.as_ref()),
    }
}

fn run_map(value: Option<&MetaValue>) -> Option<&MapValue> {
    match value {
        Some(MetaValue::Map(map)) => Some(map),
        _ => None,
    }
}

fn checkpoint_items(value: Option<&MetaValue>) -> &[MetaValue] {
    match value {
        Some(MetaValue::List(items) | MetaValue::Tuple(items)) => items.as_slice(),
        _ => &[],
    }
}

fn project_keys(map: Option<&MapValue>) -> (Vec<String>, Vec<(String, String)>, usize, bool) {
    let Some(map) = map else {
        return (Vec::new(), Vec::new(), 0, false);
    };
    if map.items_raise {
        return (Vec::new(), Vec::new(), 0, false);
    }
    let mut rows: Vec<(String, &MetaValue)> = map
        .entries
        .iter()
        .map(|(key, value)| (key.text(), value))
        .collect();
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let total = rows.len();
    let truncated = total > MAX_PROJECTED_RUN_STATE_KEYS;
    let mut keys = Vec::new();
    let mut shapes = Vec::new();
    for (text, value) in rows.into_iter().take(MAX_PROJECTED_RUN_STATE_KEYS) {
        let (rendered, _) = safe_discriminator(PyValue::Str(&text));
        let safe = dedup_key(&rendered, &shapes);
        keys.push(safe.clone());
        shapes.push((safe, shape_of(value)));
    }
    (keys, shapes, total, truncated)
}

fn dedup_key(rendered: &str, shapes: &[(String, String)]) -> String {
    if !shape_has(shapes, rendered) {
        return rendered.to_owned();
    }
    let mut suffix = 1usize;
    loop {
        let candidate = format!("{rendered}#{suffix}");
        if !shape_has(shapes, &candidate) || suffix == usize::MAX {
            return candidate;
        }
        suffix += 1;
    }
}

fn shape_has(shapes: &[(String, String)], key: &str) -> bool {
    shapes.iter().any(|(name, _)| name == key)
}

fn truncation(
    truncated: bool,
    total_keys: usize,
    total_checkpoints: usize,
) -> Option<TruncationTotals> {
    if !truncated {
        return None;
    }
    Some(TruncationTotals {
        total_keys,
        total_checkpoints,
        truncated_keys: total_keys.saturating_sub(MAX_PROJECTED_RUN_STATE_KEYS),
        truncated_checkpoints: total_checkpoints.saturating_sub(MAX_PROJECTED_CHECKPOINTS),
    })
}

fn project_checkpoint(value: &MetaValue) -> ProjectedCheckpoint {
    match value {
        MetaValue::Map(map) => project_fields(FieldRead::Map(map)),
        MetaValue::Object(obj) => project_fields(FieldRead::Object(obj)),
        MetaValue::Null
        | MetaValue::Bool(_)
        | MetaValue::Int(_)
        | MetaValue::Float(_)
        | MetaValue::Str(_)
        | MetaValue::Bytes(_) => invalid_checkpoint(),
        MetaValue::List(_) | MetaValue::Tuple(_) | MetaValue::Set(_) => {
            project_fields(FieldRead::Empty)
        }
    }
}

enum FieldRead<'a> {
    Map(&'a MapValue),
    Object(&'a AttrObject),
    Empty,
}

impl<'a> FieldRead<'a> {
    fn get(&self, name: &str) -> Option<&'a MetaValue> {
        match self {
            Self::Map(map) => map_get(map, name),
            Self::Object(obj) => obj.field(name),
            Self::Empty => None,
        }
    }
}

fn map_get<'a>(map: &'a MapValue, key: &str) -> Option<&'a MetaValue> {
    map.entries
        .iter()
        .rev()
        .find(|(entry, _)| matches!(entry, MapKey::Str(text) if text == key))
        .map(|(_, value)| value)
}

fn project_fields(fields: FieldRead<'_>) -> ProjectedCheckpoint {
    let id = match first_truthy(&[fields.get("id"), fields.get("checkpoint_id")]) {
        Some(value) => render_id(value),
        None => String::new(),
    };
    let seq = parse_seq(raw_seq(fields.get("seq"), fields.get("checkpoint_seq")));
    let hash = hash_shape(or_chain(&[
        fields.get("hash"),
        fields.get("payload_hash"),
        fields.get("state_hash"),
    ]));
    let ts = or_chain(&[fields.get("ts"), fields.get("created_at")]).is_some_and(is_truthy);
    ProjectedCheckpoint { hash, id, seq, ts }
}

fn invalid_checkpoint() -> ProjectedCheckpoint {
    ProjectedCheckpoint {
        hash: "<NoneType>".to_owned(),
        id: "<invalid>".to_owned(),
        seq: None,
        ts: false,
    }
}

fn first_truthy<'a>(values: &[Option<&'a MetaValue>]) -> Option<&'a MetaValue> {
    values
        .iter()
        .copied()
        .find(|value| value.is_some_and(is_truthy))
        .flatten()
}

fn or_chain<'a>(values: &[Option<&'a MetaValue>]) -> Option<&'a MetaValue> {
    let mut last = None;
    for value in values.iter().copied() {
        match value {
            Some(item) if is_truthy(item) => return Some(item),
            Some(item) => last = Some(item),
            None => last = None,
        }
    }
    last
}

fn raw_seq<'a>(
    seq: Option<&'a MetaValue>,
    checkpoint_seq: Option<&'a MetaValue>,
) -> Option<&'a MetaValue> {
    match seq {
        Some(value) if !value.is_null() => Some(value),
        _ => checkpoint_seq,
    }
}

fn hash_shape(raw: Option<&MetaValue>) -> String {
    match raw {
        Some(value) if !value.is_null() => shape_of(value),
        _ => "<NoneType>".to_owned(),
    }
}

fn parse_seq(value: Option<&MetaValue>) -> Option<SeqNumber> {
    match value {
        Some(MetaValue::Int(number)) => Some(SeqNumber::Small(*number)),
        Some(MetaValue::Str(text)) => parse_seq_str(text),
        _ => None,
    }
}

fn parse_seq_str(text: &str) -> Option<SeqNumber> {
    let stripped = python_strip(text);
    if stripped.is_empty() || !stripped.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(seq_from_ascii_digits(stripped))
}

fn seq_from_ascii_digits(digits: &str) -> SeqNumber {
    let trimmed = digits.trim_start_matches('0');
    let body = if trimmed.is_empty() { "0" } else { trimmed };
    match body.parse::<i64>() {
        Ok(number) => SeqNumber::Small(number),
        Err(_) => SeqNumber::Big(body.to_owned()),
    }
}

fn render_id(value: &MetaValue) -> String {
    let Some(text) = id_text(value) else {
        return "<redacted>".to_owned();
    };
    let (safe, truncated) = safe_discriminator(PyValue::Str(&text));
    if truncated {
        "<redacted>".to_owned()
    } else {
        safe
    }
}

/// `Some` when `str(value)` is determined. `None` when the default `str`
/// fails the discriminator allowlist, so the id is `<redacted>`.
fn id_text(value: &MetaValue) -> Option<String> {
    match value {
        MetaValue::Str(text) => Some(text.clone()),
        MetaValue::Int(number) => Some(number.to_string()),
        MetaValue::Bool(true) => Some("True".to_owned()),
        MetaValue::Bool(false) => Some("False".to_owned()),
        MetaValue::Float(bits) => Some(python_float_str(f64::from_bits(*bits))),
        MetaValue::Null => Some("None".to_owned()),
        MetaValue::Bytes(_)
        | MetaValue::List(_)
        | MetaValue::Tuple(_)
        | MetaValue::Map(_)
        | MetaValue::Set(_)
        | MetaValue::Object(_) => None,
    }
}

fn shape_of(value: &MetaValue) -> String {
    safe_type_value(py_of(value))
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

fn is_truthy(value: &MetaValue) -> bool {
    match value {
        MetaValue::Null => false,
        MetaValue::Bool(flag) => *flag,
        MetaValue::Int(number) => *number != 0,
        MetaValue::Float(bits) => f64::from_bits(*bits) != 0.0,
        MetaValue::Str(text) => !text.is_empty(),
        MetaValue::Bytes(len) | MetaValue::Set(len) => *len != 0,
        MetaValue::List(items) | MetaValue::Tuple(items) => !items.is_empty(),
        MetaValue::Map(map) => !map.entries.is_empty(),
        MetaValue::Object(_) => true,
    }
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

fn python_strip(text: &str) -> &str {
    let mut start = 0usize;
    for ch in text.chars() {
        if !is_python_space(ch) {
            break;
        }
        start += ch.len_utf8();
    }
    let Some(tail) = text.get(start..) else {
        return "";
    };
    let mut end = tail.len();
    for ch in tail.chars().rev() {
        if !is_python_space(ch) {
            break;
        }
        end -= ch.len_utf8();
    }
    tail.get(..end).unwrap_or_default()
}

/// Python `re` `\s` and `str.isspace` for a Unicode scalar.
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
            | 0x2000..=0x200A | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x3000
    )
}

/// Python `repr` for `str`, preferring single quotes.
fn python_str_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(value.len().saturating_add(2));
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            found if found == quote => {
                out.push('\\');
                out.push(quote);
            }
            found if python_repr_literal(found) => out.push(found),
            found if u32::from(found) < 0x100 => push_hex(&mut out, "\\x", u32::from(found), 2),
            found if u32::from(found) < 0x10000 => push_hex(&mut out, "\\u", u32::from(found), 4),
            found => push_hex(&mut out, "\\U", u32::from(found), 8),
        }
    }
    out.push(quote);
    out
}

fn python_repr_literal(ch: char) -> bool {
    if ch.is_ascii() {
        return ch == ' ' || ch.is_ascii_graphic();
    }
    !ch.is_control() && !matches!(ch, '\u{2028}' | '\u{2029}')
}

fn push_hex(out: &mut String, prefix: &str, value: u32, width: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str(prefix);
    for shift in (0..width).rev() {
        let nibble = (value >> (shift * 4)) & 0x0f;
        let Some(index) = usize::try_from(nibble).ok() else {
            return;
        };
        let Some(byte) = HEX.get(index).copied() else {
            return;
        };
        out.push(char::from(byte));
    }
}

/// Magic bytes identifying SQLite database files.
///
/// Python: `SQLITE_MAGIC`.
pub const SQLITE_MAGIC: &[u8] = b"SQLite format 3\x00";

/// `sesslint.io._STRICT_JSON_DECODER.decode` is not in this crate.
pub const STRICT_JSON_DECODE_UNAVAILABLE: &str =
    "sesslint.io._STRICT_JSON_DECODER.decode is not available";

/// `str()` cannot be built for a bytes, set, or custom object value.
pub const STR_UNRENDERED: &str = "str() is not available for this value";

const DETECT_PREFIX_BYTES: usize = 4096;

const UTF8_BOM: &[u8] = b"\xef\xbb\xbf";

const EPOCH_TIMESTAMP: &str = "1970-01-01T00:00:00Z";

const ROLLOUT_ENVELOPES: [&str; 6] = [
    "\"type\":\"session_meta\"",
    "\"type\": \"session_meta\"",
    "\"type\":\"response_item\"",
    "\"type\": \"response_item\"",
    "\"type\":\"turn_context\"",
    "\"type\": \"turn_context\"",
];

/// Failure from [`build_payload`].
///
/// [`Display`](std::fmt::Display) is the message only.
/// [`Self::Unavailable`] is the missing decoder.
/// [`Self::Unrendered`] is a `str()` this module cannot build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildPayloadError {
    /// [`STRICT_JSON_DECODE_UNAVAILABLE`].
    Unavailable,
    /// [`STR_UNRENDERED`].
    Unrendered,
}

impl BuildPayloadError {
    /// The Python seam, or the refusal to invent `str()`.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Unavailable => STRICT_JSON_DECODE_UNAVAILABLE,
            Self::Unrendered => STR_UNRENDERED,
        }
    }
}

impl fmt::Display for BuildPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for BuildPayloadError {}

/// Extended event list carrying preserved source metadata.
///
/// Python: `EventList` at line 316. `source` is keyword-only. `None` builds a
/// new [`SourceMetadata`]. This is not [`crate::canonical::EventList`].
#[derive(Debug, Clone)]
pub struct EventList {
    events: Vec<SessionEvent>,
    /// Python attribute `source`.
    pub source: SourceMetadata,
}

impl EventList {
    /// Python: `EventList(iterable=(), *, source=None)`.
    #[must_use]
    pub fn new(events: Vec<SessionEvent>, source: Option<SourceMetadata>) -> Self {
        Self {
            events,
            source: match source {
                Some(source) => source,
                None => SourceMetadata::new(),
            },
        }
    }

    /// Events in constructor order.
    #[must_use]
    pub fn events(&self) -> &[SessionEvent] {
        &self.events
    }

    /// Python `len(events)`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Python `not events`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Normalize a raw version string.
///
/// Python: `normalize_version`. Strip Python whitespace, lowercase, then drop
/// one leading `v` when the next character is an ASCII digit.
#[must_use]
pub fn normalize_version(version: &str) -> String {
    let cleaned = python_strip(version).to_lowercase();
    strip_ascii_version_mark(&cleaned)
}

fn strip_ascii_version_mark(cleaned: &str) -> String {
    let mut chars = cleaned.chars();
    if chars.next() != Some('v') {
        return cleaned.to_owned();
    }
    match chars.next() {
        Some(second) if second.is_ascii_digit() => match cleaned.get('v'.len_utf8()..) {
            Some(rest) => rest.to_owned(),
            None => cleaned.to_owned(),
        },
        _ => cleaned.to_owned(),
    }
}

/// Heuristic confidence that `first_bytes` is an OpenAI Agents SDK export.
///
/// Python: `detect_openai_agents`. Returns `0.0`, `0.2`, `0.3`, `0.5`, `0.8`,
/// or `1.0`. `filename` is lowercased and its suffix is read.
#[must_use]
pub fn detect_openai_agents(first_bytes: &[u8], filename: &str) -> f64 {
    let fn_lower = filename.to_lowercase();
    if !openai_filename(&fn_lower) {
        return 0.0;
    }
    if first_bytes.is_empty() {
        return 0.0;
    }
    if first_bytes.starts_with(SQLITE_MAGIC) {
        if fn_lower.ends_with(".sqlite") || fn_lower.ends_with(".db") {
            return 1.0;
        }
        return 0.5;
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
    if rollout_envelope(&decoded) {
        return 0.3;
    }
    let signals = signal_count(&decoded);
    if signals >= 3 {
        return 1.0;
    }
    if signals >= 1 {
        return 0.8;
    }
    if fn_lower.ends_with(".json") || fn_lower.ends_with(".jsonl") {
        return 0.2;
    }
    0.0
}

fn openai_filename(fn_lower: &str) -> bool {
    fn_lower.ends_with(".json")
        || fn_lower.ends_with(".jsonl")
        || fn_lower.ends_with(".sqlite")
        || fn_lower.ends_with(".db")
}

fn rollout_envelope(decoded: &str) -> bool {
    ROLLOUT_ENVELOPES
        .iter()
        .any(|needle| decoded.contains(needle))
}

fn signal_count(decoded: &str) -> u32 {
    let mut signals = 0u32;
    if decoded.contains("\"items\"") {
        signals += 2;
    }
    if decoded.contains("\"run_state\"") {
        signals += 3;
    }
    if decoded.contains("\"checkpoints\"") {
        signals += 3;
    }
    if decoded.contains("\"call_id\"") {
        signals += 2;
    }
    if decoded.contains("\"tool_call\"") || decoded.contains("\"tool_result\"") {
        signals += 2;
    }
    if decoded.contains("\"function_call\"") || decoded.contains("\"function_call_output\"") {
        signals += 2;
    }
    if decoded.contains("\"handoff\"") {
        signals += 2;
    }
    if decoded.contains("\"agent_sdk_version\"") || decoded.contains("\"export_version\"") {
        signals += 2;
    }
    signals
}

/// Ensure a timestamp is the pin's ISO shape, or the epoch sentinel.
///
/// Python: `_normalize_timestamp`. A non-`str`, or a string that is empty
/// after stripping, is `1970-01-01T00:00:00Z`. A matching string is returned
/// without the surrounding whitespace. Naive timestamps match and stay.
#[must_use]
pub fn normalize_timestamp(raw_ts: &MetaValue) -> String {
    let MetaValue::Str(text) = raw_ts else {
        return EPOCH_TIMESTAMP.to_owned();
    };
    let val = python_strip(text);
    if val.is_empty() || !timestamp_shape(val) {
        return EPOCH_TIMESTAMP.to_owned();
    }
    val.to_owned()
}

fn timestamp_shape(val: &str) -> bool {
    walk_timestamp(val.as_bytes()).is_some()
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

/// Construct the content payload for one canonical kind.
///
/// Python: `_build_payload`. `kind` is compared as a string. A tool-call
/// string input renders the name and call id first, then stops at
/// [`STRICT_JSON_DECODE_UNAVAILABLE`] and does not return a payload.
///
/// # Errors
///
/// [`BuildPayloadError::Unavailable`] when a tool-call input is a `str`.
/// [`BuildPayloadError::Unrendered`] when `str()` cannot be built.
pub fn build_payload(
    obj: &MapValue,
    actor: &str,
    kind: &str,
    rec_id: &str,
    raw_type: &MetaValue,
) -> Result<MapValue, BuildPayloadError> {
    if kind == "tool_call" {
        return payload_tool_call(obj, rec_id);
    }
    if kind == "tool_result" {
        return payload_tool_result(obj);
    }
    if kind == "handoff" {
        return payload_handoff(obj);
    }
    if kind == "checkpoint" {
        return payload_checkpoint(obj, rec_id);
    }
    if kind == "compaction_boundary" {
        return payload_compaction(obj);
    }
    if kind == "unknown" {
        return payload_unknown(raw_type);
    }
    payload_message(obj, actor)
}

fn payload_tool_call(obj: &MapValue, rec_id: &str) -> Result<MapValue, BuildPayloadError> {
    let raw_name = first_non_null(obj, &["name", "tool_name", "function"]);
    let raw_call = first_non_null(obj, &["call_id", "tool_call_id"]);
    let raw_input = first_non_null(obj, &["args", "arguments", "input"]);
    let tool_name = match raw_name {
        Some(value) => meta_text(value)?,
        None => String::new(),
    };
    let call_id = match raw_call {
        Some(value) => meta_text(value)?,
        None => rec_id.to_owned(),
    };
    if matches!(raw_input, Some(MetaValue::Str(_))) {
        return Err(BuildPayloadError::Unavailable);
    }
    let input_payload = match raw_input {
        None => MetaValue::Map(MapValue::new(Vec::new())),
        Some(MetaValue::Map(map)) => MetaValue::Map(map.clone()),
        Some(other) => wrapped_value(other),
    };
    Ok(field_map(vec![
        ("call_id", MetaValue::Str(call_id.clone())),
        ("input", input_payload),
        ("name", MetaValue::Str(tool_name.clone())),
        ("tool_name", MetaValue::Str(tool_name)),
        ("tool_use_id", MetaValue::Str(call_id)),
    ]))
}

fn payload_tool_result(obj: &MapValue) -> Result<MapValue, BuildPayloadError> {
    let raw_call = first_non_null(obj, &["call_id", "tool_call_id"]);
    let call_id = match raw_call {
        Some(value) => meta_text(value)?,
        None => String::new(),
    };
    let content = match first_non_null(obj, &["content", "output", "result"]) {
        Some(value) => value.clone(),
        None => MetaValue::Str(String::new()),
    };
    let is_err = match first_non_null(obj, &["is_error", "error"]) {
        Some(value) => is_truthy(value),
        None => false,
    };
    Ok(field_map(vec![
        ("call_id", MetaValue::Str(call_id.clone())),
        ("content", content),
        ("is_error", MetaValue::Bool(is_err)),
        ("tool_use_id", MetaValue::Str(call_id)),
    ]))
}

fn payload_handoff(obj: &MapValue) -> Result<MapValue, BuildPayloadError> {
    let target = match first_non_null(obj, &["target", "handoff_to", "agent"]) {
        Some(value) => MetaValue::Str(meta_text(value)?),
        None => MetaValue::Null,
    };
    let mut fields = vec![("target", target)];
    if let Some(reason) = map_get(obj, "reason") {
        let (safe_reason, _) = safe_discriminator(py_of(reason));
        fields.push(("reason", MetaValue::Str(safe_reason)));
    }
    Ok(field_map(fields))
}

fn payload_checkpoint(obj: &MapValue, rec_id: &str) -> Result<MapValue, BuildPayloadError> {
    let chk_id = match first_non_null(obj, &["checkpoint_id", "id"]) {
        Some(value) => meta_text(value)?,
        None => rec_id.to_owned(),
    };
    let mut fields = vec![("checkpoint_id", MetaValue::Str(chk_id))];
    if let Some(seq) = map_get(obj, "seq") {
        fields.push(("seq", seq.clone()));
    }
    if let Some(hash) = map_get(obj, "hash") {
        fields.push(("hash", MetaValue::Str(meta_text(hash)?)));
    }
    if let Some(state) = map_get(obj, "state") {
        fields.push(("state", state.clone()));
    }
    Ok(field_map(fields))
}

fn payload_compaction(obj: &MapValue) -> Result<MapValue, BuildPayloadError> {
    let summary = match first_non_null(obj, &["summary", "content"]) {
        Some(value) => meta_text(value)?,
        None => String::new(),
    };
    Ok(field_map(vec![("summary", MetaValue::Str(summary))]))
}

fn payload_unknown(raw_type: &MetaValue) -> Result<MapValue, BuildPayloadError> {
    let type_text = if raw_type.is_null() {
        "<missing>".to_owned()
    } else {
        meta_text(raw_type)?
    };
    Ok(field_map(vec![("type", MetaValue::Str(type_text))]))
}

fn payload_message(obj: &MapValue, actor: &str) -> Result<MapValue, BuildPayloadError> {
    let content = match first_non_null(obj, &["content", "message", "text"]) {
        Some(value) => value.clone(),
        None => MetaValue::Str(String::new()),
    };
    Ok(field_map(vec![
        ("content", content),
        ("role", MetaValue::Str(actor.to_owned())),
    ]))
}

fn first_non_null<'a>(map: &'a MapValue, keys: &[&str]) -> Option<&'a MetaValue> {
    for key in keys {
        if let Some(value) = map_get(map, key) {
            if !value.is_null() {
                return Some(value);
            }
        }
    }
    None
}

fn field_map(fields: Vec<(&str, MetaValue)>) -> MapValue {
    MapValue::new(
        fields
            .into_iter()
            .map(|(key, value)| (MapKey::Str(key.to_owned()), value))
            .collect(),
    )
}

fn wrapped_value(value: &MetaValue) -> MetaValue {
    MetaValue::Map(field_map(vec![("value", value.clone())]))
}

fn meta_text(value: &MetaValue) -> Result<String, BuildPayloadError> {
    match python_meta_str(value) {
        Some(text) => Ok(text),
        None => Err(BuildPayloadError::Unrendered),
    }
}

fn python_meta_str(value: &MetaValue) -> Option<String> {
    match value {
        MetaValue::Str(text) => Some(text.clone()),
        other => python_meta_repr(other),
    }
}

fn python_meta_repr(value: &MetaValue) -> Option<String> {
    match value {
        MetaValue::Null => Some("None".to_owned()),
        MetaValue::Bool(true) => Some("True".to_owned()),
        MetaValue::Bool(false) => Some("False".to_owned()),
        MetaValue::Int(number) => Some(number.to_string()),
        MetaValue::Float(bits) => Some(python_float_str(f64::from_bits(*bits))),
        MetaValue::Str(text) => Some(python_str_repr(text)),
        MetaValue::List(items) => join_repr("[", "]", false, items),
        MetaValue::Tuple(items) => join_repr("(", ")", true, items),
        MetaValue::Map(map) => map_repr(map),
        MetaValue::Bytes(_) | MetaValue::Set(_) | MetaValue::Object(_) => None,
    }
}

fn join_repr(open: &str, close: &str, tuple: bool, items: &[MetaValue]) -> Option<String> {
    let mut out = String::from(open);
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_meta_repr(item)?);
    }
    if tuple && items.len() == 1 {
        out.push(',');
    }
    out.push_str(close);
    Some(out)
}

fn map_repr(map: &MapValue) -> Option<String> {
    let mut out = String::from("{");
    for (index, (key, value)) in map.entries.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&key_repr(key)?);
        out.push_str(": ");
        out.push_str(&python_meta_repr(value)?);
    }
    out.push('}');
    Some(out)
}

fn key_repr(key: &MapKey) -> Option<String> {
    match key {
        MapKey::Str(text) => Some(python_str_repr(text)),
        MapKey::Int(number) => Some(number.to_string()),
        MapKey::Bool(true) => Some("True".to_owned()),
        MapKey::Bool(false) => Some("False".to_owned()),
        MapKey::Null => Some("None".to_owned()),
        MapKey::Float(bits) => Some(python_float_str(f64::from_bits(*bits))),
        MapKey::Rendered(_) => None,
    }
}

/// Python `DEFAULT_MAX_FILE_BYTES` from `src/sesslint/io.py` at the pin.
///
/// `100 * 1024 * 1024`. This is not the scan crate's copy.
pub const DEFAULT_MAX_FILE_BYTES: i64 = 100 * 1024 * 1024;

/// `sesslint.checks.hygiene.SecretScanTracker` is not in this crate.
pub const SECRET_SCAN_TRACKER_UNAVAILABLE: &str =
    "sesslint.checks.hygiene.SecretScanTracker is not available";

/// `sesslint.checks.hygiene.SecretScanTracker.feed_blob` is not in this crate.
pub const SECRET_SCAN_FEED_BLOB_UNAVAILABLE: &str =
    "sesslint.checks.hygiene.SecretScanTracker.feed_blob is not available";

/// `sesslint.checks.hygiene.SecretScanTracker.feed` is not in this crate.
pub const SECRET_SCAN_FEED_UNAVAILABLE: &str =
    "sesslint.checks.hygiene.SecretScanTracker.feed is not available";

/// `sesslint.io.MalformedTailTracker` is not in this crate.
pub const MALFORMED_TAIL_TRACKER_UNAVAILABLE: &str =
    "sesslint.io.MalformedTailTracker is not available";

/// `sesslint.io.extract_record_id` is not in this crate.
pub const EXTRACT_RECORD_ID_UNAVAILABLE: &str = "sesslint.io.extract_record_id is not available";

/// `sesslint.io.decode_json_dupaware` is not in this crate.
pub const DECODE_JSON_DUPAWARE_UNAVAILABLE: &str =
    "sesslint.io.decode_json_dupaware is not available";

const SIZE_LIMIT_TEMPLATE: &str = "File size exceeds maximum limit [detail: LIMIT]";

const SQLITE_REFUSAL_TEMPLATE: &str = "Refused live SQLite database; SessLint requires exported items or checkpoints [detail: refused_live_db]";

const JSON_OBJECT_MARKERS: [&[u8]; 5] = [
    b"\"items\"",
    b"\"run_state\"",
    b"\"checkpoints\"",
    b"\"sdk_version\"",
    b"\"export_version\"",
];

/// `max_file_bytes` passed to [`load_openai_agents`].
///
/// [`Self::Bool`] is not an [`Self::Int`]. `True` is not `1` and `False` is not `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxFileBytes {
    /// Python `int` that is not `bool`.
    Int(i64),
    /// Python `bool`.
    Bool(bool),
}

/// Input of [`load_openai_agents`].
pub enum OpenAiAgentsSource<'a> {
    /// `bytes`. The path is `<bytes>`.
    Bytes(&'a [u8]),
    /// `str`, `Path`, or `PathLike`.
    Path(&'a Path),
    /// A binary stream. `name` is the `name` attribute. `None` is `<stream>`.
    Stream {
        /// Byte source. This is not closed.
        reader: &'a mut dyn Read,
        /// `getattr(stream, "name", "<stream>")` when that value is text.
        name: Option<&'a str>,
    },
}

/// JSON document or JSONL, decided before the secret-tracker seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentsDocumentKind {
    /// Top-level JSON document.
    Json,
    /// JSONL stream.
    Jsonl,
}

/// Failure from [`load_openai_agents`].
///
/// [`Self::SecretScanTracker`] displays [`SECRET_SCAN_TRACKER_UNAVAILABLE`].
/// The document kind is not part of that text.
#[derive(Debug)]
pub enum LoadOpenAiAgentsError {
    /// `FileNotFoundError`: `Session file not found: {path}`.
    NotFound(String),
    /// `IsADirectoryError`: `Expected session file, got directory: {path}`.
    IsADirectory(String),
    /// A bool was supplied where `max_file_bytes` must be an int.
    MaxFileBytes(String),
    /// `open` or `read` failed.
    Io(io::Error),
    /// [`make_finding`] stopped before `canonical_json_bytes`.
    ///
    /// `path` is the source path passed into that call. It is not part of
    /// [`Display`].
    Finding {
        /// Size-limit gate or SQLite refusal.
        gate: FindingGate,
        /// Source path. Slashes are already normalized.
        path: String,
        /// Codec seam, or an earlier `make_finding` rejection.
        error: model::errors::FindingError,
    },
    /// Classified document, stopped at `SecretScanTracker()`.
    SecretScanTracker(AgentsDocumentKind),
}

/// Which pure gate reached [`make_finding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingGate {
    /// File or buffer longer than `max_file_bytes`.
    Size,
    /// Leading `SQLite format 3\0`.
    Sqlite,
}

impl LoadOpenAiAgentsError {
    /// JSON or JSONL when the secret-tracker seam was reached.
    #[must_use]
    pub fn document_kind(&self) -> Option<AgentsDocumentKind> {
        match self {
            Self::SecretScanTracker(kind) => Some(*kind),
            _ => None,
        }
    }

    /// Size or SQLite gate when [`make_finding`] was called.
    #[must_use]
    pub fn finding_gate(&self) -> Option<FindingGate> {
        match self {
            Self::Finding { gate, .. } => Some(*gate),
            _ => None,
        }
    }

    /// Source path passed to [`make_finding`]. Not included in [`Display`].
    #[must_use]
    pub fn source_path(&self) -> Option<&str> {
        match self {
            Self::Finding { path, .. } => Some(path),
            _ => None,
        }
    }
}

impl fmt::Display for LoadOpenAiAgentsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(message) | Self::IsADirectory(message) | Self::MaxFileBytes(message) => {
                formatter.write_str(message)
            }
            Self::Io(err) => err.fmt(formatter),
            Self::Finding { error, .. } => error.fmt(formatter),
            Self::SecretScanTracker(_) => formatter.write_str(SECRET_SCAN_TRACKER_UNAVAILABLE),
        }
    }
}

impl Error for LoadOpenAiAgentsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Finding { error, .. } => Some(error),
            _ => None,
        }
    }
}

/// Ingest an OpenAI Agents SDK session export through the pure gates.
///
/// Python: `load_openai_agents` lines 528–670. `max_file_bytes` `None` uses
/// [`DEFAULT_MAX_FILE_BYTES`]. After JSON-versus-JSONL classification this
/// returns [`LoadOpenAiAgentsError::SecretScanTracker`].
///
/// # Errors
///
/// A missing path, a directory, a bool cap, I/O, a rejected finding, or the
/// secret-tracker seam.
#[must_use = "the tracker seam and the gate findings are the result"]
pub fn load_openai_agents(
    source: OpenAiAgentsSource<'_>,
    max_file_bytes: Option<MaxFileBytes>,
) -> Result<(EventList, Vec<Finding>), LoadOpenAiAgentsError> {
    let max_bytes = resolve_max_file_bytes(max_file_bytes)?;
    match source {
        OpenAiAgentsSource::Bytes(bytes) => {
            let mut cursor = io::Cursor::new(bytes);
            ingest(&mut cursor, "<bytes>", max_bytes)
        }
        OpenAiAgentsSource::Stream { reader, name } => {
            let path_str = name.unwrap_or("<stream>").replace('\\', "/");
            ingest(reader, &path_str, max_bytes)
        }
        OpenAiAgentsSource::Path(path) => load_path(path, max_bytes),
    }
}

fn resolve_max_file_bytes(limit: Option<MaxFileBytes>) -> Result<i64, LoadOpenAiAgentsError> {
    match limit {
        None => Ok(DEFAULT_MAX_FILE_BYTES),
        Some(MaxFileBytes::Int(value)) => Ok(value),
        Some(MaxFileBytes::Bool(value)) => {
            let rendered = if value { "True" } else { "False" };
            Err(LoadOpenAiAgentsError::MaxFileBytes(format!(
                "max_file_bytes must be a positive integer, got {rendered}"
            )))
        }
    }
}

fn load_path(
    path: &Path,
    max_bytes: i64,
) -> Result<(EventList, Vec<Finding>), LoadOpenAiAgentsError> {
    let displayed = python_path_text(path);
    let finding_path = displayed.replace('\\', "/");
    if path.metadata().is_err() {
        return Err(LoadOpenAiAgentsError::NotFound(format!(
            "Session file not found: {displayed}"
        )));
    }
    match path.metadata() {
        Ok(meta) if meta.is_dir() => {
            return Err(LoadOpenAiAgentsError::IsADirectory(format!(
                "Expected session file, got directory: {displayed}"
            )));
        }
        Ok(_) => {}
        Err(_) => {}
    }
    match path.metadata() {
        Ok(meta) if meta.is_file() && exceeds_limit(meta.len(), max_bytes) => {
            let finding = size_finding(&finding_path, max_bytes)?;
            return Ok((empty_list(), vec![finding]));
        }
        Ok(_) => {}
        Err(_) => {}
    }
    let mut file = File::open(path).map_err(LoadOpenAiAgentsError::Io)?;
    let outcome = ingest(&mut file, &finding_path, max_bytes);
    drop(file);
    outcome
}

fn ingest(
    reader: &mut dyn Read,
    path_str: &str,
    max_bytes: i64,
) -> Result<(EventList, Vec<Finding>), LoadOpenAiAgentsError> {
    let first = read_limited(reader, 16)?;
    if first.starts_with(SQLITE_MAGIC) {
        let finding = sqlite_finding(path_str)?;
        return Ok((refused_list(), vec![finding]));
    }
    let extra = extra_to_read(max_bytes, first.len());
    let mut full = first;
    full.extend(read_limited(reader, extra)?);
    if bytes_exceed(full.len(), max_bytes) {
        let finding = size_finding(path_str, max_bytes)?;
        return Ok((empty_list(), vec![finding]));
    }
    let stripped = strip_ascii_ws(strip_bom(&full));
    if stripped.is_empty() {
        return Ok((empty_list(), Vec::new()));
    }
    let kind = classify_document(stripped);
    Err(LoadOpenAiAgentsError::SecretScanTracker(kind))
}

fn empty_list() -> EventList {
    EventList::new(Vec::new(), Some(SourceMetadata::new()))
}

fn refused_list() -> EventList {
    EventList::new(
        Vec::new(),
        Some(SourceMetadata::from_entries([(
            "format",
            MetaValue::Str("refused_live_db".to_owned()),
        )])),
    )
}

fn read_limited(reader: &mut dyn Read, max: usize) -> Result<Vec<u8>, LoadOpenAiAgentsError> {
    let mut out = Vec::new();
    if max == 0 {
        return Ok(out);
    }
    let mut buf = [0u8; 8192];
    while out.len() < max {
        let want = (max - out.len()).min(buf.len());
        match reader.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(count) => out.extend_from_slice(&buf[..count]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(LoadOpenAiAgentsError::Io(err)),
        }
    }
    Ok(out)
}

fn extra_to_read(max_bytes: i64, first_len: usize) -> usize {
    let max = i128::from(max_bytes);
    let first = i128::from(u64::try_from(first_len).map_or(u64::MAX, |value| value));
    let raw = max - first + 1;
    if raw <= 0 {
        0
    } else {
        usize::try_from(raw).unwrap_or(usize::MAX)
    }
}

fn exceeds_limit(len: u64, max_bytes: i64) -> bool {
    match u64::try_from(max_bytes) {
        Ok(max) => len > max,
        Err(_) => true,
    }
}

fn bytes_exceed(len: usize, max_bytes: i64) -> bool {
    let len = u64::try_from(len).map_or(u64::MAX, |value| value);
    exceeds_limit(len, max_bytes)
}

fn strip_bom(data: &[u8]) -> &[u8] {
    data.strip_prefix(UTF8_BOM).unwrap_or(data)
}

fn strip_ascii_ws(data: &[u8]) -> &[u8] {
    let start = data
        .iter()
        .position(|byte| !is_python_byte_space(*byte))
        .unwrap_or(data.len());
    let end = data
        .iter()
        .rposition(|byte| !is_python_byte_space(*byte))
        .map_or(start, |index| index + 1);
    &data[start..end]
}

fn is_python_byte_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn classify_document(data: &[u8]) -> AgentsDocumentKind {
    match data.first().copied() {
        Some(b'[') => AgentsDocumentKind::Json,
        Some(b'{') if json_object_document(data) => AgentsDocumentKind::Json,
        _ => AgentsDocumentKind::Jsonl,
    }
}

fn json_object_document(data: &[u8]) -> bool {
    let line_end = data
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(data.len());
    let first_line = strip_ascii_ws(&data[..line_end]);
    first_line == b"{"
        || JSON_OBJECT_MARKERS
            .iter()
            .any(|marker| contains_bytes(first_line, marker))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn size_finding(
    path_str: &str,
    max_bytes: i64,
) -> Result<model::finding::Finding, LoadOpenAiAgentsError> {
    let evidence = FindingValue::map(vec![
        (
            FindingValue::string("reason"),
            FindingValue::string("size_limit_exceeded"),
        ),
        (FindingValue::string("limit"), FindingValue::int(max_bytes)),
    ]);
    gate_finding(
        FindingGate::Size,
        path_str,
        Severity::Error,
        Repairability::Manual,
        SIZE_LIMIT_TEMPLATE,
        evidence,
    )
}

fn sqlite_finding(path_str: &str) -> Result<model::finding::Finding, LoadOpenAiAgentsError> {
    let evidence = FindingValue::map(vec![(
        FindingValue::string("reason"),
        FindingValue::string("refused_live_db"),
    )]);
    gate_finding(
        FindingGate::Sqlite,
        path_str,
        Severity::Fatal,
        Repairability::Unsupported,
        SQLITE_REFUSAL_TEMPLATE,
        evidence,
    )
}

fn gate_finding(
    gate: FindingGate,
    path_str: &str,
    severity: Severity,
    repairability: Repairability,
    template: &str,
    evidence: FindingValue,
) -> Result<model::finding::Finding, LoadOpenAiAgentsError> {
    let source = SourceRef::try_new(path_str, Some(SourceLine::Int(1)), None).map_err(|error| {
        LoadOpenAiAgentsError::Finding {
            gate,
            path: path_str.to_owned(),
            error,
        }
    })?;
    make_finding(&MakeFindingInput {
        code: FindingValue::string(SL001),
        severity: FindingValue::severity(severity),
        repairability: FindingValue::repairability(repairability),
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
    })
    .map_err(|error| LoadOpenAiAgentsError::Finding {
        gate,
        path: path_str.to_owned(),
        error,
    })
}

fn python_path_text(path: &Path) -> String {
    let mut prefix = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix_component) => {
                prefix = prefix_text(&prefix_component);
            }
            Component::RootDir => rooted = true,
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_owned()),
            Component::Normal(text) => parts.push(text.to_string_lossy().into_owned()),
        }
    }
    join_python_path(&prefix, rooted, &parts)
}

fn prefix_text(component: &PrefixComponent<'_>) -> String {
    component.as_os_str().to_string_lossy().into_owned()
}

fn join_python_path(prefix: &str, rooted: bool, parts: &[String]) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    if prefix.is_empty() && !rooted && parts.is_empty() {
        return ".".to_owned();
    }
    let mut out = String::new();
    if !prefix.is_empty() {
        out.push_str(prefix);
    }
    if rooted && !out.ends_with(sep) {
        out.push(sep);
    }
    for (index, part) in parts.iter().enumerate() {
        let drive_relative = index == 0 && !rooted && prefix.ends_with(':');
        if !out.is_empty() && !out.ends_with(sep) && !drive_relative {
            out.push(sep);
        }
        out.push_str(part);
    }
    if out.is_empty() {
        ".".to_owned()
    } else {
        out
    }
}

/// Witness that the caller already holds a `SecretScanTracker`.
///
/// This is not that class. It has no hits and no buffer. This crate does not
/// construct `SecretScanTracker`, and this witness has no `feed_blob`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuppliedSecretScanTracker;

/// Failure from [`load_openai_agents_json`].
///
/// [`Display`](std::fmt::Display) is [`SECRET_SCAN_FEED_BLOB_UNAVAILABLE`].
/// The document is not part of that text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadOpenAiAgentsJsonError;

impl LoadOpenAiAgentsJsonError {
    /// [`SECRET_SCAN_FEED_BLOB_UNAVAILABLE`].
    #[must_use]
    pub const fn message(self) -> &'static str {
        SECRET_SCAN_FEED_BLOB_UNAVAILABLE
    }
}

impl fmt::Display for LoadOpenAiAgentsJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for LoadOpenAiAgentsJsonError {}

/// Parse one JSON document export, stopping at `feed_blob`.
///
/// Python: `_load_openai_agents_json` lines 673–904. The first statement is
/// `secret_tracker.feed_blob(data)`. Python scans the whole persisted
/// document before any validation. That method is not in this crate, so this
/// returns [`LoadOpenAiAgentsJsonError`] and does not read `data`.
///
/// `path_str` and `limits` are the keyword arguments. Validation that would
/// use them is not reached. [`SuppliedSecretScanTracker`] is the supplied
/// tracker. This function does not build one and does not call `feed_blob`
/// on it. [`load_openai_agents`] does not call this function.
///
/// # Errors
///
/// [`SECRET_SCAN_FEED_BLOB_UNAVAILABLE`] for every document. NUL, invalid
/// UTF-8, malformed JSON, a dict, and a list all use that display. This does
/// not return an [`EventList`].
#[must_use = "the feed_blob seam is the result"]
pub fn load_openai_agents_json(
    data: &[u8],
    path_str: &str,
    limits: SuppliedReaderLimits,
    secret_tracker: SuppliedSecretScanTracker,
) -> Result<(), LoadOpenAiAgentsJsonError> {
    let _ = (data, path_str, limits, secret_tracker);
    Err(LoadOpenAiAgentsJsonError)
}

/// Rejected `byte_offset`, `byte_end`, or `record_ordinal` on a [`RawLine`].
///
/// Python `ValueError` from `_validate_stream_coordinates`. [`Display`] is
/// that message. A bool is not an [`i64`], so `True` and `False` are not
/// representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLineError {
    message: String,
}

impl RawLineError {
    fn new(message: String) -> Self {
        Self { message }
    }

    /// The Python exception text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RawLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for RawLineError {}

/// One non-empty physical line and its stream coordinates.
///
/// Python: `_RawLine` in `sesslint.io`. This is not the scan crate's line.
/// This crate does not depend on scan. Construction checks the coordinates.
/// `byte_offset` defaults to 0, `byte_end` to 0, and `record_ordinal` to 1
/// through [`RawLine::from_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLine {
    line_number: i64,
    raw_bytes: Vec<u8>,
    truncated_limit: bool,
    byte_offset: i64,
    byte_end: i64,
    record_ordinal: i64,
}

impl RawLine {
    /// Python: `_RawLine(line_number, raw_bytes, truncated_limit)`.
    ///
    /// # Errors
    ///
    /// The default coordinates are valid. This still returns [`RawLineError`]
    /// when a future change breaks that.
    #[must_use = "a rejected coordinate is the result"]
    pub fn from_parts(
        line_number: i64,
        raw_bytes: Vec<u8>,
        truncated_limit: bool,
    ) -> Result<Self, RawLineError> {
        Self::try_new(line_number, raw_bytes, truncated_limit, 0, 0, 1)
    }

    /// Python: `_RawLine` with explicit coordinates.
    ///
    /// # Errors
    ///
    /// `byte_offset < 0`, `byte_end < byte_offset`, or `record_ordinal < 1`.
    #[must_use = "a rejected coordinate is the result"]
    pub fn try_new(
        line_number: i64,
        raw_bytes: Vec<u8>,
        truncated_limit: bool,
        byte_offset: i64,
        byte_end: i64,
        record_ordinal: i64,
    ) -> Result<Self, RawLineError> {
        reject_bad_coordinates(byte_offset, byte_end, record_ordinal)?;
        Ok(Self {
            line_number,
            raw_bytes,
            truncated_limit,
            byte_offset,
            byte_end,
            record_ordinal,
        })
    }

    /// Python field `line_number`.
    #[must_use]
    pub const fn line_number(&self) -> i64 {
        self.line_number
    }

    /// Persisted line bytes.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// The line was longer than the reader line cap.
    #[must_use]
    pub const fn truncated_limit(&self) -> bool {
        self.truncated_limit
    }

    /// Python field `byte_offset`.
    #[must_use]
    pub const fn byte_offset(&self) -> i64 {
        self.byte_offset
    }

    /// Python field `byte_end`.
    #[must_use]
    pub const fn byte_end(&self) -> i64 {
        self.byte_end
    }

    /// Python field `record_ordinal`.
    #[must_use]
    pub const fn record_ordinal(&self) -> i64 {
        self.record_ordinal
    }
}

/// Failure from [`load_openai_agents_jsonl`].
///
/// [`Display`](std::fmt::Display) is [`MALFORMED_TAIL_TRACKER_UNAVAILABLE`].
/// The buffer is not part of that text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadOpenAiAgentsJsonlError;

impl LoadOpenAiAgentsJsonlError {
    /// [`MALFORMED_TAIL_TRACKER_UNAVAILABLE`].
    #[must_use]
    pub const fn message(self) -> &'static str {
        MALFORMED_TAIL_TRACKER_UNAVAILABLE
    }
}

impl fmt::Display for LoadOpenAiAgentsJsonlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for LoadOpenAiAgentsJsonlError {}

/// Stream a JSONL export, stopping at `MalformedTailTracker`.
///
/// Python: `_load_openai_agents_jsonl` lines 907–1016. The statements before
/// the line loop build the event list, the finding list, [`SourceMetadata`],
/// [`SyntheticIdCollisionGuard`], and [`DriftTracker`]. The next statement
/// is `MalformedTailTracker()`. That type is not in this crate, so this
/// returns [`LoadOpenAiAgentsJsonlError`] and does not enter the loop.
///
/// `data` is not split. `secret_tracker` is not asked to `feed`. No
/// [`EventList`] is returned. [`process_jsonl_line`] is not called.
/// [`load_openai_agents`] and [`load_openai_agents_json`] do not call this
/// function.
///
/// # Errors
///
/// [`MALFORMED_TAIL_TRACKER_UNAVAILABLE`] for every buffer. Empty input,
/// whitespace, NUL, and a JSON object all use that display.
#[must_use = "the tail tracker seam is the result"]
pub fn load_openai_agents_jsonl(
    data: &[u8],
    path_str: &str,
    limits: SuppliedReaderLimits,
    secret_tracker: SuppliedSecretScanTracker,
) -> Result<(), LoadOpenAiAgentsJsonlError> {
    let _events: Vec<SessionEvent> = Vec::new();
    let _findings: Vec<Finding> = Vec::new();
    let mut source_metadata = SourceMetadata::from_entries([
        ("format", MetaValue::Str("openai-agents".to_owned())),
        ("checkpoints", MetaValue::List(Vec::new())),
    ]);
    source_metadata.insert("record_sizes", MetaValue::List(Vec::new()));
    let _guard = SyntheticIdCollisionGuard::new();
    let _seen_version_sl301 = false;
    let _drift = DriftTracker::new("openai-agents");
    let _current_offset = 0i64;
    let _line_number = 0i64;
    let _record_count = 0i64;
    let _total_len = data.len();
    let _pending_raw: Option<RawLine> = None;
    let _ = (path_str, limits, secret_tracker, source_metadata);
    Err(LoadOpenAiAgentsJsonlError)
}

/// Failure from [`process_jsonl_line`].
///
/// [`Display`](std::fmt::Display) is one unavailable call. It is not an SL
/// code, a record id, or a fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessJsonlLineError {
    /// [`SECRET_SCAN_FEED_UNAVAILABLE`].
    Feed,
    /// [`EXTRACT_RECORD_ID_UNAVAILABLE`].
    ExtractRecordId,
    /// [`DECODE_JSON_DUPAWARE_UNAVAILABLE`].
    DecodeJsonDupaware,
}

impl ProcessJsonlLineError {
    /// The missing call.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Feed => SECRET_SCAN_FEED_UNAVAILABLE,
            Self::ExtractRecordId => EXTRACT_RECORD_ID_UNAVAILABLE,
            Self::DecodeJsonDupaware => DECODE_JSON_DUPAWARE_UNAVAILABLE,
        }
    }
}

impl fmt::Display for ProcessJsonlLineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ProcessJsonlLineError {}

/// Process one JSONL line, stopping at `feed`, `extract_record_id`, or
/// `decode_json_dupaware`.
///
/// Python: `_process_jsonl_line` lines 1019–1201. When `secret_tracker` is
/// supplied, the first action is `secret_tracker.feed(...)`. That method is
/// not in this crate. The display is [`SECRET_SCAN_FEED_UNAVAILABLE`]. The
/// line bytes are not read, and validation does not run.
///
/// When the tracker is absent, `feed` is not called. If `record_sizes` is a
/// list, `byte_end - byte_offset` is appended. A truncated line, a line that
/// contains NUL, and a line that is not strict UTF-8 then stop at
/// [`EXTRACT_RECORD_ID_UNAVAILABLE`] before [`model::finding::make_finding`].
/// No record id is chosen and no fingerprint is hashed. A strict UTF-8 line
/// stops at [`DECODE_JSON_DUPAWARE_UNAVAILABLE`]. JSON is not parsed.
///
/// `limits` is the keyword argument. Its fields are not read. Truncation is
/// the flag already stored on [`RawLine`]. `is_terminal`, `path_str`,
/// `events`, `findings`, `seen_version_sl301`, `guard`, and `drift` are the
/// later keyword arguments. They are not used before these seams.
/// [`load_openai_agents`] and [`load_openai_agents_json`] do not call this
/// function. [`load_openai_agents_jsonl`] does not call it either.
///
/// # Errors
///
/// [`ProcessJsonlLineError::Feed`] when a tracker is supplied.
/// [`ProcessJsonlLineError::ExtractRecordId`] for a truncated line, a NUL
/// line, or invalid UTF-8. [`ProcessJsonlLineError::DecodeJsonDupaware`] for
/// a decodable line. SL001, SL002, SL009, and SL011 are not produced.
#[allow(clippy::too_many_arguments)] // pinned keyword list, in that order
#[must_use = "the jsonl line seam is the result"]
pub fn process_jsonl_line(
    raw: &RawLine,
    is_terminal: bool,
    path_str: &str,
    limits: SuppliedReaderLimits,
    events: &[SessionEvent],
    findings: &[Finding],
    source_metadata: &mut SourceMetadata,
    seen_version_sl301: bool,
    guard: Option<&SyntheticIdCollisionGuard>,
    drift: Option<&DriftTracker>,
    secret_tracker: Option<SuppliedSecretScanTracker>,
) -> Result<(), ProcessJsonlLineError> {
    if secret_tracker.is_some() {
        return Err(ProcessJsonlLineError::Feed);
    }
    let _ = (
        is_terminal,
        path_str,
        limits,
        events,
        findings,
        seen_version_sl301,
        guard,
        drift,
    );
    append_record_size(source_metadata, raw);
    if raw.truncated_limit {
        return Err(ProcessJsonlLineError::ExtractRecordId);
    }
    if raw.raw_bytes.contains(&0) {
        return Err(ProcessJsonlLineError::ExtractRecordId);
    }
    if std::str::from_utf8(strict_decode_bytes(raw)).is_err() {
        return Err(ProcessJsonlLineError::ExtractRecordId);
    }
    Err(ProcessJsonlLineError::DecodeJsonDupaware)
}

fn reject_bad_coordinates(
    byte_offset: i64,
    byte_end: i64,
    record_ordinal: i64,
) -> Result<(), RawLineError> {
    if byte_offset < 0 {
        return Err(RawLineError::new(format!(
            "Invalid byte_offset: {byte_offset} (must be integer >= 0)"
        )));
    }
    if byte_end < byte_offset {
        return Err(RawLineError::new(format!(
            "Invalid byte_end: {byte_end} (must be integer >= byte_offset={byte_offset})"
        )));
    }
    if record_ordinal < 1 {
        return Err(RawLineError::new(format!(
            "Invalid record_ordinal: {record_ordinal} (must be integer >= 1)"
        )));
    }
    Ok(())
}

/// Python: append `byte_end - byte_offset` when `record_sizes` is a list.
///
/// The integer is the coordinate span. The line bytes are not hashed and are
/// not stored on the list.
fn append_record_size(source_metadata: &mut SourceMetadata, raw: &RawLine) {
    let Some(MetaValue::List(sizes)) = source_metadata.get_mut("record_sizes") else {
        return;
    };
    let Some(size) = raw.byte_end.checked_sub(raw.byte_offset) else {
        return;
    };
    sizes.push(MetaValue::Int(size));
}

/// Bytes passed to the strict UTF-8 check.
///
/// Line 1 drops a leading UTF-8 BOM. Python then `str.strip`s a successful
/// decode. Strip cannot fail, and the stripped text is not kept.
fn strict_decode_bytes(raw: &RawLine) -> &[u8] {
    if raw.line_number == 1 {
        raw.raw_bytes
            .strip_prefix(UTF8_BOM)
            .unwrap_or(raw.raw_bytes.as_slice())
    } else {
        raw.raw_bytes.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_payload, detect_openai_agents, load_openai_agents, load_openai_agents_json,
        load_openai_agents_jsonl, normalize_timestamp, normalize_version, process_jsonl_line,
        project_run_state, python_path_text, safe_type_value, AgentsDocumentKind, AttrObject,
        BuildPayloadError, EventList, FindingGate, LoadOpenAiAgentsError,
        LoadOpenAiAgentsJsonError, LoadOpenAiAgentsJsonlError, MapKey, MapValue, MaxFileBytes,
        MetaValue, OpenAiAgentsSource, ProcessJsonlLineError, ProjectedCheckpoint, RawLine,
        RunSource, SeqNumber, SourceMetadata, SuppliedSecretScanTracker, TruncationTotals,
        DECODE_JSON_DUPAWARE_UNAVAILABLE, DEFAULT_MAX_FILE_BYTES, EXTRACT_RECORD_ID_UNAVAILABLE,
        MALFORMED_TAIL_TRACKER_UNAVAILABLE, MAX_PROJECTED_CHECKPOINTS,
        MAX_PROJECTED_RUN_STATE_KEYS, SECRET_SCAN_FEED_BLOB_UNAVAILABLE,
        SECRET_SCAN_FEED_UNAVAILABLE, SECRET_SCAN_TRACKER_UNAVAILABLE, SQLITE_MAGIC,
        STRICT_JSON_DECODE_UNAVAILABLE, STR_UNRENDERED,
    };
    use crate::safe_value::{safe_discriminator, PyValue};
    use crate::source::SuppliedReaderLimits;
    use model::canonical::SessionEvent;
    use model::finding::{Finding, FINGERPRINT_CODEC_UNAVAILABLE};
    use std::fs;
    use std::io::{self, Read};
    use std::path::{Path, PathBuf};

    fn ix(index: usize) -> i64 {
        i64::try_from(index).expect("index fits")
    }

    fn project_mapping(meta: &SourceMetadata) -> super::RunProjection {
        project_run_state(RunSource::Mapping(meta))
    }

    fn empty_projection(proj: &super::RunProjection) {
        assert!(proj.checkpoints.is_empty());
        assert!(proj.keys.is_empty());
        assert!(proj.shapes.is_empty());
        assert!(!proj.truncated);
        assert!(proj.totals.is_none());
    }

    fn checkpoint(fields: Vec<(&str, MetaValue)>) -> MetaValue {
        let entries = fields
            .into_iter()
            .map(|(key, value)| (MapKey::Str(key.to_owned()), value))
            .collect();
        MetaValue::Map(MapValue::new(entries))
    }

    fn one_checkpoint(meta_value: MetaValue) -> ProjectedCheckpoint {
        let meta =
            SourceMetadata::from_entries([("checkpoints", MetaValue::List(vec![meta_value]))]);
        let proj = project_mapping(&meta);
        assert_eq!(proj.checkpoints.len(), 1);
        proj.checkpoints.into_iter().next().expect("checkpoint")
    }

    fn joined(proj: &super::RunProjection) -> String {
        let mut out = String::new();
        for item in &proj.checkpoints {
            out.push_str(&item.hash);
            out.push('\n');
            out.push_str(&item.id);
            out.push('\n');
        }
        for key in &proj.keys {
            out.push_str(key);
            out.push('\n');
        }
        for (key, shape) in &proj.shapes {
            out.push_str(key);
            out.push('\n');
            out.push_str(shape);
            out.push('\n');
        }
        out
    }

    #[test]
    fn caps_match_the_pin() {
        assert_eq!(MAX_PROJECTED_RUN_STATE_KEYS, 32);
        assert_eq!(MAX_PROJECTED_CHECKPOINTS, 8);
    }

    #[test]
    fn safe_type_value_delegates_to_the_adapter_shaper() {
        let samples = [
            PyValue::Str("abc"),
            PyValue::None,
            PyValue::List(2),
            PyValue::Dict(0),
            PyValue::Bool,
            PyValue::Float,
            PyValue::Int,
            PyValue::Bytes(4),
        ];
        for sample in samples {
            assert_eq!(
                safe_type_value(sample),
                crate::safe_value::safe_type_value(sample)
            );
        }
    }

    #[test]
    fn absent_sources_project_nothing() {
        empty_projection(&project_run_state(RunSource::None));
        empty_projection(&project_mapping(&SourceMetadata::new()));
        let irrelevant = SourceMetadata::from_entries([("irrelevant_field", MetaValue::Int(123))]);
        empty_projection(&project_mapping(&irrelevant));
        let bare = AttrObject::new("int");
        empty_projection(&project_run_state(RunSource::Object(&bare)));
        let mut list_state = SourceMetadata::new();
        list_state.insert("run_state", MetaValue::List(vec![MetaValue::Int(1)]));
        empty_projection(&project_mapping(&list_state));
    }

    #[test]
    fn bounds_keys_and_checkpoints_and_omits_totals_on_the_cap() {
        let entries = (0..40)
            .map(|index| {
                (
                    MapKey::Str(format!("key_{index:03}")),
                    MetaValue::Str(format!("val_{index}")),
                )
            })
            .collect();
        let checkpoints = (0..12)
            .map(|index| {
                checkpoint(vec![
                    ("id", MetaValue::Str(format!("chk_{index:02}"))),
                    ("seq", MetaValue::Int(ix(index))),
                    ("hash", MetaValue::Str(format!("sha256:{index:064}"))),
                    ("ts", MetaValue::Str("2026-09-08T12:00:00Z".to_owned())),
                ])
            })
            .collect();
        let meta = SourceMetadata::from_entries([
            ("run_state", MetaValue::Map(MapValue::new(entries))),
            ("checkpoints", MetaValue::List(checkpoints)),
        ]);
        let proj = project_mapping(&meta);
        assert_eq!(proj.keys.len(), 32);
        assert_eq!(proj.shapes.len(), 32);
        assert_eq!(proj.keys.first().map(String::as_str), Some("key_000"));
        assert_eq!(proj.keys.get(31).map(String::as_str), Some("key_031"));
        assert_eq!(proj.checkpoints.len(), 8);
        assert_eq!(
            proj.checkpoints.first().map(|item| item.id.as_str()),
            Some("chk_00")
        );
        assert_eq!(
            proj.checkpoints.get(7).map(|item| item.id.as_str()),
            Some("chk_07")
        );
        assert!(proj.truncated);
        assert_eq!(
            proj.totals,
            Some(TruncationTotals {
                total_keys: 40,
                total_checkpoints: 12,
                truncated_keys: 8,
                truncated_checkpoints: 4,
            })
        );

        let exact_keys = (0..32)
            .map(|index| {
                (
                    MapKey::Str(format!("k{index:02}")),
                    MetaValue::Int(ix(index)),
                )
            })
            .collect();
        let exact_checks = (0..8)
            .map(|index| checkpoint(vec![("id", MetaValue::Str(format!("c{index}")))]))
            .collect();
        let exact = SourceMetadata::from_entries([
            ("run_state", MetaValue::Map(MapValue::new(exact_keys))),
            ("checkpoints", MetaValue::List(exact_checks)),
        ]);
        let on_cap = project_mapping(&exact);
        assert!(!on_cap.truncated);
        assert!(on_cap.totals.is_none());
        assert_eq!(on_cap.keys.len(), 32);
        assert_eq!(on_cap.checkpoints.len(), 8);

        let keys_only = SourceMetadata::from_entries([(
            "run_state",
            MetaValue::Map(MapValue::new(
                (0..33)
                    .map(|index| {
                        (
                            MapKey::Str(format!("k{index:02}")),
                            MetaValue::Str("v".to_owned()),
                        )
                    })
                    .collect(),
            )),
        )]);
        let keys_over = project_mapping(&keys_only);
        assert_eq!(
            keys_over.totals,
            Some(TruncationTotals {
                total_keys: 33,
                total_checkpoints: 0,
                truncated_keys: 1,
                truncated_checkpoints: 0,
            })
        );
    }

    #[test]
    fn redacts_values_and_hostile_top_level_fields() {
        let secret_key = "sk-proj-super-secret-production-key-99999";
        let secret_prompt = "You are an internal system agent with credentials to access prod DB.";
        let raw_hash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let run_state = MetaValue::Map(MapValue::new(vec![
            (
                MapKey::Str("api_key".to_owned()),
                MetaValue::Str(secret_key.to_owned()),
            ),
            (
                MapKey::Str("system_prompt".to_owned()),
                MetaValue::Str(secret_prompt.to_owned()),
            ),
            (
                MapKey::Str("nested_config".to_owned()),
                MetaValue::Map(MapValue::new(vec![
                    (MapKey::Str("retries".to_owned()), MetaValue::Int(3)),
                    (
                        MapKey::Str("env".to_owned()),
                        MetaValue::Str("prod".to_owned()),
                    ),
                ])),
            ),
            (
                MapKey::Str("tag_list".to_owned()),
                MetaValue::List(vec![
                    MetaValue::Str("tag1".to_owned()),
                    MetaValue::Str("tag2".to_owned()),
                ]),
            ),
            (MapKey::Str("count".to_owned()), MetaValue::Int(42)),
        ]));
        let meta = SourceMetadata::from_entries([
            ("run_state", run_state),
            (
                "checkpoints",
                MetaValue::List(vec![checkpoint(vec![
                    ("id", MetaValue::Str("chk_init".to_owned())),
                    ("seq", MetaValue::Int(1)),
                    ("hash", MetaValue::Str(raw_hash.to_owned())),
                    ("ts", MetaValue::Int(1_726_156_800)),
                ])]),
            ),
            (
                "keys",
                MetaValue::List(vec![MetaValue::Str("k1".to_owned())]),
            ),
            (
                "shapes",
                MetaValue::Map(MapValue::new(vec![(
                    MapKey::Str("leak".to_owned()),
                    MetaValue::Str("raw_sensitive_prompt".to_owned()),
                )])),
            ),
            ("truncated", MetaValue::Bool(false)),
        ]);
        let proj = project_mapping(&meta);
        assert_eq!(
            proj.shape("api_key"),
            Some(format!("<str:len={}>", secret_key.chars().count()).as_str())
        );
        assert_eq!(
            proj.shape("system_prompt"),
            Some(format!("<str:len={}>", secret_prompt.chars().count()).as_str())
        );
        assert_eq!(proj.shape("nested_config"), Some("<dict:len=2>"));
        assert_eq!(proj.shape("tag_list"), Some("<list:len=2>"));
        assert_eq!(proj.shape("count"), Some("<int>"));
        let item = proj.checkpoints.first().expect("checkpoint");
        assert_eq!(item.id, "chk_init");
        assert_eq!(item.seq, Some(SeqNumber::Small(1)));
        assert_eq!(item.hash, format!("<str:len={}>", raw_hash.chars().count()));
        assert!(item.ts);
        let text = joined(&proj);
        assert!(!text.contains(secret_key));
        assert!(!text.contains(secret_prompt));
        assert!(!text.contains(raw_hash));
        assert!(!text.contains("raw_sensitive_prompt"));
        assert!(proj.shape("leak").is_none());
    }

    #[test]
    fn object_attributes_and_ignored_projection_field() {
        let mut chk = AttrObject::new("MockCheckpoint");
        chk.id = Some(MetaValue::Str("chk_obj".to_owned()));
        chk.seq = Some(MetaValue::Str("5".to_owned()));
        chk.hash = Some(MetaValue::Str("sha256:abc".to_owned()));
        chk.ts = Some(MetaValue::Str("2026-09-08T00:00:00Z".to_owned()));
        let mut source = AttrObject::new("MockSource");
        source.run_state = Some(MetaValue::Map(MapValue::new(vec![(
            MapKey::Str("state_var".to_owned()),
            MetaValue::Str("active".to_owned()),
        )])));
        source.checkpoints = Some(MetaValue::List(vec![MetaValue::Object(Box::new(chk))]));
        let proj = project_run_state(RunSource::Object(&source));
        assert_eq!(proj.keys, vec!["state_var".to_owned()]);
        assert_eq!(proj.shape("state_var"), Some("<str:len=6>"));
        let item = proj.checkpoints.first().expect("checkpoint");
        assert_eq!(item.id, "chk_obj");
        assert_eq!(item.seq, Some(SeqNumber::Small(5)));
        assert_eq!(item.hash, "<str:len=10>");
        assert!(item.ts);
        assert!(!proj.truncated);

        let bare = AttrObject::new("MockWithProj");
        let ignored = project_run_state(RunSource::Object(&bare));
        empty_projection(&ignored);

        let mut both = AttrObject::new("MockWithBoth");
        both.run_state = Some(MetaValue::Map(MapValue::new(
            (0..50)
                .map(|index| {
                    (
                        MapKey::Str(format!("k_{index:03}")),
                        MetaValue::Str(format!("secret_value_{index}")),
                    )
                })
                .collect(),
        )));
        both.checkpoints = Some(MetaValue::List(
            (0..20)
                .map(|index| {
                    checkpoint(vec![
                        ("id", MetaValue::Str(format!("chk_{index:03}"))),
                        ("seq", MetaValue::Int(ix(index))),
                        ("ts", MetaValue::Bool(true)),
                    ])
                })
                .collect(),
        ));
        let clamped = project_run_state(RunSource::Object(&both));
        assert_eq!(clamped.keys.len(), 32);
        assert_eq!(clamped.checkpoints.len(), 8);
        assert!(clamped.truncated);
        assert!(!joined(&clamped).contains("secret_value"));
    }

    #[test]
    fn non_string_keys_sort_and_checkpoint_ids_redact() {
        let run_state = MetaValue::Map(MapValue::new(vec![
            (MapKey::Int(1), MetaValue::Str("int_key_val".to_owned())),
            (MapKey::Int(2), MetaValue::Str("another_int_key".to_owned())),
            (
                MapKey::Str("bad key with spaces 1".to_owned()),
                MetaValue::Str("val1".to_owned()),
            ),
            (
                MapKey::Str("bad key with spaces 2".to_owned()),
                MetaValue::Str("val2".to_owned()),
            ),
            (
                MapKey::Str("1".to_owned()),
                MetaValue::Str("str_one".to_owned()),
            ),
            (MapKey::Bool(false), MetaValue::Int(0)),
            (MapKey::Null, MetaValue::Bool(true)),
        ]));
        let meta = SourceMetadata::from_entries([
            ("run_state", run_state),
            (
                "checkpoints",
                MetaValue::List(vec![
                    checkpoint(vec![
                        ("id", MetaValue::Str("c1".to_owned())),
                        ("seq", MetaValue::Str("42".to_owned())),
                    ]),
                    checkpoint(vec![
                        ("id", MetaValue::Str("sk-secret-token".to_owned())),
                        ("seq", MetaValue::Int(43)),
                    ]),
                ]),
            ),
        ]);
        let proj = project_mapping(&meta);
        assert_eq!(
            proj.keys,
            vec![
                "1".to_owned(),
                "1#1".to_owned(),
                "2".to_owned(),
                "False".to_owned(),
                "None".to_owned(),
                "<str:len=21>".to_owned(),
                "<str:len=21>#1".to_owned(),
            ]
        );
        assert_eq!(proj.shape("1"), Some("<str:len=11>"));
        assert_eq!(proj.shape("1#1"), Some("<str:len=7>"));
        assert_eq!(proj.shape("2"), Some("<str:len=15>"));
        assert_eq!(proj.shape("False"), Some("<int>"));
        assert_eq!(proj.shape("None"), Some("<bool>"));
        assert_eq!(proj.shape("<str:len=21>"), Some("<str:len=4>"));
        assert_eq!(proj.checkpoints[0].id, "c1");
        assert_eq!(proj.checkpoints[0].seq, Some(SeqNumber::Small(42)));
        assert_eq!(proj.checkpoints[1].id, "<redacted>");
        assert_eq!(proj.checkpoints[1].seq, Some(SeqNumber::Small(43)));
        let shape_names: Vec<&str> = proj.shapes.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            shape_names,
            proj.keys.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn items_exception_drops_keys_and_keeps_checkpoints() {
        let run_state = MetaValue::Map(MapValue::raising(vec![
            (MapKey::Str("a".to_owned()), MetaValue::Int(1)),
            (MapKey::Str("b".to_owned()), MetaValue::Int(2)),
        ]));
        let meta = SourceMetadata::from_entries([
            ("run_state", run_state),
            (
                "checkpoints",
                MetaValue::List(vec![checkpoint(vec![
                    ("id", MetaValue::Str("c1".to_owned())),
                    ("seq", MetaValue::Int(1)),
                ])]),
            ),
        ]);
        let proj = project_mapping(&meta);
        assert!(proj.keys.is_empty());
        assert!(!proj.truncated);
        assert_eq!(proj.checkpoints.len(), 1);
        assert_eq!(proj.checkpoints[0].id, "c1");
        assert_eq!(proj.checkpoints[0].seq, Some(SeqNumber::Small(1)));
    }

    #[test]
    fn checkpoint_id_or_chain_and_invalid_items() {
        let abc = one_checkpoint(checkpoint(vec![
            ("id", MetaValue::Int(0)),
            ("checkpoint_id", MetaValue::Str("abc".to_owned())),
        ]));
        assert_eq!(abc.id, "abc");
        let fallback = one_checkpoint(checkpoint(vec![
            ("id", MetaValue::Str(String::new())),
            ("checkpoint_id", MetaValue::Str("z".to_owned())),
        ]));
        assert_eq!(fallback.id, "z");
        let from_false = one_checkpoint(checkpoint(vec![
            ("id", MetaValue::Bool(false)),
            ("checkpoint_id", MetaValue::Str("t".to_owned())),
        ]));
        assert_eq!(from_false.id, "t");
        let number = one_checkpoint(checkpoint(vec![("id", MetaValue::Int(7))]));
        assert_eq!(number.id, "7");
        let truth = one_checkpoint(checkpoint(vec![("id", MetaValue::Bool(true))]));
        assert_eq!(truth.id, "True");
        let spaced = one_checkpoint(checkpoint(vec![("id", MetaValue::Str(" chk ".to_owned()))]));
        assert_eq!(spaced.id, "<redacted>");
        let only_cp = one_checkpoint(checkpoint(vec![(
            "checkpoint_id",
            MetaValue::Str("cp".to_owned()),
        )]));
        assert_eq!(only_cp.id, "cp");
        let float_id = one_checkpoint(checkpoint(vec![("id", MetaValue::float(1.0))]));
        assert_eq!(float_id.id, "1.0");
        let float_half = one_checkpoint(checkpoint(vec![("id", MetaValue::float(1.5))]));
        assert_eq!(float_half.id, "1.5");
        let float_exp = one_checkpoint(checkpoint(vec![("id", MetaValue::float(1e20))]));
        assert_eq!(float_exp.id, "<redacted>");
        let list_id = one_checkpoint(checkpoint(vec![(
            "id",
            MetaValue::List(vec![MetaValue::Int(1)]),
        )]));
        assert_eq!(list_id.id, "<redacted>");
        let empty_list_id = one_checkpoint(checkpoint(vec![
            ("id", MetaValue::List(Vec::new())),
            ("checkpoint_id", MetaValue::Str("z".to_owned())),
        ]));
        assert_eq!(empty_list_id.id, "z");

        for sample in [
            MetaValue::Str("str-chk".to_owned()),
            MetaValue::Bytes(9),
            MetaValue::Int(1),
            MetaValue::float(1.5),
            MetaValue::Bool(true),
            MetaValue::Bool(false),
            MetaValue::Null,
        ] {
            let item = one_checkpoint(sample);
            assert_eq!(item.id, "<invalid>");
            assert_eq!(item.hash, "<NoneType>");
            assert!(item.seq.is_none());
            assert!(!item.ts);
        }
        for sample in [
            MetaValue::List(Vec::new()),
            MetaValue::List(vec![MetaValue::Int(1)]),
            MetaValue::Tuple(Vec::new()),
            MetaValue::Tuple(vec![MetaValue::Int(1)]),
            MetaValue::Map(MapValue::new(Vec::new())),
            MetaValue::Set(0),
            MetaValue::Set(2),
        ] {
            let item = one_checkpoint(sample);
            assert_eq!(item.id, "");
            assert_eq!(item.hash, "<NoneType>");
        }
    }

    #[test]
    fn checkpoint_seq_hash_and_ts_follow_the_pin() {
        let zero = one_checkpoint(checkpoint(vec![
            ("id", MetaValue::Str("a".to_owned())),
            ("seq", MetaValue::Int(0)),
        ]));
        assert_eq!(zero.seq, Some(SeqNumber::Small(0)));
        let false_blocks = one_checkpoint(checkpoint(vec![
            ("id", MetaValue::Str("a".to_owned())),
            ("seq", MetaValue::Bool(false)),
            ("checkpoint_seq", MetaValue::Int(3)),
        ]));
        assert!(false_blocks.seq.is_none());
        let true_blocks = one_checkpoint(checkpoint(vec![
            ("id", MetaValue::Str("a".to_owned())),
            ("seq", MetaValue::Bool(true)),
        ]));
        assert!(true_blocks.seq.is_none());
        let missing = one_checkpoint(checkpoint(vec![("checkpoint_seq", MetaValue::Int(3))]));
        assert_eq!(missing.seq, Some(SeqNumber::Small(3)));
        let null_falls = one_checkpoint(checkpoint(vec![
            ("seq", MetaValue::Null),
            ("checkpoint_seq", MetaValue::Int(3)),
        ]));
        assert_eq!(null_falls.seq, Some(SeqNumber::Small(3)));
        let padded = one_checkpoint(checkpoint(vec![("seq", MetaValue::Str(" 08 ".to_owned()))]));
        assert_eq!(padded.seq, Some(SeqNumber::Small(8)));
        let nbsp = one_checkpoint(checkpoint(vec![(
            "seq",
            MetaValue::Str(" 42\u{00a0}".to_owned()),
        )]));
        assert_eq!(nbsp.seq, Some(SeqNumber::Small(42)));
        let not_digits =
            one_checkpoint(checkpoint(vec![("seq", MetaValue::Str("1.0".to_owned()))]));
        assert!(not_digits.seq.is_none());
        let negative = one_checkpoint(checkpoint(vec![("seq", MetaValue::Str("-1".to_owned()))]));
        assert!(negative.seq.is_none());
        let superscript = one_checkpoint(checkpoint(vec![(
            "seq",
            MetaValue::Str("\u{00b2}".to_owned()),
        )]));
        assert!(superscript.seq.is_none());
        let arabic = one_checkpoint(checkpoint(vec![(
            "seq",
            MetaValue::Str("\u{0661}".to_owned()),
        )]));
        assert!(arabic.seq.is_none());
        let big = one_checkpoint(checkpoint(vec![("seq", MetaValue::Str("9".repeat(40)))]));
        assert_eq!(big.seq, Some(SeqNumber::Big("9".repeat(40))));
        assert!(big.seq.expect("seq").as_i64().is_none());
        let float_seq = one_checkpoint(checkpoint(vec![("seq", MetaValue::float(1.0))]));
        assert!(float_seq.seq.is_none());

        let hash_state = one_checkpoint(checkpoint(vec![
            ("hash", MetaValue::Int(0)),
            ("state_hash", MetaValue::Str("abc".to_owned())),
        ]));
        assert_eq!(hash_state.hash, "<str:len=3>");
        let hash_empty = one_checkpoint(checkpoint(vec![("hash", MetaValue::Str(String::new()))]));
        assert_eq!(hash_empty.hash, "<NoneType>");
        let hash_zero = one_checkpoint(checkpoint(vec![("hash", MetaValue::Int(0))]));
        assert_eq!(hash_zero.hash, "<NoneType>");
        let all_zero = one_checkpoint(checkpoint(vec![
            ("hash", MetaValue::Int(0)),
            ("payload_hash", MetaValue::Int(0)),
            ("state_hash", MetaValue::Int(0)),
        ]));
        assert_eq!(all_zero.hash, "<int>");
        let only_state_zero = one_checkpoint(checkpoint(vec![("state_hash", MetaValue::Int(0))]));
        assert_eq!(only_state_zero.hash, "<int>");
        let bytes_hash = one_checkpoint(checkpoint(vec![
            ("hash", MetaValue::Bytes(0)),
            ("state_hash", MetaValue::Bytes(2)),
        ]));
        assert_eq!(bytes_hash.hash, "<bytes:len=2>");
        let nested = one_checkpoint(checkpoint(vec![(
            "hash",
            MetaValue::Map(MapValue::new(vec![(
                MapKey::Str("a".to_owned()),
                MetaValue::Int(1),
            )])),
        )]));
        assert_eq!(nested.hash, "<dict:len=1>");
        let list_hash = one_checkpoint(checkpoint(vec![(
            "hash",
            MetaValue::List(vec![
                MetaValue::Int(1),
                MetaValue::Int(2),
                MetaValue::Int(3),
            ]),
        )]));
        assert_eq!(list_hash.hash, "<list:len=3>");

        let ts_created = one_checkpoint(checkpoint(vec![
            ("ts", MetaValue::Int(0)),
            ("created_at", MetaValue::Str("x".to_owned())),
        ]));
        assert!(ts_created.ts);
        let ts_zero = one_checkpoint(checkpoint(vec![("ts", MetaValue::Int(0))]));
        assert!(!ts_zero.ts);
        let ts_empty = one_checkpoint(checkpoint(vec![("ts", MetaValue::Str(String::new()))]));
        assert!(!ts_empty.ts);
        let ts_false = one_checkpoint(checkpoint(vec![("ts", MetaValue::Bool(false))]));
        assert!(!ts_false.ts);
        let ts_true = one_checkpoint(checkpoint(vec![("ts", MetaValue::Bool(true))]));
        assert!(ts_true.ts);
        let ts_list = one_checkpoint(checkpoint(vec![("ts", MetaValue::List(Vec::new()))]));
        assert!(!ts_list.ts);
    }

    #[test]
    fn sequences_are_lists_and_tuples_only() {
        let tuple = SourceMetadata::from_entries([(
            "checkpoints",
            MetaValue::Tuple(vec![
                checkpoint(vec![
                    ("id", MetaValue::Str("t0".to_owned())),
                    ("seq", MetaValue::Int(1)),
                ]),
                checkpoint(vec![("id", MetaValue::Str("t1".to_owned()))]),
            ]),
        )]);
        let proj = project_mapping(&tuple);
        assert_eq!(proj.checkpoints.len(), 2);
        assert_eq!(proj.checkpoints[0].id, "t0");
        assert_eq!(proj.checkpoints[0].seq, Some(SeqNumber::Small(1)));
        assert_eq!(proj.checkpoints[1].id, "t1");

        for ignored in [
            MetaValue::Str("abc".to_owned()),
            MetaValue::Bytes(3),
            MetaValue::Map(MapValue::new(vec![(
                MapKey::Str("id".to_owned()),
                MetaValue::Str("nope".to_owned()),
            )])),
        ] {
            let meta = SourceMetadata::from_entries([("checkpoints", ignored)]);
            assert!(project_mapping(&meta).checkpoints.is_empty());
        }
    }

    #[test]
    fn float_keys_use_python_str() {
        let meta = SourceMetadata::from_entries([(
            "run_state",
            MetaValue::Map(MapValue::new(vec![
                (MapKey::float(1.0), MetaValue::Int(1)),
                (MapKey::float(1.5), MetaValue::Int(2)),
                (MapKey::float(1e20), MetaValue::Int(3)),
            ])),
        )]);
        let proj = project_mapping(&meta);
        assert_eq!(
            proj.keys,
            vec!["1.0".to_owned(), "1.5".to_owned(), "<str:len=5>".to_owned()]
        );
        assert_eq!(proj.shape("1.0"), Some("<int>"));
        assert_eq!(proj.shape("<str:len=5>"), Some("<int>"));
    }

    #[test]
    fn source_metadata_is_a_dict_with_attribute_errors() {
        let mut meta = SourceMetadata::new();
        let missing = meta.attribute("missing").expect_err("missing");
        assert_eq!(
            missing.to_string(),
            "SourceMetadata has no attribute 'missing'"
        );
        let quoted = meta.attribute("it's").expect_err("quote");
        assert_eq!(
            quoted.to_string(),
            "SourceMetadata has no attribute \"it's\""
        );
        let newline = meta.attribute("a\nb").expect_err("newline");
        assert_eq!(
            newline.to_string(),
            "SourceMetadata has no attribute 'a\\nb'"
        );
        assert_eq!(
            meta.item("missing").expect_err("item").to_string(),
            "'missing'"
        );
        let checkpoints = meta.attribute("checkpoints").expect_err("checkpoints");
        assert_eq!(
            checkpoints.to_string(),
            "SourceMetadata has no attribute 'checkpoints'"
        );
        assert!(meta.entries().is_empty());

        meta.set_attribute("format", MetaValue::Str("openai-agents".to_owned()));
        meta.insert("checkpoints", MetaValue::List(vec![MetaValue::Int(1)]));
        meta.insert("format", MetaValue::Str("kept".to_owned()));
        assert_eq!(
            meta.entries()
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec!["format", "checkpoints"]
        );
        assert_eq!(
            meta.attribute("format").expect("format"),
            &MetaValue::Str("kept".to_owned())
        );
        assert_eq!(
            meta.attribute("checkpoints").expect("stored"),
            &MetaValue::List(vec![MetaValue::Int(1)])
        );
        assert_eq!(meta.get("format"), Some(&MetaValue::Str("kept".to_owned())));
        meta.set_attribute("checkpoints", MetaValue::List(Vec::new()));
        assert_eq!(
            meta.item("checkpoints").expect("item"),
            &MetaValue::List(Vec::new())
        );
    }

    #[test]
    fn object_checkpoint_reads_payload_hash_and_checkpoint_id() {
        let mut obj = AttrObject::new("Row");
        obj.checkpoint_id = Some(MetaValue::Str("cp".to_owned()));
        obj.seq = Some(MetaValue::Str(" 08 ".to_owned()));
        obj.payload_hash = Some(MetaValue::Str("abc".to_owned()));
        obj.created_at = Some(MetaValue::Int(1));
        let item = one_checkpoint(MetaValue::Object(Box::new(obj)));
        assert_eq!(item.id, "cp");
        assert_eq!(item.seq, Some(SeqNumber::Small(8)));
        assert_eq!(item.hash, "<str:len=3>");
        assert!(item.ts);
    }

    fn record(fields: Vec<(&str, MetaValue)>) -> MapValue {
        MapValue::new(
            fields
                .into_iter()
                .map(|(key, value)| (MapKey::Str(key.to_owned()), value))
                .collect(),
        )
    }

    fn payload_of(obj: &MapValue, actor: &str, kind: &str, rec_id: &str) -> MapValue {
        build_payload(obj, actor, kind, rec_id, &MetaValue::Null).expect("payload")
    }

    fn field<'a>(payload: &'a MapValue, key: &str) -> Option<&'a MetaValue> {
        payload
            .entries
            .iter()
            .rev()
            .find(|(entry, _)| matches!(entry, MapKey::Str(text) if text == key))
            .map(|(_, value)| value)
    }

    fn keys_of(payload: &MapValue) -> Vec<&str> {
        payload
            .entries
            .iter()
            .map(|(key, _)| match key {
                MapKey::Str(text) => text.as_str(),
                _ => "",
            })
            .collect()
    }

    #[test]
    fn event_list_keeps_its_own_source_metadata() {
        let event = SessionEvent::new("e1", None, 0, "1970-01-01T00:00:00Z", "user", "message");
        let listed = EventList::new(vec![event], None);
        assert_eq!(listed.len(), 1);
        assert!(!listed.is_empty());
        assert!(listed.source.entries().is_empty());
        assert_eq!(
            listed.events().first().map(|item| item.id.as_str()),
            Some("e1")
        );
        assert_eq!(
            listed.events().first().map(|item| item.actor.as_str()),
            Some("user")
        );

        let mut source = SourceMetadata::new();
        source.insert("format", MetaValue::Str("openai-agents".to_owned()));
        let kept = EventList::new(Vec::new(), Some(source));
        assert!(kept.is_empty());
        assert_eq!(kept.len(), 0);
        assert_eq!(
            kept.source.get("format"),
            Some(&MetaValue::Str("openai-agents".to_owned()))
        );
        assert!(listed.source.entries().is_empty());
    }

    #[test]
    fn normalize_version_strips_one_ascii_mark() {
        assert_eq!(normalize_version("  V1.2.3 "), "1.2.3");
        assert_eq!(normalize_version("V1.2-RC1"), "1.2-rc1");
        assert_eq!(normalize_version("v"), "v");
        assert_eq!(normalize_version("V"), "v");
        assert_eq!(normalize_version("vv1"), "vv1");
        assert_eq!(normalize_version("version"), "version");
        assert_eq!(
            normalize_version("  openai-agents-v1  "),
            "openai-agents-v1"
        );
        assert_eq!(normalize_version("\u{00a0}v2"), "2");
        assert_eq!(normalize_version("v\u{0662}"), "v\u{0662}");
    }

    #[test]
    fn detect_openai_agents_uses_filename_magic_and_substrings() {
        assert_eq!(SQLITE_MAGIC, b"SQLite format 3\x00");
        assert_eq!(detect_openai_agents(br#"{"items":[]}"#, "notes.txt"), 0.0);
        assert_eq!(detect_openai_agents(b"", "session.json"), 0.0);
        assert_eq!(detect_openai_agents(SQLITE_MAGIC, "live.DB"), 1.0);
        assert_eq!(detect_openai_agents(SQLITE_MAGIC, "live.sqlite"), 1.0);
        assert_eq!(detect_openai_agents(SQLITE_MAGIC, "export.JSON"), 0.5);
        assert_eq!(detect_openai_agents(br#"{"call_id":"c"}"#, "a.json"), 0.8);
        assert_eq!(detect_openai_agents(br#"{"run_state":{}}"#, "a.jsonl"), 1.0);
        assert_eq!(
            detect_openai_agents(br#"{"items":[],"call_id":"c"}"#, "a.json"),
            1.0
        );
        assert_eq!(
            detect_openai_agents(br#"{"tool_call":1,"tool_result":2}"#, "a.json"),
            0.8
        );
        assert_eq!(detect_openai_agents(b"hello", "session.json"), 0.2);
        assert_eq!(detect_openai_agents(b"hello", "session.db"), 0.0);
        let rollout = br#"{"type": "session_meta","items":[]}"#;
        assert_eq!(detect_openai_agents(rollout, "rollout.jsonl"), 0.3);
        assert_eq!(
            detect_openai_agents(br#"{"type":"turn_context"}"#, "t.json"),
            0.3
        );
        assert_eq!(detect_openai_agents(b"session_meta", "plain.json"), 0.2);
        let mut late = vec![b'x'; 4096];
        late.extend_from_slice(br#"{"items":[]}"#);
        assert_eq!(detect_openai_agents(&late, "late.json"), 0.2);
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(br#"{"items":1}"#);
        assert_eq!(detect_openai_agents(&bom, "bom.JSON"), 0.8);
    }

    #[test]
    fn normalize_timestamp_walks_the_iso_shape() {
        let stamped = MetaValue::Str("  2020-01-01T00:00:00Z  ".to_owned());
        assert_eq!(normalize_timestamp(&stamped), "2020-01-01T00:00:00Z");
        let naive = MetaValue::Str("2020-13-40T99:99:99".to_owned());
        assert_eq!(normalize_timestamp(&naive), "2020-13-40T99:99:99");
        let fraction = MetaValue::Str("2020-01-01T00:00:00.123456789+05:30".to_owned());
        assert_eq!(
            normalize_timestamp(&fraction),
            "2020-01-01T00:00:00.123456789+05:30"
        );
        let offset = MetaValue::Str("\u{00a0}2020-01-01T00:00:00-00:00".to_owned());
        assert_eq!(normalize_timestamp(&offset), "2020-01-01T00:00:00-00:00");
        let bare_fraction = MetaValue::Str("2020-01-01T00:00:00.0".to_owned());
        assert_eq!(normalize_timestamp(&bare_fraction), "2020-01-01T00:00:00.0");
        for raw in [
            "nope",
            "2020-01-01T00:00:00z",
            "2020-01-01T00:00:00.Z",
            "2020-01-01T00:00:00+0000",
            "2020-01-01 00:00:00Z",
            "",
            "   ",
            "2024-\u{0660}1-01T00:00:00Z",
        ] {
            assert_eq!(
                normalize_timestamp(&MetaValue::Str(raw.to_owned())),
                "1970-01-01T00:00:00Z",
                "{raw}"
            );
        }
        assert_eq!(
            normalize_timestamp(&MetaValue::Null),
            "1970-01-01T00:00:00Z"
        );
        assert_eq!(
            normalize_timestamp(&MetaValue::Int(1)),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn build_payload_follows_kind_and_stops_on_a_string_tool_input() {
        let message = payload_of(
            &record(vec![
                ("content", MetaValue::Null),
                ("message", MetaValue::Int(7)),
            ]),
            "user",
            "message",
            "r0",
        );
        assert_eq!(keys_of(&message), vec!["content", "role"]);
        assert_eq!(field(&message, "content"), Some(&MetaValue::Int(7)));
        assert_eq!(
            field(&message, "role"),
            Some(&MetaValue::Str("user".to_owned()))
        );

        let empty_name = payload_of(
            &record(vec![
                ("name", MetaValue::Str(String::new())),
                ("tool_name", MetaValue::Str("real".to_owned())),
                ("call_id", MetaValue::Str(String::new())),
                ("tool_call_id", MetaValue::Str("other".to_owned())),
                (
                    "arguments",
                    MetaValue::Map(record(vec![("q", MetaValue::Int(1))])),
                ),
            ]),
            "assistant",
            "tool_call",
            "rec",
        );
        assert_eq!(
            keys_of(&empty_name),
            vec!["call_id", "input", "name", "tool_name", "tool_use_id"]
        );
        assert_eq!(
            field(&empty_name, "name"),
            Some(&MetaValue::Str(String::new()))
        );
        assert_eq!(
            field(&empty_name, "call_id"),
            Some(&MetaValue::Str(String::new()))
        );
        assert_eq!(
            field(&empty_name, "input"),
            Some(&MetaValue::Map(record(vec![("q", MetaValue::Int(1))])))
        );

        let named = payload_of(
            &record(vec![
                ("tool_name", MetaValue::Bool(false)),
                ("args", MetaValue::Null),
                (
                    "input",
                    MetaValue::List(vec![MetaValue::Int(1), MetaValue::Int(2)]),
                ),
            ]),
            "assistant",
            "tool_call",
            "rec-9",
        );
        assert_eq!(
            field(&named, "name"),
            Some(&MetaValue::Str("False".to_owned()))
        );
        assert_eq!(
            field(&named, "tool_use_id"),
            Some(&MetaValue::Str("rec-9".to_owned()))
        );
        assert_eq!(
            field(&named, "input"),
            Some(&MetaValue::Map(record(vec![(
                "value",
                MetaValue::List(vec![MetaValue::Int(1), MetaValue::Int(2)])
            )])))
        );

        let tuple_name = payload_of(
            &record(vec![(
                "function",
                MetaValue::Tuple(vec![MetaValue::Int(1)]),
            )]),
            "assistant",
            "tool_call",
            "rec",
        );
        assert_eq!(
            field(&tuple_name, "name"),
            Some(&MetaValue::Str("(1,)".to_owned()))
        );
        assert_eq!(
            field(&tuple_name, "input"),
            Some(&MetaValue::Map(MapValue::new(Vec::new())))
        );

        let seam = build_payload(
            &record(vec![
                ("name", MetaValue::Str("search".to_owned())),
                ("args", MetaValue::Str("{\"q\":1}".to_owned())),
                (
                    "arguments",
                    MetaValue::Map(record(vec![("q", MetaValue::Int(1))])),
                ),
            ]),
            "assistant",
            "tool_call",
            "rec",
            &MetaValue::Null,
        );
        let err = seam.expect_err("string input requires the decoder");
        assert_eq!(err, BuildPayloadError::Unavailable);
        assert_eq!(err.to_string(), STRICT_JSON_DECODE_UNAVAILABLE);
        assert_eq!(
            err.to_string(),
            "sesslint.io._STRICT_JSON_DECODER.decode is not available"
        );

        let empty_string = build_payload(
            &record(vec![
                ("args", MetaValue::Null),
                ("arguments", MetaValue::Str(String::new())),
            ]),
            "assistant",
            "tool_call",
            "rec",
            &MetaValue::Str("ignored".to_owned()),
        );
        assert_eq!(
            empty_string
                .expect_err("empty string still calls decode")
                .to_string(),
            STRICT_JSON_DECODE_UNAVAILABLE
        );

        let bytes_and_string = build_payload(
            &record(vec![
                ("name", MetaValue::Bytes(4)),
                ("args", MetaValue::Str("{}".to_owned())),
            ]),
            "assistant",
            "tool_call",
            "rec",
            &MetaValue::Null,
        );
        assert_eq!(
            bytes_and_string
                .expect_err("str(name) runs before decode")
                .to_string(),
            STR_UNRENDERED
        );

        let bytes_name = build_payload(
            &record(vec![("name", MetaValue::Bytes(4))]),
            "assistant",
            "tool_call",
            "rec",
            &MetaValue::Null,
        );
        let unrendered = bytes_name.expect_err("bytes have no str()");
        assert_eq!(unrendered, BuildPayloadError::Unrendered);
        assert_eq!(unrendered.to_string(), STR_UNRENDERED);
        assert_ne!(unrendered.to_string(), STRICT_JSON_DECODE_UNAVAILABLE);
    }

    #[test]
    fn build_payload_covers_the_other_kinds() {
        let result = payload_of(
            &record(vec![
                ("content", MetaValue::Null),
                ("output", MetaValue::Str("out".to_owned())),
                ("is_error", MetaValue::Bool(false)),
                ("error", MetaValue::Bool(true)),
                ("tool_call_id", MetaValue::Int(3)),
            ]),
            "tool",
            "tool_result",
            "rec",
        );
        assert_eq!(
            keys_of(&result),
            vec!["call_id", "content", "is_error", "tool_use_id"]
        );
        assert_eq!(
            field(&result, "call_id"),
            Some(&MetaValue::Str("3".to_owned()))
        );
        assert_eq!(
            field(&result, "content"),
            Some(&MetaValue::Str("out".to_owned()))
        );
        assert_eq!(field(&result, "is_error"), Some(&MetaValue::Bool(false)));

        let flagged = payload_of(
            &record(vec![("error", MetaValue::Str("x".to_owned()))]),
            "tool",
            "tool_result",
            "rec",
        );
        assert_eq!(
            field(&flagged, "call_id"),
            Some(&MetaValue::Str(String::new()))
        );
        assert_eq!(field(&flagged, "is_error"), Some(&MetaValue::Bool(true)));
        assert_eq!(
            field(&flagged, "content"),
            Some(&MetaValue::Str(String::new()))
        );

        let reason = MetaValue::Str("user_ok".to_owned());
        let handoff = payload_of(
            &record(vec![
                ("target", MetaValue::Null),
                ("agent", MetaValue::Int(1)),
                ("reason", reason),
            ]),
            "assistant",
            "handoff",
            "rec",
        );
        let (expected, truncated) = safe_discriminator(PyValue::Str("user_ok"));
        assert!(!truncated);
        assert_eq!(keys_of(&handoff), vec!["target", "reason"]);
        assert_eq!(
            field(&handoff, "target"),
            Some(&MetaValue::Str("1".to_owned()))
        );
        assert_eq!(field(&handoff, "reason"), Some(&MetaValue::Str(expected)));

        let shaped = payload_of(
            &record(vec![
                ("handoff_to", MetaValue::Str("agent".to_owned())),
                ("reason", MetaValue::Null),
            ]),
            "assistant",
            "handoff",
            "rec",
        );
        let (none_shape, none_truncated) = safe_discriminator(PyValue::None);
        assert!(none_truncated);
        assert_eq!(
            field(&shaped, "target"),
            Some(&MetaValue::Str("agent".to_owned()))
        );
        assert_eq!(field(&shaped, "reason"), Some(&MetaValue::Str(none_shape)));

        let bare = payload_of(&MapValue::new(Vec::new()), "assistant", "handoff", "rec");
        assert_eq!(keys_of(&bare), vec!["target"]);
        assert_eq!(field(&bare, "target"), Some(&MetaValue::Null));

        let checkpoint = payload_of(
            &record(vec![
                ("id", MetaValue::Str("cp".to_owned())),
                ("seq", MetaValue::Null),
                ("hash", MetaValue::Null),
                (
                    "state",
                    MetaValue::Map(record(vec![("k", MetaValue::Int(1))])),
                ),
            ]),
            "system",
            "checkpoint",
            "fallback",
        );
        assert_eq!(
            keys_of(&checkpoint),
            vec!["checkpoint_id", "seq", "hash", "state"]
        );
        assert_eq!(
            field(&checkpoint, "checkpoint_id"),
            Some(&MetaValue::Str("cp".to_owned()))
        );
        assert_eq!(field(&checkpoint, "seq"), Some(&MetaValue::Null));
        assert_eq!(
            field(&checkpoint, "hash"),
            Some(&MetaValue::Str("None".to_owned()))
        );

        let fallback_id = payload_of(&MapValue::new(Vec::new()), "system", "checkpoint", "rec-id");
        assert_eq!(
            field(&fallback_id, "checkpoint_id"),
            Some(&MetaValue::Str("rec-id".to_owned()))
        );
        assert_eq!(keys_of(&fallback_id), vec!["checkpoint_id"]);

        let summary = payload_of(
            &record(vec![
                ("summary", MetaValue::Null),
                ("content", MetaValue::Int(3)),
            ]),
            "system",
            "compaction_boundary",
            "rec",
        );
        assert_eq!(
            field(&summary, "summary"),
            Some(&MetaValue::Str("3".to_owned()))
        );

        let blank = payload_of(
            &MapValue::new(Vec::new()),
            "system",
            "compaction_boundary",
            "rec",
        );
        assert_eq!(
            field(&blank, "summary"),
            Some(&MetaValue::Str(String::new()))
        );

        let unknown = build_payload(
            &MapValue::new(Vec::new()),
            "system",
            "unknown",
            "rec",
            &MetaValue::Null,
        )
        .expect("unknown");
        assert_eq!(
            field(&unknown, "type"),
            Some(&MetaValue::Str("<missing>".to_owned()))
        );
        let typed = build_payload(
            &MapValue::new(Vec::new()),
            "system",
            "unknown",
            "rec",
            &MetaValue::Str("widget".to_owned()),
        )
        .expect("typed");
        assert_eq!(
            field(&typed, "type"),
            Some(&MetaValue::Str("widget".to_owned()))
        );

        let passed = payload_of(
            &record(vec![("content", MetaValue::Str("hi".to_owned()))]),
            "assistant",
            "function_call",
            "rec",
        );
        assert_eq!(keys_of(&passed), vec!["content", "role"]);
        assert_eq!(
            field(&passed, "content"),
            Some(&MetaValue::Str("hi".to_owned()))
        );
        assert_eq!(
            field(&passed, "role"),
            Some(&MetaValue::Str("assistant".to_owned()))
        );
    }

    struct ByteReader<'a> {
        data: &'a [u8],
        pos: usize,
    }

    impl Read for ByteReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("sesslint-oa03-{}-{label}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("temp dir");
            Self { path }
        }

        fn child(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn kind_of(bytes: &[u8]) -> AgentsDocumentKind {
        let err = load_openai_agents(OpenAiAgentsSource::Bytes(bytes), None).expect_err("seam");
        assert_eq!(err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        err.document_kind().expect("classified")
    }

    fn assert_empty_ok(bytes: &[u8]) {
        let (events, findings) =
            load_openai_agents(OpenAiAgentsSource::Bytes(bytes), None).expect("empty");
        assert!(events.is_empty());
        assert!(findings.is_empty());
        assert!(events.source.entries().is_empty());
    }

    fn assert_codec_gate(bytes: &[u8], cap: i64, gate: FindingGate) -> LoadOpenAiAgentsError {
        let err = load_openai_agents(
            OpenAiAgentsSource::Bytes(bytes),
            Some(MaxFileBytes::Int(cap)),
        )
        .expect_err("codec");
        assert_eq!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(err.finding_gate(), Some(gate));
        assert_eq!(err.source_path(), Some("<bytes>"));
        assert!(err.document_kind().is_none());
        assert!(!err.to_string().contains("MARKER"));
        err
    }

    #[test]
    fn default_cap_matches_the_pin_io_constant() {
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 100 * 1024 * 1024);
        assert_eq!(DEFAULT_MAX_FILE_BYTES, 104_857_600);
    }

    #[test]
    fn python_path_text_matches_pathlib_samples() {
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(python_path_text(Path::new("")), ".");
        assert_eq!(python_path_text(Path::new(".")), ".");
        assert_eq!(python_path_text(Path::new("./dir")), "dir");
        assert_eq!(python_path_text(Path::new("foo/")), "foo");
        assert_eq!(
            python_path_text(Path::new("foo/../bar")),
            format!("foo{sep}..{sep}bar")
        );
        assert_eq!(python_path_text(Path::new("a//b")), format!("a{sep}b"));
        assert_eq!(python_path_text(Path::new("a/./b")), format!("a{sep}b"));
        assert_eq!(
            python_path_text(Path::new("missing/file.json")),
            format!("missing{sep}file.json")
        );
    }

    #[cfg(windows)]
    #[test]
    fn python_path_text_matches_windows_pathlib() {
        assert_eq!(python_path_text(Path::new("C:/nope/x")), r"C:\nope\x");
        assert_eq!(python_path_text(Path::new(r"/abs/file")), r"\abs\file");
        assert_eq!(python_path_text(Path::new("C:foo")), "C:foo");
        assert_eq!(python_path_text(Path::new("C:/")), r"C:\");
        assert_eq!(python_path_text(Path::new("/")), r"\");
        assert_eq!(
            python_path_text(Path::new(r"\\server\share\f")),
            r"\\server\share\f"
        );
    }

    #[test]
    fn bool_cap_is_not_an_integer() {
        let true_err = load_openai_agents(
            OpenAiAgentsSource::Bytes(b""),
            Some(MaxFileBytes::Bool(true)),
        )
        .expect_err("true");
        assert_eq!(
            true_err.to_string(),
            "max_file_bytes must be a positive integer, got True"
        );
        assert!(true_err.document_kind().is_none());
        let false_err = load_openai_agents(
            OpenAiAgentsSource::Bytes(b"["),
            Some(MaxFileBytes::Bool(false)),
        )
        .expect_err("false");
        assert_eq!(
            false_err.to_string(),
            "max_file_bytes must be a positive integer, got False"
        );
        assert!(matches!(false_err, LoadOpenAiAgentsError::MaxFileBytes(_)));
    }

    #[test]
    fn empty_bytes_skip_the_tracker() {
        assert_empty_ok(b"");
        assert_empty_ok(b" \t\r\n\x0b\x0c ");
        assert_empty_ok(b"\xef\xbb\xbf");
        assert_empty_ok(b"\xef\xbb\xbf \n");
        let (events, findings) =
            load_openai_agents(OpenAiAgentsSource::Bytes(b""), Some(MaxFileBytes::Int(0)))
                .expect("zero cap empty");
        assert!(events.is_empty());
        assert!(findings.is_empty());
    }

    #[test]
    fn negative_cap_is_still_an_integer_size_gate() {
        assert_codec_gate(b"", -1, FindingGate::Size);
    }

    #[test]
    fn bytes_size_gate_and_sqlite_gate_keep_pin_order() {
        let marker = b"MARKERMARKERMARKER";
        assert_codec_gate(marker, 4, FindingGate::Size);
        let mut magic = SQLITE_MAGIC.to_vec();
        magic.extend_from_slice(b"MARKER");
        assert_codec_gate(&magic, 8, FindingGate::Sqlite);
        assert_codec_gate(SQLITE_MAGIC, 8, FindingGate::Sqlite);
    }

    #[test]
    fn stream_names_are_slash_normalized_and_default_to_stream() {
        let mut named = ByteReader {
            data: SQLITE_MAGIC,
            pos: 0,
        };
        let named_err = load_openai_agents(
            OpenAiAgentsSource::Stream {
                reader: &mut named,
                name: Some(r"a\b"),
            },
            Some(MaxFileBytes::Int(8)),
        )
        .expect_err("named");
        assert_eq!(named_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(named_err.finding_gate(), Some(FindingGate::Sqlite));
        assert_eq!(named_err.source_path(), Some("a/b"));

        let mut quoted = ByteReader {
            data: SQLITE_MAGIC,
            pos: 0,
        };
        let quoted_err = load_openai_agents(
            OpenAiAgentsSource::Stream {
                reader: &mut quoted,
                name: Some("a\"b"),
            },
            None,
        )
        .expect_err("quoted");
        assert_eq!(quoted_err.source_path(), Some("a\"b"));
        assert_eq!(quoted_err.finding_gate(), Some(FindingGate::Sqlite));

        let mut unnamed = ByteReader {
            data: SQLITE_MAGIC,
            pos: 0,
        };
        let unnamed_err = load_openai_agents(
            OpenAiAgentsSource::Stream {
                reader: &mut unnamed,
                name: None,
            },
            None,
        )
        .expect_err("unnamed");
        assert_eq!(unnamed_err.source_path(), Some("<stream>"));

        let payload = b"MARKERMARKERMARKERMARKER";
        let mut slow = ByteReader {
            data: payload,
            pos: 0,
        };
        let slow_err = load_openai_agents(
            OpenAiAgentsSource::Stream {
                reader: &mut slow,
                name: Some(r"a\b"),
            },
            Some(MaxFileBytes::Int(18)),
        )
        .expect_err("slow size");
        assert_eq!(slow_err.finding_gate(), Some(FindingGate::Size));
        assert_eq!(slow_err.source_path(), Some("a/b"));
        assert!(!slow_err.to_string().contains("MARKER"));
        assert_eq!(slow.pos, 19);
    }

    #[test]
    fn partial_sqlite_prefix_is_classified_not_refused() {
        assert_eq!(kind_of(b"SQLite format 3"), AgentsDocumentKind::Jsonl);
        assert_eq!(kind_of(b"\xff"), AgentsDocumentKind::Jsonl);
    }

    #[test]
    fn classification_stops_at_the_tracker_seam() {
        assert_eq!(kind_of(b"["), AgentsDocumentKind::Json);
        assert_eq!(kind_of(b"  [\n"), AgentsDocumentKind::Json);
        assert_eq!(kind_of(b"{"), AgentsDocumentKind::Json);
        assert_eq!(kind_of(b"{\n\"z\":1}"), AgentsDocumentKind::Json);
        assert_eq!(kind_of(b"{\r\n\"z\":1}"), AgentsDocumentKind::Json);
        assert_eq!(kind_of(b"{\"items\":[]}"), AgentsDocumentKind::Json);
        assert_eq!(kind_of(b"{\"run_state\":{}}"), AgentsDocumentKind::Json);
        assert_eq!(kind_of(b"{\"checkpoints\":[]}"), AgentsDocumentKind::Json);
        assert_eq!(kind_of(b"{\"sdk_version\":1}"), AgentsDocumentKind::Json);
        assert_eq!(kind_of(b"{\"export_version\":1}"), AgentsDocumentKind::Json);
        assert_eq!(
            kind_of(b"\xef\xbb\xbf{\"items\":[]}"),
            AgentsDocumentKind::Json
        );
        assert_eq!(kind_of(b"{\"other\":1}"), AgentsDocumentKind::Jsonl);
        assert_eq!(kind_of(b"{\"items_extra\":1}"), AgentsDocumentKind::Jsonl);
        assert_eq!(kind_of(b"x\n{\"items\":1}"), AgentsDocumentKind::Jsonl);
        let err = load_openai_agents(OpenAiAgentsSource::Bytes(b"{\"items\":[]}"), None)
            .expect_err("doc");
        assert!(err.to_string().contains("SecretScanTracker"));
        assert!(!err.to_string().contains("SL301"));
        assert!(!err.to_string().contains("SL302"));
        assert!(matches!(
            err,
            LoadOpenAiAgentsError::SecretScanTracker(AgentsDocumentKind::Json)
        ));
    }

    #[test]
    fn path_errors_happen_before_open_and_keep_path_text() {
        let missing = Path::new("sesslint-missing/nope.json");
        let missing_err =
            load_openai_agents(OpenAiAgentsSource::Path(missing), None).expect_err("missing");
        let missing_text = python_path_text(missing);
        assert_eq!(
            missing_err.to_string(),
            format!("Session file not found: {missing_text}")
        );
        assert!(missing_text.contains(std::path::MAIN_SEPARATOR) || !missing_text.contains('/'));
        assert!(matches!(missing_err, LoadOpenAiAgentsError::NotFound(_)));

        let tree = TempTree::new("dir");
        let directory = tree.child("folder");
        fs::create_dir(&directory).expect("dir");
        let dir_err =
            load_openai_agents(OpenAiAgentsSource::Path(&directory), None).expect_err("dir");
        let dir_text = python_path_text(&directory);
        assert_eq!(
            dir_err.to_string(),
            format!("Expected session file, got directory: {dir_text}")
        );
        assert!(matches!(dir_err, LoadOpenAiAgentsError::IsADirectory(_)));

        let bool_err = load_openai_agents(
            OpenAiAgentsSource::Path(missing),
            Some(MaxFileBytes::Bool(true)),
        )
        .expect_err("bool before path");
        assert!(bool_err.to_string().contains("got True"));
        assert!(!bool_err.to_string().contains("Session file not found"));
    }

    #[test]
    fn file_stat_gate_beats_sqlite_magic_and_closes_the_opened_file() {
        let tree = TempTree::new("files");
        let oversize = tree.child("oversize.bin");
        let mut body = SQLITE_MAGIC.to_vec();
        body.extend(std::iter::repeat_n(b'M', 32));
        fs::write(&oversize, &body).expect("write");
        let before = fs::read(&oversize).expect("read");
        let oversize_err = load_openai_agents(
            OpenAiAgentsSource::Path(&oversize),
            Some(MaxFileBytes::Int(8)),
        )
        .expect_err("stat size");
        assert_eq!(oversize_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(oversize_err.finding_gate(), Some(FindingGate::Size));
        let oversize_path = oversize_err.source_path().expect("path");
        assert!(!oversize_path.contains('\\'));
        assert!(oversize_path.contains("oversize.bin"));
        assert!(!oversize_err.to_string().contains("MARKER"));
        assert_eq!(fs::read(&oversize).expect("unchanged"), before);
        fs::remove_file(&oversize).expect("closed after stat return");

        let exact = tree.child("exact.bin");
        fs::write(&exact, SQLITE_MAGIC).expect("magic");
        let db_err = load_openai_agents(
            OpenAiAgentsSource::Path(&exact),
            Some(MaxFileBytes::Int(16)),
        )
        .expect_err("sqlite file");
        assert_eq!(db_err.finding_gate(), Some(FindingGate::Sqlite));
        assert_eq!(db_err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        let db_path = db_err.source_path().expect("path");
        assert!(!db_path.contains('\\'));
        assert!(db_path.contains("exact.bin"));
        fs::remove_file(&exact).expect("closed after sqlite return");

        let tiny = tree.child("tiny.bin");
        fs::write(&tiny, b"{").expect("tiny");
        let tiny_err =
            load_openai_agents(OpenAiAgentsSource::Path(&tiny), Some(MaxFileBytes::Int(1)))
                .expect_err("equal cap continues");
        assert_eq!(tiny_err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert_eq!(tiny_err.document_kind(), Some(AgentsDocumentKind::Json));
        fs::remove_file(&tiny).expect("closed after tracker");

        let wide = tree.child("wide.bin");
        fs::write(&wide, b"{\"other\":1}").expect("wide");
        let wide_err =
            load_openai_agents(OpenAiAgentsSource::Path(&wide), None).expect_err("default cap");
        assert_eq!(wide_err.document_kind(), Some(AgentsDocumentKind::Jsonl));
        assert_eq!(wide_err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
    }

    #[test]
    fn json_document_loader_stops_at_feed_blob() {
        let documents: [&[u8]; 9] = [
            b"",
            b"\x00",
            b"a\x00b",
            b"\xff",
            b"\x80\x81",
            b"{",
            b"not-json",
            b"{}",
            b"[]",
        ];
        for data in documents {
            let err = load_openai_agents_json(
                data,
                "synthetic-export.json",
                SuppliedReaderLimits,
                SuppliedSecretScanTracker,
            )
            .expect_err("feed_blob");
            assert_eq!(err, LoadOpenAiAgentsJsonError);
            assert_eq!(err.message(), SECRET_SCAN_FEED_BLOB_UNAVAILABLE);
            assert_eq!(
                err.to_string(),
                "sesslint.checks.hygiene.SecretScanTracker.feed_blob is not available"
            );
            assert!(!err.to_string().contains("synthetic-export.json"));
            assert!(!err.to_string().contains("SL001"));
            assert!(!err.to_string().contains("SL009"));
            assert!(!err.to_string().contains("SL301"));
            assert!(!err.to_string().contains("SL302"));
        }

        let gated = load_openai_agents(OpenAiAgentsSource::Bytes(b"{\"items\":[]}"), None)
            .expect_err("gate");
        assert_eq!(gated.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert_ne!(gated.to_string(), SECRET_SCAN_FEED_BLOB_UNAVAILABLE);
        assert_eq!(gated.document_kind(), Some(AgentsDocumentKind::Json));
    }

    fn size_list(values: &[i64]) -> SourceMetadata {
        let mut meta = SourceMetadata::new();
        meta.insert(
            "record_sizes",
            MetaValue::List(values.iter().copied().map(MetaValue::Int).collect()),
        );
        meta
    }

    fn sizes(meta: &SourceMetadata) -> Vec<i64> {
        let Some(MetaValue::List(items)) = meta.get("record_sizes") else {
            return Vec::new();
        };
        items
            .iter()
            .map(|item| match item {
                MetaValue::Int(value) => *value,
                _ => panic!("record size"),
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)] // one field per pinned coordinate
    fn run_line(
        bytes: &[u8],
        truncated: bool,
        line_number: i64,
        byte_offset: i64,
        byte_end: i64,
        is_terminal: bool,
        tracker: Option<SuppliedSecretScanTracker>,
        meta: &mut SourceMetadata,
    ) -> ProcessJsonlLineError {
        let raw = RawLine::try_new(
            line_number,
            bytes.to_vec(),
            truncated,
            byte_offset,
            byte_end,
            3,
        )
        .expect("coordinates");
        let events = Vec::<SessionEvent>::new();
        let findings = Vec::<Finding>::new();
        let err = process_jsonl_line(
            &raw,
            is_terminal,
            "synthetic-jsonl.jsonl",
            SuppliedReaderLimits,
            &events,
            &findings,
            meta,
            false,
            None,
            None,
            tracker,
        )
        .expect_err("line seam");
        let text = err.to_string();
        assert_eq!(text, err.message());
        assert!(!text.contains("synthetic-jsonl.jsonl"));
        assert!(!text.contains("evt_"));
        assert!(!text.contains("SL001"));
        assert!(!text.contains("SL002"));
        assert!(!text.contains("SL009"));
        assert!(!text.contains("SL011"));
        assert_ne!(text, FINGERPRINT_CODEC_UNAVAILABLE);
        assert!(events.is_empty());
        assert!(findings.is_empty());
        err
    }

    #[test]
    fn jsonl_loader_stops_at_the_tail_tracker() {
        let samples: [&[u8]; 6] = [
            b"",
            b" \t\r\n",
            b"\x00",
            b"{}",
            b"{\"items\":[]}",
            b"{}\n{\"id\":\"evt_hidden\"}\n",
        ];
        for data in samples {
            let err = load_openai_agents_jsonl(
                data,
                "synthetic-jsonl.jsonl",
                SuppliedReaderLimits,
                SuppliedSecretScanTracker,
            )
            .expect_err("tail tracker");
            assert_eq!(err, LoadOpenAiAgentsJsonlError);
            assert_eq!(err.message(), MALFORMED_TAIL_TRACKER_UNAVAILABLE);
            assert_eq!(
                err.to_string(),
                "sesslint.io.MalformedTailTracker is not available"
            );
            assert!(!err.to_string().contains("synthetic-jsonl.jsonl"));
            assert!(!err.to_string().contains("evt_"));
            assert!(!err.to_string().contains("feed"));
            assert!(!err.to_string().contains("SL001"));
            assert!(!err.to_string().contains("SL002"));
            assert!(!err.to_string().contains("SL009"));
            assert!(!err.to_string().contains("SL011"));
            assert_ne!(err.to_string(), SECRET_SCAN_FEED_UNAVAILABLE);
            assert_ne!(err.to_string(), EXTRACT_RECORD_ID_UNAVAILABLE);
            assert_ne!(err.to_string(), DECODE_JSON_DUPAWARE_UNAVAILABLE);
            assert_ne!(err.to_string(), SECRET_SCAN_FEED_BLOB_UNAVAILABLE);
            assert_ne!(err.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        }

        let outer = load_openai_agents(OpenAiAgentsSource::Bytes(b"{}\n{\"id\":1}\n"), None)
            .expect_err("outer gate");
        assert_eq!(outer.to_string(), SECRET_SCAN_TRACKER_UNAVAILABLE);
        assert_ne!(outer.to_string(), MALFORMED_TAIL_TRACKER_UNAVAILABLE);

        let document = load_openai_agents_json(
            b"{}",
            "synthetic-export.json",
            SuppliedReaderLimits,
            SuppliedSecretScanTracker,
        )
        .expect_err("document");
        assert_eq!(document.to_string(), SECRET_SCAN_FEED_BLOB_UNAVAILABLE);
        assert_ne!(document.to_string(), MALFORMED_TAIL_TRACKER_UNAVAILABLE);
    }

    #[test]
    fn supplied_tracker_stops_at_feed_before_validation() {
        let samples: [(&[u8], bool); 6] = [
            (b"", false),
            (b" \t", false),
            (b"\x00", false),
            (b"\xff", false),
            (b"{", false),
            (b"{\"id\":\"evt_hidden\"}", true),
        ];
        for (bytes, truncated) in samples {
            let mut meta = size_list(&[11]);
            let err = run_line(
                bytes,
                truncated,
                1,
                2,
                9,
                true,
                Some(SuppliedSecretScanTracker),
                &mut meta,
            );
            assert_eq!(err, ProcessJsonlLineError::Feed);
            assert_eq!(
                err.to_string(),
                "sesslint.checks.hygiene.SecretScanTracker.feed is not available"
            );
            assert_eq!(sizes(&meta), vec![11]);
        }
    }

    #[test]
    fn jsonl_line_appends_span_then_stops() {
        let mut meta = size_list(&[9]);
        let decoded = run_line(b"{", false, 1, 4, 5, false, None, &mut meta);
        assert_eq!(decoded, ProcessJsonlLineError::DecodeJsonDupaware);
        assert_eq!(
            decoded.to_string(),
            "sesslint.io.decode_json_dupaware is not available"
        );
        assert_eq!(decoded.message(), DECODE_JSON_DUPAWARE_UNAVAILABLE);
        assert_eq!(sizes(&meta), vec![9, 1]);

        let nul = run_line(b"\x00", false, 2, 5, 8, true, None, &mut meta);
        assert_eq!(nul, ProcessJsonlLineError::ExtractRecordId);
        assert_eq!(
            nul.to_string(),
            "sesslint.io.extract_record_id is not available"
        );
        assert_eq!(sizes(&meta), vec![9, 1, 3]);

        let mut other = size_list(&[]);
        let not_terminal = run_line(b"a\x00b", false, 1, 0, 3, false, None, &mut other);
        assert_eq!(not_terminal, nul);
        assert_eq!(sizes(&other), vec![3]);

        let mut bad = size_list(&[]);
        let invalid = run_line(b"\xff", false, 1, 3, 4, true, None, &mut bad);
        assert_eq!(invalid, ProcessJsonlLineError::ExtractRecordId);
        assert_eq!(invalid.message(), EXTRACT_RECORD_ID_UNAVAILABLE);
        assert_eq!(sizes(&bad), vec![1]);

        let mut torn = size_list(&[]);
        let bom_bad = run_line(b"\xef\xbb\xbf\xff", false, 1, 0, 4, false, None, &mut torn);
        assert_eq!(bom_bad, ProcessJsonlLineError::ExtractRecordId);
        assert_eq!(sizes(&torn), vec![4]);

        let mut cut = size_list(&[]);
        let truncated = run_line(
            b"{\"id\":\"evt_hidden\"}",
            true,
            1,
            0,
            40,
            true,
            None,
            &mut cut,
        );
        assert_eq!(truncated, ProcessJsonlLineError::ExtractRecordId);
        assert_eq!(sizes(&cut), vec![40]);
        assert_ne!(
            sizes(&cut),
            vec![i64::try_from(b"{\"id\":\"evt_hidden\"}".len()).expect("len")]
        );
    }

    #[test]
    fn decodable_line_stops_at_decode_without_parsing() {
        let mut text = size_list(&[]);
        for (bytes, line_number) in [
            (b"".as_slice(), 1),
            (b" \t\n".as_slice(), 4),
            (b"{}".as_slice(), 2),
            (b"{\"id\":\"evt_hidden\"}".as_slice(), 8),
            (b"\xef\xbb\xbf{".as_slice(), 1),
            (b"\xef\xbb\xbf".as_slice(), 1),
        ] {
            let err = run_line(bytes, false, line_number, 1, 4, false, None, &mut text);
            assert_eq!(err, ProcessJsonlLineError::DecodeJsonDupaware);
            assert_eq!(err.message(), DECODE_JSON_DUPAWARE_UNAVAILABLE);
        }
        assert_eq!(sizes(&text), vec![3, 3, 3, 3, 3, 3]);
    }

    #[test]
    fn record_sizes_append_skips_a_non_list_and_ignores_guard_drift() {
        let mut missing = SourceMetadata::new();
        let err = run_line(b"{}", false, 1, 0, 2, false, None, &mut missing);
        assert_eq!(err, ProcessJsonlLineError::DecodeJsonDupaware);
        assert!(missing.get("record_sizes").is_none());

        let mut tuple_meta = SourceMetadata::new();
        tuple_meta.insert("record_sizes", MetaValue::Tuple(vec![MetaValue::Int(4)]));
        let err = run_line(b"\xff", false, 1, 0, 1, true, None, &mut tuple_meta);
        assert_eq!(err, ProcessJsonlLineError::ExtractRecordId);
        assert_eq!(
            tuple_meta.get("record_sizes"),
            Some(&MetaValue::Tuple(vec![MetaValue::Int(4)]))
        );

        let guard = crate::synthetic::SyntheticIdCollisionGuard::new();
        let drift = crate::drift::DriftTracker::new("openai-agents");
        let raw = RawLine::try_new(1, b"{}".to_vec(), false, 2, 6, 3).expect("line");
        assert_eq!(raw.line_number(), 1);
        assert_eq!(raw.raw_bytes(), b"{}");
        assert!(!raw.truncated_limit());
        assert_eq!(raw.byte_offset(), 2);
        assert_eq!(raw.byte_end(), 6);
        assert_eq!(raw.record_ordinal(), 3);
        let mut held = size_list(&[]);
        let events = Vec::<SessionEvent>::new();
        let findings = Vec::<Finding>::new();
        let err = process_jsonl_line(
            &raw,
            true,
            "synthetic-jsonl.jsonl",
            SuppliedReaderLimits,
            &events,
            &findings,
            &mut held,
            true,
            Some(&guard),
            Some(&drift),
            None,
        )
        .expect_err("decode");
        assert_eq!(err, ProcessJsonlLineError::DecodeJsonDupaware);
        assert_eq!(err.to_string(), DECODE_JSON_DUPAWARE_UNAVAILABLE);
        assert_ne!(err.to_string(), FINGERPRINT_CODEC_UNAVAILABLE);
        assert_eq!(sizes(&held), vec![4]);
        assert!(events.is_empty());
        assert!(findings.is_empty());
    }

    #[test]
    fn raw_line_rejects_invalid_coordinates() {
        let offset = RawLine::try_new(1, Vec::new(), false, -1, 0, 1).expect_err("offset");
        assert_eq!(
            offset.to_string(),
            "Invalid byte_offset: -1 (must be integer >= 0)"
        );
        let end = RawLine::try_new(1, Vec::new(), false, 2, 1, 1).expect_err("end");
        assert_eq!(
            end.to_string(),
            "Invalid byte_end: 1 (must be integer >= byte_offset=2)"
        );
        let ordinal = RawLine::try_new(1, Vec::new(), false, 0, 0, 0).expect_err("ordinal");
        assert_eq!(
            ordinal.to_string(),
            "Invalid record_ordinal: 0 (must be integer >= 1)"
        );
        let defaults = RawLine::from_parts(7, b"{}".to_vec(), false).expect("defaults");
        assert_eq!(defaults.byte_offset(), 0);
        assert_eq!(defaults.byte_end(), 0);
        assert_eq!(defaults.record_ordinal(), 1);
        assert_eq!(defaults.line_number(), 7);
    }
}
