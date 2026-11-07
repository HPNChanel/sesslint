//! OpenAI Agents SDK run-state projection and source metadata.
//!
//! Port of `src/sesslint/adapters/openai_agents.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e` lines 1–313.
//! Stops before `EventList` (line 316). The next function is
//! `normalize_version` (line 331).
//!
//! This slice ports [`safe_type_value`] (Python `_safe_type_value`),
//! [`project_run_state`], and [`SourceMetadata`]. [`SourceMetadata`] is the
//! class at line 303. It is not [`crate::canonical::SourceMetadata`].
//!
//! [`safe_type_value`] calls [`crate::safe_value::safe_type_value`]. It does
//! not shape values itself. [`project_run_state`] calls that wrapper and
//! [`crate::safe_value::safe_discriminator`]. Both are in this crate. This
//! slice has no late import, so it does not return a
//! `{module.function} is not available` error and it does not invent an SL
//! code.
//!
//! [`project_run_state`] keeps the pin order: read `run_state` and
//! `checkpoints`, take `items()` (an exception yields no keys), sort by
//! `str(key)`, project at most 32 keys, then project at most 8 checkpoints.
//!
//! Gaps vs Python (recorded, not papered over):
//! - `SQLITE_MAGIC`, `SUPPORTED_OPENAI_AGENTS_VERSIONS`, `CRITICAL_KEYS`,
//!   `KNOWN_RECORD_KEYS`, `ITEM_TYPE_MAP`, `CanonicalEvent`, and
//!   `_TIMESTAMP_ISO_REGEX` sit in this line range and are not read by the
//!   functions above. They are not ported. The regex is not walked.
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

use std::error::Error;
use std::fmt;

use crate::safe_value::safe_discriminator;
use crate::safe_value::PyValue;

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

#[cfg(test)]
mod tests {
    use super::{
        project_run_state, safe_type_value, AttrObject, MapKey, MapValue, MetaValue,
        ProjectedCheckpoint, RunSource, SeqNumber, SourceMetadata, TruncationTotals,
        MAX_PROJECTED_CHECKPOINTS, MAX_PROJECTED_RUN_STATE_KEYS,
    };
    use crate::safe_value::PyValue;

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
}
