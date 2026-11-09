//! Canonical serialization and cryptographic hashing codec (T-01 / S1).
//!
//! Port of `src/sesslint/_canonical_codec.py`
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Lines 1–307 are the codec type. Lines 310–393 are the module wrappers
//! ([`resolve_active_codec`] through [`ALL`]).
//!
//! Byte contract for plain values: Python
//! `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`
//! encoded as UTF-8, plus a trailing `\n` when `newline` is set. This is not RFC 8785 / JCS.
//!
//! `sesslint.canonical.SessionEvent` is not ported. Content-identity methods fail closed
//! instead of hashing a stand-in event. Provenance names are owned by that path and are
//! not stripped from [`PurePythonCanonicalCodec::canonical_json_bytes`].
//!
//! Python binds `_ACTIVE_CODEC` at import. Rust has no import, so the cell is resolved
//! on the first [`get_active_codec`] and then only [`set_active_codec`] replaces it.
//! A later change to `SESSLINT_DISABLE_ACCEL` does not resolve again.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::rc::Rc;
use std::sync::{Arc, Mutex, MutexGuard};

use model::errors::SchemaError;
use sha2::{Digest, Sha256};

/// Python: `CODEC_INTERFACE_VERSION`.
pub const CODEC_INTERFACE_VERSION: &str = "1.0.0";

/// Provenance keys removed only on the content-identity path.
///
/// Python: `_PROVENANCE_FIELD_NAMES`. [`PurePythonCanonicalCodec::canonical_json_bytes`]
/// keeps these keys. Content identity cannot apply them until `SessionEvent` exists.
pub const PROVENANCE_FIELD_NAMES: [&str; 3] =
    ["source_line", "source_location", "source_record_hash"];

/// Python: `_NON_STRING_KEY_ERROR`.
pub const NON_STRING_KEY_ERROR: &str = "Non-string dictionary key rejected by SessLint codec: ";

const SESSION_EVENT_UNAVAILABLE: &str = "sesslint.canonical.SessionEvent is not available";

const CYCLE_MESSAGE: &str = "Cyclic reference detected during canonical serialization";

const DEPTH_MESSAGE: &str = "Object nesting depth exceeded during canonical serialization";

const ALREADY_BORROWED: &str =
    "Canonical serialization error: value is already borrowed during canonical serialization";

/// Dict-chain containers accepted by the encoder walk.
///
/// CPython 3.11.9, top-level `canonical_json_bytes`: 992 dict wraps succeed and 993
/// raise the depth [`SchemaError`] (the limit is the interpreter stack, so this is the
/// fixed budget for that calibration, not `sys.getrecursionlimit()` itself).
const ENCODE_MAX_CONTAINERS: usize = 993;

/// `_normalize` frame budget. Arrays cost 2 because Python's list comprehension adds a
/// frame; objects and dataclasses cost 1. The same calibration accepts 497 list wraps
/// and rejects 498.
const NORMALIZE_MAX_UNITS: usize = 996;

/// Failure from this codec. Schema messages match the Python `SchemaError` text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    Schema(SchemaError),
    /// Late import of an unported module. The string is a stable, content-free message.
    Unsupported(&'static str),
    /// The active-codec [`Mutex`] was poisoned. This is not an input failure.
    LockPoisoned(&'static str),
}

impl CanonicalError {
    pub fn message(&self) -> &str {
        match self {
            Self::Schema(error) => error.message(),
            Self::Unsupported(message) | Self::LockPoisoned(message) => message,
        }
    }

    fn schema(message: impl Into<String>) -> Self {
        Self::Schema(SchemaError::new(message))
    }
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for CanonicalError {}

impl From<SchemaError> for CanonicalError {
    fn from(value: SchemaError) -> Self {
        Self::Schema(value)
    }
}

enum NormalizeError {
    Schema(SchemaError),
    /// Python `TypeError` message, without the `TypeError:` prefix.
    Type(String),
}

impl NormalizeError {
    fn schema(message: impl Into<String>) -> Self {
        Self::Schema(SchemaError::new(message))
    }

    fn into_public(self) -> CanonicalError {
        match self {
            Self::Schema(error) => CanonicalError::Schema(error),
            Self::Type(message) => {
                CanonicalError::schema(format!("Canonical serialization error: {message}"))
            }
        }
    }
}

/// Python `int` decimal spelling. No leading zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntValue {
    negative: bool,
    digits: String,
}

impl IntValue {
    /// Construct a lossless integer from canonical decimal digits, without a machine-size cap.
    pub fn from_decimal(value: &str) -> Result<Self, CanonicalError> {
        let result = Self {
            negative: value.starts_with('-'),
            digits: value.strip_prefix('-').unwrap_or(value).to_owned(),
        };
        if result.is_canonical() {
            Ok(result)
        } else {
            Err(CanonicalError::schema("Invalid canonical integer spelling"))
        }
    }

    pub fn from_i64(value: i64) -> Self {
        Self::from_i128(i128::from(value))
    }

    pub fn from_u64(value: u64) -> Self {
        Self {
            negative: false,
            digits: value.to_string(),
        }
    }

    pub fn from_i128(value: i128) -> Self {
        if value == i128::MIN {
            return Self {
                negative: true,
                digits: "170141183460469231731687303715884105728".to_string(),
            };
        }
        if value < 0 {
            Self {
                negative: true,
                digits: (-value).to_string(),
            }
        } else {
            Self {
                negative: false,
                digits: value.to_string(),
            }
        }
    }

    fn is_canonical(&self) -> bool {
        let bytes = self.digits.as_bytes();
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
            return false;
        }
        if bytes.len() > 1 && bytes[0] == b'0' {
            return false;
        }
        if self.negative && self.digits == "0" {
            return false;
        }
        true
    }
}

/// Dictionary key. Non-string keys carry the Python `repr` used in the rejection text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectKey {
    String(String),
    NonString(String),
}

impl ObjectKey {
    pub fn string(name: impl Into<String>) -> Self {
        Self::String(name.into())
    }

    pub fn non_string(python_repr: impl Into<String>) -> Self {
        Self::NonString(python_repr.into())
    }
}

/// One dataclass field, in `dataclasses.fields` order.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub name: String,
    pub value: Value,
}

impl Field {
    pub fn new(name: impl Into<String>, value: Value) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }
}

/// Plain JSON value, mapping, sequence, or dataclass.
///
/// There is no `SessionEvent` variant. Arrays stand for both Python `list` and `tuple`.
/// Objects stand for `dict` and other string-key mappings. Shared `Rc` identity is the
/// cycle identity Python tracks with `id()`.
#[derive(Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Int(IntValue),
    Float(f64),
    String(String),
    Array(Rc<RefCell<Vec<Value>>>),
    Object(Rc<RefCell<Vec<(ObjectKey, Value)>>>),
    Dataclass(Rc<RefCell<Vec<Field>>>),
    /// Python type name used in `Object of type {name} is not JSON serializable`.
    Foreign(&'static str),
}

impl fmt::Debug for Value {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => formatter.write_str("Null"),
            Self::Bool(value) => write!(formatter, "Bool({value})"),
            Self::Int(value) => write!(formatter, "Int({value:?})"),
            Self::Float(value) => write!(formatter, "Float({value:?})"),
            Self::String(value) => write!(formatter, "String({value:?})"),
            Self::Array(_) => formatter.write_str("Array(..)"),
            Self::Object(_) => formatter.write_str("Object(..)"),
            Self::Dataclass(_) => formatter.write_str("Dataclass(..)"),
            Self::Foreign(name) => write!(formatter, "Foreign({name})"),
        }
    }
}

/// Shared object cell. Callers clone the [`Value`] and push into the cell to form cycles.
pub type ObjectCell = Rc<RefCell<Vec<(ObjectKey, Value)>>>;

impl Value {
    pub fn null() -> Self {
        Self::Null
    }

    pub fn bool(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn int(value: i64) -> Self {
        Self::Int(IntValue::from_i64(value))
    }

    pub fn int_u64(value: u64) -> Self {
        Self::Int(IntValue::from_u64(value))
    }

    pub fn int_i128(value: i128) -> Self {
        Self::Int(IntValue::from_i128(value))
    }

    pub fn float(value: f64) -> Self {
        Self::Float(value)
    }

    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    pub fn array(items: Vec<Self>) -> Self {
        Self::Array(Rc::new(RefCell::new(items)))
    }

    pub fn array_cell(items: Vec<Self>) -> (Self, Rc<RefCell<Vec<Self>>>) {
        let cell = Rc::new(RefCell::new(items));
        (Self::Array(Rc::clone(&cell)), cell)
    }

    pub fn object(entries: Vec<(ObjectKey, Self)>) -> Self {
        Self::Object(Rc::new(RefCell::new(entries)))
    }

    pub fn object_cell(entries: Vec<(ObjectKey, Self)>) -> (Self, ObjectCell) {
        let cell = Rc::new(RefCell::new(entries));
        (Self::Object(Rc::clone(&cell)), cell)
    }

    pub fn dataclass(fields: Vec<Field>) -> Self {
        Self::Dataclass(Rc::new(RefCell::new(fields)))
    }

    pub fn foreign(type_name: &'static str) -> Self {
        Self::Foreign(type_name)
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Int(left), Self::Int(right)) => left == right,
            (Self::Float(left), Self::Float(right)) => left.to_bits() == right.to_bits(),
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Foreign(left), Self::Foreign(right)) => left == right,
            (Self::Array(left), Self::Array(right)) => Rc::ptr_eq(left, right),
            (Self::Object(left), Self::Object(right)) => Rc::ptr_eq(left, right),
            (Self::Dataclass(left), Self::Dataclass(right)) => Rc::ptr_eq(left, right),
            _ => false,
        }
    }
}

/// `True` when `name` is excluded from content identity and nowhere else.
pub fn is_provenance_field(name: &str) -> bool {
    PROVENANCE_FIELD_NAMES.contains(&name)
}

/// Strict contract for canonical serialization and hashing.
///
/// `content_identity_bytes` and `content_identity_hash` have no event argument:
/// `SessionEvent` is not ported, and the methods do not hash a plain JSON object
/// in its place.
pub trait CanonicalCodec {
    fn codec_name(&self) -> &str;
    fn codec_version(&self) -> &str;
    fn canonical_json_bytes(&self, obj: &Value, newline: bool) -> Result<Vec<u8>, CanonicalError>;
    fn content_identity_bytes(&self) -> Result<Vec<u8>, CanonicalError>;
    fn content_identity_hash(&self) -> Result<String, CanonicalError>;
    fn payload_content_hash(&self, payload: &Value) -> Result<String, CanonicalError>;
    fn plan_fingerprint(
        &self,
        plan_data: &Value,
        policy: Option<&str>,
    ) -> Result<String, CanonicalError>;
}

/// Pure-Rust reference implementation of [`CanonicalCodec`].
#[derive(Debug, Default, Clone, Copy)]
pub struct PurePythonCanonicalCodec;

impl PurePythonCanonicalCodec {
    pub const CODEC_NAME: &'static str = "pure_python";

    pub const fn new() -> Self {
        Self
    }

    fn prepare_plan(
        &self,
        plan_data: &Value,
        policy: Option<&str>,
    ) -> Result<Value, CanonicalError> {
        let Value::Object(entries) = plan_data else {
            return Err(CanonicalError::schema(
                "Canonical serialization error: plan fingerprint requires a mapping",
            ));
        };
        let entries = borrow_vec(entries).map_err(NormalizeError::into_public)?;
        let mut cleaned = Vec::new();
        let mut has_policy = false;
        for (key, value) in entries {
            match key {
                ObjectKey::String(name) if name == "fingerprint" => {}
                ObjectKey::String(name) => {
                    if name == "policy" {
                        has_policy = true;
                    }
                    cleaned.push((ObjectKey::String(name), value));
                }
                other => cleaned.push((other, value)),
            }
        }
        if let Some(policy_name) = policy {
            if !has_policy {
                cleaned.push((ObjectKey::string("policy"), Value::string(policy_name)));
            }
        }
        Ok(Value::object(cleaned))
    }
}

impl CanonicalCodec for PurePythonCanonicalCodec {
    fn codec_name(&self) -> &str {
        Self::CODEC_NAME
    }

    fn codec_version(&self) -> &str {
        CODEC_INTERFACE_VERSION
    }

    fn canonical_json_bytes(&self, obj: &Value, newline: bool) -> Result<Vec<u8>, CanonicalError> {
        let normalized = normalize_tree(obj).map_err(NormalizeError::into_public)?;
        let mut encoded = Vec::new();
        encode_tree(&normalized, &mut encoded)?;
        if newline {
            encoded.push(b'\n');
        }
        Ok(encoded)
    }

    fn content_identity_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        // Late import: `from sesslint.canonical import SessionEvent`.
        // The exclusion list stays on this path and is not applied to canonical JSON.
        if PROVENANCE_FIELD_NAMES.iter().any(|name| name.is_empty()) {
            return Err(CanonicalError::schema(
                "Canonical serialization error: provenance exclusion set is incomplete",
            ));
        }
        let _ = is_provenance_field(PROVENANCE_FIELD_NAMES[0]);
        Err(CanonicalError::Unsupported(SESSION_EVENT_UNAVAILABLE))
    }

    fn content_identity_hash(&self) -> Result<String, CanonicalError> {
        let bytes = self.content_identity_bytes()?;
        Ok(sha256_hex(&bytes))
    }

    fn payload_content_hash(&self, payload: &Value) -> Result<String, CanonicalError> {
        let encoded = self.canonical_json_bytes(payload, false)?;
        Ok(format!("sha256:{}", sha256_hex(&encoded)))
    }

    fn plan_fingerprint(
        &self,
        plan_data: &Value,
        policy: Option<&str>,
    ) -> Result<String, CanonicalError> {
        let cleaned = self.prepare_plan(plan_data, policy)?;
        let encoded = self.canonical_json_bytes(&cleaned, false)?;
        Ok(sha256_hex(&encoded))
    }
}

fn container_units(value: &Value) -> usize {
    match value {
        Value::Array(_) => 2,
        Value::Object(_) | Value::Dataclass(_) => 1,
        _ => 0,
    }
}

fn reject_non_finite(value: f64) -> Result<(), NormalizeError> {
    if value.is_nan() {
        return Err(NormalizeError::schema(
            "Float value nan is not valid in SessLint canonical JSON",
        ));
    }
    if value.is_infinite() {
        let spelling = if value.is_sign_negative() {
            "-inf"
        } else {
            "inf"
        };
        return Err(NormalizeError::schema(format!(
            "Float value {spelling} is not valid in SessLint canonical JSON"
        )));
    }
    Ok(())
}

fn non_string_key(python_repr: &str) -> NormalizeError {
    NormalizeError::schema(format!("{NON_STRING_KEY_ERROR}{python_repr}"))
}

fn borrow_vec<T: Clone>(cell: &RefCell<Vec<T>>) -> Result<Vec<T>, NormalizeError> {
    match cell.try_borrow() {
        Ok(guard) => Ok(guard.clone()),
        Err(_) => Err(NormalizeError::schema(ALREADY_BORROWED)),
    }
}

const NORMALIZE_UNDERFLOW: &str = "Canonical serialization error: normalize stack underflow";

enum Node {
    Null,
    Bool(bool),
    Int(IntValue),
    Float(f64),
    String(String),
    Array(Vec<usize>),
    Object(BTreeMap<String, usize>),
}

struct Tree {
    nodes: Vec<Node>,
    root: usize,
}

enum Pending {
    ObjectEntry(ObjectKey, Value),
    ArrayItem(Value),
    Field(Field),
    Extra(ObjectKey, Value),
}

struct OpenFrame {
    pointer: *const (),
    units: usize,
    pending: Vec<Pending>,
    keys: Vec<String>,
    ids: Vec<usize>,
    waiting: bool,
    list: bool,
}

struct NormMachine {
    nodes: Vec<Node>,
    ready: Vec<usize>,
    path: Vec<*const ()>,
    frames: Vec<OpenFrame>,
}

fn normalize_tree(value: &Value) -> Result<Tree, NormalizeError> {
    let mut machine = NormMachine {
        nodes: Vec::new(),
        ready: Vec::new(),
        path: Vec::new(),
        frames: Vec::new(),
    };
    machine.push_value(value.clone(), 0)?;
    while !machine.frames.is_empty() {
        machine.step()?;
    }
    match machine.ready.pop() {
        Some(root) if machine.ready.is_empty() => Ok(Tree {
            nodes: machine.nodes,
            root,
        }),
        _ => Err(NormalizeError::schema(NORMALIZE_UNDERFLOW)),
    }
}

impl NormMachine {
    fn step(&mut self) -> Result<(), NormalizeError> {
        if self.frames.last().is_some_and(|frame| frame.waiting) {
            let id = self.ready.pop().ok_or_else(underflow)?;
            let frame = self.frames.last_mut().ok_or_else(underflow)?;
            frame.ids.push(id);
            frame.waiting = false;
            return Ok(());
        }
        let Some(item) = self.frames.last_mut().and_then(|frame| frame.pending.pop()) else {
            return self.finish_frame();
        };
        let units = self.frames.last().ok_or_else(underflow)?.units;
        self.dispatch(item, units)
    }

    fn dispatch(&mut self, item: Pending, units: usize) -> Result<(), NormalizeError> {
        match item {
            Pending::ObjectEntry(ObjectKey::NonString(python_repr), _)
            | Pending::Extra(ObjectKey::NonString(python_repr), _) => {
                Err(non_string_key(&python_repr))
            }
            Pending::ObjectEntry(ObjectKey::String(name), child) => {
                self.schedule(Some(name), child, units)
            }
            Pending::ArrayItem(child) => self.schedule(None, child, units),
            Pending::Field(field) => self.dispatch_field(field, units),
            Pending::Extra(ObjectKey::String(name), child) => {
                let present = self
                    .frames
                    .last()
                    .ok_or_else(underflow)?
                    .keys
                    .iter()
                    .any(|key| key == &name);
                if name.starts_with("experimental_") && !present {
                    self.schedule(Some(name), child, units)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn dispatch_field(&mut self, field: Field, units: usize) -> Result<(), NormalizeError> {
        if field.name == "extra_fields" {
            if let Value::Object(extra) = field.value {
                let entries = borrow_vec(&extra)?;
                let frame = self.frames.last_mut().ok_or_else(underflow)?;
                for (key, child) in entries.into_iter().rev() {
                    frame.pending.push(Pending::Extra(key, child));
                }
            }
            return Ok(());
        }
        if matches!(field.value, Value::Null) && field.name != "parent_id" {
            return Ok(());
        }
        if field.name == "metadata" && empty_object(&field.value)? {
            return Ok(());
        }
        self.schedule(Some(field.name), field.value, units)
    }

    fn schedule(
        &mut self,
        key: Option<String>,
        child: Value,
        units: usize,
    ) -> Result<(), NormalizeError> {
        {
            let frame = self.frames.last_mut().ok_or_else(underflow)?;
            if let Some(key) = key {
                frame.keys.push(key);
            }
            frame.waiting = true;
        }
        self.push_value(child, units)
    }

    fn finish_frame(&mut self) -> Result<(), NormalizeError> {
        let frame = self.frames.pop().ok_or_else(underflow)?;
        if self.path.pop() != Some(frame.pointer) {
            return Err(underflow());
        }
        let node = if frame.list {
            Node::Array(frame.ids)
        } else {
            let mut object = BTreeMap::new();
            for (key, id) in frame.keys.into_iter().zip(frame.ids) {
                object.insert(key, id);
            }
            Node::Object(object)
        };
        let id = self.alloc(node);
        self.ready.push(id);
        Ok(())
    }

    fn push_value(&mut self, value: Value, parent_units: usize) -> Result<(), NormalizeError> {
        let extra = container_units(&value);
        let next = parent_units.saturating_add(extra);
        if extra > 0 && next > NORMALIZE_MAX_UNITS {
            return Err(NormalizeError::schema(DEPTH_MESSAGE));
        }
        let units = if extra > 0 { next } else { parent_units };
        match value {
            Value::Null => self.push_node(Node::Null),
            Value::Bool(item) => self.push_node(Node::Bool(item)),
            Value::Int(item) => self.push_node(Node::Int(item)),
            Value::String(item) => self.push_node(Node::String(item)),
            Value::Float(item) => {
                reject_non_finite(item)?;
                self.push_node(Node::Float(item));
            }
            Value::Foreign(type_name) => {
                return Err(NormalizeError::Type(format!(
                    "Object of type {type_name} is not JSON serializable"
                )));
            }
            Value::Object(entries) => self.open_container(entries, units, true)?,
            Value::Array(items) => self.open_container(items, units, false)?,
            Value::Dataclass(fields) => self.open_dataclass(fields, units)?,
        }
        Ok(())
    }

    fn open_container<T>(
        &mut self,
        cell: Rc<RefCell<Vec<T>>>,
        units: usize,
        object: bool,
    ) -> Result<(), NormalizeError>
    where
        T: Clone + IntoPending,
    {
        let pointer = Rc::as_ptr(&cell).cast::<()>();
        if self.path.contains(&pointer) {
            return Err(NormalizeError::schema(CYCLE_MESSAGE));
        }
        let entries = borrow_vec(&cell)?;
        self.path.push(pointer);
        let pending = entries
            .into_iter()
            .rev()
            .map(IntoPending::into_pending)
            .collect();
        self.frames.push(OpenFrame {
            pointer,
            units,
            pending,
            keys: Vec::new(),
            ids: Vec::new(),
            waiting: false,
            list: !object,
        });
        Ok(())
    }

    fn open_dataclass(
        &mut self,
        cell: Rc<RefCell<Vec<Field>>>,
        units: usize,
    ) -> Result<(), NormalizeError> {
        let pointer = Rc::as_ptr(&cell).cast::<()>();
        if self.path.contains(&pointer) {
            return Err(NormalizeError::schema(CYCLE_MESSAGE));
        }
        let fields = borrow_vec(&cell)?;
        self.path.push(pointer);
        let pending = fields.into_iter().rev().map(Pending::Field).collect();
        self.frames.push(OpenFrame {
            pointer,
            units,
            pending,
            keys: Vec::new(),
            ids: Vec::new(),
            waiting: false,
            list: false,
        });
        Ok(())
    }

    fn alloc(&mut self, node: Node) -> usize {
        let id = self.nodes.len();
        self.nodes.push(node);
        id
    }

    fn push_node(&mut self, node: Node) {
        let id = self.alloc(node);
        self.ready.push(id);
    }
}

trait IntoPending {
    fn into_pending(self) -> Pending;
}

impl IntoPending for (ObjectKey, Value) {
    fn into_pending(self) -> Pending {
        Pending::ObjectEntry(self.0, self.1)
    }
}

impl IntoPending for Value {
    fn into_pending(self) -> Pending {
        Pending::ArrayItem(self)
    }
}

fn underflow() -> NormalizeError {
    NormalizeError::schema(NORMALIZE_UNDERFLOW)
}

fn empty_object(value: &Value) -> Result<bool, NormalizeError> {
    match value {
        Value::Object(entries) => Ok(borrow_vec(entries)?.is_empty()),
        _ => Ok(false),
    }
}

enum EmitTask {
    Node {
        index: usize,
        parent_depth: usize,
    },
    Object {
        pairs: Vec<(String, usize)>,
        depth: usize,
        cursor: usize,
    },
    Array {
        items: Vec<usize>,
        depth: usize,
        cursor: usize,
    },
}

fn encode_tree(tree: &Tree, out: &mut Vec<u8>) -> Result<(), SchemaError> {
    let mut tasks = vec![EmitTask::Node {
        index: tree.root,
        parent_depth: 0,
    }];
    while let Some(task) = tasks.pop() {
        match task {
            EmitTask::Node {
                index,
                parent_depth,
            } => {
                let Some(node) = tree.nodes.get(index) else {
                    return Err(SchemaError::new(NORMALIZE_UNDERFLOW));
                };
                emit_node(node, parent_depth, &mut tasks, out)?;
            }
            EmitTask::Object {
                pairs,
                depth,
                cursor,
            } => emit_children(true, pairs, Vec::new(), depth, cursor, &mut tasks, out)?,
            EmitTask::Array {
                items,
                depth,
                cursor,
            } => emit_children(false, Vec::new(), items, depth, cursor, &mut tasks, out)?,
        }
    }
    Ok(())
}

fn emit_node(
    node: &Node,
    parent_depth: usize,
    tasks: &mut Vec<EmitTask>,
    out: &mut Vec<u8>,
) -> Result<(), SchemaError> {
    match node {
        Node::Null => out.extend_from_slice(b"null"),
        Node::Bool(true) => out.extend_from_slice(b"true"),
        Node::Bool(false) => out.extend_from_slice(b"false"),
        Node::Int(value) => push_int(out, value)?,
        Node::Float(value) => {
            let text = python_json::format_finite(*value)?;
            out.extend_from_slice(text.as_bytes());
        }
        Node::String(value) => push_string(out, value),
        Node::Array(items) => {
            let depth = parent_depth + 1;
            if depth > ENCODE_MAX_CONTAINERS {
                return Err(SchemaError::new(DEPTH_MESSAGE));
            }
            out.push(b'[');
            tasks.push(EmitTask::Array {
                items: items.clone(),
                depth,
                cursor: 0,
            });
        }
        Node::Object(entries) => {
            let depth = parent_depth + 1;
            if depth > ENCODE_MAX_CONTAINERS {
                return Err(SchemaError::new(DEPTH_MESSAGE));
            }
            out.push(b'{');
            let pairs = entries.iter().map(|(key, id)| (key.clone(), *id)).collect();
            tasks.push(EmitTask::Object {
                pairs,
                depth,
                cursor: 0,
            });
        }
    }
    Ok(())
}

fn emit_children(
    object: bool,
    pairs: Vec<(String, usize)>,
    items: Vec<usize>,
    depth: usize,
    cursor: usize,
    tasks: &mut Vec<EmitTask>,
    out: &mut Vec<u8>,
) -> Result<(), SchemaError> {
    let len = if object { pairs.len() } else { items.len() };
    if cursor == len {
        out.push(if object { b'}' } else { b']' });
        return Ok(());
    }
    if cursor > 0 {
        out.push(b',');
    }
    let child = if object {
        let (key, id) = &pairs[cursor];
        push_string(out, key);
        out.push(b':');
        *id
    } else {
        items[cursor]
    };
    if object {
        tasks.push(EmitTask::Object {
            pairs,
            depth,
            cursor: cursor + 1,
        });
    } else {
        tasks.push(EmitTask::Array {
            items,
            depth,
            cursor: cursor + 1,
        });
    }
    tasks.push(EmitTask::Node {
        index: child,
        parent_depth: depth,
    });
    Ok(())
}

fn push_int(out: &mut Vec<u8>, value: &IntValue) -> Result<(), SchemaError> {
    if !value.is_canonical() {
        return Err(SchemaError::new(
            "Canonical serialization error: integer digits are not canonical",
        ));
    }
    if value.negative {
        out.push(b'-');
    }
    out.extend_from_slice(value.digits.as_bytes());
    Ok(())
}

fn push_string(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\u{0008}' => out.extend_from_slice(br#"\b"#),
            '\u{000c}' => out.extend_from_slice(br#"\f"#),
            '\n' => out.extend_from_slice(br#"\n"#),
            '\r' => out.extend_from_slice(br#"\r"#),
            '\t' => out.extend_from_slice(br#"\t"#),
            other if (other as u32) < 0x20 => push_control_escape(out, other as u8),
            other => {
                let mut buffer = [0u8; 4];
                let encoded = other.encode_utf8(&mut buffer);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn push_control_escape(out: &mut Vec<u8>, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(b"\\u00");
    out.push(HEX[usize::from(byte >> 4)]);
    out.push(HEX[usize::from(byte & 0x0f)]);
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(Sha256::digest(bytes).as_slice())
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

mod python_json {
    use super::SchemaError;

    #[derive(Clone, PartialEq, Eq)]
    struct Big {
        limbs: Vec<u32>,
    }

    impl Big {
        fn from_u64(mut value: u64) -> Self {
            let mut limbs = Vec::new();
            while value > 0 {
                limbs.push((value & 0xffff_ffff) as u32);
                value >>= 32;
            }
            Self { limbs }
        }

        fn shrink(&mut self) {
            while self.limbs.last() == Some(&0) {
                self.limbs.pop();
            }
        }

        fn mul_u32(&self, factor: u32) -> Self {
            if factor == 0 || self.limbs.is_empty() {
                return Self { limbs: Vec::new() };
            }
            let mut limbs = Vec::with_capacity(self.limbs.len() + 1);
            let mut carry = 0u64;
            for limb in &self.limbs {
                let product = u64::from(*limb) * u64::from(factor) + carry;
                limbs.push(product as u32);
                carry = product >> 32;
            }
            if carry > 0 {
                limbs.push(carry as u32);
            }
            Self { limbs }
        }

        fn add(&self, other: &Self) -> Self {
            let width = self.limbs.len().max(other.limbs.len());
            let mut limbs = Vec::with_capacity(width + 1);
            let mut carry = 0u64;
            for index in 0..width {
                let left = self.limbs.get(index).copied().unwrap_or(0);
                let right = other.limbs.get(index).copied().unwrap_or(0);
                let sum = u64::from(left) + u64::from(right) + carry;
                limbs.push(sum as u32);
                carry = sum >> 32;
            }
            if carry > 0 {
                limbs.push(carry as u32);
            }
            let mut result = Self { limbs };
            result.shrink();
            result
        }

        fn shl(&self, bits: u32) -> Self {
            if self.limbs.is_empty() || bits == 0 {
                return self.clone();
            }
            let words = (bits / 32) as usize;
            let rem = bits % 32;
            let mut limbs = vec![0u32; words];
            let mut carry = 0u32;
            for limb in &self.limbs {
                let combined = (u64::from(*limb) << rem) | u64::from(carry);
                limbs.push(combined as u32);
                carry = (combined >> 32) as u32;
            }
            if carry > 0 {
                limbs.push(carry);
            }
            Self { limbs }
        }

        fn mul_pow10(&self, mut exponent: u32) -> Self {
            let mut value = self.shl(exponent);
            while exponent > 0 {
                let step = exponent.min(13);
                let mut factor = 1u32;
                for _ in 0..step {
                    factor *= 5;
                }
                value = value.mul_u32(factor);
                exponent -= step;
            }
            value
        }
    }

    #[derive(Clone)]
    struct Parts {
        negative: bool,
        digits: Vec<u8>,
        exp10: i32,
    }

    impl Parts {
        fn parse(input: &str) -> Option<Self> {
            let (negative, rest) = if let Some(stripped) = input.strip_prefix('-') {
                (true, stripped)
            } else {
                (false, input)
            };
            if rest == "0.0" || rest == "0" {
                return Some(Self {
                    negative,
                    digits: vec![0],
                    exp10: 0,
                });
            }
            let (body, exponent) = if let Some((mantissa, exponent)) = rest.split_once('e') {
                (mantissa, Some(exponent.parse::<i32>().ok()?))
            } else {
                (rest, None)
            };
            let (before, after) = if let Some((whole, fraction)) = body.split_once('.') {
                (whole, fraction)
            } else {
                (body, "")
            };
            if before.is_empty()
                || !before.bytes().all(|byte| byte.is_ascii_digit())
                || !after.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            let raw: Vec<u8> = before
                .bytes()
                .chain(after.bytes())
                .map(|byte| byte - b'0')
                .collect();
            let first = raw.iter().position(|digit| *digit != 0)?;
            let mut digits = raw[first..].to_vec();
            while digits.len() > 1 && digits.last() == Some(&0) {
                digits.pop();
            }
            let exp10 = if let Some(exponent) = exponent {
                exponent - i32::try_from(first).ok()?
            } else if before.bytes().all(|byte| byte == b'0') {
                let zeros = after.bytes().take_while(|byte| *byte == b'0').count();
                -i32::try_from(zeros).ok()? - 1
            } else {
                i32::try_from(before.len()).ok()? - 1 - i32::try_from(first).ok()?
            };
            Some(Self {
                negative,
                digits,
                exp10,
            })
        }

        fn adjust(&self, delta: i8) -> Option<Self> {
            let mut digits = self.digits.clone();
            let mut exp10 = self.exp10;
            if delta == -1 {
                let mut index = digits.len() - 1;
                loop {
                    if digits[index] > 0 {
                        digits[index] -= 1;
                        break;
                    }
                    digits[index] = 9;
                    if index == 0 {
                        return None;
                    }
                    index -= 1;
                }
            } else if delta == 1 {
                let mut index = digits.len() as isize - 1;
                let mut carry = 1u8;
                while index >= 0 && carry == 1 {
                    let slot = index as usize;
                    let sum = digits[slot] + carry;
                    digits[slot] = sum % 10;
                    carry = sum / 10;
                    index -= 1;
                }
                if carry == 1 {
                    digits.insert(0, 1);
                    exp10 += 1;
                }
            } else {
                return None;
            }
            while digits.len() > 1 && digits.last() == Some(&0) {
                digits.pop();
            }
            if digits.is_empty() || digits.iter().all(|digit| *digit == 0) {
                return Some(Self {
                    negative: false,
                    digits: vec![0],
                    exp10: 0,
                });
            }
            Some(Self {
                negative: self.negative,
                digits,
                exp10,
            })
        }

        fn format(&self) -> String {
            if self.digits == [0] {
                return if self.negative {
                    "-0.0".to_string()
                } else {
                    "0.0".to_string()
                };
            }
            let mut out = String::new();
            if self.negative {
                out.push('-');
            }
            let exponent = self.exp10;
            if !(-4..16).contains(&exponent) {
                out.push(char::from(b'0' + self.digits[0]));
                if self.digits.len() > 1 {
                    out.push('.');
                    for digit in &self.digits[1..] {
                        out.push(char::from(b'0' + *digit));
                    }
                }
                out.push('e');
                out.push(if exponent >= 0 { '+' } else { '-' });
                let absolute = exponent.unsigned_abs();
                if absolute < 10 {
                    out.push('0');
                }
                out.push_str(&absolute.to_string());
            } else if exponent >= 0 {
                let point = exponent as usize;
                if point + 1 >= self.digits.len() {
                    for digit in &self.digits {
                        out.push(char::from(b'0' + *digit));
                    }
                    for _ in 0..(point + 1 - self.digits.len()) {
                        out.push('0');
                    }
                    out.push_str(".0");
                } else {
                    for digit in &self.digits[..=point] {
                        out.push(char::from(b'0' + *digit));
                    }
                    out.push('.');
                    for digit in &self.digits[point + 1..] {
                        out.push(char::from(b'0' + *digit));
                    }
                }
            } else {
                out.push_str("0.");
                for _ in 0..((-exponent - 1) as usize) {
                    out.push('0');
                }
                for digit in &self.digits {
                    out.push(char::from(b'0' + *digit));
                }
            }
            out
        }

        fn coefficient(&self) -> Big {
            let mut value = Big::from_u64(0);
            for digit in &self.digits {
                value = value.mul_u32(10).add(&Big::from_u64(u64::from(*digit)));
            }
            value
        }

        fn power(&self) -> i32 {
            self.exp10 - i32::try_from(self.digits.len()).unwrap_or(i32::MAX) + 1
        }
    }

    pub(super) fn format_finite(value: f64) -> Result<String, SchemaError> {
        let normalized = normalize_exponent(&format!("{value:?}"));
        let Some(parts) = Parts::parse(&normalized) else {
            return Err(SchemaError::new(
                "Canonical serialization error: float formatting failed",
            ));
        };
        let rendered = parts.format();
        let last = parts.digits.last().copied().unwrap_or(0);
        if last % 2 == 0 {
            return Ok(rendered);
        }
        for delta in [-1i8, 1] {
            let Some(candidate) = parts.adjust(delta) else {
                continue;
            };
            if candidate.digits.last().copied().unwrap_or(1) % 2 != 0 {
                continue;
            }
            let text = candidate.format();
            let Ok(parsed) = text.parse::<f64>() else {
                continue;
            };
            if parsed.to_bits() != value.to_bits() {
                continue;
            }
            if magnitudes_are_equidistant(value, &parts, &candidate) {
                return Ok(text);
            }
        }
        Ok(rendered)
    }

    fn normalize_exponent(input: &str) -> String {
        let Some((mantissa, exponent)) = input.split_once('e') else {
            return input.to_string();
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

    fn magnitudes_are_equidistant(value: f64, left: &Parts, right: &Parts) -> bool {
        let (mantissa, binary_exponent) = float_magnitude(value);
        if mantissa == 0 {
            return false;
        }
        let left_power = left.power();
        let right_power = right.power();
        let minimum = left_power.min(right_power);
        let Some(left_scale) = u32::try_from(left_power - minimum).ok() else {
            return false;
        };
        let Some(right_scale) = u32::try_from(right_power - minimum).ok() else {
            return false;
        };
        let sum = left
            .coefficient()
            .mul_pow10(left_scale)
            .add(&right.coefficient().mul_pow10(right_scale));
        let shift = binary_exponent + 1;
        let mut left_side = Big::from_u64(mantissa);
        let mut right_side = sum;
        if shift >= 0 {
            let Some(bits) = u32::try_from(shift).ok() else {
                return false;
            };
            left_side = left_side.shl(bits);
        } else {
            let Some(bits) = u32::try_from(-shift).ok() else {
                return false;
            };
            right_side = right_side.shl(bits);
        }
        if minimum >= 0 {
            let Some(exponent) = u32::try_from(minimum).ok() else {
                return false;
            };
            right_side = right_side.mul_pow10(exponent);
        } else {
            let Some(exponent) = u32::try_from(-minimum).ok() else {
                return false;
            };
            left_side = left_side.mul_pow10(exponent);
        }
        left_side == right_side
    }

    fn float_magnitude(value: f64) -> (u64, i32) {
        let bits = value.to_bits() & !(1u64 << 63);
        let biased = ((bits >> 52) & 0x7ff) as i32;
        let fraction = bits & ((1u64 << 52) - 1);
        if biased == 0 {
            (fraction, -1074)
        } else {
            (fraction | (1u64 << 52), biased - 1023 - 52)
        }
    }
}

const DISABLE_ACCEL_ENV: &str = "SESSLINT_DISABLE_ACCEL";

const DISABLE_ACCEL_TOKENS: [&str; 3] = ["1", "true", "yes"];

const ACTIVE_LOCK_POISONED: &str = "active canonical codec lock is poisoned";

fn accel_disabled(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| DISABLE_ACCEL_TOKENS.contains(&value.trim()))
}

fn read_disable_accel_flag() -> Option<String> {
    // `NotPresent` and `NotUnicode` are both "not a disable token".
    // The caller then takes the missing-accel fallback, which is the pure codec.
    std::env::var(DISABLE_ACCEL_ENV).ok()
}

fn resolve_from_disable_flag(raw: Option<&str>) -> PurePythonCanonicalCodec {
    if accel_disabled(raw) {
        return PurePythonCanonicalCodec::new();
    }
    // `import sesslint._accel` is not linked. Python's `except Exception`
    // (including a missing module) falls through to the pure codec.
    // That miss is not [`CanonicalError::Unsupported`].
    fallback_pure_codec()
}

fn fallback_pure_codec() -> PurePythonCanonicalCodec {
    PurePythonCanonicalCodec::new()
}

fn materialize(tree: &Tree) -> Result<Value, CanonicalError> {
    let mut values = Vec::with_capacity(tree.nodes.len());
    for node in &tree.nodes {
        let next = materialize_node(node, &values)?;
        values.push(next);
    }
    values
        .get(tree.root)
        .cloned()
        .ok_or_else(|| CanonicalError::schema(NORMALIZE_UNDERFLOW))
}

fn materialize_node(node: &Node, values: &[Value]) -> Result<Value, CanonicalError> {
    match node {
        Node::Null => Ok(Value::null()),
        Node::Bool(item) => Ok(Value::bool(*item)),
        Node::Int(item) => Ok(Value::Int(item.clone())),
        Node::Float(item) => Ok(Value::float(*item)),
        Node::String(item) => Ok(Value::string(item.clone())),
        Node::Array(items) => {
            let mut array = Vec::with_capacity(items.len());
            for id in items {
                array.push(copied_child(values, *id)?);
            }
            Ok(Value::array(array))
        }
        Node::Object(entries) => {
            let mut object = Vec::with_capacity(entries.len());
            for (key, id) in entries {
                object.push((ObjectKey::string(key.clone()), copied_child(values, *id)?));
            }
            Ok(Value::object(object))
        }
    }
}

fn copied_child(values: &[Value], index: usize) -> Result<Value, CanonicalError> {
    values
        .get(index)
        .cloned()
        .ok_or_else(|| CanonicalError::schema(NORMALIZE_UNDERFLOW))
}

impl PurePythonCanonicalCodec {
    fn reify_normalized(&self, obj: &Value) -> Result<Value, CanonicalError> {
        let tree = normalize_tree(obj).map_err(NormalizeError::into_public)?;
        materialize(&tree)
    }
}

/// Python `_resolve_active_codec`.
///
/// A stripped `SESSLINT_DISABLE_ACCEL` of `1`, `true`, or `yes` returns the
/// pure codec. Otherwise the missing `sesslint._accel` module is the
/// `except Exception` path and also returns the pure codec.
pub fn resolve_active_codec() -> PurePythonCanonicalCodec {
    resolve_from_disable_flag(read_disable_accel_flag().as_deref())
}

/// Shared handle for the active [`CanonicalCodec`].
///
/// Python returns the module instance. This `Arc` is that identity:
/// [`set_active_codec`] stores it and [`get_active_codec`] returns it.
pub type SharedCodec = Arc<dyn CanonicalCodec + Send + Sync>;

/// Python `_ACTIVE_CODEC`.
///
/// Empty until the first [`get_active_codec`] or any [`set_active_codec`].
/// Resolution runs only while the cell is empty. A later environment change
/// does not resolve again.
static ACTIVE_CODEC: Mutex<Option<SharedCodec>> = Mutex::new(None);

/// Python `_DEFAULT_PURE_CODEC`. [`normalize_canonical`] uses this, not the cell.
const DEFAULT_PURE_CODEC: PurePythonCanonicalCodec = PurePythonCanonicalCodec::new();

fn lock_active() -> Result<MutexGuard<'static, Option<SharedCodec>>, CanonicalError> {
    ACTIVE_CODEC
        .lock()
        .map_err(|_| CanonicalError::LockPoisoned(ACTIVE_LOCK_POISONED))
}

#[cfg(test)]
fn clear_active_codec() -> Result<(), CanonicalError> {
    let mut cell = lock_active()?;
    *cell = None;
    Ok(())
}

/// Python `get_active_codec`.
///
/// Resolves on the first call when the cell is empty. Later calls return that
/// handle. A poisoned lock is [`CanonicalError::LockPoisoned`].
pub fn get_active_codec() -> Result<SharedCodec, CanonicalError> {
    let mut cell = lock_active()?;
    if let Some(codec) = cell.as_ref() {
        return Ok(Arc::clone(codec));
    }
    let resolved: SharedCodec = Arc::new(resolve_active_codec());
    *cell = Some(Arc::clone(&resolved));
    Ok(resolved)
}

/// Python `set_active_codec`.
///
/// Replaces the cell. A later [`get_active_codec`] returns this handle and
/// does not read `SESSLINT_DISABLE_ACCEL` again. A set before the first get
/// skips resolution. A poisoned lock is [`CanonicalError::LockPoisoned`].
pub fn set_active_codec(codec: SharedCodec) -> Result<(), CanonicalError> {
    let mut cell = lock_active()?;
    *cell = Some(codec);
    Ok(())
}

/// Python `normalize_canonical`.
///
/// Uses the default pure codec (`_DEFAULT_PURE_CODEC`), not the active cell.
/// Object keys come out in the sorted order `normalize_tree` already stores
/// in a `BTreeMap`. Python's `_normalize` dict keeps insertion order and sorts
/// only inside `json.dumps`. There is no external `seen` argument: cycle
/// identity stays inside that normalizer.
pub fn normalize_canonical(obj: &Value) -> Result<Value, CanonicalError> {
    DEFAULT_PURE_CODEC.reify_normalized(obj)
}

/// Python `canonical_json_bytes`. Delegates to the active codec.
pub fn canonical_json_bytes(obj: &Value, newline: bool) -> Result<Vec<u8>, CanonicalError> {
    get_active_codec()?.canonical_json_bytes(obj, newline)
}

/// Python `content_identity_bytes`.
///
/// `SessionEvent` is not ported, so this takes no event and does not hash a
/// plain JSON object in its place. The active pure codec returns
/// [`CanonicalError::Unsupported`] with
/// `sesslint.canonical.SessionEvent is not available`.
pub fn content_identity_bytes() -> Result<Vec<u8>, CanonicalError> {
    get_active_codec()?.content_identity_bytes()
}

/// Python `content_identity_hash`. Same `SessionEvent` gap as
/// [`content_identity_bytes`].
pub fn content_identity_hash() -> Result<String, CanonicalError> {
    get_active_codec()?.content_identity_hash()
}

/// Python `payload_content_hash`. Delegates to the active codec.
pub fn payload_content_hash(payload: &Value) -> Result<String, CanonicalError> {
    get_active_codec()?.payload_content_hash(payload)
}

/// Python `plan_fingerprint`. Delegates to the active codec.
pub fn plan_fingerprint(plan_data: &Value, policy: Option<&str>) -> Result<String, CanonicalError> {
    get_active_codec()?.plan_fingerprint(plan_data, policy)
}

/// Python `__all__`, in that order.
pub const ALL: [&str; 11] = [
    "CODEC_INTERFACE_VERSION",
    "CanonicalCodec",
    "PurePythonCanonicalCodec",
    "canonical_json_bytes",
    "content_identity_bytes",
    "content_identity_hash",
    "get_active_codec",
    "normalize_canonical",
    "payload_content_hash",
    "plan_fingerprint",
    "set_active_codec",
];

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn codec() -> PurePythonCanonicalCodec {
        PurePythonCanonicalCodec::new()
    }

    fn key(name: &str) -> ObjectKey {
        ObjectKey::string(name)
    }

    fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::object(
            pairs
                .into_iter()
                .map(|(name, value)| (key(name), value))
                .collect(),
        )
    }

    fn bytes_of(value: &Value) -> Vec<u8> {
        codec().canonical_json_bytes(value, false).unwrap()
    }

    fn err_message(value: &Value) -> String {
        codec()
            .canonical_json_bytes(value, false)
            .unwrap_err()
            .message()
            .to_string()
    }

    #[test]
    fn codec_name_and_version_match_python() {
        let implementation = codec();
        let trait_object: &dyn CanonicalCodec = &implementation;
        assert_eq!(trait_object.codec_name(), "pure_python");
        assert_eq!(trait_object.codec_version(), "1.0.0");
        assert_eq!(CODEC_INTERFACE_VERSION, "1.0.0");
    }

    #[test]
    fn nested_object_keys_are_sorted() {
        let value = obj(vec![
            ("b", obj(vec![("z", Value::int(1)), ("a", Value::int(2))])),
            ("a", Value::int(1)),
        ]);
        assert_eq!(bytes_of(&value), br#"{"a":1,"b":{"a":2,"z":1}}"#);
    }

    #[test]
    fn unicode_is_not_escaped() {
        let value = obj(vec![
            ("emoji", Value::string("🚀✨")),
            ("multilingual", Value::string("Tiếng Việt / 日本語 / 🌍")),
        ]);
        let expected =
            "{\"emoji\":\"🚀✨\",\"multilingual\":\"Tiếng Việt / 日本語 / 🌍\"}".as_bytes();
        assert_eq!(bytes_of(&value), expected);
    }

    #[test]
    fn controls_are_escaped_and_line_separators_are_raw_utf8() {
        let text = "a/b\"c\\d\n\t\r\u{0008}\u{000c}\u{0001}\u{2028}\u{2029}";
        let value = obj(vec![("s", Value::string(text))]);
        let mut expected = b"{\"s\":\"a/b\\\"c\\\\d\\n\\t\\r\\b\\f\\u0001".to_vec();
        expected.extend("\u{2028}\u{2029}".as_bytes());
        expected.extend(br#""}"#);
        assert_eq!(bytes_of(&value), expected);
    }

    #[test]
    fn non_string_key_is_rejected_in_insertion_order() {
        let value = Value::object(vec![
            (ObjectKey::non_string("3"), Value::int(1)),
            (ObjectKey::non_string("20"), Value::float(f64::NAN)),
        ]);
        assert_eq!(
            err_message(&value),
            "Non-string dictionary key rejected by SessLint codec: 3"
        );
    }

    #[test]
    fn nan_infinity_and_negative_infinity_are_rejected() {
        assert_eq!(
            err_message(&Value::float(f64::NAN)),
            "Float value nan is not valid in SessLint canonical JSON"
        );
        assert_eq!(
            err_message(&Value::float(f64::from_bits(0xfff8_0000_0000_0001))),
            "Float value nan is not valid in SessLint canonical JSON"
        );
        assert_eq!(
            err_message(&Value::float(f64::INFINITY)),
            "Float value inf is not valid in SessLint canonical JSON"
        );
        assert_eq!(
            err_message(&Value::float(f64::NEG_INFINITY)),
            "Float value -inf is not valid in SessLint canonical JSON"
        );
    }

    #[test]
    fn cycle_is_rejected_and_a_diamond_is_not() {
        let (value, cell) = Value::object_cell(vec![(key("key"), Value::string("val"))]);
        cell.borrow_mut().push((key("self"), value.clone()));
        assert_eq!(
            err_message(&value),
            "Cyclic reference detected during canonical serialization"
        );

        let shared = obj(vec![("a", Value::int(1))]);
        let diamond = obj(vec![("x", shared.clone()), ("y", shared)]);
        assert_eq!(bytes_of(&diamond), br#"{"x":{"a":1},"y":{"a":1}}"#);
    }

    #[test]
    fn payload_hash_uses_sha256_prefix_of_sorted_bytes() {
        let payload = obj(vec![
            ("b", Value::int(2)),
            ("a", Value::int(1)),
            ("sub", obj(vec![("k", Value::string("v"))])),
        ]);
        let digest = codec().payload_content_hash(&payload).unwrap();
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), 7 + 64);
        assert_eq!(
            digest,
            "sha256:8e85dbb225e7132386d632db002333c3a8755be9ffa26994cca2e4487cca0916"
        );
        assert_eq!(bytes_of(&payload), br#"{"a":1,"b":2,"sub":{"k":"v"}}"#);
    }

    #[test]
    fn plan_fingerprint_ignores_input_fingerprint_and_binds_policy() {
        let with_fingerprint = obj(vec![
            ("session_id", Value::string("sess_123")),
            (
                "actions",
                Value::array(vec![obj(vec![
                    ("code", Value::string("DROP_DANGLING")),
                    ("id", Value::string("evt_99")),
                ])]),
            ),
            ("fingerprint", Value::string("will_be_ignored_fp")),
        ]);
        let without_fingerprint = obj(vec![
            (
                "actions",
                Value::array(vec![obj(vec![
                    ("id", Value::string("evt_99")),
                    ("code", Value::string("DROP_DANGLING")),
                ])]),
            ),
            ("session_id", Value::string("sess_123")),
        ]);
        let implementation = codec();
        let first = implementation
            .plan_fingerprint(&with_fingerprint, Some("conservative"))
            .unwrap();
        let second = implementation
            .plan_fingerprint(&without_fingerprint, Some("conservative"))
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert_eq!(
            first,
            "f32b9383f852e425c5051c022549f599db5bd9eb396e76f8294c70f24822a669"
        );
        let salvage = implementation
            .plan_fingerprint(&with_fingerprint, Some("salvage"))
            .unwrap();
        assert_ne!(first, salvage);

        let kept = obj(vec![
            ("policy", Value::string("keep")),
            ("session_id", Value::string("sess_123")),
            ("fingerprint", Value::float(f64::NAN)),
        ]);
        let plain = obj(vec![
            ("policy", Value::string("keep")),
            ("session_id", Value::string("sess_123")),
        ]);
        assert_eq!(
            implementation
                .plan_fingerprint(&kept, Some("other"))
                .unwrap(),
            implementation.plan_fingerprint(&plain, None).unwrap()
        );
    }

    #[test]
    fn plain_json_goldens_match_python_dumps() {
        assert_eq!(
            bytes_of(&obj(vec![
                ("a", Value::string("x")),
                ("n", Value::float(0.0)),
                ("z", Value::array(vec![Value::bool(true), Value::null()]),),
            ])),
            br#"{"a":"x","n":0.0,"z":[true,null]}"#
        );
        assert_eq!(
            bytes_of(&obj(vec![
                ("zero", Value::float(0.0)),
                ("exp_pos", Value::float(1e20)),
                ("exp_neg", Value::float(1e-20)),
                ("val", Value::float("3.14159".parse().unwrap())),
            ])),
            br#"{"exp_neg":1e-20,"exp_pos":1e+20,"val":3.14159,"zero":0.0}"#
        );
        assert_eq!(
            bytes_of(&obj(vec![
                ("empty_dict", Value::object(vec![])),
                ("empty_list", Value::array(vec![])),
                ("empty_str", Value::string("")),
                ("none_val", Value::null()),
            ])),
            br#"{"empty_dict":{},"empty_list":[],"empty_str":"","none_val":null}"#
        );
        assert_eq!(bytes_of(&Value::float(-0.0)), b"-0.0");
        assert_eq!(bytes_of(&Value::int(-1)), b"-1");
        assert_eq!(
            bytes_of(&Value::int_u64(1u64 << 63)),
            b"9223372036854775808"
        );
        assert_eq!(bytes_of(&Value::float(1e15)), b"1000000000000000.0");
        assert_eq!(bytes_of(&Value::float(1e16)), b"1e+16");
        assert_eq!(bytes_of(&Value::float(1e-5)), b"1e-05");
        assert_eq!(bytes_of(&Value::float(f64::from_bits(1))), b"5e-324");
    }

    #[test]
    fn halfway_float_ties_use_the_even_python_digit() {
        let cases = [
            (0xc30f_a36f_d398_d412, "-1113178120592002.2"),
            (0xc31e_96ec_8f3e_5029, "-2152548015248394.2"),
            (0xc2ea_9725_7f23_20b4, "-233891771783429.62"),
            (0xc302_1f6c_f47f_7ae2, "-637637799964508.2"),
            (0xc318_ab06_9c92_298d, "-1735861081508451.2"),
            (0x42d9_636d_0366_5f08, "111659285584252.12"),
            (0xc318_6545_5e26_41f1, "-1716687011942524.2"),
        ];
        for (bits, expected) in cases {
            assert_eq!(
                bytes_of(&Value::float(f64::from_bits(bits))),
                expected.as_bytes(),
                "{bits:016x}"
            );
        }
    }

    #[test]
    fn newline_appends_one_lf_and_provenance_keys_stay() {
        let value = obj(vec![
            ("source_line", Value::int(1)),
            ("id", Value::string("a")),
            ("source_record_hash", Value::string("abc")),
            ("source_location", Value::string("/synthetic")),
        ]);
        assert_eq!(
            codec().canonical_json_bytes(&value, true).unwrap(),
            b"{\"id\":\"a\",\"source_line\":1,\"source_location\":\"/synthetic\",\"source_record_hash\":\"abc\"}\n"
        );
        assert!(is_provenance_field("source_line"));
        assert!(!is_provenance_field("id"));
    }

    #[test]
    fn content_identity_fails_closed_without_session_event() {
        let implementation = codec();
        let bytes_error = implementation.content_identity_bytes().unwrap_err();
        let hash_error = implementation.content_identity_hash().unwrap_err();
        assert_eq!(
            bytes_error,
            CanonicalError::Unsupported(SESSION_EVENT_UNAVAILABLE)
        );
        assert_eq!(bytes_error, hash_error);
        assert_eq!(
            bytes_error.message(),
            "sesslint.canonical.SessionEvent is not available"
        );
    }

    #[test]
    fn foreign_type_uses_python_type_error_text() {
        assert_eq!(
            err_message(&Value::foreign("bytes")),
            "Canonical serialization error: Object of type bytes is not JSON serializable"
        );
    }

    #[test]
    fn dataclass_omits_empty_metadata_and_hoists_experimental_fields() {
        let value = Value::dataclass(vec![
            Field::new("actor", Value::string("user")),
            Field::new("parent_id", Value::null()),
            Field::new("note", Value::null()),
            Field::new("metadata", Value::object(vec![])),
            Field::new(
                "extra_fields",
                Value::object(vec![
                    (key("alpha_tag"), Value::float(f64::NAN)),
                    (key("experimental_mode"), Value::bool(true)),
                    (key("experimental_mode"), Value::float(f64::NAN)),
                ]),
            ),
        ]);
        assert_eq!(
            bytes_of(&value),
            br#"{"actor":"user","experimental_mode":true,"parent_id":null}"#
        );
    }

    #[test]
    fn dataclass_extra_field_rejects_non_string_key_before_hoist() {
        let value = Value::dataclass(vec![Field::new(
            "extra_fields",
            Value::object(vec![(ObjectKey::non_string("(1,)"), Value::int(1))]),
        )]);
        assert_eq!(
            err_message(&value),
            "Non-string dictionary key rejected by SessLint codec: (1,)"
        );
    }

    #[test]
    fn nesting_budget_matches_cpython_311_top_level_calibration() {
        assert!(codec()
            .canonical_json_bytes(&nested_dicts(992), false)
            .is_ok());
        assert_eq!(
            err_message(&nested_dicts(993)),
            "Object nesting depth exceeded during canonical serialization"
        );
        assert!(codec()
            .canonical_json_bytes(&nested_lists(497), false)
            .is_ok());
        assert_eq!(
            err_message(&nested_lists(498)),
            "Object nesting depth exceeded during canonical serialization"
        );
    }

    fn nested_dicts(wraps: usize) -> Value {
        let mut value = obj(vec![("leaf", Value::int(1))]);
        for _ in 0..wraps {
            value = obj(vec![("k", value)]);
        }
        value
    }

    fn nested_lists(wraps: usize) -> Value {
        let mut value = Value::array(vec![Value::int(1)]);
        for _ in 0..wraps {
            value = Value::array(vec![value]);
        }
        value
    }

    fn lock_cell_tests() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    struct RestorePureCodec;

    impl Drop for RestorePureCodec {
        fn drop(&mut self) {
            let _ = set_active_codec(Arc::new(PurePythonCanonicalCodec::new()));
        }
    }

    fn key_names(value: &Value) -> Vec<String> {
        let Value::Object(cell) = value else {
            panic!("expected object");
        };
        cell.borrow()
            .iter()
            .map(|(key, _)| match key {
                ObjectKey::String(name) => name.clone(),
                ObjectKey::NonString(python_repr) => panic!("non-string key {python_repr}"),
            })
            .collect()
    }

    struct InstalledCodec {
        name: &'static str,
        json: &'static [u8],
    }

    impl CanonicalCodec for InstalledCodec {
        fn codec_name(&self) -> &str {
            self.name
        }

        fn codec_version(&self) -> &str {
            CODEC_INTERFACE_VERSION
        }

        fn canonical_json_bytes(
            &self,
            _obj: &Value,
            _newline: bool,
        ) -> Result<Vec<u8>, CanonicalError> {
            Ok(self.json.to_vec())
        }

        fn content_identity_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
            Err(CanonicalError::Unsupported(SESSION_EVENT_UNAVAILABLE))
        }

        fn content_identity_hash(&self) -> Result<String, CanonicalError> {
            Err(CanonicalError::Unsupported(SESSION_EVENT_UNAVAILABLE))
        }

        fn payload_content_hash(&self, _payload: &Value) -> Result<String, CanonicalError> {
            Ok("sha256:installed".to_string())
        }

        fn plan_fingerprint(
            &self,
            _plan_data: &Value,
            _policy: Option<&str>,
        ) -> Result<String, CanonicalError> {
            Ok("installed-plan".to_string())
        }
    }

    #[test]
    fn disable_accel_and_missing_accel_return_the_pure_codec() {
        assert!(accel_disabled(Some("1")));
        assert!(accel_disabled(Some("true")));
        assert!(accel_disabled(Some("yes")));
        assert!(accel_disabled(Some("  yes  ")));
        assert!(accel_disabled(Some("\t1\n")));
        assert!(!accel_disabled(None));
        assert!(!accel_disabled(Some("")));
        assert!(!accel_disabled(Some("   ")));
        assert!(!accel_disabled(Some("TRUE")));
        assert!(!accel_disabled(Some("Yes")));
        assert!(!accel_disabled(Some("0")));
        assert!(!accel_disabled(Some("no")));

        for raw in [
            Some("1"),
            Some(" true "),
            Some("yes"),
            None,
            Some(""),
            Some("TRUE"),
            Some("no"),
        ] {
            let codec = resolve_from_disable_flag(raw);
            assert_eq!(codec.codec_name(), PurePythonCanonicalCodec::CODEC_NAME);
            assert_eq!(codec.codec_version(), CODEC_INTERFACE_VERSION);
        }

        let live = resolve_active_codec();
        assert_eq!(live.codec_name(), "pure_python");
        assert_eq!(live.codec_version(), "1.0.0");
    }

    #[test]
    fn set_then_get_round_trips_and_skips_reresolve() {
        let _lock = lock_cell_tests();
        let _restore = RestorePureCodec;
        clear_active_codec().unwrap();
        let resolved = get_active_codec().unwrap();
        assert_eq!(resolved.codec_name(), "pure_python");
        assert!(Arc::ptr_eq(&resolved, &get_active_codec().unwrap()));
        let installed: SharedCodec = Arc::new(InstalledCodec {
            name: "installed",
            json: b"installed",
        });
        set_active_codec(Arc::clone(&installed)).unwrap();
        let got = get_active_codec().unwrap();
        assert!(Arc::ptr_eq(&installed, &got));
        assert_eq!(got.codec_name(), "installed");
        assert_eq!(got.codec_version(), CODEC_INTERFACE_VERSION);
        assert_eq!(
            canonical_json_bytes(&Value::int(1), false).unwrap(),
            b"installed"
        );
        assert_eq!(
            payload_content_hash(&Value::object(vec![])).unwrap(),
            "sha256:installed"
        );
        assert_eq!(
            plan_fingerprint(&Value::object(vec![]), Some("conservative")).unwrap(),
            "installed-plan"
        );
        assert_eq!(resolve_active_codec().codec_name(), "pure_python");
        assert!(Arc::ptr_eq(&installed, &get_active_codec().unwrap()));
    }

    #[test]
    fn free_canonical_json_bytes_matches_pure_golden_a1() {
        let _lock = lock_cell_tests();
        let _restore = RestorePureCodec;
        set_active_codec(Arc::new(PurePythonCanonicalCodec::new())).unwrap();
        let value = obj(vec![("a", Value::int(1))]);
        let free = canonical_json_bytes(&value, false).unwrap();
        let pure = PurePythonCanonicalCodec::new()
            .canonical_json_bytes(&value, false)
            .unwrap();
        assert_eq!(free, pure);
        assert_eq!(free, br#"{"a":1}"#);
    }

    #[test]
    fn normalize_canonical_sorts_keys_on_the_default_codec() {
        let _lock = lock_cell_tests();
        let _restore = RestorePureCodec;
        set_active_codec(Arc::new(InstalledCodec {
            name: "installed",
            json: b"installed",
        }))
        .unwrap();
        assert_eq!(
            canonical_json_bytes(&Value::int(1), false).unwrap(),
            b"installed"
        );

        let value = obj(vec![
            ("b", obj(vec![("z", Value::int(1)), ("m", Value::int(2))])),
            ("a", Value::int(0)),
        ]);
        let normalized = normalize_canonical(&value).unwrap();
        assert_eq!(key_names(&normalized), ["a", "b"]);
        let nested = match &normalized {
            Value::Object(cell) => cell.borrow()[1].1.clone(),
            other => panic!("expected object, got {other:?}"),
        };
        assert_eq!(key_names(&nested), ["m", "z"]);

        let dataclass = Value::dataclass(vec![
            Field::new("note", Value::null()),
            Field::new("actor", Value::string("user")),
            Field::new(
                "extra_fields",
                Value::object(vec![(key("experimental_mode"), Value::bool(true))]),
            ),
        ]);
        assert_eq!(
            key_names(&normalize_canonical(&dataclass).unwrap()),
            ["actor", "experimental_mode"]
        );

        let bad = Value::object(vec![(ObjectKey::non_string("3"), Value::int(1))]);
        assert_eq!(
            normalize_canonical(&bad).unwrap_err().message(),
            "Non-string dictionary key rejected by SessLint codec: 3"
        );
    }

    #[test]
    fn free_content_identity_bytes_returns_unsupported() {
        let _lock = lock_cell_tests();
        let _restore = RestorePureCodec;
        set_active_codec(Arc::new(PurePythonCanonicalCodec::new())).unwrap();
        let error = content_identity_bytes().unwrap_err();
        assert_eq!(
            error,
            CanonicalError::Unsupported(SESSION_EVENT_UNAVAILABLE)
        );
        assert_eq!(
            error.message(),
            "sesslint.canonical.SessionEvent is not available"
        );
        assert_eq!(error, content_identity_hash().unwrap_err());
    }

    #[test]
    fn all_exports_match_python_dunder_all_in_order() {
        assert_eq!(
            ALL,
            [
                "CODEC_INTERFACE_VERSION",
                "CanonicalCodec",
                "PurePythonCanonicalCodec",
                "canonical_json_bytes",
                "content_identity_bytes",
                "content_identity_hash",
                "get_active_codec",
                "normalize_canonical",
                "payload_content_hash",
                "plan_fingerprint",
                "set_active_codec",
            ]
        );
        assert_eq!(ALL.len(), 11);
    }
}
