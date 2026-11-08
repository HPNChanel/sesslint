//! Repair execution prelude: live-store detection, index relocation, plan load.
//!
//! Port of `src/sesslint/repair/executor.py` lines 1–301
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`execute`] ports lines 386–476 and stops on `compute_plan_fingerprint`
//! at line 477.
//!
//! Python's module-level imports are not run. This module does not register
//! recipes, hash bytes, or publish a session file. [`RepairPlan::from_dict`]
//! parses a mapping. JSON text is read by a hand parser into [`PlanValue`]
//! because this crate does not link `serde_json`. `NaN`, `Infinity`, and
//! `-Infinity` are accepted, matching `json.loads`.
//!
//! [`SourceRef::line`](model::finding::SourceRef::line) is `Option<i64>`.
//! A bool line cannot be stored. The `>= 1` filter applies to that int.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use model::finding::Finding;

use crate::errors::{OutputInvalid, PolicyMismatch};
use crate::planner::{
    PlanKey, PlanParseError, PlanStep, PlanStepFields, PlanValue, PlannerError, RepairPlan,
};
use crate::registry::get_recipe;

/// Python: `SQLITE_MAGIC`. Sixteen bytes, including the trailing NUL.
pub const SQLITE_MAGIC: [u8; 16] = *b"SQLite format 3\x00";

/// Python: `_ORIGIN_KEY`. Leading NUL, then `sesslint.origin`.
pub const _ORIGIN_KEY: &str = "\u{0}sesslint.origin";

/// Python: `_STEP_INDEX_PARAMS`, in that order.
pub const _STEP_INDEX_PARAMS: [&str; 8] = [
    "at_index",
    "boundary_index",
    "cut_index",
    "entry_index",
    "first_index",
    "first_unsafe_index",
    "index",
    "use_index",
];

/// Python: `_STEP_INDEX_LIST_PARAMS`, in that order.
pub const _STEP_INDEX_LIST_PARAMS: [&str; 2] = ["record_indexes", "result_indexes"];

/// Python: `_ATOMIC_TEST_HOOKS`. Each value starts as `None`.
///
/// This slice does not publish, so the hooks are not called.
pub const _ATOMIC_TEST_HOOKS: [(&str, Option<()>); 5] = [
    ("pre_write", None),
    ("pre_rename", None),
    ("post_apply", None),
    ("mid_publish", None),
    ("post_publish", None),
];

/// Nested containers above this depth fail closed.
///
/// The parser is recursive. The bound keeps a hostile document off the
/// thread stack. A real plan is much shallower.
const MAX_JSON_DEPTH: usize = 128;

const NAN_BITS: u64 = 0x7ff8_0000_0000_0000;
const INFINITY_BITS: u64 = 0x7ff0_0000_0000_0000;
const NEG_INFINITY_BITS: u64 = 0xfff0_0000_0000_0000;

/// Python `str` or `os.PathLike`, a `Mapping`, or any other object.
///
/// [`LoadPlanInput::Other`] carries `type(source).__name__`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadPlanInput<'a> {
    /// Path. A string is a path in Python, not a JSON document.
    Path(&'a Path),
    /// Mapping. A non-map [`PlanValue`] is `TypeError`.
    Mapping(&'a PlanValue),
    /// Neither a path nor a mapping.
    Other {
        /// Python `type(source).__name__`.
        type_name: &'static str,
    },
}

/// Failure from [`load_plan`].
///
/// [`Display`](fmt::Display) is the Python exception message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadPlanError {
    /// `FileNotFoundError` before the file is parsed.
    FileNotFound(String),
    /// Read failed after `is_file` was true.
    Io(String),
    /// `UnicodeDecodeError`.
    UnicodeDecode(String),
    /// `json.JSONDecodeError`, or a number/string this crate cannot store.
    Json(String),
    /// `ValueError` for a non-object JSON root.
    Value(String),
    /// `TypeError`.
    Type(String),
    /// [`RepairPlan::from_dict`] failed. The error is unchanged.
    Plan(PlanParseError),
    /// [`PolicyMismatch`]. Display is the pin sentence, not `POLICY_MISMATCH`.
    Policy(PolicyMismatch),
}

impl fmt::Display for LoadPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileNotFound(message)
            | Self::Io(message)
            | Self::UnicodeDecode(message)
            | Self::Json(message)
            | Self::Value(message)
            | Self::Type(message) => formatter.write_str(message),
            Self::Plan(error) => error.fmt(formatter),
            Self::Policy(error) => error.fmt(formatter),
        }
    }
}

impl Error for LoadPlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Plan(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::FileNotFound(_)
            | Self::Io(_)
            | Self::UnicodeDecode(_)
            | Self::Json(_)
            | Self::Value(_)
            | Self::Type(_) => None,
        }
    }
}

/// Failure from [`_source_positions`].
///
/// A repeated origin is the existing [`OutputInvalid`]. Display of that
/// variant is the pin sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourcePositionError {
    /// Python `OutputInvalid`.
    Duplicate(OutputInvalid),
    /// The event is not a mapping, so its origin cannot be read.
    NotMapping(String),
    /// The enumerate index does not fit in `i128`.
    Index(String),
}

impl fmt::Display for SourcePositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(error) => error.fmt(formatter),
            Self::NotMapping(message) | Self::Index(message) => formatter.write_str(message),
        }
    }
}

impl Error for SourcePositionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Duplicate(error) => Some(error),
            Self::NotMapping(_) | Self::Index(_) => None,
        }
    }
}

/// Failure from [`_relocate_step`].
///
/// A removed source event is [`OutputInvalid`]. Rebuilding the step uses
/// [`PlanStep::try_new`], whose [`PlannerError`] is returned unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelocateError {
    /// Python `OutputInvalid`.
    OutputInvalid(OutputInvalid),
    /// [`PlanStep::try_new`] rejected the rebuilt step.
    Plan(PlannerError),
}

impl fmt::Display for RelocateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputInvalid(error) => error.fmt(formatter),
            Self::Plan(error) => error.fmt(formatter),
        }
    }
}

impl Error for RelocateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OutputInvalid(error) => Some(error),
            Self::Plan(error) => Some(error),
        }
    }
}

struct PythonPath {
    anchor: String,
    rooted: bool,
    parts: Vec<String>,
}

impl PythonPath {
    fn file_name(&self) -> &str {
        match self.parts.last() {
            Some(part) => part.as_str(),
            None => "",
        }
    }

    /// `str(pathlib.Path(path))` for the current OS.
    fn native(&self) -> String {
        let sep = std::path::MAIN_SEPARATOR;
        if self.parts.is_empty() {
            if self.anchor.is_empty() {
                return ".".to_owned();
            }
            return self.anchor.clone();
        }
        if self.rooted {
            let mut out = self.anchor.clone();
            out.push_str(&join_sep(&self.parts, sep));
            return out;
        }
        if self.anchor.is_empty() {
            return join_sep(&self.parts, sep);
        }
        let mut out = self.anchor.clone();
        let Some(first) = self.parts.first() else {
            return out;
        };
        out.push_str(first);
        if let Some(rest) = self.parts.get(1..) {
            if !rest.is_empty() {
                out.push(sep);
                out.push_str(&join_sep(rest, sep));
            }
        }
        out
    }
}

fn python_path(path: &Path) -> PythonPath {
    let mut anchor = String::new();
    let mut rooted = false;
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => {
                let text = prefix.as_os_str().to_string_lossy();
                // Python rewrites `/` to the native separator inside a UNC prefix.
                #[cfg(windows)]
                anchor.push_str(&text.replace('/', "\\"));
                #[cfg(not(windows))]
                anchor.push_str(&text);
            }
            Component::RootDir => {
                rooted = true;
                anchor.push(std::path::MAIN_SEPARATOR);
            }
            Component::CurDir => {}
            Component::ParentDir => parts.push("..".to_owned()),
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
        }
    }
    PythonPath {
        anchor,
        rooted,
        parts,
    }
}

fn join_sep(parts: &[String], sep: char) -> String {
    let mut out = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push(sep);
        }
        out.push_str(part);
    }
    out
}

/// Python `PurePath.suffix`: the last dot-suffix of the final component.
///
/// A leading-dot name such as `.db` has an empty suffix. A trailing dot has
/// an empty suffix.
fn python_suffix(name: &str) -> &str {
    let Some(index) = name.rfind('.') else {
        return "";
    };
    if index == 0 {
        return "";
    }
    let Some(rest) = name.get(index.saturating_add(1)..) else {
        return "";
    };
    if rest.is_empty() {
        return "";
    }
    name.get(index..).unwrap_or("")
}

fn has_sqlite_suffix(path: &Path) -> bool {
    let parsed = python_path(path);
    let suffix = python_suffix(parsed.file_name());
    suffix.eq_ignore_ascii_case(".db")
        || suffix.eq_ignore_ascii_case(".sqlite")
        || suffix.eq_ignore_ascii_case(".sqlite3")
}

/// Python: `_sync_dir`.
///
/// On Windows this returns immediately and does not open `path`. Elsewhere
/// it opens read-only, fsyncs, and closes. `OSError` and `PermissionError`
/// are ignored, including a close error.
pub fn _sync_dir(path: &Path) {
    #[cfg(windows)]
    {
        let _ = path;
    }
    #[cfg(not(windows))]
    {
        sync_dir_unix(path);
    }
}

#[cfg(not(windows))]
fn sync_dir_unix(path: &Path) {
    let Ok(file) = File::open(path) else {
        return;
    };
    let _ = file.sync_all();
}

/// Python: `is_live_store_path`.
///
/// A suffix of `.db`, `.sqlite`, or `.sqlite3`, compared after ASCII
/// lowercasing, returns true before any read. Otherwise a path is a live
/// store only when it exists, is a regular file, and its first 16 bytes
/// start with [`SQLITE_MAGIC`]. A directory is not opened. `OSError` while
/// reading returns false.
pub fn is_live_store_path(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    if has_sqlite_suffix(path) {
        return true;
    }
    if !(path.exists() && path.is_file()) {
        return false;
    }
    match read_prefix(path, SQLITE_MAGIC.len()) {
        Ok(head) => head.starts_with(&SQLITE_MAGIC),
        Err(_) => false,
    }
}

fn read_prefix(path: &Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buf = vec![0_u8; limit];
    let mut filled = 0_usize;
    while filled < limit {
        let Some(rest) = buf.get_mut(filled..) else {
            break;
        };
        match file.read(rest) {
            Ok(0) => break,
            Ok(count) => filled = filled.saturating_add(count),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Python: `_source_positions`.
///
/// Enumerate the current index. The origin is read with [`_ORIGIN_KEY`].
/// Only a real int counts. [`PlanValue::Bool`] is not an int. A repeated
/// origin is [`OutputInvalid`] with Display
/// `Repair duplicated source event {origin}`.
///
/// The map is a [`BTreeMap`]. Lookup is by origin. Iteration follows the
/// origin key, not Python dict insertion order.
///
/// # Errors
///
/// Returns [`SourcePositionError`]. A non-mapping event fails closed.
/// This function does not panic.
pub fn _source_positions(
    events: &[PlanValue],
) -> Result<BTreeMap<i128, i128>, SourcePositionError> {
    let mut positions = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        let Ok(current) = i128::try_from(index) else {
            return Err(SourcePositionError::Index(format!(
                "Repair source event index {index} does not fit in i128"
            )));
        };
        let PlanValue::Map(entries) = event else {
            let type_name = python_type_name(event);
            return Err(SourcePositionError::NotMapping(format!(
                "Repair source event {current} is not a mapping, got {type_name}"
            )));
        };
        let Some(PlanValue::Int(origin)) = lookup_last(entries, _ORIGIN_KEY) else {
            continue;
        };
        if positions.contains_key(origin) {
            return Err(SourcePositionError::Duplicate(OutputInvalid::new(format!(
                "Repair duplicated source event {origin}"
            ))));
        }
        positions.insert(*origin, current);
    }
    Ok(positions)
}

fn lookup_last<'a>(entries: &'a [(PlanKey, PlanValue)], key: &str) -> Option<&'a PlanValue> {
    let mut found = None;
    for (existing, value) in entries {
        if let PlanKey::Str(name) = existing {
            if name == key {
                found = Some(value);
            }
        }
    }
    found
}

/// Python: `_relocate_step`.
///
/// A bool is not an int. An int is relocated only when
/// `0 <= value < source_len` and that origin is still in `positions`.
/// Anything else passes through. A missing in-range origin is
/// [`OutputInvalid`] with the pin sentence. Scalar index params are walked
/// in [`_STEP_INDEX_PARAMS`] order, then list params in
/// [`_STEP_INDEX_LIST_PARAMS`] order, then `target_index`. A tuple list
/// becomes a list, matching Python's comprehension.
///
/// The step is rebuilt with [`PlanStep::try_new`].
///
/// # Errors
///
/// Returns [`RelocateError`]. This function does not panic.
pub fn _relocate_step(
    step: &PlanStep,
    positions: &BTreeMap<i128, i128>,
    source_len: i128,
) -> Result<PlanStep, RelocateError> {
    let mut params = step.params().to_vec();
    relocate_params(step, &mut params, positions, source_len)
        .map_err(RelocateError::OutputInvalid)?;
    let target_index = match step.target_index() {
        None => None,
        Some(index) => Some(
            relocate_index(step, index, positions, source_len)
                .map_err(RelocateError::OutputInvalid)?,
        ),
    };
    PlanStep::try_new(PlanStepFields {
        seq: step.seq(),
        recipe: step.recipe().to_owned(),
        target_finding_fp: step.target_finding_fp().to_owned(),
        target_index,
        params,
        lossy: step.lossy(),
        loss: step.loss().to_vec(),
        min_policy: step.min_policy().to_owned(),
        recipe_version: step.recipe_version().to_owned(),
    })
    .map_err(RelocateError::Plan)
}

fn relocate_params(
    step: &PlanStep,
    params: &mut [(String, PlanValue)],
    positions: &BTreeMap<i128, i128>,
    source_len: i128,
) -> Result<(), OutputInvalid> {
    for key in _STEP_INDEX_PARAMS {
        for (name, value) in params.iter_mut() {
            if name == key {
                let next = relocate_value(step, value, positions, source_len)?;
                *value = next;
            }
        }
    }
    for key in _STEP_INDEX_LIST_PARAMS {
        for (name, value) in params.iter_mut() {
            if name != key {
                continue;
            }
            let items = match value {
                PlanValue::List(items) | PlanValue::Tuple(items) => items.clone(),
                _ => continue,
            };
            let mut relocated = Vec::with_capacity(items.len());
            for item in &items {
                relocated.push(relocate_value(step, item, positions, source_len)?);
            }
            *value = PlanValue::list(relocated);
        }
    }
    Ok(())
}

fn relocate_value(
    step: &PlanStep,
    value: &PlanValue,
    positions: &BTreeMap<i128, i128>,
    source_len: i128,
) -> Result<PlanValue, OutputInvalid> {
    let PlanValue::Int(index) = value else {
        return Ok(value.clone());
    };
    Ok(PlanValue::Int(relocate_index(
        step, *index, positions, source_len,
    )?))
}

fn relocate_index(
    step: &PlanStep,
    index: i128,
    positions: &BTreeMap<i128, i128>,
    source_len: i128,
) -> Result<i128, OutputInvalid> {
    if !is_source_position(index, source_len) {
        return Ok(index);
    }
    match positions.get(&index) {
        Some(current) => Ok(*current),
        None => Err(removed_event(step, index)),
    }
}

fn is_source_position(value: i128, source_len: i128) -> bool {
    value >= 0 && value < source_len
}

fn removed_event(step: &PlanStep, value: i128) -> OutputInvalid {
    let seq = step.seq();
    let recipe = step.recipe();
    OutputInvalid::new(format!(
        "Step {seq} (recipe '{recipe}') targets source event {value}, which an earlier step removed"
    ))
}

/// Python: `_targeted_lines`.
///
/// A line is kept when the fingerprint is in `targeted_fps`, [`Finding::source`]
/// is read, and [`SourceRef::line`](model::finding::SourceRef::line) is a
/// real int `>= 1`. The result is a [`BTreeSet`], so iteration is sorted.
pub fn _targeted_lines(findings: &[Finding], targeted_fps: &BTreeSet<String>) -> BTreeSet<i64> {
    let mut lines = BTreeSet::new();
    for finding in findings {
        if !targeted_fps.contains(finding.fingerprint()) {
            continue;
        }
        let source = finding.source();
        let Some(line) = source.line() else {
            continue;
        };
        if line >= 1 {
            lines.insert(line);
        }
    }
    lines
}

/// Python: `_plan_requires_salvage`.
///
/// `policy == "salvage"` is true. `loss_accounting.total_lost > 0` is true.
/// A preview count `> 0` is true. [`Loss`](crate::planner::Loss) stores real
/// ints, so a Python `None` preview value cannot appear. A lossy step, a
/// step loss count `> 0`, or `min_policy == "salvage"` is true. Otherwise
/// [`get_recipe`] is called. `salvage_only`, `lossy`, or `min_policy`
/// `"salvage"` on that recipe is true.
pub fn _plan_requires_salvage(plan: &RepairPlan) -> bool {
    if plan.policy() == "salvage" {
        return true;
    }
    let loss = plan.loss_accounting();
    if loss.total_lost() > 0 || positive_count(loss.preview()) {
        return true;
    }
    for step in plan.steps() {
        if step.lossy() || positive_count(step.loss()) || step.min_policy() == "salvage" {
            return true;
        }
        if let Some(recipe) = get_recipe(step.recipe()) {
            if recipe.salvage_only() || recipe.lossy() || recipe.min_policy() == "salvage" {
                return true;
            }
        }
    }
    false
}

fn positive_count(counts: &[(String, i128)]) -> bool {
    counts.iter().any(|(_, value)| *value > 0)
}

/// Python: `load_plan`.
///
/// A path that is not a file raises `FileNotFoundError` with Display
/// `Plan file not found: {path}` before any parse. The path text matches
/// `str(pathlib.Path(...))`. UTF-8 text is parsed as JSON. The root must be
/// an object or the error is `Plan file root must be a JSON object, got
/// {python type name}`. A mapping is passed to [`RepairPlan::from_dict`].
/// Anything else is `Expected path or Mapping, got {python type name}`.
///
/// `policy == None` skips the policy check. `conservative` plus
/// [`_plan_requires_salvage`] raises [`PolicyMismatch`] with the salvage
/// sentence. A different `plan.policy` raises [`PolicyMismatch`] with the
/// mismatch sentence. Display is the message only.
///
/// # Errors
///
/// Returns [`LoadPlanError`]. This function does not panic and does not
/// write a session file.
pub fn load_plan(
    source: LoadPlanInput<'_>,
    policy: Option<&str>,
) -> Result<RepairPlan, LoadPlanError> {
    let raw = match source {
        LoadPlanInput::Path(path) => read_plan_file(path)?,
        LoadPlanInput::Mapping(value) => {
            if !matches!(value, PlanValue::Map(_)) {
                let type_name = python_type_name(value);
                return Err(LoadPlanError::Type(format!(
                    "Expected path or Mapping, got {type_name}"
                )));
            }
            value.clone()
        }
        LoadPlanInput::Other { type_name } => {
            return Err(LoadPlanError::Type(format!(
                "Expected path or Mapping, got {type_name}"
            )));
        }
    };
    let plan = RepairPlan::from_dict(&raw).map_err(LoadPlanError::Plan)?;
    enforce_policy(plan, policy)
}

fn read_plan_file(path: &Path) -> Result<PlanValue, LoadPlanError> {
    if !path.is_file() {
        let shown = python_path(path).native();
        return Err(LoadPlanError::FileNotFound(format!(
            "Plan file not found: {shown}"
        )));
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => return Err(LoadPlanError::Io(io_message(&err, path))),
    };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(err) => return Err(LoadPlanError::UnicodeDecode(utf8_message(err.as_bytes()))),
    };
    let parsed = match parse_plan_json(&text) {
        Ok(parsed) => parsed,
        Err(message) => return Err(LoadPlanError::Json(message)),
    };
    if !matches!(parsed, PlanValue::Map(_)) {
        let type_name = python_type_name(&parsed);
        return Err(LoadPlanError::Value(format!(
            "Plan file root must be a JSON object, got {type_name}"
        )));
    }
    Ok(parsed)
}

fn enforce_policy(plan: RepairPlan, policy: Option<&str>) -> Result<RepairPlan, LoadPlanError> {
    let Some(policy) = policy else {
        return Ok(plan);
    };
    if policy == "conservative" && _plan_requires_salvage(&plan) {
        return Err(LoadPlanError::Policy(PolicyMismatch::new(format!(
            "Plan requires 'salvage' policy due to salvage-class steps or declared loss, \
             but invocation requested '{policy}' policy"
        ))));
    }
    if plan.policy() != policy {
        let plan_policy = plan.policy();
        return Err(LoadPlanError::Policy(PolicyMismatch::new(format!(
            "Plan policy '{plan_policy}' does not match requested policy '{policy}'"
        ))));
    }
    Ok(plan)
}

fn io_message(err: &std::io::Error, path: &Path) -> String {
    let shown = python_path(path).native();
    match err.kind() {
        std::io::ErrorKind::NotFound => {
            format!("[Errno 2] No such file or directory: '{shown}'")
        }
        std::io::ErrorKind::PermissionDenied => {
            format!("[Errno 13] Permission denied: '{shown}'")
        }
        _ => format!("{err}: {shown}"),
    }
}

fn python_type_name(value: &PlanValue) -> &'static str {
    match value {
        PlanValue::None => "NoneType",
        PlanValue::Bool(_) => "bool",
        PlanValue::Int(_) => "int",
        PlanValue::Float(_) => "float",
        PlanValue::Str(_) => "str",
        PlanValue::Bytes(_) => "bytes",
        PlanValue::List(_) => "list",
        PlanValue::Tuple(_) => "tuple",
        PlanValue::Map(_) => "dict",
        PlanValue::Other { type_name } => type_name,
    }
}

fn parse_plan_json(source: &str) -> Result<PlanValue, String> {
    if source.starts_with('\u{feff}') {
        return Err(render_json_error(
            source,
            0,
            "Unexpected UTF-8 BOM (decode using utf-8-sig)",
        ));
    }
    let mut parser = Parser {
        source,
        index: 0,
        depth: 0,
    };
    let value = match parser.parse_value() {
        Ok(value) => value,
        Err(fault) => return Err(render_fault(source, &fault)),
    };
    parser.skip_ws();
    if parser.index < parser.source.len() {
        return Err(render_json_error(source, parser.index, "Extra data"));
    }
    Ok(value)
}

fn render_fault(source: &str, fault: &JsonFault) -> String {
    render_json_error(source, fault.byte_index, &fault.message)
}

fn render_json_error(source: &str, byte_index: usize, message: &str) -> String {
    let byte_index = byte_index.min(source.len());
    let head = if source.is_char_boundary(byte_index) {
        source.get(..byte_index).unwrap_or("")
    } else {
        ""
    };
    let pos = head.chars().count();
    let lineno = head
        .chars()
        .filter(|ch| *ch == '\n')
        .count()
        .saturating_add(1);
    let colno = match head.rfind('\n') {
        Some(nl) => head
            .get(nl.saturating_add(1)..)
            .unwrap_or("")
            .chars()
            .count()
            .saturating_add(1),
        None => pos.saturating_add(1),
    };
    format!("{message}: line {lineno} column {colno} (char {pos})")
}

struct JsonFault {
    byte_index: usize,
    message: String,
}

struct Parser<'a> {
    source: &'a str,
    index: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn parse_value(&mut self) -> Result<PlanValue, JsonFault> {
        self.skip_ws();
        match self.peek() {
            None => Err(self.fault(self.index, "Expecting value")),
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => Ok(PlanValue::str_value(self.parse_string()?)),
            Some('t') => self.parse_literal("true", PlanValue::bool_value(true)),
            Some('f') => self.parse_literal("false", PlanValue::bool_value(false)),
            Some('n') => self.parse_literal("null", PlanValue::none()),
            Some('N') => self.parse_literal("NaN", PlanValue::Float(NAN_BITS)),
            Some('I') => self.parse_literal("Infinity", PlanValue::Float(INFINITY_BITS)),
            Some('-' | '0'..='9') => self.parse_number(),
            Some(_) => Err(self.fault(self.index, "Expecting value")),
        }
    }

    fn parse_array(&mut self) -> Result<PlanValue, JsonFault> {
        self.bump();
        self.enter()?;
        self.skip_ws();
        if self.eat(']') {
            self.leave();
            return Ok(PlanValue::list(Vec::new()));
        }
        let mut items = Vec::new();
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            if self.eat(',') {
                continue;
            }
            if self.eat(']') {
                self.leave();
                return Ok(PlanValue::list(items));
            }
            return Err(self.fault(self.index, "Expecting ',' delimiter"));
        }
    }

    fn parse_object(&mut self) -> Result<PlanValue, JsonFault> {
        self.bump();
        self.enter()?;
        self.skip_ws();
        if self.eat('}') {
            self.leave();
            return Ok(PlanValue::map(Vec::new()));
        }
        let mut entries = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err(self.fault(
                    self.index,
                    "Expecting property name enclosed in double quotes",
                ));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if !self.eat(':') {
                return Err(self.fault(self.index, "Expecting ':' delimiter"));
            }
            let value = self.parse_value()?;
            insert_last(&mut entries, key, value);
            self.skip_ws();
            if self.eat(',') {
                continue;
            }
            if self.eat('}') {
                self.leave();
                return Ok(PlanValue::map(entries));
            }
            return Err(self.fault(self.index, "Expecting ',' delimiter"));
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonFault> {
        let begin = self.index;
        if !self.eat('"') {
            return Err(self.fault(self.index, "Expecting value"));
        }
        let mut out = String::new();
        loop {
            let Some(ch) = self.peek() else {
                return Err(self.fault(begin, "Unterminated string starting at"));
            };
            if ch == '"' {
                self.bump();
                return Ok(out);
            }
            if ch == '\\' {
                self.parse_escape(begin, &mut out)?;
                continue;
            }
            if u32::from(ch) < 0x20 {
                return Err(self.fault(self.index, "Invalid control character at"));
            }
            out.push(ch);
            self.bump();
        }
    }

    fn parse_escape(&mut self, begin: usize, out: &mut String) -> Result<(), JsonFault> {
        let slash = self.index;
        self.bump();
        let Some(ch) = self.peek() else {
            return Err(self.fault(begin, "Unterminated string starting at"));
        };
        if ch == 'u' {
            let u_pos = self.index;
            self.bump();
            return self.append_unicode(u_pos, out);
        }
        self.bump();
        let decoded = match ch {
            '"' | '\\' | '/' => Some(ch),
            'b' => Some('\u{0008}'),
            'f' => Some('\u{000c}'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            _ => None,
        };
        let Some(decoded) = decoded else {
            return Err(self.fault(slash, "Invalid \\escape"));
        };
        out.push(decoded);
        Ok(())
    }

    fn append_unicode(&mut self, u_pos: usize, out: &mut String) -> Result<(), JsonFault> {
        let Some(unit) = self.read_hex4() else {
            return Err(self.fault(u_pos, "Invalid \\uXXXX escape"));
        };
        if (0xD800..=0xDBFF).contains(&unit) {
            if self.starts_with("\\u") {
                let saved = self.index;
                self.index = self.index.saturating_add(2);
                if let Some(low) = self.read_hex4() {
                    if (0xDC00..=0xDFFF).contains(&low) {
                        let high = unit.saturating_sub(0xD800);
                        let low = low.saturating_sub(0xDC00);
                        let point = 0x1_0000_u32.saturating_add((high << 10) | low);
                        let Some(ch) = char::from_u32(point) else {
                            return Err(self.fault(u_pos, "JSON string contains a lone surrogate"));
                        };
                        out.push(ch);
                        return Ok(());
                    }
                }
                self.index = saved;
            }
            return Err(self.fault(u_pos, "JSON string contains a lone surrogate"));
        }
        if (0xDC00..=0xDFFF).contains(&unit) {
            return Err(self.fault(u_pos, "JSON string contains a lone surrogate"));
        }
        let Some(ch) = char::from_u32(unit) else {
            return Err(self.fault(u_pos, "JSON string contains a lone surrogate"));
        };
        out.push(ch);
        Ok(())
    }

    fn read_hex4(&mut self) -> Option<u32> {
        let saved = self.index;
        let mut code = 0_u32;
        for _ in 0..4 {
            let Some(ch) = self.peek() else {
                self.index = saved;
                return None;
            };
            let Some(digit) = ch.to_digit(16) else {
                self.index = saved;
                return None;
            };
            code = (code << 4) | digit;
            self.bump();
        }
        Some(code)
    }

    fn parse_number(&mut self) -> Result<PlanValue, JsonFault> {
        let start = self.index;
        if self.starts_with("-Infinity") {
            self.index = self.index.saturating_add("-Infinity".len());
            return Ok(PlanValue::Float(NEG_INFINITY_BITS));
        }
        if self.peek() == Some('-') {
            self.bump();
        }
        match self.peek() {
            Some('0') => self.bump(),
            Some('1'..='9') => {
                self.bump();
                self.consume_digits();
            }
            _ => return Err(self.fault(start, "Expecting value")),
        }
        let mut is_float = false;
        if self.peek() == Some('.') {
            let save = self.index;
            self.bump();
            if matches!(self.peek(), Some('0'..='9')) {
                self.consume_digits();
                is_float = true;
            } else {
                self.index = save;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            let save = self.index;
            self.bump();
            if matches!(self.peek(), Some('+' | '-')) {
                self.bump();
            }
            if matches!(self.peek(), Some('0'..='9')) {
                self.consume_digits();
                is_float = true;
            } else {
                self.index = save;
            }
        }
        let Some(token) = self.source.get(start..self.index) else {
            return Err(self.fault(start, "Expecting value"));
        };
        if is_float {
            return match token.parse::<f64>() {
                Ok(value) => Ok(PlanValue::float(value)),
                Err(_) => Err(self.fault(start, "JSON number is not representable as float")),
            };
        }
        match token.parse::<i128>() {
            Ok(value) => Ok(PlanValue::int(value)),
            Err(_) => Err(self.fault(start, "JSON integer does not fit in i128")),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: PlanValue) -> Result<PlanValue, JsonFault> {
        if self.starts_with(literal) {
            self.index = self.index.saturating_add(literal.len());
            return Ok(value);
        }
        Err(self.fault(self.index, "Expecting value"))
    }

    fn consume_digits(&mut self) {
        while matches!(self.peek(), Some('0'..='9')) {
            self.bump();
        }
    }

    fn enter(&mut self) -> Result<(), JsonFault> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_JSON_DEPTH {
            let message = format!("JSON nesting exceeds {MAX_JSON_DEPTH}");
            return Err(self.fault(self.index, &message));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.bump();
        }
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) {
        if let Some(ch) = self.peek() {
            self.index = self.index.saturating_add(ch.len_utf8());
        }
    }

    fn starts_with(&self, literal: &str) -> bool {
        self.rest().starts_with(literal)
    }

    fn rest(&self) -> &'a str {
        self.source.get(self.index..).unwrap_or("")
    }

    fn fault(&self, byte_index: usize, message: &str) -> JsonFault {
        JsonFault {
            byte_index,
            message: message.to_owned(),
        }
    }
}

fn insert_last(entries: &mut Vec<(PlanKey, PlanValue)>, key: String, value: PlanValue) {
    for (existing, slot) in entries.iter_mut() {
        if let PlanKey::Str(name) = existing {
            if name == &key {
                *slot = value;
                return;
            }
        }
    }
    entries.push((PlanKey::Str(key), value));
}

fn utf8_message(bytes: &[u8]) -> String {
    match utf8_fault(bytes) {
        Some((start, end, reason)) => format_utf8(bytes, start, end, reason),
        None => "invalid utf-8".to_owned(),
    }
}

fn format_utf8(bytes: &[u8], start: usize, end: usize, reason: &str) -> String {
    if end == start.saturating_add(1) {
        let byte = bytes.get(start).copied().unwrap_or(0);
        format!("'utf-8' codec can't decode byte 0x{byte:02x} in position {start}: {reason}")
    } else {
        let last = end.saturating_sub(1);
        format!("'utf-8' codec can't decode bytes in position {start}-{last}: {reason}")
    }
}

fn utf8_fault(bytes: &[u8]) -> Option<(usize, usize, &'static str)> {
    let mut index = 0_usize;
    while index < bytes.len() {
        let first = bytes.get(index).copied()?;
        if first < 0x80 {
            index = index.saturating_add(1);
            continue;
        }
        if !(0xC2..=0xF4).contains(&first) {
            return Some((index, index.saturating_add(1), "invalid start byte"));
        }
        let (need, low, high) = utf8_span(first);
        for step in 1..need {
            let Some(at) = index.checked_add(step) else {
                return Some((index, index, "unexpected end of data"));
            };
            if at >= bytes.len() {
                return Some((index, at, "unexpected end of data"));
            }
            let Some(byte) = bytes.get(at).copied() else {
                return Some((index, at, "unexpected end of data"));
            };
            let continuation = (byte & 0xC0) == 0x80;
            if step == 1 {
                if !continuation || !(low..=high).contains(&byte) {
                    return Some((index, index.saturating_add(1), "invalid continuation byte"));
                }
            } else if !continuation {
                return Some((index, at, "invalid continuation byte"));
            }
        }
        index = match index.checked_add(need) {
            Some(next) => next,
            None => return Some((index, index, "unexpected end of data")),
        };
    }
    None
}

fn utf8_span(first: u8) -> (usize, u8, u8) {
    if first <= 0xDF {
        (2, 0x80, 0xBF)
    } else if first <= 0xEF {
        let (low, high) = if first == 0xE0 {
            (0xA0, 0xBF)
        } else if first == 0xED {
            (0x80, 0x9F)
        } else {
            (0x80, 0xBF)
        };
        (3, low, high)
    } else {
        let (low, high) = if first == 0xF0 {
            (0x90, 0xBF)
        } else if first == 0xF4 {
            (0x80, 0x8F)
        } else {
            (0x80, 0xBF)
        };
        (4, low, high)
    }
}

use model::canonical::{SessionEvent, SessionHeader};

/// Failure from [`load_session_source_with_findings`], [`load_session_source`],
/// and [`load_source_for_format`].
///
/// [`Display`](fmt::Display) is the message only. A missing session file has
/// no errno prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadSessionError {
    /// `FileNotFoundError`: `Session file not found: {path}`.
    FileNotFound(String),
    /// `sesslint.adapters.load.snapshot_input` is not linked.
    SnapshotInput,
    /// `sesslint.adapters.load.is_vendor_format` is not linked.
    VendorFormat,
}

impl fmt::Display for LoadSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileNotFound(message) => formatter.write_str(message),
            Self::SnapshotInput => {
                formatter.write_str("sesslint.adapters.load.snapshot_input is not available")
            }
            Self::VendorFormat => {
                formatter.write_str("sesslint.adapters.load.is_vendor_format is not available")
            }
        }
    }
}

impl Error for LoadSessionError {}

/// Python: `load_session_source_with_findings`.
///
/// `Path(path)` is checked with `is_file` before any import. A missing path,
/// a directory, and a broken symlink display `Session file not found: {path}`
/// with no errno prefix. A symlink to a file is a file. The path text matches
/// `str(pathlib.Path(...))`.
///
/// The next statement is `from sesslint.adapters.load import snapshot_input`.
/// That crate is not a dependency, so this returns
/// `sesslint.adapters.load.snapshot_input is not available`. The file is not
/// read. `read_header`, `iter_events`, `json.loads`, and `load_canonical` are
/// not called. No header, events, or findings are invented.
///
/// `data` is accepted and not inspected.
///
/// # Errors
///
/// Returns [`LoadSessionError`]. This function does not panic.
pub fn load_session_source_with_findings(
    path: impl AsRef<Path>,
    _data: Option<&[u8]>,
) -> Result<(SessionHeader, Vec<SessionEvent>, Vec<Finding>), LoadSessionError> {
    let path = path.as_ref();
    if !path.is_file() {
        let shown = python_path(path).native();
        return Err(LoadSessionError::FileNotFound(format!(
            "Session file not found: {shown}"
        )));
    }
    Err(LoadSessionError::SnapshotInput)
}

/// Python: `load_session_source`.
///
/// Calls [`load_session_source_with_findings`] and, only if that succeeds,
/// drops the findings. This slice has no success path.
///
/// # Errors
///
/// Returns [`LoadSessionError`] from the inner call. This function does not
/// panic.
pub fn load_session_source(
    path: impl AsRef<Path>,
) -> Result<(SessionHeader, Vec<SessionEvent>), LoadSessionError> {
    let (header, events, _findings) = load_session_source_with_findings(path, None)?;
    Ok((header, events))
}

/// Python `tuple[SessionHeader | None, list[SessionEvent], list[Finding]]`.
///
/// [`load_source_for_format`] does not return this value in this slice.
pub type LoadedSourceForFormat = (Option<SessionHeader>, Vec<SessionEvent>, Vec<Finding>);

/// Python: `load_source_for_format(path, format, data=None)`.
///
/// The first statement is
/// `from sesslint.adapters.load import is_vendor_format, load_vendor_events, snapshot_input`.
/// This returns `sesslint.adapters.load.is_vendor_format is not available`
/// immediately. `path` is not statted. `format` and `data` are not inspected.
/// [`load_session_source_with_findings`] is not called.
///
/// # Errors
///
/// Returns [`LoadSessionError`]. This function does not panic.
pub fn load_source_for_format(
    _path: impl AsRef<Path>,
    _format: Option<&str>,
    _data: Option<&[u8]>,
) -> Result<LoadedSourceForFormat, LoadSessionError> {
    Err(LoadSessionError::VendorFormat)
}

/// Failure from [`execute`].
///
/// The step-cap variant is the existing [`OutputInvalid`]. Its Display is the
/// pin sentence. [`ExecuteError::FingerprintUnavailable`] displays
/// `sesslint.repair.fingerprint.compute_plan_fingerprint is not available`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecuteError {
    /// Python `OutputInvalid` when the step count is above the cap.
    OutputInvalid(OutputInvalid),
    /// `plan.to_dict()` cannot be passed to `compute_plan_fingerprint`.
    FingerprintUnavailable,
}

impl fmt::Display for ExecuteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputInvalid(error) => error.fmt(formatter),
            Self::FingerprintUnavailable => formatter
                .write_str("sesslint.repair.fingerprint.compute_plan_fingerprint is not available"),
        }
    }
}

impl Error for ExecuteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OutputInvalid(error) => Some(error),
            Self::FingerprintUnavailable => None,
        }
    }
}

/// Python: `execute`.
///
/// The plan parameter is `&RepairPlan`.
///
/// The step count is `plan.steps().len() as i64`. When it is greater than
/// [`crate::planner::MAX_STEPS`], this returns [`OutputInvalid::new`] with
/// Display `Plan step count ({n}) exceeds maximum allowed cap (256)`. The
/// cap check opens no file.
///
/// The next pin statements are [`RepairPlan::to_dict`] and
/// `compute_plan_fingerprint(plan_dict)` with `policy` omitted. `to_dict`
/// returns `Vec<(String, PlanValue)>`.
/// [`crate::fingerprint::compute_plan_fingerprint`] takes
/// `&codec::canonical_codec::Value`. The two types stay distinct. Display is
/// `sesslint.repair.fingerprint.compute_plan_fingerprint is not available`.
///
/// # Errors
///
/// Returns [`ExecuteError`]. Success is [`Infallible`]. This function does
/// not panic.
pub fn execute(plan: &RepairPlan) -> Result<Infallible, ExecuteError> {
    let step_count = plan.steps().len() as i64;
    if step_count > crate::planner::MAX_STEPS {
        return Err(ExecuteError::OutputInvalid(OutputInvalid::new(format!(
            "Plan step count ({step_count}) exceeds maximum allowed cap ({})",
            crate::planner::MAX_STEPS
        ))));
    }
    let _plan_dict: Vec<(String, PlanValue)> = plan.to_dict();
    Err(ExecuteError::FingerprintUnavailable)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use model::codes::{Repairability, Severity};
    use model::finding::{Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION};

    use crate::errors::{OutputInvalid, PolicyMismatch};
    use crate::planner::{
        Loss, PlanKey, PlanStep, PlanStepFields, PlanValue, RepairPlan, RepairPlanFields,
        PLAN_VERSION,
    };
    use crate::registry::get_recipe;

    use super::{
        has_sqlite_suffix, is_live_store_path, load_plan, parse_plan_json, python_path,
        utf8_message, LoadPlanError, LoadPlanInput, RelocateError, SourcePositionError,
        _plan_requires_salvage, _relocate_step, _source_positions, _sync_dir, _targeted_lines,
        SQLITE_MAGIC, _ATOMIC_TEST_HOOKS, _ORIGIN_KEY, _STEP_INDEX_LIST_PARAMS, _STEP_INDEX_PARAMS,
    };

    fn native(path: &str) -> String {
        python_path(Path::new(path)).native()
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("sesslint-executor-rx-p43");
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join(name)
    }

    fn event_origin(origin: PlanValue) -> PlanValue {
        PlanValue::map(vec![(PlanKey::str_key(_ORIGIN_KEY), origin)])
    }

    fn bare_plan(policy: &str, steps: Vec<PlanStep>, loss: Loss) -> RepairPlan {
        RepairPlan::new(RepairPlanFields {
            source_hash: String::new(),
            profile: "neutral".to_owned(),
            steps,
            blocked: Vec::new(),
            loss_accounting: loss,
            fingerprint: "abc".to_owned(),
            version: PLAN_VERSION.to_owned(),
            policy: policy.to_owned(),
        })
    }

    fn step_fields(target: Option<i128>, params: Vec<(String, PlanValue)>) -> PlanStep {
        let mut fields = PlanStepFields::new(7, "drop-record", "fp-keep", target);
        fields.params = params;
        fields.min_policy = "salvage".to_owned();
        fields.recipe_version = "9.9.9".to_owned();
        fields.lossy = true;
        fields.loss = vec![("none".to_owned(), 2)];
        PlanStep::try_new(fields).expect("step")
    }

    fn finding_at(fingerprint: &str, line: Option<i64>) -> Finding {
        let source = SourceRef::try_new("a.json", line.map(SourceLine::Int), None).expect("source");
        Finding::try_new(FindingInput {
            code: PyValue::string("SL001"),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("line marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string(fingerprint),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence: PyValue::None,
        })
        .expect("finding")
    }

    fn plan_value(policy: &str, steps: Vec<PlanValue>) -> PlanValue {
        PlanValue::string_map(vec![
            ("fingerprint".to_owned(), PlanValue::str_value("abc")),
            ("policy".to_owned(), PlanValue::str_value(policy)),
            ("steps".to_owned(), PlanValue::list(steps)),
        ])
    }

    fn step_value(min_policy: &str, lossy: bool) -> PlanValue {
        let mut entries = vec![
            ("seq".to_owned(), PlanValue::int(1)),
            (
                "recipe".to_owned(),
                PlanValue::str_value("executor-card-absent-recipe"),
            ),
            ("min_policy".to_owned(), PlanValue::str_value(min_policy)),
            ("recipe_version".to_owned(), PlanValue::str_value("1.0.0")),
        ];
        if lossy {
            entries.push(("lossy".to_owned(), PlanValue::bool_value(true)));
        }
        PlanValue::string_map(entries)
    }

    fn load_mapping(value: &PlanValue, policy: Option<&str>) -> Result<RepairPlan, LoadPlanError> {
        load_plan(LoadPlanInput::Mapping(value), policy)
    }

    #[test]
    fn constants_match_the_pin() {
        assert_eq!(SQLITE_MAGIC.len(), 16);
        assert_eq!(&SQLITE_MAGIC, b"SQLite format 3\x00");
        assert_eq!(_ORIGIN_KEY.as_bytes()[0], 0);
        assert_eq!(&_ORIGIN_KEY.as_bytes()[1..], b"sesslint.origin");
        assert_eq!(
            _STEP_INDEX_PARAMS,
            [
                "at_index",
                "boundary_index",
                "cut_index",
                "entry_index",
                "first_index",
                "first_unsafe_index",
                "index",
                "use_index",
            ]
        );
        assert_eq!(
            _STEP_INDEX_LIST_PARAMS,
            ["record_indexes", "result_indexes"]
        );
        assert!(_ATOMIC_TEST_HOOKS.iter().all(|(_, hook)| hook.is_none()));
        assert_eq!(
            _ATOMIC_TEST_HOOKS.map(|(name, _)| name),
            [
                "pre_write",
                "pre_rename",
                "post_apply",
                "mid_publish",
                "post_publish",
            ]
        );
    }

    #[test]
    fn python_path_text_matches_pathlib() {
        assert_eq!(native("."), ".");
        assert_eq!(native(""), ".");
        assert_eq!(native("./plan.json"), "plan.json");
        assert_eq!(native("plan.json"), "plan.json");
        let slash = if cfg!(windows) { "\\" } else { "/" };
        assert_eq!(native("foo/./bar"), format!("foo{slash}bar"));
        assert_eq!(native("foo//bar"), format!("foo{slash}bar"));
        assert_eq!(native("foo/bar/"), format!("foo{slash}bar"));
        assert_eq!(native("foo/../bar"), format!("foo{slash}..{slash}bar"));
        assert_eq!(python_suffix_name(".db"), "");
        assert_eq!(python_suffix_name("a."), "");
        assert_eq!(python_suffix_name("a.DB"), ".DB");
        assert_eq!(python_suffix_name(".hidden.db"), ".db");
        assert_eq!(python_suffix_name("a.db "), ".db ");
        assert!(has_sqlite_suffix(Path::new("foo.db/")));
        assert!(has_sqlite_suffix(Path::new("FILE.SQLITE")));
        assert!(has_sqlite_suffix(Path::new("x.sqlite3")));
        assert!(!has_sqlite_suffix(Path::new(".db")));
        assert!(!has_sqlite_suffix(Path::new("a.db.bak")));
        #[cfg(windows)]
        {
            assert_eq!(native("C:/tmp/plan.json"), "C:\\tmp\\plan.json");
            assert_eq!(native("//server/share/a.json"), "\\\\server\\share\\a.json");
        }
    }

    fn python_suffix_name(name: &str) -> String {
        super::python_suffix(name).to_owned()
    }

    #[test]
    fn sync_dir_returns_without_an_error() {
        let dir = temp_path("sync-parent");
        std::fs::create_dir_all(&dir).expect("dir");
        _sync_dir(&dir);
        _sync_dir(Path::new("sesslint-missing-sync-dir-rx-p43"));
        assert!(dir.is_dir());
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn live_store_suffix_is_true_before_a_read() {
        assert!(is_live_store_path("missing-rx-p43.db"));
        assert!(is_live_store_path("missing-rx-p43.DB"));
        assert!(is_live_store_path("missing-rx-p43.sqlite"));
        assert!(is_live_store_path("missing-rx-p43.SQLITE3"));
        assert!(is_live_store_path("foo.db/"));
        assert!(!is_live_store_path("missing-rx-p43.txt"));
        assert!(!is_live_store_path(".db"));
        assert!(!is_live_store_path("archive.db.bak"));
        let dir = temp_path("store.db");
        let _ = std::fs::remove_dir(&dir);
        std::fs::create_dir_all(&dir).expect("db dir");
        assert!(is_live_store_path(&dir));
        let _ = std::fs::remove_dir(&dir);
        let plain = temp_path("plain-dir");
        std::fs::create_dir_all(&plain).expect("plain");
        assert!(!is_live_store_path(&plain));
        let _ = std::fs::remove_dir(&plain);
    }

    #[test]
    fn live_store_reads_magic_only_for_a_file() {
        let magic = temp_path("notes.bin");
        let mut bytes = SQLITE_MAGIC.to_vec();
        bytes.extend_from_slice(b"rest");
        std::fs::write(&magic, &bytes).expect("magic");
        assert!(is_live_store_path(&magic));
        std::fs::write(&magic, b"SQLite format 3").expect("short");
        assert!(!is_live_store_path(&magic));
        std::fs::write(&magic, b"hello").expect("text");
        assert!(!is_live_store_path(&magic));
        let _ = std::fs::remove_file(&magic);
    }

    #[test]
    fn source_positions_count_only_real_ints() {
        let events = [
            event_origin(PlanValue::int(2)),
            event_origin(PlanValue::bool_value(true)),
            event_origin(PlanValue::float(1.0)),
            event_origin(PlanValue::str_value("4")),
            event_origin(PlanValue::none()),
            PlanValue::string_map(vec![("sesslint.origin".to_owned(), PlanValue::int(9))]),
            event_origin(PlanValue::int(0)),
        ];
        let positions = _source_positions(&events).expect("positions");
        assert_eq!(positions.get(&2), Some(&0));
        assert_eq!(positions.get(&0), Some(&6));
        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn duplicate_origin_is_output_invalid() {
        let events = [
            event_origin(PlanValue::int(4)),
            event_origin(PlanValue::int(4)),
        ];
        let err = _source_positions(&events).expect_err("duplicate");
        match err {
            SourcePositionError::Duplicate(inner) => {
                assert_eq!(inner.code(), OutputInvalid::DEFAULT_CODE);
                assert_eq!(inner.to_string(), "Repair duplicated source event 4");
                assert!(!inner.to_string().contains("OUTPUT_INVALID"));
            }
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn non_mapping_event_fails_closed() {
        let err = _source_positions(&[PlanValue::list(vec![])]).expect_err("list");
        assert_eq!(
            err.to_string(),
            "Repair source event 0 is not a mapping, got list"
        );
    }

    #[test]
    fn relocate_rewrites_in_range_ints_and_passes_through_the_rest() {
        let mut positions = BTreeMap::new();
        positions.insert(0, 5);
        positions.insert(2, 1);
        let step = step_fields(
            Some(0),
            vec![
                ("note".to_owned(), PlanValue::str_value("keep")),
                ("at_index".to_owned(), PlanValue::int(2)),
                ("use_index".to_owned(), PlanValue::int(4)),
                ("index".to_owned(), PlanValue::int(-1)),
                ("cut_index".to_owned(), PlanValue::bool_value(true)),
                (
                    "record_indexes".to_owned(),
                    PlanValue::tuple(vec![
                        PlanValue::int(0),
                        PlanValue::int(2),
                        PlanValue::bool_value(false),
                        PlanValue::int(4),
                        PlanValue::int(-3),
                    ]),
                ),
            ],
        );
        let moved = _relocate_step(&step, &positions, 4).expect("relocate");
        assert_eq!(moved.seq(), 7);
        assert_eq!(moved.recipe(), "drop-record");
        assert_eq!(moved.target_finding_fp(), "fp-keep");
        assert_eq!(moved.target_index(), Some(5));
        assert!(moved.lossy());
        assert_eq!(moved.loss(), [("none".to_owned(), 2)]);
        assert_eq!(moved.min_policy(), "salvage");
        assert_eq!(moved.recipe_version(), "9.9.9");
        assert_eq!(
            moved.params(),
            [
                ("note".to_owned(), PlanValue::str_value("keep")),
                ("at_index".to_owned(), PlanValue::int(1)),
                ("use_index".to_owned(), PlanValue::int(4)),
                ("index".to_owned(), PlanValue::int(-1)),
                ("cut_index".to_owned(), PlanValue::bool_value(true)),
                (
                    "record_indexes".to_owned(),
                    PlanValue::list(vec![
                        PlanValue::int(5),
                        PlanValue::int(1),
                        PlanValue::bool_value(false),
                        PlanValue::int(4),
                        PlanValue::int(-3),
                    ])
                ),
            ]
        );
    }

    #[test]
    fn removed_source_event_uses_the_first_pin_param() {
        let step = step_fields(
            Some(2),
            vec![
                ("at_index".to_owned(), PlanValue::int(1)),
                (
                    "record_indexes".to_owned(),
                    PlanValue::list(vec![PlanValue::int(9)]),
                ),
            ],
        );
        let err = _relocate_step(&step, &BTreeMap::new(), 5).expect_err("removed");
        match err {
            RelocateError::OutputInvalid(inner) => {
                assert_eq!(
                    inner.to_string(),
                    "Step 7 (recipe 'drop-record') targets source event 1, which an earlier step removed"
                );
            }
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn removed_list_element_is_reported_before_a_later_one() {
        let mut positions = BTreeMap::new();
        positions.insert(0, 4);
        let step = step_fields(
            None,
            vec![(
                "record_indexes".to_owned(),
                PlanValue::list(vec![PlanValue::int(0), PlanValue::int(1)]),
            )],
        );
        let err = _relocate_step(&step, &positions, 3).expect_err("removed");
        assert_eq!(
            err.to_string(),
            "Step 7 (recipe 'drop-record') targets source event 1, which an earlier step removed"
        );
    }

    #[test]
    fn none_target_passes_through() {
        let step = step_fields(None, Vec::new());
        let moved = _relocate_step(&step, &BTreeMap::new(), 0).expect("none");
        assert_eq!(moved.target_index(), None);
    }

    #[test]
    fn targeted_lines_keep_real_ints_at_least_one() {
        let mut fps = BTreeSet::new();
        fps.insert("0123456789abcdef".to_owned());
        let findings = [
            finding_at("0123456789abcdef", Some(3)),
            finding_at("0123456789abcdef", Some(1)),
            finding_at("0123456789abcdef", None),
            finding_at("fedcba9876543210", Some(5)),
            finding_at("0123456789abcdef", Some(3)),
        ];
        let lines = _targeted_lines(&findings, &fps);
        assert_eq!(lines.iter().copied().collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn salvage_policy_loss_preview_and_steps() {
        let clean = bare_plan("conservative", Vec::new(), Loss::default());
        assert!(!_plan_requires_salvage(&clean));
        assert!(_plan_requires_salvage(&bare_plan(
            "salvage",
            Vec::new(),
            Loss::default()
        )));
        assert!(!_plan_requires_salvage(&bare_plan(
            "Salvage",
            Vec::new(),
            Loss::default()
        )));
        let preview = Loss::new(
            vec![("discarded-suffix".to_owned(), 0), ("none".to_owned(), 1)],
            0,
            0,
        );
        assert!(_plan_requires_salvage(&bare_plan(
            "conservative",
            Vec::new(),
            preview
        )));
        assert!(_plan_requires_salvage(&bare_plan(
            "conservative",
            Vec::new(),
            Loss::new(vec![("none".to_owned(), 0)], 1, 0)
        )));
        assert!(!_plan_requires_salvage(&bare_plan(
            "conservative",
            Vec::new(),
            Loss::new(vec![("none".to_owned(), -1)], -1, 0)
        )));
        let mut lossy = PlanStepFields::new(1, "executor-card-absent-recipe", "", None);
        lossy.lossy = true;
        let lossy = PlanStep::try_new(lossy).expect("lossy");
        assert!(_plan_requires_salvage(&bare_plan(
            "conservative",
            vec![lossy],
            Loss::default()
        )));
        let mut counted = PlanStepFields::new(1, "executor-card-absent-recipe", "", None);
        counted.loss = vec![("none".to_owned(), 1)];
        let counted = PlanStep::try_new(counted).expect("count");
        assert!(_plan_requires_salvage(&bare_plan(
            "conservative",
            vec![counted],
            Loss::default()
        )));
        let mut zero = PlanStepFields::new(1, "executor-card-absent-recipe", "", None);
        zero.loss = vec![("none".to_owned(), 0), ("torn-record".to_owned(), -1)];
        let zero = PlanStep::try_new(zero).expect("zero");
        assert!(!_plan_requires_salvage(&bare_plan(
            "conservative",
            vec![zero],
            Loss::default()
        )));
        let mut salvage_step = PlanStepFields::new(1, "executor-card-absent-recipe", "", None);
        salvage_step.min_policy = "salvage".to_owned();
        let salvage_step = PlanStep::try_new(salvage_step).expect("policy");
        assert!(_plan_requires_salvage(&bare_plan(
            "conservative",
            vec![salvage_step],
            Loss::default()
        )));
        assert!(get_recipe("executor-card-absent-recipe").is_none());
    }

    #[test]
    fn json_literals_match_cpython() {
        assert_eq!(parse_plan_json("null").expect("null"), PlanValue::none());
        assert_eq!(
            parse_plan_json("true").expect("true"),
            PlanValue::bool_value(true)
        );
        assert_eq!(
            parse_plan_json("false").expect("false"),
            PlanValue::bool_value(false)
        );
        assert_eq!(parse_plan_json("-0").expect("-0"), PlanValue::int(0));
        assert_eq!(
            parse_plan_json(&i128::MAX.to_string()).expect("max"),
            PlanValue::int(i128::MAX)
        );
        assert_eq!(
            parse_plan_json(&i128::MIN.to_string()).expect("min"),
            PlanValue::int(i128::MIN)
        );
        assert_eq!(
            parse_plan_json("NaN").expect("nan"),
            PlanValue::Float(0x7ff8_0000_0000_0000)
        );
        assert_eq!(
            parse_plan_json("Infinity").expect("inf"),
            PlanValue::Float(0x7ff0_0000_0000_0000)
        );
        assert_eq!(
            parse_plan_json("-Infinity").expect("-inf"),
            PlanValue::Float(0xfff0_0000_0000_0000)
        );
        assert_eq!(
            parse_plan_json("1e309").expect("overflow"),
            PlanValue::Float(0x7ff0_0000_0000_0000)
        );
        assert_eq!(
            parse_plan_json("-0.0").expect("-0.0"),
            PlanValue::Float(0x8000_0000_0000_0000)
        );
        assert_eq!(
            parse_plan_json("0.1").expect("0.1"),
            PlanValue::Float(4_591_870_180_066_957_722)
        );
        assert_eq!(
            parse_plan_json("1e+2").expect("1e+2"),
            PlanValue::Float(4_636_737_291_354_636_288)
        );
        assert_eq!(parse_plan_json("[]").expect("[]"), PlanValue::list(vec![]));
        assert_eq!(
            parse_plan_json("[\n]").expect("ws array"),
            PlanValue::list(vec![])
        );
        assert_eq!(
            parse_plan_json("{\n}").expect("ws object"),
            PlanValue::map(vec![])
        );
        assert_eq!(
            parse_plan_json(r#"{"b":1,"a":2,"b":3}"#).expect("dup"),
            PlanValue::map(vec![
                (PlanKey::str_key("b"), PlanValue::int(3)),
                (PlanKey::str_key("a"), PlanValue::int(2)),
            ])
        );
        assert_eq!(
            parse_plan_json(r#""a\nb""#).expect("esc"),
            PlanValue::str_value("a\nb")
        );
        assert_eq!(
            parse_plan_json(r#""\u0000""#).expect("nul"),
            PlanValue::str_value("\u{0}")
        );
        assert_eq!(
            parse_plan_json(r#""\uD800\uDC00""#).expect("pair"),
            PlanValue::str_value("\u{10000}")
        );
        assert_eq!(
            parse_plan_json(r#"{"é":1}"#).expect("key"),
            PlanValue::map(vec![(PlanKey::str_key("é"), PlanValue::int(1))])
        );
    }

    #[test]
    fn json_errors_match_cpython_messages() {
        let cases = [
            ("", "Expecting value: line 1 column 1 (char 0)"),
            ("   ", "Expecting value: line 1 column 4 (char 3)"),
            ("[", "Expecting value: line 1 column 2 (char 1)"),
            ("[1,]", "Expecting value: line 1 column 4 (char 3)"),
            (
                "{",
                "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
            ),
            (
                r#"{"a"}"#,
                "Expecting ':' delimiter: line 1 column 5 (char 4)",
            ),
            (
                r#"{"a":1,}"#,
                "Expecting property name enclosed in double quotes: line 1 column 8 (char 7)",
            ),
            (
                r#"{"a":1 "b":2}"#,
                "Expecting ',' delimiter: line 1 column 8 (char 7)",
            ),
            ("[1 2]", "Expecting ',' delimiter: line 1 column 4 (char 3)"),
            (
                "\"unterminated",
                "Unterminated string starting at: line 1 column 1 (char 0)",
            ),
            (
                r#""\u12""#,
                "Invalid \\uXXXX escape: line 1 column 3 (char 2)",
            ),
            (r#""\q""#, "Invalid \\escape: line 1 column 2 (char 1)"),
            (r#"{"a":1} x"#, "Extra data: line 1 column 9 (char 8)"),
            ("+1", "Expecting value: line 1 column 1 (char 0)"),
            ("01", "Extra data: line 1 column 2 (char 1)"),
            ("[01]", "Expecting ',' delimiter: line 1 column 3 (char 2)"),
            ("nan", "Expecting value: line 1 column 1 (char 0)"),
            ("+Infinity", "Expecting value: line 1 column 1 (char 0)"),
            ("-", "Expecting value: line 1 column 1 (char 0)"),
            ("1e", "Extra data: line 1 column 2 (char 1)"),
            ("1e+", "Extra data: line 1 column 2 (char 1)"),
            ("1.", "Extra data: line 1 column 2 (char 1)"),
            ("True", "Expecting value: line 1 column 1 (char 0)"),
            ("InfinityX", "Extra data: line 1 column 9 (char 8)"),
            ("-InfinityX", "Extra data: line 1 column 10 (char 9)"),
            ("[\n", "Expecting value: line 2 column 1 (char 2)"),
            ("1\n2", "Extra data: line 2 column 1 (char 2)"),
            (
                "\u{feff}{}",
                "Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)",
            ),
        ];
        for (text, message) in cases {
            assert_eq!(
                parse_plan_json(text).expect_err("json"),
                message,
                "{text:?}"
            );
        }
        let control = parse_plan_json("\"\u{1}\"").expect_err("control");
        assert_eq!(
            control,
            "Invalid control character at: line 1 column 2 (char 1)"
        );
        let mut big = i128::MAX.to_string();
        big.push('0');
        let overflow = parse_plan_json(&big).expect_err("overflow");
        assert!(
            overflow.starts_with("JSON integer does not fit in i128:"),
            "{overflow}"
        );
        let lone = parse_plan_json(r#""\uD800""#).expect_err("surrogate");
        assert!(
            lone.starts_with("JSON string contains a lone surrogate:"),
            "{lone}"
        );
    }

    #[test]
    fn utf8_faults_match_cpython_messages() {
        let samples: &[(&[u8], &str)] = &[
            (
                &[0xff],
                "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
            ),
            (
                &[0x80],
                "'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte",
            ),
            (
                &[0xc3],
                "'utf-8' codec can't decode byte 0xc3 in position 0: unexpected end of data",
            ),
            (
                &[0xc3, 0x28],
                "'utf-8' codec can't decode byte 0xc3 in position 0: invalid continuation byte",
            ),
            (
                &[0xe2, 0x82],
                "'utf-8' codec can't decode bytes in position 0-1: unexpected end of data",
            ),
            (
                &[0xe2, 0x82, 0x28],
                "'utf-8' codec can't decode bytes in position 0-1: invalid continuation byte",
            ),
        ];
        for (bytes, message) in samples {
            assert_eq!(utf8_message(bytes), *message, "{bytes:?}");
        }
    }

    #[test]
    fn load_plan_file_errors_use_pin_messages() {
        let missing = load_plan(
            LoadPlanInput::Path(Path::new("./sesslint-missing-plan-rx-p43.json")),
            None,
        )
        .expect_err("missing");
        assert_eq!(
            missing.to_string(),
            "Plan file not found: sesslint-missing-plan-rx-p43.json"
        );
        let nested = if cfg!(windows) {
            "Plan file not found: sesslint-missing-rx-p43\\plan.json"
        } else {
            "Plan file not found: sesslint-missing-rx-p43/plan.json"
        };
        let err = load_plan(
            LoadPlanInput::Path(Path::new("sesslint-missing-rx-p43/plan.json")),
            None,
        )
        .expect_err("nested");
        assert_eq!(err.to_string(), nested);
        let dir = temp_path("plan-dir");
        std::fs::create_dir_all(&dir).expect("dir");
        let err = load_plan(LoadPlanInput::Path(&dir), None).expect_err("dir");
        assert_eq!(
            err.to_string(),
            format!("Plan file not found: {}", python_path(&dir).native())
        );
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_plan_parses_json_then_from_dict() {
        let path = temp_path("ok-plan.json");
        std::fs::write(&path, r#"{"fingerprint":"abc","policy":"conservative"}"#).expect("write");
        let plan = load_plan(LoadPlanInput::Path(&path), Some("conservative")).expect("plan");
        assert_eq!(plan.policy(), "conservative");
        assert_eq!(plan.fingerprint(), "abc");
        assert_eq!(plan.profile(), "neutral");
        assert!(plan.steps().is_empty());
        let bad = temp_path("bad-plan.json");
        std::fs::write(&bad, "[1]").expect("write");
        let err = load_plan(LoadPlanInput::Path(&bad), None).expect_err("list");
        assert_eq!(
            err.to_string(),
            "Plan file root must be a JSON object, got list"
        );
        let roots = [
            ("null", "NoneType"),
            ("true", "bool"),
            ("1", "int"),
            ("1.5", "float"),
            ("NaN", "float"),
            ("\"x\"", "str"),
        ];
        for (text, type_name) in roots {
            std::fs::write(&bad, text).expect("write");
            let err = load_plan(LoadPlanInput::Path(&bad), None).expect_err(text);
            assert_eq!(
                err.to_string(),
                format!("Plan file root must be a JSON object, got {type_name}")
            );
        }
        std::fs::write(&bad, r#"{"fingerprint":NaN}"#).expect("nan");
        let err = load_plan(LoadPlanInput::Path(&bad), None).expect_err("nan field");
        assert_eq!(err.to_string(), "Plan fingerprint must be a string");
        std::fs::write(&bad, r#"{"fingerprint":"abc","steps":[Infinity]}"#).expect("inf");
        let err = load_plan(LoadPlanInput::Path(&bad), None).expect_err("inf");
        assert_eq!(err.to_string(), "Plan step must be an object");
        std::fs::write(&bad, [0xff]).expect("bytes");
        let err = load_plan(LoadPlanInput::Path(&bad), None).expect_err("utf8");
        assert_eq!(
            err.to_string(),
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
        );
        std::fs::write(&bad, "").expect("empty");
        let err = load_plan(LoadPlanInput::Path(&bad), None).expect_err("empty");
        assert_eq!(err.to_string(), "Expecting value: line 1 column 1 (char 0)");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn load_plan_policy_messages_are_the_pin_sentences() {
        let clean = plan_value("conservative", Vec::new());
        let plan = load_mapping(&clean, None).expect("none");
        assert_eq!(plan.policy(), "conservative");
        let plan = load_mapping(&clean, Some("conservative")).expect("match");
        assert_eq!(plan.fingerprint(), "abc");
        let err = load_mapping(&clean, Some("salvage")).expect_err("mismatch");
        match err {
            LoadPlanError::Policy(inner) => {
                assert_eq!(inner.code(), PolicyMismatch::DEFAULT_CODE);
                assert_eq!(
                    inner.to_string(),
                    "Plan policy 'conservative' does not match requested policy 'salvage'"
                );
                assert_ne!(inner.to_string(), "POLICY_MISMATCH");
            }
            other => panic!("unexpected {other}"),
        }
        let salvage = plan_value("salvage", Vec::new());
        let err = load_mapping(&salvage, Some("conservative")).expect_err("needs salvage");
        assert_eq!(
            err.to_string(),
            "Plan requires 'salvage' policy due to salvage-class steps or declared loss, but invocation requested 'conservative' policy"
        );
        assert!(load_mapping(&salvage, None).is_ok());
        let lossy = plan_value("conservative", vec![step_value("conservative", true)]);
        let err = load_mapping(&lossy, Some("conservative")).expect_err("lossy");
        assert_eq!(
            err.to_string(),
            "Plan requires 'salvage' policy due to salvage-class steps or declared loss, but invocation requested 'conservative' policy"
        );
        let typed = load_plan(LoadPlanInput::Other { type_name: "int" }, None).expect_err("type");
        assert_eq!(typed.to_string(), "Expected path or Mapping, got int");
        let list = PlanValue::list(vec![]);
        let err = load_mapping(&list, None).expect_err("list");
        assert_eq!(err.to_string(), "Expected path or Mapping, got list");
        let number = PlanValue::int(1);
        let err = load_mapping(&number, None).expect_err("int");
        assert_eq!(err.to_string(), "Expected path or Mapping, got int");
        let flag = PlanValue::bool_value(true);
        assert_eq!(
            load_mapping(&flag, None).expect_err("bool").to_string(),
            "Expected path or Mapping, got bool"
        );
        assert_eq!(
            load_mapping(&PlanValue::none(), None)
                .expect_err("none")
                .to_string(),
            "Expected path or Mapping, got NoneType"
        );
        let broken = PlanValue::string_map(vec![(
            "steps".to_owned(),
            PlanValue::list(vec![PlanValue::map(vec![])]),
        )]);
        let err = load_mapping(&broken, None).expect_err("from_dict");
        assert_eq!(err.to_string(), "Plan step missing required field 'seq'");
    }
}

#[cfg(test)]
mod session_source_load_tests {
    use std::path::{Path, PathBuf};

    use super::{
        load_session_source, load_session_source_with_findings, load_source_for_format,
        python_path, LoadSessionError,
    };

    const SNAPSHOT_INPUT: &str = "sesslint.adapters.load.snapshot_input is not available";
    const IS_VENDOR_FORMAT: &str = "sesslint.adapters.load.is_vendor_format is not available";

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("sesslint-executor-rx-p43-source");
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join(name)
    }

    fn not_found(path: &Path) -> String {
        format!("Session file not found: {}", python_path(path).native())
    }

    fn assert_not_found(err: &LoadSessionError, path: &Path) {
        let message = not_found(path);
        assert_eq!(err.to_string(), message);
        assert!(!message.contains("Errno"));
        assert!(!message.starts_with('['));
        assert!(matches!(err, LoadSessionError::FileNotFound(text) if text == &message));
    }

    fn link_file(original: &Path, link: &Path) {
        let _ = std::fs::remove_file(link);
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(original, link).expect("symlink");
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(original, link).expect("symlink");
        }
    }

    #[test]
    fn missing_session_file_message_has_no_errno_prefix() {
        let path = Path::new("sesslint-missing-session-rx-p43.jsonl");
        let err = load_session_source_with_findings(path, None).expect_err("missing");
        assert_not_found(&err, path);
        assert_eq!(
            err.to_string(),
            "Session file not found: sesslint-missing-session-rx-p43.jsonl"
        );
        let err =
            load_session_source_with_findings(path, Some(b"synthetic-rx-p43")).expect_err("data");
        assert_not_found(&err, path);
        let err = load_session_source(path).expect_err("wrapper");
        assert_not_found(&err, path);
        let empty = Path::new("");
        let err = load_session_source_with_findings(empty, None).expect_err("empty");
        assert_not_found(&err, empty);
        assert_eq!(err.to_string(), "Session file not found: .");
    }

    #[test]
    fn directory_session_path_message_has_no_errno_prefix() {
        let dir = temp_path("session-dir");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let err = load_session_source_with_findings(&dir, None).expect_err("dir");
        assert_not_found(&err, &dir);
        let err = load_session_source_with_findings(&dir, Some(b"{}")).expect_err("data");
        assert_not_found(&err, &dir);
        let err = load_session_source(&dir).expect_err("wrapper");
        assert_not_found(&err, &dir);
        let dot = Path::new(".");
        let err = load_session_source_with_findings(dot, None).expect_err("dot");
        assert_not_found(&err, dot);
        assert_eq!(err.to_string(), "Session file not found: .");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_stops_at_snapshot_input_without_reading() {
        let path = temp_path("synthetic-session.jsonl");
        let bytes = b"synthetic-rx-p43\n";
        std::fs::write(&path, bytes).expect("write");
        let err = load_session_source_with_findings(&path, None).expect_err("stop");
        assert_eq!(err.to_string(), SNAPSHOT_INPUT);
        assert!(matches!(err, LoadSessionError::SnapshotInput));
        let err =
            load_session_source_with_findings(&path, Some(b"synthetic-rx-p43")).expect_err("data");
        assert_eq!(err.to_string(), SNAPSHOT_INPUT);
        let err = load_session_source(&path).expect_err("wrapper");
        assert_eq!(err.to_string(), SNAPSHOT_INPUT);
        assert_eq!(std::fs::read(&path).expect("read"), bytes);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn symlink_to_a_file_is_a_file_and_a_broken_link_is_not() {
        let dir = temp_path("links");
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("target.jsonl");
        let bytes = b"synthetic-rx-p43\n";
        std::fs::write(&target, bytes).expect("write");
        let link = dir.join("link.jsonl");
        let broken = dir.join("broken.jsonl");
        link_file(&target, &link);
        link_file(&dir.join("absent.jsonl"), &broken);
        let err = load_session_source_with_findings(&link, None).expect_err("link");
        assert_eq!(err.to_string(), SNAPSHOT_INPUT);
        let err = load_session_source(&link).expect_err("wrapper");
        assert_eq!(err.to_string(), SNAPSHOT_INPUT);
        let err = load_session_source_with_findings(&broken, Some(b"synthetic-rx-p43"))
            .expect_err("broken");
        assert_not_found(&err, &broken);
        assert_eq!(std::fs::read(&target).expect("read"), bytes);
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&broken);
        let _ = std::fs::remove_file(&target);
    }

    #[test]
    fn vendor_format_stops_before_any_stat() {
        let missing = Path::new("sesslint-missing-vendor-rx-p43.jsonl");
        let err = load_source_for_format(missing, None, None).expect_err("missing");
        assert_eq!(err.to_string(), IS_VENDOR_FORMAT);
        assert!(matches!(err, LoadSessionError::VendorFormat));
        assert!(!err.to_string().contains("Session file not found"));
        let err = load_source_for_format(missing, Some("canonical"), Some(b"synthetic-rx-p43"))
            .expect_err("args");
        assert_eq!(err.to_string(), IS_VENDOR_FORMAT);
        let dir = temp_path("vendor-dir");
        std::fs::create_dir_all(&dir).expect("dir");
        let err = load_source_for_format(&dir, Some("codex"), None).expect_err("dir");
        assert_eq!(err.to_string(), IS_VENDOR_FORMAT);
        let file = temp_path("vendor-file.jsonl");
        std::fs::write(&file, b"synthetic-rx-p43\n").expect("write");
        let err = load_source_for_format(&file, None, Some(b"{}")).expect_err("file");
        assert_eq!(err.to_string(), IS_VENDOR_FORMAT);
        assert_ne!(err.to_string(), SNAPSHOT_INPUT);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&file);
    }
}

#[cfg(test)]
mod execute_prefix_tests {
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};

    use crate::errors::OutputInvalid;
    use crate::planner::{
        Loss, PlanStep, PlanStepFields, RepairPlan, RepairPlanFields, PLAN_VERSION,
    };

    use super::{execute, ExecuteError};

    const CAP_257: &str = "Plan step count (257) exceeds maximum allowed cap (256)";
    const FINGERPRINT: &str =
        "sesslint.repair.fingerprint.compute_plan_fingerprint is not available";
    const DECOY: &str = "sesslint-execute-rx-p43-decoy.jsonl";
    const SENTINEL: &[u8] = b"synthetic-rx-p43\n";

    fn synthetic_plan(steps: usize, policy: &str) -> RepairPlan {
        let steps = (0..steps)
            .map(|index| {
                let seq = i128::try_from(index).expect("seq");
                PlanStep::try_new(PlanStepFields::new(
                    seq,
                    "drop-record",
                    format!("synthetic-fp-{index}"),
                    None,
                ))
                .expect("step")
            })
            .collect();
        RepairPlan::new(RepairPlanFields {
            source_hash: DECOY.to_owned(),
            profile: "neutral".to_owned(),
            steps,
            blocked: Vec::new(),
            loss_accounting: Loss::default(),
            fingerprint: "synthetic-plan-fp".to_owned(),
            version: PLAN_VERSION.to_owned(),
            policy: policy.to_owned(),
        })
    }

    struct Scratch {
        dir: PathBuf,
        before: Vec<(String, Vec<u8>)>,
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
            let _ = fs::remove_file(DECOY);
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("sesslint-executor-rx-p43-execute")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        fs::write(dir.join("sentinel.txt"), SENTINEL).expect("sentinel");
        dir
    }

    fn listing(dir: &Path) -> Vec<(String, Vec<u8>)> {
        let mut rows = Vec::new();
        for entry in fs::read_dir(dir).expect("list") {
            let entry = entry.expect("entry");
            let path = entry.path();
            let bytes = if path.is_file() {
                fs::read(&path).expect("read")
            } else {
                Vec::new()
            };
            rows.push((entry.file_name().to_string_lossy().into_owned(), bytes));
        }
        rows.sort();
        rows
    }

    fn prepare(name: &str) -> Scratch {
        let _ = fs::remove_file(DECOY);
        assert!(!Path::new(DECOY).exists());
        let dir = scratch(name);
        assert!(!dir.join(DECOY).exists());
        let before = listing(&dir);
        assert_eq!(before, vec![("sentinel.txt".to_owned(), SENTINEL.to_vec())]);
        Scratch { dir, before }
    }

    fn assert_untouched(scratch: &Scratch) {
        assert!(!Path::new(DECOY).exists());
        assert!(!scratch.dir.join(DECOY).exists());
        assert_eq!(listing(&scratch.dir), scratch.before);
        assert_eq!(
            fs::read(scratch.dir.join("sentinel.txt")).expect("sentinel"),
            SENTINEL
        );
    }

    #[test]
    fn two_hundred_fifty_seven_steps_return_the_cap_and_do_not_touch_files() {
        let scratch = prepare("cap");
        let err = execute(&synthetic_plan(257, "conservative")).expect_err("cap");
        assert_eq!(err.to_string(), CAP_257);
        let ExecuteError::OutputInvalid(inner) = &err else {
            panic!("expected OutputInvalid, got {err}");
        };
        assert_eq!(inner.message(), CAP_257);
        assert_eq!(inner.code(), OutputInvalid::DEFAULT_CODE);
        assert_eq!(err.to_string(), inner.message());
        assert_eq!(
            err.source().map(ToString::to_string),
            Some(CAP_257.to_owned())
        );
        assert!(!err.to_string().contains("not available"));
        assert_untouched(&scratch);
    }

    #[test]
    fn two_hundred_fifty_six_or_fewer_steps_stop_at_the_fingerprint_seam() {
        let cases = [
            (0_usize, "conservative"),
            (1, "salvage"),
            (256, "conservative"),
        ];
        for (count, policy) in cases {
            let scratch = prepare(&format!("fp-{count}-{policy}"));
            let err = execute(&synthetic_plan(count, policy)).expect_err("fingerprint");
            assert_eq!(
                err.to_string(),
                FINGERPRINT,
                "count {count} policy {policy}"
            );
            assert!(matches!(err, ExecuteError::FingerprintUnavailable));
            assert!(err.source().is_none());
            assert!(!err.to_string().contains("exceeds maximum allowed cap"));
            assert!(!err.to_string().contains(DECOY));
            assert_untouched(&scratch);
        }
    }
}
