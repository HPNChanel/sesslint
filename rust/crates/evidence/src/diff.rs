//! Structural session comparator (ux-reporting T-02).
//!
//! Port of `src/sesslint/diff.py` lines 1–315
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`,
//! blob `aaa086bf6c3cdd7e3fb4141c150f705e8e11a7fb`.
//!
//! Pass 1 pairs on event id. Duplicate ids pair earliest-first, and a bucket
//! head that is already matched is skipped. Pass 2 pairs the indexes still
//! unmatched by `(kind, parent_id or "", content hash)`.
//!
//! [`codec::canonical_codec::content_identity_hash`] is called while building
//! each unmatched B fallback key, then each unmatched A fallback key, then
//! during the content comparison of every pair after the kind and parent
//! checks. The first error is returned immediately. Deltas already built are
//! discarded, and removed rows, added rows, and the final sort do not run.
//! Empty sequences do not call it.
//!
//! [`SessionDiff::to_dict`] and [`SessionDiff::render_human`] stop on
//! `sesslint.report.minimize_path` before a dictionary or text exists.
//! [`SessionDiff::to_json`] calls [`SessionDiff::to_dict`] first.
//! [`SessionDiff::identical`] and [`SessionDiff::counts`] do not.
//!
//! Lines 318–408 append [`_load_side`], [`diff_sessions`],
//! [`get_diff_schema_path`], and [`load_diff_schema`]. [`diff_sessions`]
//! checks path A and then path B before [`_load_side`]. A missing path is
//! `FileNotFoundError`. A directory, including a symlink to a directory, is
//! [`DiffInputError`]. Once both paths are files, [`_load_side`] stops on
//! `sesslint.adapters.detect.resolve_format` and returns no [`SessionDiff`].
//! It does not call `minimize_path`, `load_events_for_format`, [`diff_events`],
//! or `CLI_VERSION`. The schema helpers stop on
//! `sesslint._resources.schema_path` and do not build a `schemas/` path.
//! Empty [`diff_events`] still does not hash, and the report methods still
//! stop on `minimize_path`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

use codec::canonical_codec::CanonicalError;

/// Python `DIFF_SCHEMA_VERSION`.
pub const DIFF_SCHEMA_VERSION: &str = "sesslint.diff/v1";

/// Python `DELTA_CATEGORIES`, in declaration order.
pub const DELTA_CATEGORIES: [&str; 6] = [
    "added",
    "removed",
    "kind-changed",
    "parent-relinked",
    "seq-reordered",
    "content-changed",
];

/// Python `MAX_ROWS`. Human output bound for one category.
pub const MAX_ROWS: usize = 100;

/// Display text when `sesslint.report.minimize_path` cannot be imported.
pub const MINIMIZE_PATH_UNAVAILABLE: &str = "sesslint.report.minimize_path is not available";

type FallbackKey = (String, String, String);

/// Structured input failure for diff (detection or load), exit code 2.
///
/// [`diff_sessions`] returns this when an input is a directory, including a
/// symlink to a directory. Alignment does not return it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffInputError {
    message: String,
}

impl DiffInputError {
    /// Build an error whose [`Display`](fmt::Display) is the Python message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DiffInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for DiffInputError {}

/// `sesslint.report.minimize_path` is not linked from this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MinimizePathUnavailable;

impl fmt::Display for MinimizePathUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(MINIMIZE_PATH_UNAVAILABLE)
    }
}

impl Error for MinimizePathUnavailable {}

/// Python `DeltaCategory`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaCategory {
    Added,
    Removed,
    KindChanged,
    ParentRelinked,
    SeqReordered,
    ContentChanged,
}

impl DeltaCategory {
    /// Category string stored on a delta and in [`DELTA_CATEGORIES`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::KindChanged => "kind-changed",
            Self::ParentRelinked => "parent-relinked",
            Self::SeqReordered => "seq-reordered",
            Self::ContentChanged => "content-changed",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::Added => 0,
            Self::Removed => 1,
            Self::KindChanged => 2,
            Self::ParentRelinked => 3,
            Self::SeqReordered => 4,
            Self::ContentChanged => 5,
        }
    }
}

/// JSON value for [`Delta::to_dict`].
///
/// Objects keep the insertion order of the Python dict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffJson {
    Int(i64),
    String(String),
    Object(Vec<(String, DiffJson)>),
}

/// Local stand-in for the event fields this slice reads.
///
/// `id`, `kind`, and `parent_id`. The model crate is not imported.
/// `parent_id` keeps `None` and `""` distinct; the fallback key maps both to `""`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffEvent {
    pub id: String,
    pub kind: String,
    pub parent_id: Option<String>,
}

impl DiffEvent {
    /// Python `SessionEvent.content_identity_hash`.
    ///
    /// Calls [`codec::canonical_codec::content_identity_hash`]. No digest is
    /// stored on the event, and this does not hash with `sha2`.
    fn content_identity_hash(&self) -> Result<String, CanonicalError> {
        codec::canonical_codec::content_identity_hash()
    }
}

/// One structural difference between the two sessions (content-free).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    pub category: DeltaCategory,
    pub event_id: Option<String>,
    pub a_index: Option<i64>,
    pub b_index: Option<i64>,
    /// Pair insertion order. An empty list is omitted by [`Self::to_dict`].
    pub detail: Vec<(String, String)>,
}

impl Delta {
    /// Python `Delta.to_dict`.
    ///
    /// Omits `event_id`, `a_index`, and `b_index` when they are `None`.
    /// Omits `detail` when it is empty. A non-empty detail is copied.
    #[must_use]
    pub fn to_dict(&self) -> DiffJson {
        let mut pairs = vec![(
            "category".to_owned(),
            DiffJson::String(self.category.as_str().to_owned()),
        )];
        if let Some(event_id) = &self.event_id {
            pairs.push(("event_id".to_owned(), DiffJson::String(event_id.clone())));
        }
        if let Some(a_index) = self.a_index {
            pairs.push(("a_index".to_owned(), DiffJson::Int(a_index)));
        }
        if let Some(b_index) = self.b_index {
            pairs.push(("b_index".to_owned(), DiffJson::Int(b_index)));
        }
        if !self.detail.is_empty() {
            let copied = self
                .detail
                .iter()
                .map(|(key, value)| (key.clone(), DiffJson::String(value.clone())))
                .collect();
            pairs.push(("detail".to_owned(), DiffJson::Object(copied)));
        }
        DiffJson::Object(pairs)
    }
}

/// Frozen structural diff result (`sesslint.diff/v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionDiff {
    pub a_path: String,
    pub b_path: String,
    pub a_format: String,
    pub b_format: String,
    pub a_event_count: i64,
    pub b_event_count: i64,
    pub tool_version: String,
    pub deltas: Vec<Delta>,
}

impl SessionDiff {
    /// Python `SessionDiff.identical`. True when `deltas` is empty.
    #[must_use]
    pub fn identical(&self) -> bool {
        self.deltas.is_empty()
    }

    /// Python `SessionDiff.counts`.
    ///
    /// Every [`DELTA_CATEGORIES`] entry starts at 0, then each delta increments
    /// its category. The array is in that category order.
    #[must_use]
    pub fn counts(&self) -> [(&'static str, i64); DELTA_CATEGORIES.len()] {
        let mut totals = [0_i64; DELTA_CATEGORIES.len()];
        for delta in &self.deltas {
            totals[delta.category.index()] += 1;
        }
        std::array::from_fn(|index| (DELTA_CATEGORIES[index], totals[index]))
    }

    /// Python `SessionDiff.to_dict`.
    ///
    /// The body imports `sesslint.report.minimize_path` before any other work.
    /// That import is unavailable. No dictionary is built.
    ///
    /// # Errors
    ///
    /// Always [`MinimizePathUnavailable`]. Success is [`Infallible`].
    pub fn to_dict(&self, _home: Option<&Path>) -> Result<Infallible, MinimizePathUnavailable> {
        Err(MinimizePathUnavailable)
    }

    /// Python `SessionDiff.to_json`.
    ///
    /// Calls [`Self::to_dict`] first. The same error is returned. `json.dumps`
    /// does not run.
    ///
    /// # Errors
    ///
    /// Always [`MinimizePathUnavailable`]. Success is [`Infallible`].
    pub fn to_json(&self, home: Option<&Path>) -> Result<Infallible, MinimizePathUnavailable> {
        let document = self.to_dict(home)?;
        match document {}
    }

    /// Python `SessionDiff.render_human`.
    ///
    /// Imports `sesslint.report.minimize_path` before any other work, including
    /// the [`MAX_ROWS`] truncation. No human text is built.
    ///
    /// # Errors
    ///
    /// Always [`MinimizePathUnavailable`]. Success is [`Infallible`].
    pub fn render_human(
        &self,
        _home: Option<&Path>,
    ) -> Result<Infallible, MinimizePathUnavailable> {
        Err(MinimizePathUnavailable)
    }
}

/// Python `_delta_label`.
///
/// Both indexes render as `a[{i}] -> b[{j}]`. Otherwise the present side is
/// used. ` id={event_id}` is appended when the id is `Some`. A non-empty
/// detail appends a space and `k=v` pairs with keys sorted.
#[must_use]
pub fn _delta_label(delta: &Delta) -> String {
    let side = match (delta.a_index, delta.b_index) {
        (Some(a_index), Some(b_index)) => format!("a[{a_index}] -> b[{b_index}]"),
        (Some(a_index), None) => format!("a[{a_index}]"),
        (None, Some(b_index)) => format!("b[{b_index}]"),
        (None, None) => "b[None]".to_owned(),
    };
    let mut label = side;
    if let Some(event_id) = &delta.event_id {
        label.push_str(" id=");
        label.push_str(event_id);
    }
    if !delta.detail.is_empty() {
        let mut items = delta.detail.clone();
        items.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let rendered = items
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        label.push(' ');
        label.push_str(&rendered);
    }
    label
}

/// Align two event sequences and emit sorted content-free deltas.
///
/// Deterministic when the content-hash seam succeeds: equal inputs yield the
/// same delta list. Empty sequences return an empty list and do not hash.
/// Any event on either side reaches [`codec::canonical_codec::content_identity_hash`]
/// before a successful list is returned. The first error discards deltas
/// already built.
///
/// # Errors
///
/// The content-hash seam. [`DiffInputError`] is not used.
pub fn diff_events(
    events_a: &[DiffEvent],
    events_b: &[DiffEvent],
) -> Result<Vec<Delta>, CanonicalError> {
    let mut alignment = pair_by_id(events_a, events_b);
    let still_unmatched_a = extend_fallback(events_a, events_b, &mut alignment)?;
    let mut deltas = Vec::new();
    append_pair_deltas(&mut deltas, events_a, events_b, &alignment.pairs)?;
    append_reorders(&mut deltas, events_a, &alignment.pairs);
    append_unmatched(
        &mut deltas,
        events_a,
        events_b,
        &still_unmatched_a,
        &alignment.matched_b,
    );
    sort_deltas(&mut deltas);
    Ok(deltas)
}

struct IdAlignment {
    pairs: Vec<(usize, usize)>,
    unmatched_a: Vec<usize>,
    matched_b: HashSet<usize>,
}

fn pair_by_id(events_a: &[DiffEvent], events_b: &[DiffEvent]) -> IdAlignment {
    let mut b_by_id: HashMap<&str, VecDeque<usize>> = HashMap::new();
    for (index, event) in events_b.iter().enumerate() {
        b_by_id
            .entry(event.id.as_str())
            .or_default()
            .push_back(index);
    }

    let mut pairs = Vec::new();
    let mut unmatched_a = Vec::new();
    let mut matched_b = HashSet::new();
    for (index, event) in events_a.iter().enumerate() {
        let paired = match b_by_id.get_mut(event.id.as_str()) {
            Some(bucket) => pop_unmatched(bucket, &matched_b),
            None => None,
        };
        if let Some(b_index) = paired {
            matched_b.insert(b_index);
            pairs.push((index, b_index));
        } else {
            unmatched_a.push(index);
        }
    }
    IdAlignment {
        pairs,
        unmatched_a,
        matched_b,
    }
}

/// Drop a bucket head that was already matched, then pop the next index.
fn pop_unmatched(bucket: &mut VecDeque<usize>, matched: &HashSet<usize>) -> Option<usize> {
    while bucket.front().is_some_and(|head| matched.contains(head)) {
        bucket.pop_front();
    }
    bucket.pop_front()
}

fn extend_fallback(
    events_a: &[DiffEvent],
    events_b: &[DiffEvent],
    alignment: &mut IdAlignment,
) -> Result<Vec<usize>, CanonicalError> {
    let mut b_by_key: HashMap<FallbackKey, VecDeque<usize>> = HashMap::new();
    for (index, event) in events_b.iter().enumerate() {
        if alignment.matched_b.contains(&index) {
            continue;
        }
        let key = _fallback_key(event)?;
        b_by_key.entry(key).or_default().push_back(index);
    }

    let unmatched_a = alignment.unmatched_a.clone();
    let mut still_unmatched_a = Vec::new();
    for index in unmatched_a {
        let key = _fallback_key(&events_a[index])?;
        let paired = b_by_key
            .get_mut(&key)
            .and_then(|bucket| pop_unmatched(bucket, &alignment.matched_b));
        if let Some(b_index) = paired {
            alignment.matched_b.insert(b_index);
            alignment.pairs.push((index, b_index));
        } else {
            still_unmatched_a.push(index);
        }
    }
    Ok(still_unmatched_a)
}

fn _fallback_key(event: &DiffEvent) -> Result<FallbackKey, CanonicalError> {
    let kind = event.kind.clone();
    let parent = parent_or_empty(event.parent_id.as_deref());
    let hash = event.content_identity_hash()?;
    Ok((kind, parent, hash))
}

/// Python `parent_id or ""`. `None` and `""` are both `""`.
fn parent_or_empty(parent_id: Option<&str>) -> String {
    match parent_id {
        Some(value) if !value.is_empty() => value.to_owned(),
        _ => String::new(),
    }
}

fn append_pair_deltas(
    deltas: &mut Vec<Delta>,
    events_a: &[DiffEvent],
    events_b: &[DiffEvent],
    pairs: &[(usize, usize)],
) -> Result<(), CanonicalError> {
    for &(a_pos, b_pos) in pairs {
        let left = &events_a[a_pos];
        let right = &events_b[b_pos];
        let a_index = py_index(a_pos);
        let b_index = py_index(b_pos);
        push_kind_and_parent(deltas, left, right, a_index, b_index);
        let hash_a = take_content_hash(deltas, left)?;
        let hash_b = take_content_hash(deltas, right)?;
        if hash_a != hash_b {
            let shown_a = prefix16(&take_content_hash(deltas, left)?);
            let shown_b = prefix16(&take_content_hash(deltas, right)?);
            deltas.push(Delta {
                category: DeltaCategory::ContentChanged,
                event_id: Some(left.id.clone()),
                a_index: Some(a_index),
                b_index: Some(b_index),
                detail: detail(&[("hash_a", shown_a.as_str()), ("hash_b", shown_b.as_str())]),
            });
        }
    }
    Ok(())
}

fn push_kind_and_parent(
    deltas: &mut Vec<Delta>,
    left: &DiffEvent,
    right: &DiffEvent,
    a_index: i64,
    b_index: i64,
) {
    if left.kind != right.kind {
        deltas.push(Delta {
            category: DeltaCategory::KindChanged,
            event_id: Some(left.id.clone()),
            a_index: Some(a_index),
            b_index: Some(b_index),
            detail: detail(&[
                ("kind_a", left.kind.as_str()),
                ("kind_b", right.kind.as_str()),
            ]),
        });
    }
    if left.parent_id != right.parent_id {
        deltas.push(Delta {
            category: DeltaCategory::ParentRelinked,
            event_id: Some(left.id.clone()),
            a_index: Some(a_index),
            b_index: Some(b_index),
            detail: vec![
                (
                    "parent_a".to_owned(),
                    parent_or_empty(left.parent_id.as_deref()),
                ),
                (
                    "parent_b".to_owned(),
                    parent_or_empty(right.parent_id.as_deref()),
                ),
            ],
        });
    }
}

fn take_content_hash(deltas: &mut Vec<Delta>, event: &DiffEvent) -> Result<String, CanonicalError> {
    event.content_identity_hash().inspect_err(|_| {
        deltas.clear();
    })
}

fn prefix16(hash: &str) -> String {
    hash.chars().take(16).collect()
}

fn append_reorders(deltas: &mut Vec<Delta>, events_a: &[DiffEvent], pairs: &[(usize, usize)]) {
    let mut ordered = pairs.to_vec();
    ordered.sort();
    let mut running_max = -1_i64;
    for (a_pos, b_pos) in ordered {
        let b_index = py_index(b_pos);
        if b_index < running_max {
            deltas.push(Delta {
                category: DeltaCategory::SeqReordered,
                event_id: Some(events_a[a_pos].id.clone()),
                a_index: Some(py_index(a_pos)),
                b_index: Some(b_index),
                detail: Vec::new(),
            });
        } else {
            running_max = b_index;
        }
    }
}

fn append_unmatched(
    deltas: &mut Vec<Delta>,
    events_a: &[DiffEvent],
    events_b: &[DiffEvent],
    still_unmatched_a: &[usize],
    matched_b: &HashSet<usize>,
) {
    for &index in still_unmatched_a {
        let event = &events_a[index];
        deltas.push(Delta {
            category: DeltaCategory::Removed,
            event_id: Some(event.id.clone()),
            a_index: Some(py_index(index)),
            b_index: None,
            detail: detail(&[("kind", event.kind.as_str())]),
        });
    }
    for (index, event) in events_b.iter().enumerate() {
        if matched_b.contains(&index) {
            continue;
        }
        deltas.push(Delta {
            category: DeltaCategory::Added,
            event_id: Some(event.id.clone()),
            a_index: None,
            b_index: Some(py_index(index)),
            detail: detail(&[("kind", event.kind.as_str())]),
        });
    }
}

fn sort_deltas(deltas: &mut [Delta]) {
    deltas.sort_by(|left, right| {
        left.category
            .index()
            .cmp(&right.category.index())
            .then(sort_index(left.a_index).cmp(&sort_index(right.a_index)))
            .then(sort_index(left.b_index).cmp(&sort_index(right.b_index)))
            .then(sort_event_id(&left.event_id).cmp(sort_event_id(&right.event_id)))
    });
}

fn sort_index(index: Option<i64>) -> i64 {
    index.unwrap_or(-1)
}

fn sort_event_id(event_id: &Option<String>) -> &str {
    event_id.as_deref().unwrap_or("")
}

fn py_index(index: usize) -> i64 {
    i64::try_from(index).unwrap_or(i64::MAX)
}

fn detail(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .copied()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// Display text when `sesslint.adapters.detect.resolve_format` cannot be called.
pub const RESOLVE_FORMAT_UNAVAILABLE: &str =
    "sesslint.adapters.detect.resolve_format is not available";

/// `sesslint.adapters.detect.resolve_format` is not linked from this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolveFormatUnavailable;

impl fmt::Display for ResolveFormatUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(RESOLVE_FORMAT_UNAVAILABLE)
    }
}

impl Error for ResolveFormatUnavailable {}

/// Display text when `sesslint._resources.schema_path` cannot be imported.
pub const SCHEMA_PATH_UNAVAILABLE: &str = "sesslint._resources.schema_path is not available";

/// `sesslint._resources.schema_path` is not linked from this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchemaPathUnavailable;

impl fmt::Display for SchemaPathUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SCHEMA_PATH_UNAVAILABLE)
    }
}

impl Error for SchemaPathUnavailable {}

/// Failure from [`diff_sessions`].
///
/// A missing path uses the pin's `FileNotFoundError` sentence. A directory uses
/// [`DiffInputError`]. A file pair uses the [`ResolveFormatUnavailable`] sentence.
/// Display text does not include the Python exception type name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffSessionsError {
    /// Python `FileNotFoundError`: `Path not found: {path}`.
    PathNotFound(String),
    /// Python `DiffInputError` for a directory, including a symlink to one.
    Input(DiffInputError),
    /// `sesslint.adapters.detect.resolve_format` is not linked.
    ResolveFormat(ResolveFormatUnavailable),
}

impl fmt::Display for DiffSessionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathNotFound(path) => write!(formatter, "Path not found: {path}"),
            Self::Input(error) => fmt::Display::fmt(error, formatter),
            Self::ResolveFormat(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for DiffSessionsError {}

impl From<ResolveFormatUnavailable> for DiffSessionsError {
    fn from(error: ResolveFormatUnavailable) -> Self {
        Self::ResolveFormat(error)
    }
}

/// Python `_load_side`.
///
/// The first call is `sesslint.adapters.detect.resolve_format`. That function
/// is not linked, so this returns [`ResolveFormatUnavailable`]. It does not
/// stat `path`, call `minimize_path` or `load_events_for_format`, or invent a
/// format string. [`diff_sessions`] checks both paths before this runs.
///
/// # Errors
///
/// Always [`ResolveFormatUnavailable`]. Success is [`Infallible`].
pub fn _load_side(
    path: &Path,
    explicit_format: Option<&str>,
) -> Result<Infallible, ResolveFormatUnavailable> {
    let _ = (path, explicit_format);
    Err(ResolveFormatUnavailable)
}

/// Python `diff_sessions`.
///
/// `format_a` and `format_b` are Python `None` when the caller omitted them.
/// Path A is checked, then path B, before [`_load_side`]. `exists` and
/// `is_dir` follow symlinks, matching pathlib. A missing path, including a
/// broken symlink, is `FileNotFoundError`. A directory, including a symlink
/// to a directory, is [`DiffInputError`].
///
/// Once both paths are files, [`_load_side`] stops on `resolve_format`. This
/// does not call `minimize_path`, `load_events_for_format`, [`diff_events`],
/// or `CLI_VERSION`. It does not invent a format and does not build a
/// [`SessionDiff`]. `format_b` is not read: the load of path A stops first.
///
/// # Errors
///
/// [`DiffSessionsError::PathNotFound`], [`DiffSessionsError::Input`], or
/// [`DiffSessionsError::ResolveFormat`]. Success is [`Infallible`].
pub fn diff_sessions(
    a: impl AsRef<Path>,
    b: impl AsRef<Path>,
    format_a: Option<&str>,
    format_b: Option<&str>,
) -> Result<Infallible, DiffSessionsError> {
    let path_a = a.as_ref();
    let path_b = b.as_ref();
    for path in [path_a, path_b] {
        require_diff_file(path)?;
    }
    let _ = format_b;
    let loaded = _load_side(path_a, format_a)?;
    match loaded {}
}

/// Python `get_diff_schema_path`.
///
/// The first statement imports `sesslint._resources.schema_path`. That
/// function is not linked. This does not build a `schemas/` path and does
/// not read a schema file.
///
/// # Errors
///
/// Always [`SchemaPathUnavailable`].
pub fn get_diff_schema_path() -> Result<PathBuf, SchemaPathUnavailable> {
    Err(SchemaPathUnavailable)
}

/// Python `load_diff_schema`.
///
/// Calls [`get_diff_schema_path`] before any file check. The resource import
/// fails there, so this returns that same error. This does not read a schema
/// file and does not parse JSON.
///
/// # Errors
///
/// Always [`SchemaPathUnavailable`]. Success is [`Infallible`].
pub fn load_diff_schema() -> Result<Infallible, SchemaPathUnavailable> {
    let _schema_path = get_diff_schema_path()?;
    Err(SchemaPathUnavailable)
}

/// `Path.exists` then `Path.is_dir`, both following symlinks.
///
/// A missing path, including a broken symlink, is `FileNotFoundError`.
/// A directory, including a symlink to a directory, is [`DiffInputError`].
fn require_diff_file(path: &Path) -> Result<(), DiffSessionsError> {
    if !path.exists() {
        return Err(DiffSessionsError::PathNotFound(path_text(path)));
    }
    if path.is_dir() {
        let shown = path_text(path);
        return Err(DiffSessionsError::Input(DiffInputError::new(format!(
            "Diff input must be a file, not a directory: {shown}"
        ))));
    }
    Ok(())
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};
    use std::convert::Infallible;
    use std::error::Error;
    use std::path::Path;

    use codec::canonical_codec::{content_identity_hash, CanonicalError};

    // rustfmt 1.91 panics while ordering this import list.
    #[rustfmt::skip]
    use super::{
        append_pair_deltas, append_reorders, append_unmatched, diff_events, extend_fallback,
        pair_by_id, pop_unmatched, push_kind_and_parent, sort_deltas, _delta_label, _fallback_key,
        Delta, DeltaCategory, DiffEvent, DiffInputError, DiffJson, MinimizePathUnavailable,
        SessionDiff, DELTA_CATEGORIES, DIFF_SCHEMA_VERSION, MAX_ROWS, MINIMIZE_PATH_UNAVAILABLE,
    };

    const HASH_SEAM: &str = "sesslint.canonical.SessionEvent is not available";

    #[test]
    fn constants_match_the_pinned_slice() {
        assert_eq!(DIFF_SCHEMA_VERSION, "sesslint.diff/v1");
        assert_eq!(MAX_ROWS, 100);
        assert_eq!(
            DELTA_CATEGORIES,
            [
                "added",
                "removed",
                "kind-changed",
                "parent-relinked",
                "seq-reordered",
                "content-changed",
            ]
        );
        assert_eq!(
            MINIMIZE_PATH_UNAVAILABLE,
            "sesslint.report.minimize_path is not available"
        );
        let categories = [
            DeltaCategory::Added,
            DeltaCategory::Removed,
            DeltaCategory::KindChanged,
            DeltaCategory::ParentRelinked,
            DeltaCategory::SeqReordered,
            DeltaCategory::ContentChanged,
        ];
        for (index, category) in categories.iter().copied().enumerate() {
            assert_eq!(category.as_str(), DELTA_CATEGORIES[index]);
            assert_eq!(category.index(), index);
        }
    }

    #[test]
    fn delta_to_dict_omits_none_and_copies_detail() {
        let bare = Delta {
            category: DeltaCategory::Removed,
            event_id: None,
            a_index: None,
            b_index: None,
            detail: Vec::new(),
        };
        assert_eq!(object_keys(&bare.to_dict()), vec!["category"]);

        let mut copied = Delta {
            category: DeltaCategory::KindChanged,
            event_id: Some(String::new()),
            a_index: Some(0),
            b_index: Some(2),
            detail: vec![
                ("z".to_owned(), "2".to_owned()),
                ("a".to_owned(), "1".to_owned()),
            ],
        };
        let dict = copied.to_dict();
        assert_eq!(
            object_keys(&dict),
            vec!["category", "event_id", "a_index", "b_index", "detail"]
        );
        assert_eq!(detail_entries(&dict), vec![("z", "2"), ("a", "1")]);
        copied.detail[0].1 = "changed".to_owned();
        assert_eq!(detail_entries(&dict), vec![("z", "2"), ("a", "1")]);
        assert_eq!(string_field(&dict, "event_id"), "");
        assert_eq!(int_field(&dict, "a_index"), 0);
        assert_eq!(int_field(&dict, "b_index"), 2);
        assert_eq!(string_field(&dict, "category"), "kind-changed");
    }

    #[test]
    fn delta_label_formats_sides_id_and_sorted_detail() {
        assert_eq!(
            _delta_label(&labeled(Some(1), Some(2), None, vec![])),
            "a[1] -> b[2]"
        );
        assert_eq!(_delta_label(&labeled(Some(4), None, None, vec![])), "a[4]");
        assert_eq!(_delta_label(&labeled(None, Some(3), None, vec![])), "b[3]");
        assert_eq!(_delta_label(&labeled(None, None, None, vec![])), "b[None]");
        assert_eq!(
            _delta_label(&labeled(Some(1), Some(2), Some("e"), vec![])),
            "a[1] -> b[2] id=e"
        );
        assert_eq!(
            _delta_label(&labeled(Some(1), None, Some(""), vec![])),
            "a[1] id="
        );
        let detail = vec![
            ("z".to_owned(), "2".to_owned()),
            ("a".to_owned(), "1".to_owned()),
        ];
        assert_eq!(
            _delta_label(&labeled(Some(1), Some(2), Some("e"), detail.clone())),
            "a[1] -> b[2] id=e a=1 z=2"
        );
        assert_eq!(
            _delta_label(&labeled(Some(1), None, None, detail)),
            "a[1] a=1 z=2"
        );
    }

    #[test]
    fn identical_and_counts_do_not_need_minimize_path() {
        let empty = session(Vec::new());
        assert!(empty.identical());
        assert_eq!(
            empty.counts(),
            [
                ("added", 0),
                ("removed", 0),
                ("kind-changed", 0),
                ("parent-relinked", 0),
                ("seq-reordered", 0),
                ("content-changed", 0),
            ]
        );

        let mixed = session(vec![
            labeled(Some(0), Some(1), Some("e"), vec![]),
            Delta {
                category: DeltaCategory::ContentChanged,
                ..labeled(Some(0), Some(1), Some("e"), vec![])
            },
            Delta {
                category: DeltaCategory::Added,
                event_id: Some("n".to_owned()),
                a_index: None,
                b_index: Some(3),
                detail: vec![("kind".to_owned(), "span".to_owned())],
            },
            Delta {
                category: DeltaCategory::ContentChanged,
                ..labeled(Some(2), Some(4), Some("f"), vec![])
            },
        ]);
        assert!(!mixed.identical());
        assert_eq!(
            mixed.counts(),
            [
                ("added", 1),
                ("removed", 0),
                ("kind-changed", 1),
                ("parent-relinked", 0),
                ("seq-reordered", 0),
                ("content-changed", 2),
            ]
        );
    }

    #[test]
    fn report_methods_stop_at_minimize_path() {
        let diff = session(Vec::new());
        assert_minimize(diff.to_dict(None));
        assert_minimize(diff.render_human(Some(Path::new("synthetic"))));
        let json_error = diff.to_json(None).unwrap_err();
        let dict_error = diff.to_dict(None).unwrap_err();
        assert_eq!(json_error, dict_error);
        assert_minimize(Err(json_error));
    }

    #[test]
    fn diff_input_error_is_a_separate_type() {
        let input = DiffInputError::new("detection failed");
        assert_eq!(input.to_string(), "detection failed");
        let as_error: &dyn Error = &input;
        assert_eq!(as_error.to_string(), "detection failed");
        let hash_error = diff_events(&[event("e0", "span", None)], &[]).unwrap_err();
        assert_eq!(hash_error.to_string(), HASH_SEAM);
        assert_ne!(hash_error.to_string(), input.to_string());
    }

    #[test]
    fn empty_sequences_return_no_deltas() {
        let deltas = diff_events(&[], &[]).expect("empty sequences do not hash");
        assert!(deltas.is_empty());
    }

    #[test]
    fn any_event_returns_the_content_hash_seam() {
        let expected = content_identity_hash().unwrap_err();
        assert_eq!(expected.to_string(), HASH_SEAM);
        let samples = [
            (vec![event("e0", "span", None)], vec![]),
            (vec![], vec![event("e1", "span", None)]),
            (
                vec![event("e0", "span", None)],
                vec![event("e0", "note", Some(""))],
            ),
            (
                vec![event("e0", "span", None)],
                vec![event("e1", "span", None)],
            ),
            (
                vec![event("e0", "span", None), event("e1", "note", Some("p0"))],
                vec![event("e1", "note", Some("p0")), event("e2", "span", None)],
            ),
        ];
        for (events_a, events_b) in samples {
            let error = diff_events(&events_a, &events_b).unwrap_err();
            assert_eq!(error, expected);
            assert_eq!(
                error,
                CanonicalError::Unsupported("sesslint.canonical.SessionEvent is not available")
            );
            let as_error: &dyn Error = &error;
            assert_eq!(as_error.to_string(), HASH_SEAM);
        }
    }

    #[test]
    fn id_pairs_are_earliest_first_and_unmatched_a_stays_in_order() {
        let events_a = [
            event("e", "span", None),
            event("e", "span", None),
            event("f", "note", None),
        ];
        let events_b = [
            event("f", "span", None),
            event("e", "note", None),
            event("e", "span", None),
        ];
        let alignment = pair_by_id(&events_a, &events_b);
        assert_eq!(alignment.pairs, vec![(0, 1), (1, 2), (2, 0)]);
        assert!(alignment.unmatched_a.is_empty());
        assert_eq!(alignment.matched_b, HashSet::from([0, 1, 2]));

        let partial_a = [
            event("c", "span", None),
            event("a", "span", None),
            event("b", "span", None),
        ];
        let partial_b = [event("a", "span", None)];
        let partial = pair_by_id(&partial_a, &partial_b);
        assert_eq!(partial.pairs, vec![(1, 0)]);
        assert_eq!(partial.unmatched_a, vec![0, 2]);

        let duplicate_a = [event("e", "span", None), event("e", "span", None)];
        let one_b = [event("e", "span", None)];
        let earliest = pair_by_id(&duplicate_a, &one_b);
        assert_eq!(earliest.pairs, vec![(0, 0)]);
        assert_eq!(earliest.unmatched_a, vec![1]);

        let one_a = [event("e", "span", None)];
        let duplicate_b = [event("e", "span", None), event("e", "span", None)];
        let b_side = pair_by_id(&one_a, &duplicate_b);
        assert_eq!(b_side.pairs, vec![(0, 0)]);
        assert_eq!(b_side.matched_b, HashSet::from([0]));
    }

    #[test]
    fn pop_unmatched_skips_a_matched_bucket_head() {
        let mut bucket = VecDeque::from([1, 2, 2]);
        let matched = HashSet::from([1]);
        assert_eq!(pop_unmatched(&mut bucket, &matched), Some(2));
        assert_eq!(bucket, VecDeque::from([2]));

        let mut matched_only = VecDeque::from([4]);
        let matched = HashSet::from([4]);
        assert_eq!(pop_unmatched(&mut matched_only, &matched), None);
        assert!(matched_only.is_empty());
    }

    #[test]
    fn kind_and_parent_both_emit_when_each_differs() {
        let left = event("e0", "span", Some("p0"));
        let right = event("e0", "note", Some("p1"));
        let mut deltas = Vec::new();
        push_kind_and_parent(&mut deltas, &left, &right, 0, 1);
        assert_eq!(
            deltas
                .iter()
                .map(|delta| delta.category)
                .collect::<Vec<_>>(),
            vec![DeltaCategory::KindChanged, DeltaCategory::ParentRelinked]
        );
        assert_eq!(
            deltas[0].detail,
            vec![
                ("kind_a".to_owned(), "span".to_owned()),
                ("kind_b".to_owned(), "note".to_owned()),
            ]
        );
        assert_eq!(
            deltas[1].detail,
            vec![
                ("parent_a".to_owned(), "p0".to_owned()),
                ("parent_b".to_owned(), "p1".to_owned()),
            ]
        );
        assert_eq!(deltas[0].event_id.as_deref(), Some("e0"));
        assert_eq!(deltas[0].a_index, Some(0));
        assert_eq!(deltas[0].b_index, Some(1));

        let mut same = Vec::new();
        push_kind_and_parent(&mut same, &left, &left, 0, 0);
        assert!(same.is_empty());
    }

    #[test]
    fn parent_none_and_empty_render_as_empty_but_still_differ() {
        let missing = event("e0", "span", None);
        let blank = event("e0", "span", Some(""));
        let mut deltas = Vec::new();
        push_kind_and_parent(&mut deltas, &missing, &blank, 3, 4);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].category, DeltaCategory::ParentRelinked);
        assert_eq!(
            deltas[0].detail,
            vec![
                ("parent_a".to_owned(), String::new()),
                ("parent_b".to_owned(), String::new()),
            ]
        );

        let mut both_missing = Vec::new();
        push_kind_and_parent(&mut both_missing, &missing, &missing, 0, 0);
        assert!(both_missing.is_empty());

        let mut both_blank = Vec::new();
        push_kind_and_parent(&mut both_blank, &blank, &blank, 0, 0);
        assert!(both_blank.is_empty());

        let named = event("e0", "span", Some("p0"));
        let mut named_deltas = Vec::new();
        push_kind_and_parent(&mut named_deltas, &named, &missing, 1, 2);
        assert_eq!(
            named_deltas[0].detail,
            vec![
                ("parent_a".to_owned(), "p0".to_owned()),
                ("parent_b".to_owned(), String::new()),
            ]
        );
    }

    #[test]
    fn fallback_calls_the_hash_seam_and_matched_ids_do_not() {
        let error = _fallback_key(&event("e0", "span", None)).unwrap_err();
        assert_eq!(error.to_string(), HASH_SEAM);
        assert_eq!(
            _fallback_key(&event("e0", "span", Some("")))
                .unwrap_err()
                .to_string(),
            HASH_SEAM
        );
        assert_eq!(
            _fallback_key(&event("e0", "span", Some("p0")))
                .unwrap_err()
                .to_string(),
            HASH_SEAM
        );

        let events_a = [event("e0", "span", None)];
        let events_b = [event("e0", "note", Some("p0"))];
        let mut matched = pair_by_id(&events_a, &events_b);
        let still = extend_fallback(&events_a, &events_b, &mut matched)
            .expect("an id pair does not build a fallback key");
        assert!(still.is_empty());
        assert_eq!(matched.pairs, vec![(0, 0)]);

        let unmatched_b = [event("e1", "span", None)];
        let mut alignment = pair_by_id(&events_a, &unmatched_b);
        assert!(alignment.pairs.is_empty());
        let error = extend_fallback(&events_a, &unmatched_b, &mut alignment).unwrap_err();
        assert_eq!(error.to_string(), HASH_SEAM);
        assert!(alignment.pairs.is_empty());

        let only_a = [event("e0", "span", None)];
        let mut a_only = pair_by_id(&only_a, &[]);
        assert_eq!(a_only.unmatched_a, vec![0]);
        assert_eq!(
            extend_fallback(&only_a, &[], &mut a_only)
                .unwrap_err()
                .to_string(),
            HASH_SEAM
        );
    }

    #[test]
    fn content_comparison_discards_deltas_from_the_hash_seam() {
        let events_a = [event("e0", "span", None)];
        let events_b = [event("e0", "note", Some("p0"))];
        let mut deltas = vec![labeled(Some(9), None, Some("keep"), vec![])];
        let error = append_pair_deltas(&mut deltas, &events_a, &events_b, &[(0, 0)]).unwrap_err();
        assert_eq!(error.to_string(), HASH_SEAM);
        assert!(deltas.is_empty());

        let mut untouched = Vec::new();
        append_pair_deltas(&mut untouched, &events_a, &events_b, &[])
            .expect("no pairs do not hash");
        assert!(untouched.is_empty());
    }

    #[test]
    fn seq_reordered_emits_only_when_b_regresses() {
        let events = [event("e0", "span", None), event("e1", "note", None)];
        let mut deltas = Vec::new();
        append_reorders(&mut deltas, &events, &[(1, 0), (0, 2)]);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].category, DeltaCategory::SeqReordered);
        assert_eq!(deltas[0].event_id.as_deref(), Some("e1"));
        assert_eq!(deltas[0].a_index, Some(1));
        assert_eq!(deltas[0].b_index, Some(0));
        assert!(deltas[0].detail.is_empty());

        let mut equal = Vec::new();
        append_reorders(&mut equal, &events, &[(0, 1), (1, 1)]);
        assert!(equal.is_empty());

        let longer = [
            event("e0", "span", None),
            event("e1", "span", None),
            event("e2", "span", None),
            event("e3", "span", None),
            event("e4", "span", None),
        ];
        let mut running = Vec::new();
        append_reorders(
            &mut running,
            &longer,
            &[(2, 4), (0, 0), (4, 5), (1, 5), (3, 6)],
        );
        let rows: Vec<_> = running
            .iter()
            .map(|delta| (delta.event_id.as_deref(), delta.a_index, delta.b_index))
            .collect();
        assert_eq!(
            rows,
            vec![
                (Some("e2"), Some(2), Some(4)),
                (Some("e4"), Some(4), Some(5))
            ]
        );
    }

    #[test]
    fn removed_added_and_final_sort_follow_the_pin() {
        let events_a = [
            event("a0", "ka", None),
            event("a1", "kb", None),
            event("a2", "kc", None),
        ];
        let events_b = [
            event("b0", "kx", None),
            event("b1", "ky", None),
            event("b2", "kz", None),
        ];
        let matched = HashSet::from([1]);
        let mut deltas = Vec::new();
        append_unmatched(&mut deltas, &events_a, &events_b, &[2, 0], &matched);
        assert_eq!(deltas[0].category, DeltaCategory::Removed);
        assert_eq!(deltas[0].event_id.as_deref(), Some("a2"));
        assert_eq!(deltas[0].a_index, Some(2));
        assert_eq!(deltas[0].b_index, None);
        assert_eq!(deltas[0].detail, vec![("kind".to_owned(), "kc".to_owned())]);
        assert_eq!(deltas[1].a_index, Some(0));
        assert_eq!(deltas[1].detail, vec![("kind".to_owned(), "ka".to_owned())]);
        assert_eq!(deltas[2].category, DeltaCategory::Added);
        assert_eq!(deltas[2].event_id.as_deref(), Some("b0"));
        assert_eq!(deltas[2].a_index, None);
        assert_eq!(deltas[2].b_index, Some(0));
        assert_eq!(deltas[2].detail, vec![("kind".to_owned(), "kx".to_owned())]);
        assert_eq!(deltas[3].b_index, Some(2));
        assert_eq!(deltas[3].event_id.as_deref(), Some("b2"));

        sort_deltas(&mut deltas);
        assert_eq!(
            deltas
                .iter()
                .map(|delta| (delta.category, delta.event_id.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                (DeltaCategory::Added, Some("b0")),
                (DeltaCategory::Added, Some("b2")),
                (DeltaCategory::Removed, Some("a0")),
                (DeltaCategory::Removed, Some("a2")),
            ]
        );

        let mut mixed = vec![
            Delta {
                category: DeltaCategory::ContentChanged,
                event_id: Some("c".to_owned()),
                a_index: Some(0),
                b_index: Some(0),
                detail: Vec::new(),
            },
            Delta {
                category: DeltaCategory::Removed,
                event_id: Some("r".to_owned()),
                a_index: Some(0),
                b_index: None,
                detail: Vec::new(),
            },
            Delta {
                category: DeltaCategory::SeqReordered,
                event_id: Some("s".to_owned()),
                a_index: Some(0),
                b_index: Some(0),
                detail: Vec::new(),
            },
            Delta {
                category: DeltaCategory::KindChanged,
                event_id: Some("k".to_owned()),
                a_index: Some(0),
                b_index: Some(0),
                detail: Vec::new(),
            },
        ];
        sort_deltas(&mut mixed);
        assert_eq!(
            mixed.iter().map(|delta| delta.category).collect::<Vec<_>>(),
            vec![
                DeltaCategory::Removed,
                DeltaCategory::KindChanged,
                DeltaCategory::SeqReordered,
                DeltaCategory::ContentChanged,
            ]
        );

        let mut indexes = vec![
            Delta {
                category: DeltaCategory::Removed,
                event_id: Some("z".to_owned()),
                a_index: Some(0),
                b_index: None,
                detail: Vec::new(),
            },
            Delta {
                category: DeltaCategory::Removed,
                event_id: Some("a".to_owned()),
                a_index: None,
                b_index: Some(0),
                detail: Vec::new(),
            },
        ];
        sort_deltas(&mut indexes);
        assert_eq!(indexes[0].event_id.as_deref(), Some("a"));
        assert_eq!(indexes[0].a_index, None);

        let mut ids = vec![
            Delta {
                category: DeltaCategory::Added,
                event_id: Some("b".to_owned()),
                a_index: None,
                b_index: Some(0),
                detail: Vec::new(),
            },
            Delta {
                category: DeltaCategory::Added,
                event_id: None,
                a_index: None,
                b_index: Some(0),
                detail: Vec::new(),
            },
            Delta {
                category: DeltaCategory::Added,
                event_id: Some("a".to_owned()),
                a_index: None,
                b_index: Some(0),
                detail: Vec::new(),
            },
        ];
        sort_deltas(&mut ids);
        assert_eq!(
            ids.iter()
                .map(|delta| delta.event_id.clone())
                .collect::<Vec<_>>(),
            vec![None, Some("a".to_owned()), Some("b".to_owned())]
        );
    }

    fn event(id: &str, kind: &str, parent_id: Option<&str>) -> DiffEvent {
        DiffEvent {
            id: id.to_owned(),
            kind: kind.to_owned(),
            parent_id: parent_id.map(str::to_owned),
        }
    }

    fn session(deltas: Vec<Delta>) -> SessionDiff {
        SessionDiff {
            a_path: "a.jsonl".to_owned(),
            b_path: "b.jsonl".to_owned(),
            a_format: "synthetic".to_owned(),
            b_format: "synthetic".to_owned(),
            a_event_count: 0,
            b_event_count: 0,
            tool_version: "0".to_owned(),
            deltas,
        }
    }

    fn labeled(
        a_index: Option<i64>,
        b_index: Option<i64>,
        event_id: Option<&str>,
        detail: Vec<(String, String)>,
    ) -> Delta {
        Delta {
            category: DeltaCategory::KindChanged,
            event_id: event_id.map(str::to_owned),
            a_index,
            b_index,
            detail,
        }
    }

    fn object_keys(value: &DiffJson) -> Vec<&str> {
        let DiffJson::Object(pairs) = value else {
            panic!("delta dict is an object");
        };
        pairs.iter().map(|(key, _)| key.as_str()).collect()
    }

    fn string_field<'a>(value: &'a DiffJson, name: &str) -> &'a str {
        let DiffJson::Object(pairs) = value else {
            panic!("delta dict is an object");
        };
        let Some((_, DiffJson::String(text))) = pairs.iter().find(|(key, _)| key == name) else {
            panic!("missing string {name}");
        };
        text
    }

    fn int_field(value: &DiffJson, name: &str) -> i64 {
        let DiffJson::Object(pairs) = value else {
            panic!("delta dict is an object");
        };
        let Some((_, DiffJson::Int(number))) = pairs.iter().find(|(key, _)| key == name) else {
            panic!("missing int {name}");
        };
        *number
    }

    fn detail_entries(value: &DiffJson) -> Vec<(&str, &str)> {
        let DiffJson::Object(pairs) = value else {
            panic!("delta dict is an object");
        };
        let Some((_, DiffJson::Object(entries))) = pairs.iter().find(|(key, _)| key == "detail")
        else {
            panic!("missing detail");
        };
        entries
            .iter()
            .map(|(key, entry)| {
                let DiffJson::String(text) = entry else {
                    panic!("detail value is a string");
                };
                (key.as_str(), text.as_str())
            })
            .collect()
    }

    fn assert_minimize(result: Result<Infallible, MinimizePathUnavailable>) {
        let error = match result {
            Ok(never) => match never {},
            Err(error) => error,
        };
        let displayed = error.to_string();
        assert_eq!(displayed, "sesslint.report.minimize_path is not available");
        let as_error: &dyn Error = &error;
        assert_eq!(as_error.to_string(), displayed);
    }
}

#[cfg(test)]
mod session_load {
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{
        _load_side, diff_events, diff_sessions, get_diff_schema_path, load_diff_schema, path_text,
        DiffEvent, DiffInputError, DiffSessionsError, ResolveFormatUnavailable,
        SchemaPathUnavailable, SessionDiff, MINIMIZE_PATH_UNAVAILABLE, RESOLVE_FORMAT_UNAVAILABLE,
        SCHEMA_PATH_UNAVAILABLE,
    };

    #[test]
    fn missing_and_directory_paths_stop_before_load() {
        let tree = TempTree::new("paths");
        let missing_a = tree.path.join("absent-a.jsonl");
        let file_b = tree.path.join("file-b.jsonl");
        fs::write(&file_b, b"MARKER_B\n").unwrap();
        let missing_first = sessions_err(&missing_a, &file_b, Some("fmt-a"), Some("fmt-b"));
        assert_eq!(
            missing_first,
            DiffSessionsError::PathNotFound(path_text(&missing_a))
        );
        assert_eq!(
            missing_first.to_string(),
            format!("Path not found: {}", path_text(&missing_a))
        );
        assert!(!missing_first.to_string().contains("file-b.jsonl"));
        assert!(!missing_first.to_string().contains("MARKER_B"));
        assert!(!missing_first.to_string().contains("fmt-a"));
        assert!(!missing_first.to_string().contains("resolve_format"));
        assert_same_display(&missing_first);

        let file_a = tree.path.join("file-a.jsonl");
        fs::write(&file_a, b"MARKER_A\n").unwrap();
        let missing_b = tree.path.join("absent-b.jsonl");
        let missing_second = sessions_err(&file_a, &missing_b, None, Some("fmt-b"));
        assert_eq!(
            missing_second,
            DiffSessionsError::PathNotFound(path_text(&missing_b))
        );
        assert_eq!(
            missing_second.to_string(),
            format!("Path not found: {}", path_text(&missing_b))
        );
        assert!(!missing_second.to_string().contains("MARKER_A"));
        assert!(!missing_second.to_string().contains("resolve_format"));
        assert_eq!(fs::read(&file_a).unwrap(), b"MARKER_A\n");

        let dir_a = tree.path.join("dir-a");
        fs::create_dir(&dir_a).unwrap();
        fs::write(dir_a.join("child.jsonl"), b"CHILD_MARKER").unwrap();
        let directory_first = sessions_err(&dir_a, &missing_b, Some("fmt-a"), None);
        let directory_message = format!(
            "Diff input must be a file, not a directory: {}",
            path_text(&dir_a)
        );
        assert_eq!(
            directory_first,
            DiffSessionsError::Input(DiffInputError::new(directory_message.clone()))
        );
        assert_eq!(directory_first.to_string(), directory_message);
        assert!(directory_first.to_string().contains("dir-a"));
        assert!(!directory_first.to_string().contains("absent-b"));
        assert!(!directory_first.to_string().contains("CHILD_MARKER"));
        assert!(!directory_first.to_string().contains("child.jsonl"));
        assert!(!directory_first.to_string().contains("resolve_format"));
        assert_same_display(&directory_first);

        let dir_b = tree.path.join("dir-b");
        fs::create_dir(&dir_b).unwrap();
        let directory_second = sessions_err(&file_a, &dir_b, None, None);
        assert_eq!(
            directory_second,
            DiffSessionsError::Input(DiffInputError::new(format!(
                "Diff input must be a file, not a directory: {}",
                path_text(&dir_b)
            )))
        );
        assert!(directory_second.to_string().contains("dir-b"));
        assert!(!directory_second.to_string().contains("file-a.jsonl"));
        assert!(!directory_second.to_string().contains("resolve_format"));

        let via_dot = tree.path.join("dir-a").join("..").join("absent-dot.jsonl");
        let dotted = sessions_err(&via_dot, &file_b, None, None);
        assert_eq!(dotted, DiffSessionsError::PathNotFound(path_text(&via_dot)));
        assert!(dotted.to_string().contains(".."));
        assert!(dotted.to_string().contains("absent-dot.jsonl"));
    }

    #[test]
    fn symlink_to_a_directory_is_a_directory() {
        let tree = TempTree::new("links");
        let target = tree.path.join("target-dir");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("inside.jsonl"), b"INSIDE_MARKER").unwrap();
        let link = tree.path.join("link-dir");
        symlink_dir(&target, &link).unwrap_or_else(|err| panic!("symlink dir: {err}"));
        let file = tree.path.join("real.jsonl");
        fs::write(&file, b"REAL_MARKER\n").unwrap();

        let linked_dir = sessions_err(&link, &file, Some("fmt-a"), None);
        assert_eq!(
            linked_dir,
            DiffSessionsError::Input(DiffInputError::new(format!(
                "Diff input must be a file, not a directory: {}",
                path_text(&link)
            )))
        );
        assert!(linked_dir.to_string().contains("link-dir"));
        assert!(!linked_dir.to_string().contains("target-dir"));
        assert!(!linked_dir.to_string().contains("INSIDE_MARKER"));
        assert!(!linked_dir.to_string().contains("resolve_format"));
        assert_same_display(&linked_dir);

        let linked_second = sessions_err(&file, &link, None, Some("fmt-b"));
        assert_eq!(
            linked_second,
            DiffSessionsError::Input(DiffInputError::new(format!(
                "Diff input must be a file, not a directory: {}",
                path_text(&link)
            )))
        );
        assert!(!linked_second.to_string().contains("REAL_MARKER"));

        let original = tree.path.join("original.jsonl");
        fs::write(&original, b"ORIGINAL_MARKER\n").unwrap();
        let file_link = tree.path.join("link-file.jsonl");
        symlink_file(&original, &file_link).unwrap_or_else(|err| panic!("symlink file: {err}"));
        let file_pair = sessions_err(&file_link, &file, Some("not-a-format"), Some("other"));
        assert_eq!(
            file_pair,
            DiffSessionsError::ResolveFormat(ResolveFormatUnavailable)
        );
        assert_eq!(file_pair.to_string(), RESOLVE_FORMAT_UNAVAILABLE);
        assert!(!file_pair.to_string().contains("ORIGINAL_MARKER"));
        assert!(!file_pair.to_string().contains("not-a-format"));
        assert_eq!(fs::read(&original).unwrap(), b"ORIGINAL_MARKER\n");

        let broken = tree.path.join("broken-link.jsonl");
        symlink_file(&tree.path.join("missing-target.jsonl"), &broken)
            .unwrap_or_else(|err| panic!("broken symlink: {err}"));
        let broken_first = sessions_err(&broken, &file, None, None);
        assert_eq!(
            broken_first,
            DiffSessionsError::PathNotFound(path_text(&broken))
        );
        assert_eq!(
            broken_first.to_string(),
            format!("Path not found: {}", path_text(&broken))
        );
        assert!(!broken_first.to_string().contains("resolve_format"));

        let broken_second = sessions_err(&file, &broken, None, None);
        assert_eq!(
            broken_second,
            DiffSessionsError::PathNotFound(path_text(&broken))
        );
    }

    #[test]
    fn two_files_stop_at_resolve_format() {
        let tree = TempTree::new("files");
        let file_a = tree.path.join("side-a.jsonl");
        let file_b = tree.path.join("side-b.jsonl");
        fs::write(&file_a, b"SECRET_PAYLOAD_XYZ\n").unwrap();
        fs::write(&file_b, b"").unwrap();
        let formats = [
            (None, None),
            (Some("claude-code-jsonl"), None),
            (None, Some("codex")),
            (Some("left-format"), Some("right-format")),
        ];
        for (format_a, format_b) in formats {
            let error = sessions_err(&file_a, &file_b, format_a, format_b);
            assert_eq!(
                error,
                DiffSessionsError::ResolveFormat(ResolveFormatUnavailable)
            );
            assert_eq!(
                error.to_string(),
                "sesslint.adapters.detect.resolve_format is not available"
            );
            assert_eq!(error.to_string(), RESOLVE_FORMAT_UNAVAILABLE);
            assert!(!error.to_string().contains("SECRET_PAYLOAD_XYZ"));
            assert!(!error.to_string().contains("side-a"));
            assert!(!error.to_string().contains("side-b"));
            assert!(!error.to_string().contains("left-format"));
            assert!(!error.to_string().contains("right-format"));
            assert!(!error.to_string().contains("claude-code-jsonl"));
            assert_ne!(error.to_string(), MINIMIZE_PATH_UNAVAILABLE);
            assert_ne!(
                error.to_string(),
                "sesslint.canonical.SessionEvent is not available"
            );
            assert_ne!(error.to_string(), SCHEMA_PATH_UNAVAILABLE);
            assert_same_display(&error);
        }
        assert_eq!(fs::read(&file_a).unwrap(), b"SECRET_PAYLOAD_XYZ\n");
        assert_eq!(fs::read(&file_b).unwrap(), b"");

        let same = sessions_err(&file_a, &file_a, None, None);
        assert_eq!(same.to_string(), RESOLVE_FORMAT_UNAVAILABLE);
    }

    #[test]
    fn load_side_does_not_stat_or_invent_a_format() {
        let tree = TempTree::new("load");
        let missing = tree.path.join("absent.jsonl");
        let directory = tree.path.join("dir-load");
        fs::create_dir(&directory).unwrap();
        let file = tree.path.join("file-load.jsonl");
        fs::write(&file, b"LOAD_MARKER\n").unwrap();

        for (path, format) in [
            (missing.as_path(), None),
            (directory.as_path(), Some("claude-code-jsonl")),
            (file.as_path(), Some("")),
        ] {
            let error = _load_side(path, format).unwrap_err();
            assert_eq!(error, ResolveFormatUnavailable);
            assert_eq!(error.to_string(), RESOLVE_FORMAT_UNAVAILABLE);
            assert_eq!(
                error.to_string(),
                "sesslint.adapters.detect.resolve_format is not available"
            );
            assert!(!error.to_string().contains("LOAD_MARKER"));
            assert!(!error.to_string().contains("claude-code"));
            assert!(!error.to_string().contains("absent.jsonl"));
            let as_error: &dyn Error = &error;
            assert_eq!(as_error.to_string(), RESOLVE_FORMAT_UNAVAILABLE);
            assert!(as_error.source().is_none());
        }

        let from_sessions = sessions_err(&file, &file, Some("synthetic"), None);
        assert_eq!(
            from_sessions.to_string(),
            _load_side(&file, Some("synthetic"))
                .unwrap_err()
                .to_string()
        );
        assert!(directory.is_dir());
        assert!(!missing.exists());
    }

    #[test]
    fn schema_helpers_stop_on_schema_path() {
        let path_error = get_diff_schema_path().unwrap_err();
        assert_eq!(path_error, SchemaPathUnavailable);
        assert_eq!(path_error.to_string(), SCHEMA_PATH_UNAVAILABLE);
        assert_eq!(
            path_error.to_string(),
            "sesslint._resources.schema_path is not available"
        );
        assert!(!path_error.to_string().contains("schemas"));
        assert!(!path_error.to_string().contains(".json"));
        assert!(!path_error.to_string().contains("Diff schema not found"));
        let as_error: &dyn Error = &path_error;
        assert!(as_error.source().is_none());
        assert_ne!(path_error.to_string(), RESOLVE_FORMAT_UNAVAILABLE);

        let load_error = match load_diff_schema() {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_eq!(load_error, path_error);
        assert_eq!(
            load_error.to_string(),
            "sesslint._resources.schema_path is not available"
        );
        assert!(std::error::Error::source(&load_error).is_none());
    }

    #[test]
    fn part_one_hash_and_report_seams_remain() {
        let empty = diff_events(&[], &[]).expect("empty sequences do not hash");
        assert!(empty.is_empty());

        let hashed = diff_events(
            &[DiffEvent {
                id: "e0".to_owned(),
                kind: "span".to_owned(),
                parent_id: None,
            }],
            &[],
        )
        .unwrap_err();
        assert_eq!(
            hashed.to_string(),
            "sesslint.canonical.SessionEvent is not available"
        );

        let report = SessionDiff {
            a_path: "a.jsonl".to_owned(),
            b_path: "b.jsonl".to_owned(),
            a_format: "synthetic".to_owned(),
            b_format: "synthetic".to_owned(),
            a_event_count: 0,
            b_event_count: 0,
            tool_version: "0".to_owned(),
            deltas: Vec::new(),
        };
        assert!(report.identical());
        assert_eq!(report.counts()[0], ("added", 0));
        let dict_error = report.to_dict(None).unwrap_err();
        assert_eq!(dict_error.to_string(), MINIMIZE_PATH_UNAVAILABLE);
        assert_eq!(
            dict_error.to_string(),
            "sesslint.report.minimize_path is not available"
        );
        assert_eq!(
            report.to_json(None).unwrap_err().to_string(),
            dict_error.to_string()
        );
        assert_eq!(
            report.render_human(None).unwrap_err().to_string(),
            dict_error.to_string()
        );
    }

    fn sessions_err(
        a: &Path,
        b: &Path,
        format_a: Option<&str>,
        format_b: Option<&str>,
    ) -> DiffSessionsError {
        match diff_sessions(a, b, format_a, format_b) {
            Ok(never) => match never {},
            Err(error) => error,
        }
    }

    fn assert_same_display(error: &DiffSessionsError) {
        let as_error: &dyn Error = error;
        assert_eq!(as_error.to_string(), error.to_string());
        assert!(as_error.source().is_none());
    }

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("sesslint-diff-{label}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn symlink_dir(original: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(original, link)
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(original, link)
        }
    }

    fn symlink_file(original: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(original, link)
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(original, link)
        }
    }
}
