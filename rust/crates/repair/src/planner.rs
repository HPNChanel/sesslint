//! Deterministic repair-plan values through loss accounting (TASK-018).
//!
//! Port of `src/sesslint/repair/planner.py` lines 1–270
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! Stops before `RepairPlan`. No I/O. Invalid input returns [`PlannerError`]
//! and does not panic. Type errors do not echo the rejected value.
//!
//! [`PlanStep::try_new`] checks loss-class names in insertion order.
//! [`PlanStep::from_dict`], [`Blocked::from_dict`], and [`Loss::from_dict`]
//! keep the pin's first-failure order. `params` and `loss` stay in insertion
//! order. A `BTreeMap` would sort those keys, so they are `Vec` pairs.

use std::error::Error;
use std::fmt;

use crate::refusals::{refusal_rationale_for, RefusalError, RefusalRationale};

/// Python: `MAX_STEPS`.
pub const MAX_STEPS: i64 = 256;

/// Python: `PLAN_VERSION`.
pub const PLAN_VERSION: &str = "sesslint.plan/v1";

/// Python: `EMPTY_EVENTS_HASH` (SHA-256 of empty input).
pub const EMPTY_EVENTS_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Python: `ALLOWED_LOSS_CLASSES`.
///
/// Membership is the contract. This slice is the pin literal order.
pub const ALLOWED_LOSS_CLASSES: [&str; 8] = [
    "amputated-branch",
    "discarded-suffix",
    "none",
    "orphan-result",
    "projected-orphans",
    "torn-record",
    "truncated-projection",
    "truncated-side-effects",
];

/// Python: `NON_EVENT_LOSS_CLASSES`.
///
/// Membership is the contract. A torn record is not a canonical event.
pub const NON_EVENT_LOSS_CLASSES: [&str; 1] = ["torn-record"];

/// Python: `EVENT_DROP_RECIPES`.
///
/// Membership is the contract. This slice is the pin literal order.
pub const EVENT_DROP_RECIPES: [&str; 9] = [
    "duplicate-projection-removal",
    "identical-duplicate-collapse",
    "identical-duplicate-drop",
    "orphan-result-drop",
    "side-effect-unknown-truncate",
    "terminal-suffix-discard",
    "torn-compaction-project",
    "torn-terminal-record-discard",
    "unresolvable-branch-amputate",
];

/// Python: `SYNTHETIC_STEP_FP`.
pub const SYNTHETIC_STEP_FP: &str = "-";

/// Python: `UNDECODED_RECORD_CODES`.
///
/// Membership is the contract. Order is the pin literal `SL001`, then `SL002`.
pub const UNDECODED_RECORD_CODES: [&str; 2] = ["SL001", "SL002"];

const DEFAULT_LOSS_PREVIEW: [(&str, i128); 3] = [
    ("discarded-suffix", 0),
    ("none", 0),
    ("truncated-projection", 0),
];

/// Python `ValueError` from plan-step, blocked-entry, and loss parsing.
///
/// [`Display`](fmt::Display) is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerError {
    message: String,
}

impl PlannerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PlannerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for PlannerError {}

/// Key of a [`PlanValue::Map`].
///
/// A non-string key stays representable so [`_object`] can reject it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanKey {
    Str(String),
    Int(i128),
    Bool(bool),
    None,
    /// Bit pattern of a Python `float`. Not an `int`.
    Float(u64),
    Bytes(Vec<u8>),
    Other {
        type_name: &'static str,
    },
}

impl PlanKey {
    pub fn str_key(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn int(value: i128) -> Self {
        Self::Int(value)
    }

    pub fn bool_value(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn none() -> Self {
        Self::None
    }

    pub fn float(value: f64) -> Self {
        Self::Float(value.to_bits())
    }

    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    pub fn other(type_name: &'static str) -> Self {
        Self::Other { type_name }
    }
}

/// JSON-like value used by plan dictionaries.
///
/// Map entries keep insertion order. This is not a `HashMap` or a `BTreeMap`.
/// [`PlanValue::Bool`] is not [`PlanValue::Int`]. `True` is not `1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanValue {
    None,
    Bool(bool),
    Int(i128),
    /// Bit pattern of a Python `float`. `type(value) is int` is false.
    Float(u64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<PlanValue>),
    Tuple(Vec<PlanValue>),
    Map(Vec<(PlanKey, PlanValue)>),
    Other {
        type_name: &'static str,
    },
}

impl PlanValue {
    pub fn none() -> Self {
        Self::None
    }

    pub fn bool_value(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn int(value: i128) -> Self {
        Self::Int(value)
    }

    pub fn float(value: f64) -> Self {
        Self::Float(value.to_bits())
    }

    pub fn str_value(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    pub fn list(items: Vec<Self>) -> Self {
        Self::List(items)
    }

    pub fn tuple(items: Vec<Self>) -> Self {
        Self::Tuple(items)
    }

    pub fn map(entries: Vec<(PlanKey, Self)>) -> Self {
        Self::Map(entries)
    }

    pub fn string_map(entries: Vec<(String, Self)>) -> Self {
        Self::map(
            entries
                .into_iter()
                .map(|(key, value)| (PlanKey::Str(key), value))
                .collect(),
        )
    }

    pub fn other(type_name: &'static str) -> Self {
        Self::Other { type_name }
    }
}

/// Python: `_object`.
///
/// A non-mapping, or any key whose type is not `str`, is
/// `{label} must be an object`.
///
/// # Errors
///
/// Returns [`PlannerError`]. This function does not panic.
pub fn _object<'a>(
    data: &'a PlanValue,
    label: &str,
) -> Result<&'a [(PlanKey, PlanValue)], PlannerError> {
    match data {
        PlanValue::Map(entries) => {
            if entries
                .iter()
                .any(|(key, _)| !matches!(key, PlanKey::Str(_)))
            {
                return Err(object_error(label));
            }
            Ok(entries)
        }
        _ => Err(object_error(label)),
    }
}

/// Python: `_strings`.
///
/// For each requested field that is present, a non-`str` value is
/// `{label} {name} must be a string`. Absent fields are not errors.
///
/// # Errors
///
/// Returns [`PlannerError`]. This function does not panic.
pub fn _strings(
    data: &[(PlanKey, PlanValue)],
    fields: &[&str],
    label: &str,
) -> Result<(), PlannerError> {
    for name in fields {
        if let Some(value) = lookup(data, name) {
            if !matches!(value, PlanValue::Str(_)) {
                return Err(PlannerError::new(format!(
                    "{label} {name} must be a string"
                )));
            }
        }
    }
    Ok(())
}

/// Python: `_counts`.
///
/// Calls [`_object`], then every value must be a real `int` `>= 0`.
/// [`PlanValue::Bool`] fails. Insertion order is preserved.
///
/// # Errors
///
/// Returns [`PlannerError`]. A non-object uses the [`_object`] message.
/// A bad count is `{label} must contain nonnegative integer counts`.
/// This function does not panic.
pub fn _counts(data: &PlanValue, label: &str) -> Result<Vec<(String, i128)>, PlannerError> {
    let entries = _object(data, label)?;
    let mut counts = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let name = match key {
            PlanKey::Str(name) => name.clone(),
            _ => return Err(object_error(label)),
        };
        match value {
            PlanValue::Int(count) if *count >= 0 => counts.push((name, *count)),
            _ => {
                return Err(PlannerError::new(format!(
                    "{label} must contain nonnegative integer counts"
                )));
            }
        }
    }
    Ok(counts)
}

/// Fields for [`PlanStep::try_new`].
///
/// [`PlanStepFields::new`] applies the dataclass defaults: empty `params`,
/// `lossy` false, empty `loss`, `min_policy` `"conservative"`, and
/// `recipe_version` `"1.0.0"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStepFields {
    pub seq: i128,
    pub recipe: String,
    pub target_finding_fp: String,
    pub target_index: Option<i128>,
    pub params: Vec<(String, PlanValue)>,
    pub lossy: bool,
    pub loss: Vec<(String, i128)>,
    pub min_policy: String,
    pub recipe_version: String,
}

impl PlanStepFields {
    pub fn new(
        seq: i128,
        recipe: impl Into<String>,
        target_finding_fp: impl Into<String>,
        target_index: Option<i128>,
    ) -> Self {
        Self {
            seq,
            recipe: recipe.into(),
            target_finding_fp: target_finding_fp.into(),
            target_index,
            params: Vec::new(),
            lossy: false,
            loss: Vec::new(),
            min_policy: "conservative".to_owned(),
            recipe_version: "1.0.0".to_owned(),
        }
    }
}

/// An individual proposed repair step.
///
/// Python: `PlanStep` (`frozen=True`, `slots=True`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    seq: i128,
    recipe: String,
    target_finding_fp: String,
    target_index: Option<i128>,
    params: Vec<(String, PlanValue)>,
    lossy: bool,
    loss: Vec<(String, i128)>,
    min_policy: String,
    recipe_version: String,
}

impl PlanStep {
    /// Python: `PlanStep.__post_init__`.
    ///
    /// Each loss key must be in [`ALLOWED_LOSS_CLASSES`]. The walk is insertion
    /// order. Other fields are stored as given.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError`] for an unknown loss class. This function does
    /// not panic.
    pub fn try_new(fields: PlanStepFields) -> Result<Self, PlannerError> {
        validate_loss_classes(&fields.loss)?;
        Ok(Self {
            seq: fields.seq,
            recipe: fields.recipe,
            target_finding_fp: fields.target_finding_fp,
            target_index: fields.target_index,
            params: fields.params,
            lossy: fields.lossy,
            loss: fields.loss,
            min_policy: fields.min_policy,
            recipe_version: fields.recipe_version,
        })
    }

    pub fn seq(&self) -> i128 {
        self.seq
    }

    pub fn recipe(&self) -> &str {
        &self.recipe
    }

    pub fn target_finding_fp(&self) -> &str {
        &self.target_finding_fp
    }

    pub fn target_index(&self) -> Option<i128> {
        self.target_index
    }

    pub fn params(&self) -> &[(String, PlanValue)] {
        &self.params
    }

    pub fn lossy(&self) -> bool {
        self.lossy
    }

    pub fn loss(&self) -> &[(String, i128)] {
        &self.loss
    }

    pub fn min_policy(&self) -> &str {
        &self.min_policy
    }

    pub fn recipe_version(&self) -> &str {
        &self.recipe_version
    }

    /// Python: `PlanStep.to_dict`.
    ///
    /// Key order is `min_policy`, `params`, `recipe`, `recipe_version`, `seq`,
    /// `target_finding_fp`, `target_index`. `lossy` and `loss` follow, in that
    /// order, only when `lossy` is true and `loss` is non-empty.
    pub fn to_dict(&self) -> Vec<(String, PlanValue)> {
        let mut entries = vec![
            (
                "min_policy".to_owned(),
                PlanValue::str_value(&self.min_policy),
            ),
            ("params".to_owned(), pairs_as_map(&self.params)),
            ("recipe".to_owned(), PlanValue::str_value(&self.recipe)),
            (
                "recipe_version".to_owned(),
                PlanValue::str_value(&self.recipe_version),
            ),
            ("seq".to_owned(), PlanValue::int(self.seq)),
            (
                "target_finding_fp".to_owned(),
                PlanValue::str_value(&self.target_finding_fp),
            ),
            ("target_index".to_owned(), optional_int(self.target_index)),
        ];
        if self.lossy && !self.loss.is_empty() {
            entries.push(("lossy".to_owned(), PlanValue::bool_value(self.lossy)));
            entries.push(("loss".to_owned(), counts_as_map(&self.loss)));
        }
        entries
    }

    /// Python: `PlanStep.from_dict`.
    ///
    /// Check order: object, strings (`recipe`, `min_policy`, `recipe_version`,
    /// `target_finding_fp`), `seq` and `target_index`, explicit null `seq`,
    /// `min_policy` value, `lossy` type, `params` object, `loss` counts,
    /// required fields, then the loss-class allowlist.
    /// `target_finding_fp` defaults to `""`. `target_index` may be null.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError`]. This function does not panic.
    pub fn from_dict(data: &PlanValue) -> Result<Self, PlannerError> {
        let entries = _object(data, "Plan step")?;
        _strings(
            entries,
            &[
                "recipe",
                "min_policy",
                "recipe_version",
                "target_finding_fp",
            ],
            "Plan step",
        )?;
        check_step_indexes(entries)?;
        check_min_policy(entries)?;
        check_lossy_flag(entries)?;
        let params = string_map_field(entries, "params", "Plan step params")?;
        let loss = count_field(entries, "loss", "Plan step loss")?;
        require_plan_step_fields(entries)?;
        Self::try_new(PlanStepFields {
            seq: demand_nonnegative(entries, "seq")?,
            recipe: demand_string(entries, "recipe")?,
            target_finding_fp: optional_string(entries, "target_finding_fp")?,
            target_index: optional_index(entries)?,
            params,
            lossy: optional_bool(entries)?,
            loss,
            min_policy: demand_string(entries, "min_policy")?,
            recipe_version: demand_string(entries, "recipe_version")?,
        })
    }
}

/// A finding that could not be automatically planned.
///
/// Python: `Blocked` (`frozen=True`, `slots=True`).
/// `reason` is the machine token. [`Blocked::describe`] adds a documented
/// rationale when one is registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    finding_fp: String,
    code: String,
    reason: String,
}

impl Blocked {
    /// Python field order: `finding_fp`, `code`, `reason`.
    pub fn new(
        finding_fp: impl Into<String>,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            finding_fp: finding_fp.into(),
            code: code.into(),
            reason: reason.into(),
        }
    }

    pub fn finding_fp(&self) -> &str {
        &self.finding_fp
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Python: `Blocked.refusal`.
    ///
    /// [`refusal_rationale_for`] `Ok(None)` is no rationale. `Ok(Some)` is that
    /// rationale. `Err` is propagated and is not turned into `None`.
    ///
    /// # Errors
    ///
    /// Returns [`RefusalError`] when the registered row fails construction.
    /// This function does not panic.
    pub fn refusal(&self) -> Result<Option<RefusalRationale>, RefusalError> {
        refusal_rationale_for(&self.code)
    }

    /// Python: `Blocked.describe`.
    ///
    /// No rationale returns the machine reason. A rationale returns
    /// `{reason}: {entry.render(None)}`. `render(None)` uses the default
    /// path `"<file>"`.
    ///
    /// # Errors
    ///
    /// Returns [`RefusalError`] from [`Blocked::refusal`]. This function does
    /// not panic.
    pub fn describe(&self) -> Result<String, RefusalError> {
        match self.refusal()? {
            None => Ok(self.reason.clone()),
            Some(entry) => {
                let reason = &self.reason;
                let detail = entry.render(None);
                Ok(format!("{reason}: {detail}"))
            }
        }
    }

    /// Python: `Blocked.to_dict` key order (`code`, `finding_fp`, `reason`).
    pub fn to_dict(&self) -> Vec<(String, PlanValue)> {
        vec![
            ("code".to_owned(), PlanValue::str_value(&self.code)),
            (
                "finding_fp".to_owned(),
                PlanValue::str_value(&self.finding_fp),
            ),
            ("reason".to_owned(), PlanValue::str_value(&self.reason)),
        ]
    }

    /// Python: `Blocked.from_dict`.
    ///
    /// Missing `finding_fp`, `code`, and `reason` become empty strings.
    /// The keys are not required.
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError`]. This function does not panic.
    pub fn from_dict(data: &PlanValue) -> Result<Self, PlannerError> {
        let entries = _object(data, "Blocked entry")?;
        _strings(entries, &["finding_fp", "code", "reason"], "Blocked entry")?;
        Ok(Self::new(
            copied_string(entries, "finding_fp", "Blocked entry")?,
            copied_string(entries, "code", "Blocked entry")?,
            copied_string(entries, "reason", "Blocked entry")?,
        ))
    }
}

/// Preview of anticipated data-loss counts.
///
/// Python: `Loss` (`frozen=True`, `slots=True`).
/// [`Loss::default`] preview order is `discarded-suffix`, `none`,
/// `truncated-projection`, each `0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loss {
    preview: Vec<(String, i128)>,
    total_lost: i128,
    total_kept: i128,
}

impl Default for Loss {
    fn default() -> Self {
        Self {
            preview: DEFAULT_LOSS_PREVIEW
                .iter()
                .map(|(name, count)| ((*name).to_owned(), *count))
                .collect(),
            total_lost: 0,
            total_kept: 0,
        }
    }
}

impl Loss {
    /// Store `preview` in the given order. Counts are not rechecked here.
    pub fn new(preview: Vec<(String, i128)>, total_lost: i128, total_kept: i128) -> Self {
        Self {
            preview,
            total_lost,
            total_kept,
        }
    }

    pub fn preview(&self) -> &[(String, i128)] {
        &self.preview
    }

    pub fn total_lost(&self) -> i128 {
        self.total_lost
    }

    pub fn total_kept(&self) -> i128 {
        self.total_kept
    }

    /// Python: `Loss.to_dict`.
    ///
    /// The only key is `preview`. `total_lost` and `total_kept` are omitted.
    pub fn to_dict(&self) -> Vec<(String, PlanValue)> {
        vec![("preview".to_owned(), counts_as_map(&self.preview))]
    }

    /// Python: `Loss.from_dict`.
    ///
    /// `preview` defaults to `{}`. `total_lost` and `total_kept` default to
    /// `0` and must be real ints `>= 0`. A bool fails. Totals are stored and
    /// are not added to [`Loss::to_dict`].
    ///
    /// # Errors
    ///
    /// Returns [`PlannerError`]. This function does not panic.
    pub fn from_dict(data: &PlanValue) -> Result<Self, PlannerError> {
        let entries = _object(data, "Loss accounting")?;
        let preview = count_field(entries, "preview", "Loss preview")?;
        let total_lost = loss_total(entries, "total_lost")?;
        let total_kept = loss_total(entries, "total_kept")?;
        Ok(Self::new(preview, total_lost, total_kept))
    }
}

fn object_error(label: &str) -> PlannerError {
    PlannerError::new(format!("{label} must be an object"))
}

fn lookup<'a>(entries: &'a [(PlanKey, PlanValue)], name: &str) -> Option<&'a PlanValue> {
    let mut found = None;
    for (key, value) in entries {
        if let PlanKey::Str(existing) = key {
            if existing == name {
                found = Some(value);
            }
        }
    }
    found
}

fn is_nonnegative_int(value: &PlanValue) -> bool {
    matches!(value, PlanValue::Int(count) if *count >= 0)
}

fn check_step_indexes(entries: &[(PlanKey, PlanValue)]) -> Result<(), PlannerError> {
    for name in ["seq", "target_index"] {
        if let Some(value) = lookup(entries, name) {
            if !matches!(value, PlanValue::None) && !is_nonnegative_int(value) {
                return Err(PlannerError::new(format!(
                    "Plan step {name} must be a nonnegative integer"
                )));
            }
        }
    }
    if matches!(lookup(entries, "seq"), Some(PlanValue::None)) {
        return Err(PlannerError::new(
            "Plan step seq must be a nonnegative integer",
        ));
    }
    Ok(())
}

fn check_min_policy(entries: &[(PlanKey, PlanValue)]) -> Result<(), PlannerError> {
    let Some(value) = lookup(entries, "min_policy") else {
        return Ok(());
    };
    match value {
        PlanValue::Str(text) if text == "conservative" || text == "salvage" => Ok(()),
        PlanValue::Str(_) => Err(PlannerError::new("Plan step min_policy is unsupported")),
        _ => Err(PlannerError::new("Plan step min_policy must be a string")),
    }
}

fn check_lossy_flag(entries: &[(PlanKey, PlanValue)]) -> Result<(), PlannerError> {
    if let Some(value) = lookup(entries, "lossy") {
        if !matches!(value, PlanValue::Bool(_)) {
            return Err(PlannerError::new("Plan step lossy must be a boolean"));
        }
    }
    Ok(())
}

fn require_plan_step_fields(entries: &[(PlanKey, PlanValue)]) -> Result<(), PlannerError> {
    for name in ["seq", "recipe", "min_policy", "recipe_version"] {
        if lookup(entries, name).is_none() {
            let shown = python_str_repr(name);
            return Err(PlannerError::new(format!(
                "Plan step missing required field {shown}"
            )));
        }
    }
    Ok(())
}

fn demand_nonnegative(entries: &[(PlanKey, PlanValue)], name: &str) -> Result<i128, PlannerError> {
    match lookup(entries, name) {
        Some(PlanValue::Int(value)) if *value >= 0 => Ok(*value),
        _ => Err(PlannerError::new(format!(
            "Plan step {name} must be a nonnegative integer"
        ))),
    }
}

fn demand_string(entries: &[(PlanKey, PlanValue)], name: &str) -> Result<String, PlannerError> {
    match lookup(entries, name) {
        Some(PlanValue::Str(text)) => Ok(text.clone()),
        _ => {
            let shown = python_str_repr(name);
            Err(PlannerError::new(format!(
                "Plan step missing required field {shown}"
            )))
        }
    }
}

fn optional_string(entries: &[(PlanKey, PlanValue)], name: &str) -> Result<String, PlannerError> {
    match lookup(entries, name) {
        None => Ok(String::new()),
        Some(PlanValue::Str(text)) => Ok(text.clone()),
        Some(_) => Err(PlannerError::new(format!(
            "Plan step {name} must be a string"
        ))),
    }
}

fn optional_index(entries: &[(PlanKey, PlanValue)]) -> Result<Option<i128>, PlannerError> {
    match lookup(entries, "target_index") {
        None | Some(PlanValue::None) => Ok(None),
        Some(PlanValue::Int(value)) if *value >= 0 => Ok(Some(*value)),
        Some(_) => Err(PlannerError::new(
            "Plan step target_index must be a nonnegative integer",
        )),
    }
}

fn optional_bool(entries: &[(PlanKey, PlanValue)]) -> Result<bool, PlannerError> {
    match lookup(entries, "lossy") {
        None => Ok(false),
        Some(PlanValue::Bool(value)) => Ok(*value),
        Some(_) => Err(PlannerError::new("Plan step lossy must be a boolean")),
    }
}

fn string_map_field(
    entries: &[(PlanKey, PlanValue)],
    name: &str,
    label: &str,
) -> Result<Vec<(String, PlanValue)>, PlannerError> {
    let owned = match lookup(entries, name) {
        Some(value) => value.clone(),
        None => PlanValue::map(Vec::new()),
    };
    let parsed = _object(&owned, label)?;
    owned_string_map(parsed, label)
}

fn count_field(
    entries: &[(PlanKey, PlanValue)],
    name: &str,
    label: &str,
) -> Result<Vec<(String, i128)>, PlannerError> {
    let owned = match lookup(entries, name) {
        Some(value) => value.clone(),
        None => PlanValue::map(Vec::new()),
    };
    _counts(&owned, label)
}

fn copied_string(
    entries: &[(PlanKey, PlanValue)],
    name: &str,
    label: &str,
) -> Result<String, PlannerError> {
    match lookup(entries, name) {
        None => Ok(String::new()),
        Some(PlanValue::Str(text)) => Ok(text.clone()),
        Some(_) => Err(PlannerError::new(format!(
            "{label} {name} must be a string"
        ))),
    }
}

fn loss_total(entries: &[(PlanKey, PlanValue)], name: &str) -> Result<i128, PlannerError> {
    match lookup(entries, name) {
        None => Ok(0),
        Some(PlanValue::Int(value)) if *value >= 0 => Ok(*value),
        Some(_) => Err(PlannerError::new(format!(
            "Loss {name} must be a nonnegative integer"
        ))),
    }
}

fn owned_string_map(
    entries: &[(PlanKey, PlanValue)],
    label: &str,
) -> Result<Vec<(String, PlanValue)>, PlannerError> {
    let mut owned = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        match key {
            PlanKey::Str(name) => owned.push((name.clone(), value.clone())),
            _ => return Err(object_error(label)),
        }
    }
    Ok(owned)
}

fn validate_loss_classes(loss: &[(String, i128)]) -> Result<(), PlannerError> {
    for (key, _) in loss {
        if !ALLOWED_LOSS_CLASSES.contains(&key.as_str()) {
            let shown = python_str_repr(key);
            let allowed = sorted_allowed_loss_classes();
            return Err(PlannerError::new(format!(
                "Invalid loss class: {shown}. Must be one of {allowed}"
            )));
        }
    }
    Ok(())
}

fn sorted_allowed_loss_classes() -> String {
    let mut names = ALLOWED_LOSS_CLASSES;
    names.sort_unstable();
    python_list_repr(&names)
}

fn pairs_as_map(entries: &[(String, PlanValue)]) -> PlanValue {
    PlanValue::map(
        entries
            .iter()
            .map(|(key, value)| (PlanKey::Str(key.clone()), value.clone()))
            .collect(),
    )
}

fn counts_as_map(entries: &[(String, i128)]) -> PlanValue {
    PlanValue::map(
        entries
            .iter()
            .map(|(key, value)| (PlanKey::Str(key.clone()), PlanValue::int(*value)))
            .collect(),
    )
}

fn optional_int(value: Option<i128>) -> PlanValue {
    match value {
        Some(number) => PlanValue::int(number),
        None => PlanValue::none(),
    }
}

fn python_list_repr(values: &[&str]) -> String {
    let mut out = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&python_str_repr(value));
    }
    out.push(']');
    out
}

/// Python `repr` for `str` (`{value!r}`), preferring single quotes.
fn python_str_repr(value: &str) -> String {
    let use_double = value.contains('\'') && !value.contains('"');
    let quote = if use_double { '"' } else { '\'' };
    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\'' if !use_double => out.push_str("\\'"),
            '"' if use_double => out.push_str("\\\""),
            other if is_python_printable(other) => out.push(other),
            other => push_python_escape(&mut out, other),
        }
    }
    out.push(quote);
    out
}

fn is_python_printable(ch: char) -> bool {
    if ch == ' ' || ch.is_ascii_graphic() {
        return true;
    }
    if ch.is_ascii() {
        return false;
    }
    !is_python_nonprintable_non_ascii(ch)
}

fn is_python_nonprintable_non_ascii(ch: char) -> bool {
    if ch.is_control() || ch.is_whitespace() || is_noncharacter(u32::from(ch)) {
        return true;
    }
    const RANGES: [(u32, u32); 18] = [
        (0x00AD, 0x00AD),
        (0x0600, 0x0605),
        (0x061C, 0x061C),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x0890, 0x0891),
        (0x08E2, 0x08E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0xE000, 0xF8FF),
        (0xF0000, 0xFFFFD),
        (0x100000, 0x10FFFD),
        (0xE0001, 0xE0001),
    ];
    let code = u32::from(ch);
    RANGES
        .iter()
        .any(|(start, end)| code >= *start && code <= *end)
        || matches!(
            code,
            0x110BD | 0x110CD | 0x13430..=0x1343F | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A
        )
        || (0xE0020..=0xE007F).contains(&code)
        || (0xE0100..=0xE01EF).contains(&code)
}

fn is_noncharacter(code: u32) -> bool {
    (0xFDD0..=0xFDEF).contains(&code) || (code & 0xFFFE) == 0xFFFE
}

fn push_python_escape(out: &mut String, ch: char) {
    let code = u32::from(ch);
    if code < 0x100 {
        push_hex(out, "\\x", code, 2);
    } else if code < 0x10000 {
        push_hex(out, "\\u", code, 4);
    } else {
        push_hex(out, "\\U", code, 8);
    }
}

fn push_hex(out: &mut String, prefix: &str, value: u32, width: usize) {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    out.push_str(prefix);
    for shift in (0..width).rev() {
        let nibble = ((value >> (shift * 4)) & 0xf) as usize;
        out.push(char::from(HEX[nibble]));
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        Blocked, Loss, PlanKey, PlanStep, PlanStepFields, PlanValue, PlannerError, _counts,
        _object, _strings, ALLOWED_LOSS_CLASSES, EMPTY_EVENTS_HASH, EVENT_DROP_RECIPES, MAX_STEPS,
        NON_EVENT_LOSS_CLASSES, PLAN_VERSION, SYNTHETIC_STEP_FP, UNDECODED_RECORD_CODES,
    };

    const ALLOWED_REPR: &str = concat!(
        "['amputated-branch', 'discarded-suffix', 'none', 'orphan-result', ",
        "'projected-orphans', 'torn-record', 'truncated-projection', ",
        "'truncated-side-effects']"
    );

    fn obj(pairs: impl IntoIterator<Item = (&'static str, PlanValue)>) -> PlanValue {
        PlanValue::map(
            pairs
                .into_iter()
                .map(|(key, value)| (PlanKey::str_key(key), value))
                .collect(),
        )
    }

    fn text(value: &str) -> PlanValue {
        PlanValue::str_value(value)
    }

    fn step_err(data: &PlanValue) -> String {
        PlanStep::from_dict(data)
            .expect_err("rejected step")
            .to_string()
    }

    fn required(extra: impl IntoIterator<Item = (&'static str, PlanValue)>) -> PlanValue {
        let mut pairs = vec![
            ("seq", PlanValue::int(1)),
            ("recipe", text("recipe-alpha")),
            ("min_policy", text("conservative")),
            ("recipe_version", text("1.0.0")),
        ];
        pairs.extend(extra);
        obj(pairs)
    }

    fn dict_keys(entries: &[(String, PlanValue)]) -> Vec<&str> {
        entries.iter().map(|(key, _)| key.as_str()).collect()
    }

    fn nested_keys(value: &PlanValue) -> Vec<&str> {
        let PlanValue::Map(entries) = value else {
            panic!("expected map");
        };
        entries
            .iter()
            .map(|(key, _)| match key {
                PlanKey::Str(name) => name.as_str(),
                _ => panic!("expected string key"),
            })
            .collect()
    }

    #[test]
    fn module_constants_keep_pin_membership() {
        assert_eq!(MAX_STEPS, 256);
        assert_eq!(PLAN_VERSION, "sesslint.plan/v1");
        assert_eq!(
            EMPTY_EVENTS_HASH,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(SYNTHETIC_STEP_FP, "-");
        assert_eq!(
            ALLOWED_LOSS_CLASSES,
            [
                "amputated-branch",
                "discarded-suffix",
                "none",
                "orphan-result",
                "projected-orphans",
                "torn-record",
                "truncated-projection",
                "truncated-side-effects",
            ]
        );
        assert_eq!(NON_EVENT_LOSS_CLASSES, ["torn-record"]);
        assert_eq!(
            EVENT_DROP_RECIPES,
            [
                "duplicate-projection-removal",
                "identical-duplicate-collapse",
                "identical-duplicate-drop",
                "orphan-result-drop",
                "side-effect-unknown-truncate",
                "terminal-suffix-discard",
                "torn-compaction-project",
                "torn-terminal-record-discard",
                "unresolvable-branch-amputate",
            ]
        );
        assert_eq!(UNDECODED_RECORD_CODES, ["SL001", "SL002"]);
        assert!(!ALLOWED_LOSS_CLASSES.contains(&"seq-renumber"));
        assert!(!NON_EVENT_LOSS_CLASSES.contains(&"discarded-suffix"));
        assert!(!EVENT_DROP_RECIPES.contains(&"seq-renumber"));
        assert!(!UNDECODED_RECORD_CODES.contains(&"SL003"));
    }

    #[test]
    fn object_rejects_non_mappings_and_non_string_keys() {
        let expected = "Plan step must be an object";
        let non_maps = [
            PlanValue::none(),
            PlanValue::bool_value(true),
            PlanValue::int(7),
            PlanValue::float(1.0),
            PlanValue::str_value("text"),
            PlanValue::bytes(b"bytes".to_vec()),
            PlanValue::list(vec![PlanValue::int(1)]),
            PlanValue::tuple(vec![]),
            PlanValue::other("set"),
        ];
        for value in non_maps {
            let err = _object(&value, "Plan step").expect_err("non-map");
            assert_eq!(err.to_string(), expected);
            assert!(err.source().is_none());
        }
        let bad_keys = [
            PlanKey::int(7),
            PlanKey::bool_value(true),
            PlanKey::bool_value(false),
            PlanKey::none(),
            PlanKey::float(1.5),
            PlanKey::bytes(b"k".to_vec()),
            PlanKey::other("tuple"),
        ];
        for key in bad_keys {
            let value = PlanValue::map(vec![
                (key, PlanValue::str_value("hidden-value")),
                (PlanKey::str_key("recipe"), text("recipe-alpha")),
            ]);
            let err = _object(&value, "Plan step").expect_err("bad key");
            assert_eq!(err.to_string(), expected);
            assert!(!err.to_string().contains("hidden-value"));
        }
        let value = obj([("recipe", text("recipe-alpha"))]);
        let ok = _object(&value, "Plan step").expect("object");
        assert_eq!(ok.len(), 1);
    }

    #[test]
    fn strings_skip_absent_fields_and_keep_requested_order() {
        let fields = [
            "recipe",
            "min_policy",
            "recipe_version",
            "target_finding_fp",
        ];
        let absent_value = obj([("other", PlanValue::int(1))]);
        let absent = _object(&absent_value, "Plan step").expect("object");
        assert!(_strings(absent, &fields, "Plan step").is_ok());

        let later_value = obj([("min_policy", PlanValue::int(4))]);
        let later = _object(&later_value, "Plan step").expect("object");
        let err = _strings(later, &fields, "Plan step").expect_err("min_policy");
        assert_eq!(err.to_string(), "Plan step min_policy must be a string");
        assert!(!err.to_string().contains('4'));

        let both_value = obj([
            ("min_policy", PlanValue::int(1)),
            ("recipe", PlanValue::bool_value(false)),
        ]);
        let both = _object(&both_value, "Plan step").expect("object");
        let err = _strings(both, &fields, "Plan step").expect_err("recipe first");
        assert_eq!(err.to_string(), "Plan step recipe must be a string");
    }

    #[test]
    fn strings_reject_each_present_non_string() {
        let fields = ["recipe"];
        let bad = [
            PlanValue::none(),
            PlanValue::bool_value(true),
            PlanValue::int(3),
            PlanValue::float(1.0),
            PlanValue::bytes(b"xyz".to_vec()),
            PlanValue::list(vec![]),
            PlanValue::map(vec![]),
            PlanValue::other("set"),
        ];
        for value in bad {
            let data = obj([("recipe", value)]);
            let entries = _object(&data, "Plan step").expect("object");
            let err = _strings(entries, &fields, "Plan step").expect_err("type");
            assert_eq!(err.to_string(), "Plan step recipe must be a string");
            assert!(!err.to_string().contains("xyz"));
        }
        let empty_recipe = obj([("recipe", text(""))]);
        let entries = _object(&empty_recipe, "Plan step").expect("object");
        assert!(_strings(entries, &fields, "Plan step").is_ok());
    }

    #[test]
    fn counts_require_nonnegative_ints_and_keep_order() {
        let counted = _counts(
            &obj([("b", PlanValue::int(2)), ("a", PlanValue::int(0))]),
            "Loss preview",
        )
        .expect("counts");
        assert_eq!(counted, vec![("b".to_owned(), 2), ("a".to_owned(), 0)]);

        for value in [
            PlanValue::bool_value(true),
            PlanValue::bool_value(false),
            PlanValue::int(-1),
            PlanValue::float(1.0),
            PlanValue::str_value("echo-me"),
            PlanValue::none(),
            PlanValue::list(vec![]),
        ] {
            let err = _counts(&obj([("none", value)]), "Loss preview").expect_err("count");
            assert_eq!(
                err.to_string(),
                "Loss preview must contain nonnegative integer counts"
            );
            assert!(!err.to_string().contains("echo-me"));
        }
        let err = _counts(&PlanValue::list(vec![]), "Plan step loss").expect_err("list");
        assert_eq!(err.to_string(), "Plan step loss must be an object");
        let keyed = PlanValue::map(vec![(PlanKey::bool_value(true), PlanValue::int(1))]);
        let err = _counts(&keyed, "Plan step loss").expect_err("key");
        assert_eq!(err.to_string(), "Plan step loss must be an object");
    }

    #[test]
    fn plan_step_post_init_rejects_the_first_unknown_loss_class() {
        let mut fields = PlanStepFields::new(1, "recipe-alpha", "fp-alpha", Some(0));
        fields.loss = vec![("not-a-class".to_owned(), 99), ("also-bad".to_owned(), 2)];
        let err = PlanStep::try_new(fields).expect_err("class");
        assert_eq!(
            err.to_string(),
            format!("Invalid loss class: 'not-a-class'. Must be one of {ALLOWED_REPR}")
        );
        assert!(!err.to_string().contains("also-bad"));
        assert!(!err.to_string().contains("99"));

        for (key, shown) in [
            ("a'b", "\"a'b\""),
            ("a\"b", "'a\"b'"),
            ("", "''"),
            ("line\nbreak", "'line\\nbreak'"),
            ("a'b\"c", "'a\\'b\"c'"),
            ("a\\b", "'a\\\\b'"),
        ] {
            let mut fields = PlanStepFields::new(-1, "", "", None);
            fields.loss = vec![(key.to_owned(), -5)];
            let err = PlanStep::try_new(fields).expect_err("repr");
            assert_eq!(
                err.to_string(),
                format!("Invalid loss class: {shown}. Must be one of {ALLOWED_REPR}")
            );
        }
    }

    #[test]
    fn plan_step_try_new_stores_defaults_and_allowed_loss_order() {
        let step = PlanStep::try_new(PlanStepFields::new(-1, "recipe-alpha", "fp-alpha", None))
            .expect("defaults");
        assert_eq!(step.seq(), -1);
        assert!(!step.lossy());
        assert!(step.loss().is_empty());
        assert_eq!(step.min_policy(), "conservative");
        assert_eq!(step.recipe_version(), "1.0.0");
        assert_eq!(step.target_index(), None);

        let order = [
            "truncated-side-effects",
            "amputated-branch",
            "none",
            "torn-record",
            "discarded-suffix",
            "orphan-result",
            "projected-orphans",
            "truncated-projection",
        ];
        let mut fields = PlanStepFields::new(0, "recipe-alpha", "", Some(0));
        fields.lossy = true;
        fields.loss = order
            .iter()
            .enumerate()
            .map(|(index, name)| ((*name).to_owned(), i128::from(index as u32)))
            .collect();
        fields.params = vec![
            ("z-param".to_owned(), PlanValue::int(1)),
            ("a-param".to_owned(), PlanValue::bool_value(false)),
        ];
        let step = PlanStep::try_new(fields).expect("allowed");
        let encoded = step.to_dict();
        assert_eq!(
            dict_keys(&encoded),
            [
                "min_policy",
                "params",
                "recipe",
                "recipe_version",
                "seq",
                "target_finding_fp",
                "target_index",
                "lossy",
                "loss",
            ]
        );
        assert_eq!(nested_keys(&encoded[1].1), ["z-param", "a-param"]);
        assert_eq!(nested_keys(&encoded[8].1), order);
        assert_eq!(encoded[6].1, PlanValue::int(0));
        assert_eq!(encoded[7].1, PlanValue::bool_value(true));
    }

    #[test]
    fn plan_step_to_dict_omits_loss_unless_lossy_and_non_empty() {
        let mut quiet = PlanStepFields::new(2, "recipe-alpha", "fp-alpha", None);
        quiet.lossy = true;
        let step = PlanStep::try_new(quiet).expect("empty loss");
        assert!(step.lossy());
        assert_eq!(dict_keys(&step.to_dict()).len(), 7);

        let mut kept = PlanStepFields::new(2, "recipe-alpha", "fp-alpha", None);
        kept.lossy = false;
        kept.loss = vec![("none".to_owned(), 3), ("discarded-suffix".to_owned(), 1)];
        let step = PlanStep::try_new(kept).expect("stored loss");
        assert_eq!(step.loss().len(), 2);
        assert_eq!(dict_keys(&step.to_dict()).len(), 7);
        assert_eq!(step.to_dict()[6].1, PlanValue::none());
    }

    #[test]
    fn plan_step_from_dict_first_failure_order() {
        assert_eq!(
            step_err(&PlanValue::list(vec![])),
            "Plan step must be an object"
        );
        let bad_key = PlanValue::map(vec![(PlanKey::int(5), text("recipe-alpha"))]);
        assert_eq!(step_err(&bad_key), "Plan step must be an object");
        assert!(!step_err(&bad_key).contains('5'));

        assert_eq!(
            step_err(&obj([
                ("seq", text("1")),
                ("recipe", PlanValue::int(3)),
                ("min_policy", PlanValue::int(4)),
            ])),
            "Plan step recipe must be a string"
        );
        assert_eq!(
            step_err(&required([
                ("target_finding_fp", PlanValue::int(8)),
                ("seq", text("no"))
            ])),
            "Plan step target_finding_fp must be a string"
        );
        assert_eq!(
            step_err(&obj([
                ("seq", PlanValue::bool_value(true)),
                ("target_index", PlanValue::bool_value(true)),
                ("recipe", text("recipe-alpha")),
                ("min_policy", text("nope")),
                ("recipe_version", text("1.0.0")),
            ])),
            "Plan step seq must be a nonnegative integer"
        );
        assert_eq!(
            step_err(&required([
                ("seq", PlanValue::int(-1)),
                ("target_index", PlanValue::float(1.0))
            ])),
            "Plan step seq must be a nonnegative integer"
        );
        assert_eq!(
            step_err(&required([
                ("target_index", PlanValue::bool_value(true)),
                ("min_policy", text("nope")),
            ])),
            "Plan step target_index must be a nonnegative integer"
        );
        assert_eq!(
            step_err(&required([
                ("seq", PlanValue::none()),
                ("min_policy", text("nope"))
            ])),
            "Plan step seq must be a nonnegative integer"
        );
        assert_eq!(
            step_err(&required([
                ("min_policy", text("nope")),
                ("lossy", PlanValue::int(1)),
            ])),
            "Plan step min_policy is unsupported"
        );
        assert_eq!(
            step_err(&required([("min_policy", PlanValue::int(1))])),
            "Plan step min_policy must be a string"
        );
        assert_eq!(
            step_err(&required([
                ("lossy", text("yes")),
                ("params", PlanValue::list(vec![])),
            ])),
            "Plan step lossy must be a boolean"
        );
        assert_eq!(
            step_err(&required([
                ("params", PlanValue::list(vec![])),
                ("loss", text("bad")),
            ])),
            "Plan step params must be an object"
        );
        let params = PlanValue::map(vec![(PlanKey::int(9), PlanValue::int(1))]);
        assert_eq!(
            step_err(&required([("params", params)])),
            "Plan step params must be an object"
        );
        assert_eq!(
            step_err(&obj([
                ("seq", PlanValue::int(1)),
                ("min_policy", text("conservative")),
                ("recipe_version", text("1.0.0")),
                ("loss", obj([("none", PlanValue::int(-1))]),),
            ])),
            "Plan step loss must contain nonnegative integer counts"
        );
        assert_eq!(
            step_err(&required([(
                "loss",
                obj([("none", PlanValue::bool_value(true))])
            )])),
            "Plan step loss must contain nonnegative integer counts"
        );
        assert_eq!(
            step_err(&obj([("recipe", text("recipe-alpha"))])),
            "Plan step missing required field 'seq'"
        );
        assert_eq!(
            step_err(&obj([
                ("seq", PlanValue::int(0)),
                ("min_policy", text("salvage")),
                ("recipe_version", text("1.0.0")),
            ])),
            "Plan step missing required field 'recipe'"
        );
        assert_eq!(
            step_err(&obj([
                ("seq", PlanValue::int(0)),
                ("recipe", text("recipe-alpha")),
                ("recipe_version", text("1.0.0")),
                ("loss", obj([("not-a-class", PlanValue::int(1))])),
            ])),
            "Plan step missing required field 'min_policy'"
        );
        assert_eq!(
            step_err(&obj([
                ("seq", PlanValue::int(0)),
                ("recipe", text("recipe-alpha")),
                ("min_policy", text("conservative")),
                ("loss", obj([("not-a-class", PlanValue::int(1))])),
            ])),
            "Plan step missing required field 'recipe_version'"
        );
        assert_eq!(
            step_err(&required([(
                "loss",
                obj([
                    ("not-a-class", PlanValue::int(4)),
                    ("also-bad", PlanValue::int(5)),
                ]),
            )])),
            format!("Invalid loss class: 'not-a-class'. Must be one of {ALLOWED_REPR}")
        );
    }

    #[test]
    fn plan_step_from_dict_accepts_boundaries_and_preserves_params() {
        let parsed = PlanStep::from_dict(&required([
            ("seq", PlanValue::int(0)),
            ("recipe", text("")),
            ("min_policy", text("salvage")),
            ("target_index", PlanValue::int(0)),
            ("target_finding_fp", text("fp-alpha")),
            ("lossy", PlanValue::bool_value(true)),
            (
                "params",
                obj([
                    ("z-param", PlanValue::int(1)),
                    ("a-param", PlanValue::none()),
                    ("f-param", PlanValue::float(1.5)),
                    ("L-param", PlanValue::list(vec![text("item")])),
                ]),
            ),
            (
                "loss",
                obj([
                    ("none", PlanValue::int(2)),
                    ("discarded-suffix", PlanValue::int(1)),
                ]),
            ),
            ("extra", PlanValue::int(9)),
        ]))
        .expect("step");
        assert_eq!(parsed.seq(), 0);
        assert_eq!(parsed.recipe(), "");
        assert_eq!(parsed.min_policy(), "salvage");
        assert_eq!(parsed.target_index(), Some(0));
        assert_eq!(parsed.target_finding_fp(), "fp-alpha");
        assert!(parsed.lossy());
        assert_eq!(
            parsed
                .params()
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            ["z-param", "a-param", "f-param", "L-param"]
        );
        assert_eq!(
            parsed.loss(),
            [("none".to_owned(), 2), ("discarded-suffix".to_owned(), 1)]
        );
        let encoded = parsed.to_dict();
        assert_eq!(nested_keys(&encoded[8].1), ["none", "discarded-suffix"]);
        let again = PlanStep::from_dict(&PlanValue::string_map(encoded)).expect("round trip");
        assert_eq!(again, parsed);

        let missing_index = PlanStep::from_dict(&required([])).expect("missing index");
        assert_eq!(missing_index.target_index(), None);
        assert_eq!(missing_index.target_finding_fp(), "");
        assert!(!missing_index.lossy());
        let explicit_null = PlanStep::from_dict(&required([("target_index", PlanValue::none())]))
            .expect("null index");
        assert_eq!(explicit_null.target_index(), None);

        let lossy_only = PlanStep::from_dict(&required([("lossy", PlanValue::bool_value(true))]))
            .expect("lossy");
        assert!(lossy_only.lossy());
        assert!(lossy_only.loss().is_empty());
        assert_eq!(dict_keys(&lossy_only.to_dict()).len(), 7);
    }

    #[test]
    fn blocked_dict_order_and_optional_fields() {
        let blocked = Blocked::new("fp-alpha", "SL001", "cap-overflow");
        assert_eq!(
            dict_keys(&blocked.to_dict()),
            ["code", "finding_fp", "reason"]
        );
        let again =
            Blocked::from_dict(&PlanValue::string_map(blocked.to_dict())).expect("round trip");
        assert_eq!(again, blocked);

        let empty = Blocked::from_dict(&obj([])).expect("empty");
        assert_eq!(empty.finding_fp(), "");
        assert_eq!(empty.code(), "");
        assert_eq!(empty.reason(), "");

        let extra = Blocked::from_dict(&obj([
            ("code", text("SL203")),
            ("extra", PlanValue::int(1)),
        ]))
        .expect("extra");
        assert_eq!(extra.code(), "SL203");
        assert_eq!(extra.finding_fp(), "");

        let err = Blocked::from_dict(&obj([
            ("code", PlanValue::int(1)),
            ("finding_fp", PlanValue::int(4)),
        ]))
        .expect_err("types");
        assert_eq!(err.to_string(), "Blocked entry finding_fp must be a string");
        assert!(!err.to_string().contains('4'));
        assert_eq!(
            Blocked::from_dict(&PlanValue::list(vec![]))
                .expect_err("list")
                .to_string(),
            "Blocked entry must be an object"
        );
        let bad_key = PlanValue::map(vec![(PlanKey::none(), text("x"))]);
        assert_eq!(
            Blocked::from_dict(&bad_key).expect_err("key").to_string(),
            "Blocked entry must be an object"
        );
    }

    #[test]
    fn blocked_describe_uses_registered_rationale_or_machine_reason() {
        let unknown = Blocked::new("fp-alpha", "cap-overflow", "cap-overflow");
        assert!(unknown.refusal().expect("lookup").is_none());
        assert_eq!(unknown.describe().expect("describe"), "cap-overflow");

        let sl001 = Blocked::new("fp-alpha", "SL001", "blocked-token");
        let entry = sl001.refusal().expect("registry").expect("rationale");
        let rendered = entry.render(None);
        assert_eq!(
            sl001.describe().expect("describe"),
            format!("blocked-token: {rendered}")
        );
        assert!(rendered.contains("<file>"));
        assert!(rendered.contains("DEMAND: AC-004"));
        assert!(!rendered.contains("{path}"));

        let sl203 = Blocked::new("fp-alpha", "SL203", "SL203-refusal");
        let entry = sl203.refusal().expect("registry").expect("rationale");
        assert!(entry.salvage_path().is_none());
        let text = sl203.describe().expect("describe");
        assert_eq!(text, format!("SL203-refusal: {}", entry.render(None)));
        assert!(!text.contains("<file>"));
        assert!(text.contains("FR-060"));
    }

    #[test]
    fn loss_default_preview_order_and_totals_stay_off_the_dict() {
        let loss = Loss::default();
        assert_eq!(
            loss.preview(),
            [
                ("discarded-suffix".to_owned(), 0),
                ("none".to_owned(), 0),
                ("truncated-projection".to_owned(), 0),
            ]
        );
        assert_eq!(loss.total_lost(), 0);
        assert_eq!(loss.total_kept(), 0);
        let encoded = loss.to_dict();
        assert_eq!(dict_keys(&encoded), ["preview"]);
        assert_eq!(
            nested_keys(&encoded[0].1),
            ["discarded-suffix", "none", "truncated-projection"]
        );

        let custom = Loss::new(
            vec![("z-class".to_owned(), 2), ("a-class".to_owned(), 0)],
            4,
            5,
        );
        assert_eq!(custom.total_lost(), 4);
        assert_eq!(custom.total_kept(), 5);
        let encoded = custom.to_dict();
        assert_eq!(dict_keys(&encoded), ["preview"]);
        assert_eq!(nested_keys(&encoded[0].1), ["z-class", "a-class"]);
        let again = Loss::from_dict(&PlanValue::string_map(encoded)).expect("round trip");
        assert_eq!(again.preview(), custom.preview());
        assert_eq!(again.total_lost(), 0);
        assert_eq!(again.total_kept(), 0);
    }

    #[test]
    fn loss_from_dict_first_failure_and_defaults() {
        let empty = Loss::from_dict(&obj([])).expect("empty");
        assert!(empty.preview().is_empty());
        assert_eq!(empty.total_lost(), 0);
        assert_eq!(empty.total_kept(), 0);

        let parsed = Loss::from_dict(&obj([
            (
                "preview",
                obj([
                    ("torn-record", PlanValue::int(0)),
                    ("none", PlanValue::int(3)),
                ]),
            ),
            ("total_lost", PlanValue::int(8)),
            ("extra", text("ignored")),
        ]))
        .expect("preview");
        assert_eq!(
            parsed.preview(),
            [("torn-record".to_owned(), 0), ("none".to_owned(), 3)]
        );
        assert_eq!(parsed.total_lost(), 8);
        assert_eq!(parsed.total_kept(), 0);
        assert_eq!(dict_keys(&parsed.to_dict()), ["preview"]);

        assert_eq!(
            Loss::from_dict(&PlanValue::int(1))
                .expect_err("type")
                .to_string(),
            "Loss accounting must be an object"
        );
        let bad_key = PlanValue::map(vec![(PlanKey::int(99), PlanValue::int(1))]);
        let err = Loss::from_dict(&bad_key).expect_err("key");
        assert_eq!(err.to_string(), "Loss accounting must be an object");
        assert!(!err.to_string().contains("99"));

        assert_eq!(
            Loss::from_dict(&obj([
                ("total_lost", PlanValue::bool_value(true)),
                ("preview", PlanValue::int(1)),
            ]))
            .expect_err("preview")
            .to_string(),
            "Loss preview must be an object"
        );
        let err = Loss::from_dict(&obj([(
            "preview",
            obj([("none", PlanValue::str_value("echo-me"))]),
        )]))
        .expect_err("count");
        assert_eq!(
            err.to_string(),
            "Loss preview must contain nonnegative integer counts"
        );
        assert!(!err.to_string().contains("echo-me"));

        assert_eq!(
            Loss::from_dict(&obj([
                ("total_kept", PlanValue::int(-1)),
                ("total_lost", PlanValue::bool_value(true)),
            ]))
            .expect_err("lost")
            .to_string(),
            "Loss total_lost must be a nonnegative integer"
        );
        assert_eq!(
            Loss::from_dict(&obj([("total_kept", PlanValue::none())]))
                .expect_err("kept")
                .to_string(),
            "Loss total_kept must be a nonnegative integer"
        );
        assert_eq!(
            Loss::from_dict(&obj([("total_lost", PlanValue::bool_value(false))]))
                .expect_err("bool")
                .to_string(),
            "Loss total_lost must be a nonnegative integer"
        );
    }

    #[test]
    fn planner_error_display_is_the_message_only() {
        let err = PlannerError::new("Plan step must be an object");
        assert_eq!(err.message(), "Plan step must be an object");
        assert_eq!(err.to_string(), "Plan step must be an object");
        assert!(err.source().is_none());
    }
}
