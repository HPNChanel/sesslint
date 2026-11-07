//! Deterministic repair-plan values through the conservative recipe import.
//!
//! Port of `src/sesslint/repair/planner.py` lines 1–457
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//! [`plan`] stops at `sesslint.repair.recipes_conservative.register_all`.
//! That function is not available. No I/O. Invalid input returns an error and
//! does not panic. Parser type errors do not echo the rejected value. An
//! invalid `policy` includes Python `repr`.
//!
//! [`PlanStep::try_new`] checks loss-class names in insertion order.
//! [`PlanStep::from_dict`], [`Blocked::from_dict`], and [`Loss::from_dict`]
//! keep the pin's first-failure order. `params` and `loss` stay in insertion
//! order. A `BTreeMap` would sort those keys, so they are `Vec` pairs.
//!
//! [`RepairPlan::from_dict`] recomputes a missing or empty fingerprint through
//! [`compute_plan_fingerprint`] with `policy` `None`.
//! [`compute_events_source_hash`] does not hash a non-empty sequence.
//! [`plan`] checks `policy`, then `source_hash`, then `profile`, then the
//! conservative `register_all` import. Findings are not read. Events are read
//! only when `source_hash` is `None`. `acknowledge_side_effects` and
//! `input_format` are not validated.
//!
//! [`get_plan_schema_path`] and [`load_plan_schema`] are `planner.py`
//! lines 993–1024. The first statement of [`get_plan_schema_path`] is
//! `from sesslint._resources import schema_path`. That function is not in
//! this crate. Both helpers display [`SCHEMA_PATH_UNAVAILABLE`].
//! [`load_plan_schema`] calls [`get_plan_schema_path`] first.
//! [`ALL`] is the pin `__all__`.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use codec::canonical_codec::{CanonicalError, ObjectKey, Value};
use model::canonical::{canonical_bytes, CanonicalUnavailable, SessionEvent};
use model::events::{event_id, EventError, EventMapping, EventValue, PYTHON_STR_UNREPRESENTABLE};
use model::finding::{DictValue, Finding};

use crate::fingerprint::compute_plan_fingerprint;
use crate::preconditions::{PreconditionError, _find_torn_compaction_dropped_indices};
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

/// `hashlib.sha256` is not linked in this crate.
pub const HASHLIB_SHA256_UNAVAILABLE: &str = "hashlib.sha256 is not available";

/// Failure from [`RepairPlan::from_dict`].
///
/// [`Display`](fmt::Display) is the inner message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanParseError {
    /// Python `ValueError` from plan parsing.
    Plan(PlannerError),
    /// [`compute_plan_fingerprint`] failed. The codec error is unchanged.
    Fingerprint(CanonicalError),
}

impl fmt::Display for PlanParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(error) => error.fmt(formatter),
            Self::Fingerprint(error) => error.fmt(formatter),
        }
    }
}

impl Error for PlanParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Plan(error) => Some(error),
            Self::Fingerprint(error) => Some(error),
        }
    }
}

impl From<PlannerError> for PlanParseError {
    fn from(error: PlannerError) -> Self {
        Self::Plan(error)
    }
}

impl From<CanonicalError> for PlanParseError {
    fn from(error: CanonicalError) -> Self {
        Self::Fingerprint(error)
    }
}

/// Fields for [`RepairPlan::new`].
///
/// Python dataclass order: `source_hash`, `profile`, `steps`, `blocked`,
/// `loss_accounting`, `fingerprint`, `version`, `policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlanFields {
    pub source_hash: String,
    pub profile: String,
    pub steps: Vec<PlanStep>,
    pub blocked: Vec<Blocked>,
    pub loss_accounting: Loss,
    pub fingerprint: String,
    pub version: String,
    pub policy: String,
}

/// Complete deterministic dry-run proposal for session repair.
///
/// Python: `RepairPlan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    source_hash: String,
    profile: String,
    steps: Vec<PlanStep>,
    blocked: Vec<Blocked>,
    loss_accounting: Loss,
    fingerprint: String,
    version: String,
    policy: String,
}

impl RepairPlan {
    /// Store the fields as given. This does not validate policy or profile.
    pub fn new(fields: RepairPlanFields) -> Self {
        Self {
            source_hash: fields.source_hash,
            profile: fields.profile,
            steps: fields.steps,
            blocked: fields.blocked,
            loss_accounting: fields.loss_accounting,
            fingerprint: fields.fingerprint,
            version: fields.version,
            policy: fields.policy,
        }
    }

    pub fn source_hash(&self) -> &str {
        &self.source_hash
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }

    pub fn blocked(&self) -> &[Blocked] {
        &self.blocked
    }

    pub fn loss_accounting(&self) -> &Loss {
        &self.loss_accounting
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn policy(&self) -> &str {
        &self.policy
    }

    /// Python: `RepairPlan.total_lost`.
    pub fn total_lost(&self) -> i128 {
        self.loss_accounting.total_lost()
    }

    /// Python: `RepairPlan.total_kept`.
    pub fn total_kept(&self) -> i128 {
        self.loss_accounting.total_kept()
    }

    /// Python: `RepairPlan.to_dict`.
    ///
    /// Key order is `blocked`, `fingerprint`, `loss_accounting`, `profile`,
    /// `source_hash`, `steps`, `version`. `loss_accounting` is
    /// [`Loss::to_dict`], which stays preview-only. When `policy` is not
    /// exactly `"conservative"`, `policy` is appended and `total_lost` /
    /// `total_kept` are added on that loss-accounting map copy.
    pub fn to_dict(&self) -> Vec<(String, PlanValue)> {
        let reveal_totals = self.policy != "conservative";
        let mut entries = vec![
            (
                "blocked".to_owned(),
                dicts_as_list(self.blocked.iter().map(Blocked::to_dict)),
            ),
            (
                "fingerprint".to_owned(),
                PlanValue::str_value(&self.fingerprint),
            ),
            (
                "loss_accounting".to_owned(),
                PlanValue::map(loss_dict_pairs(&self.loss_accounting, reveal_totals)),
            ),
            ("profile".to_owned(), PlanValue::str_value(&self.profile)),
            (
                "source_hash".to_owned(),
                PlanValue::str_value(&self.source_hash),
            ),
            (
                "steps".to_owned(),
                dicts_as_list(self.steps.iter().map(PlanStep::to_dict)),
            ),
            ("version".to_owned(), PlanValue::str_value(&self.version)),
        ];
        if reveal_totals {
            entries.push(("policy".to_owned(), PlanValue::str_value(&self.policy)));
        }
        entries
    }

    /// Python: `RepairPlan.from_dict`.
    ///
    /// Check order: object `"Plan"`, one-level `expected_plan` unwrap when
    /// that value is a mapping, [`_strings`] (`source_hash`, `profile`,
    /// `version`, `policy`, `fingerprint`), policy allowlist, non-empty
    /// profile, `steps` and `blocked` arrays, step and blocked parsers,
    /// [`Loss::from_dict`], then fingerprint. A present non-empty string
    /// fingerprint is stored as given. Missing, empty, or non-string calls
    /// [`compute_plan_fingerprint`] on the unwrapped mapping with `policy`
    /// `None` (the pin omits the argument). [`_strings`] rejects a present
    /// non-string before that call. Whitespace is not stripped.
    ///
    /// # Errors
    ///
    /// Returns [`PlanParseError`]. A fingerprint [`CanonicalError`] is
    /// propagated. This function does not panic.
    pub fn from_dict(raw_data: &PlanValue) -> Result<Self, PlanParseError> {
        let outer = _object(raw_data, "Plan")?;
        let entries = match lookup(outer, "expected_plan") {
            Some(PlanValue::Map(inner)) => inner.clone(),
            _ => outer.to_vec(),
        };
        _strings(
            &entries,
            &["source_hash", "profile", "version", "policy", "fingerprint"],
            "Plan",
        )?;
        let policy = plan_text(&entries, "policy", "conservative")?;
        if policy != "conservative" && policy != "salvage" {
            return Err(PlannerError::new("Plan policy is unsupported").into());
        }
        let profile = plan_text(&entries, "profile", "neutral")?;
        if profile.is_empty() {
            return Err(PlannerError::new("Plan profile must not be empty").into());
        }
        let step_items = plan_array(&entries, "steps")?;
        let blocked_items = plan_array(&entries, "blocked")?;
        let steps = step_items
            .iter()
            .map(PlanStep::from_dict)
            .collect::<Result<Vec<_>, _>>()?;
        let blocked = blocked_items
            .iter()
            .map(Blocked::from_dict)
            .collect::<Result<Vec<_>, _>>()?;
        let loss_owned = match lookup(&entries, "loss_accounting") {
            Some(value) => value.clone(),
            None => PlanValue::map(Vec::new()),
        };
        let loss_accounting = Loss::from_dict(&loss_owned)?;
        let fingerprint = plan_fingerprint(&entries)?;
        Ok(Self::new(RepairPlanFields {
            source_hash: plan_text(&entries, "source_hash", "")?,
            profile,
            steps,
            blocked,
            loss_accounting,
            fingerprint,
            version: plan_text(&entries, "version", PLAN_VERSION)?,
            policy,
        }))
    }
}

/// One element of [`compute_events_source_hash`].
///
/// Python `Sequence[Any]`. A [`SessionEvent`] has `to_canonical_bytes` and is
/// not a mapping. [`EventMapping`] is a mapping and does not have that
/// method. [`SourceHashEvent::Rendered`] is a successful `str(event)`.
/// [`SourceHashEvent::Unrenderable`] is a `str(event)` failure. This file has
/// no separate unrenderable-string error; that failure uses
/// [`PYTHON_STR_UNREPRESENTABLE`].
#[derive(Debug, Clone)]
pub enum SourceHashEvent {
    Session(Box<SessionEvent>),
    Mapping(EventMapping),
    Rendered(String),
    Unrenderable,
}

/// Failure from [`compute_events_source_hash`].
///
/// [`Display`](fmt::Display) is the seam message only. No digest is included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceHashError {
    /// `sesslint._canonical_codec.canonical_json_bytes` failed.
    Canonical(CanonicalUnavailable),
    /// Bytes were available and `hashlib.sha256` is not linked.
    Hashlib,
    /// `str(event)` failed before the hash seam.
    Unrenderable,
}

impl fmt::Display for SourceHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Canonical(error) => error.fmt(formatter),
            Self::Hashlib => formatter.write_str(HASHLIB_SHA256_UNAVAILABLE),
            Self::Unrenderable => formatter.write_str(PYTHON_STR_UNREPRESENTABLE),
        }
    }
}

impl Error for SourceHashError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonical(error) => Some(error),
            Self::Hashlib | Self::Unrenderable => None,
        }
    }
}

/// Python: `compute_events_source_hash`.
///
/// An empty sequence returns [`EMPTY_EVENTS_HASH`] and does not hash. A
/// non-empty sequence is walked in order and stops at the first event: every
/// event is a seam, so later events are not hashed.
/// A mapping calls [`canonical_bytes`] before any hash. `to_canonical_bytes`
/// bytes, or UTF-8 of a successful `str(event)`, would be passed to
/// `hashlib.sha256`; this crate returns [`HASHLIB_SHA256_UNAVAILABLE`] and
/// does not hash them. A `str(event)` failure is returned before that seam.
/// No non-empty input returns a digest.
///
/// # Errors
///
/// Returns [`SourceHashError`]. This function does not panic.
pub fn compute_events_source_hash(events: &[SourceHashEvent]) -> Result<String, SourceHashError> {
    let Some(event) = events.first() else {
        return Ok(EMPTY_EVENTS_HASH.to_owned());
    };
    Err(source_hash_seam(event))
}

const EVIDENCE_INDEX_KEYS: [&str; 8] = [
    "at_index",
    "first_unsafe_index",
    "index",
    "first_index",
    "cut_index",
    "boundary_index",
    "entry_index",
    "use_index",
];

const EVIDENCE_INDEX_LIST_KEYS: [&str; 2] = ["record_indexes", "result_indexes"];

/// Python: `_resolve_target_index`.
///
/// Evidence index keys are scanned in pin order. A bool is not an int.
/// `record_indexes` and `result_indexes` must be a list or tuple. When
/// `events` is present and `code` is not `SL001` or `SL002`, the id is
/// `root_id`, else `event_id`, else `source.record_id`, compared with
/// [`event_id`]. `SL001` and `SL002` never match an event id.
///
/// # Errors
///
/// Returns [`EventError`] from [`event_id`], or from an evidence id this
/// crate cannot render. An error is not treated as no match. This function
/// does not panic.
pub fn _resolve_target_index(
    finding: &Finding,
    events: Option<&[EventValue]>,
) -> Result<Option<i64>, EventError> {
    let evidence = finding_evidence(finding);
    if let Some(entries) = evidence.as_deref() {
        if let Some(index) = explicit_index(entries) {
            return Ok(Some(index));
        }
    }
    let Some(events) = events else {
        return Ok(None);
    };
    if UNDECODED_RECORD_CODES.contains(&finding.code()) {
        return Ok(None);
    }
    let Some(needle) = record_needle(finding, evidence.as_deref())? else {
        return Ok(None);
    };
    for (index, event) in events.iter().enumerate() {
        let Some(id) = event_id(event)? else {
            continue;
        };
        if id == needle {
            if let Ok(found) = i64::try_from(index) {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

/// Python: `_compute_torn_compaction_loss`.
///
/// A boundary outside `0..events.len()` returns `1` and does not call
/// [`_find_torn_compaction_dropped_indices`]. A `Value` error from that
/// helper returns `1`. An `Event` error is propagated and is not turned
/// into `1`. `Ok` returns the dropped set's length.
///
/// # Errors
///
/// Returns [`PreconditionError::Event`] unchanged. This function does not panic.
pub fn _compute_torn_compaction_loss(
    events: &[EventValue],
    boundary_idx: i64,
) -> Result<i64, PreconditionError> {
    let Ok(boundary) = usize::try_from(boundary_idx) else {
        return Ok(1);
    };
    if boundary >= events.len() {
        return Ok(1);
    }
    match _find_torn_compaction_dropped_indices(events, boundary_idx) {
        Ok(dropped) => match i64::try_from(dropped.len()) {
            Ok(count) => Ok(count),
            Err(_) => Err(PreconditionError::Value(
                "dropped index count exceeds i64".to_owned(),
            )),
        },
        Err(PreconditionError::Value(_)) => Ok(1),
        Err(error) => Err(error),
    }
}

/// `from sesslint.repair.recipes_conservative import register_all` cannot run.
pub const RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE: &str =
    "sesslint.repair.recipes_conservative.register_all is not available";

/// Python `policy` argument of [`plan`].
///
/// [`Self::Str`] is a `str`. [`Self::Bool`] is `True` or `False` and is not
/// the string `"True"`. [`Self::None`] is `None`. [`Self::Int`] is an `int`
/// and is not a bool. A list, tuple, dict, bytes, or float is not a variant.
/// This crate does not invent a container repr for `{policy!r}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanPolicy {
    /// Python `str`.
    Str(String),
    /// Python `bool`. Not an int.
    Bool(bool),
    /// Python `None`.
    None,
    /// Python `int`. Not a bool.
    Int(i128),
}

impl PlanPolicy {
    pub fn str_value(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn bool_value(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn none() -> Self {
        Self::None
    }

    pub fn int(value: i128) -> Self {
        Self::Int(value)
    }
}

/// Python `profile` argument of [`plan`].
///
/// Resolution is `getattr(profile, "name", str(profile))`.
/// [`Self::Str`] has no `name` attribute, so the string is kept.
/// [`Self::Named`] carries `name`, and that text is kept. `str(profile)` is
/// not called. [`Self::Bool`], [`Self::None`], and [`Self::Int`] have no
/// `name`. Their `str()` is `True`, `False`, `None`, or the decimal integer.
/// [`Self::Unrenderable`] has no `name` and `str()` cannot be rendered.
/// A list, tuple, dict, bytes, or float uses that variant. No container
/// repr is invented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanProfile {
    /// Python `str`. No `name` attribute.
    Str(String),
    /// Object whose `name` attribute is a `str`.
    Named(String),
    /// No `name`. `str(True)` / `str(False)`.
    Bool(bool),
    /// No `name`. `str(None)` is `None`.
    None,
    /// No `name`. `str(int)` is decimal text. Not a bool.
    Int(i128),
    /// No `name`. `str()` cannot be rendered.
    Unrenderable,
}

impl PlanProfile {
    pub fn str_value(value: impl Into<String>) -> Self {
        Self::Str(value.into())
    }

    pub fn named(name: impl Into<String>) -> Self {
        Self::Named(name.into())
    }

    pub fn bool_value(value: bool) -> Self {
        Self::Bool(value)
    }

    pub fn none() -> Self {
        Self::None
    }

    pub fn int(value: i128) -> Self {
        Self::Int(value)
    }

    pub fn unrenderable() -> Self {
        Self::Unrenderable
    }
}

/// Failure from [`plan`].
///
/// [`Display`](fmt::Display) is the message only. [`Self::SourceHash`]
/// displays the [`SourceHashError`] message. [`Self::ProfileStr`] displays
/// [`PYTHON_STR_UNREPRESENTABLE`]. This file keeps that single unrenderable
/// string and does not invent a container repr. [`Self::RegisterAll`]
/// displays [`RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// Python `ValueError` for a policy other than `conservative` or `salvage`.
    Policy(String),
    /// [`compute_events_source_hash`] failed. The error is unchanged.
    SourceHash(SourceHashError),
    /// `str(profile)` cannot be rendered.
    ProfileStr,
    /// `sesslint.repair.recipes_conservative.register_all` is not available.
    RegisterAll,
}

impl PlanError {
    fn invalid_policy(policy: &PlanPolicy) -> Self {
        let shown = policy_repr(policy);
        Self::Policy(format!(
            "Invalid repair policy: {shown}. Must be 'conservative' or 'salvage'"
        ))
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(message) => formatter.write_str(message),
            Self::SourceHash(error) => error.fmt(formatter),
            Self::ProfileStr => formatter.write_str(PYTHON_STR_UNREPRESENTABLE),
            Self::RegisterAll => formatter.write_str(RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE),
        }
    }
}

impl Error for PlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SourceHash(error) => Some(error),
            Self::Policy(_) | Self::ProfileStr | Self::RegisterAll => None,
        }
    }
}

/// Python: `plan`, through the conservative recipe import.
///
/// `policy` is checked first. The strings `conservative` and `salvage` are
/// the only accepted values. Any other value returns the Python `ValueError`
/// text and does not hash, resolve `profile`, or import.
/// `source_hash` of `None` calls [`compute_events_source_hash`]. An empty
/// sequence stores [`EMPTY_EVENTS_HASH`] and continues. A non-empty sequence
/// returns that function's error and does not import or build a
/// [`RepairPlan`]. A present `source_hash`, including `""`, is stored and
/// `events` are not read.
/// `profile` is `getattr(profile, "name", str(profile))`. A string keeps its
/// text. A value that carries `name` keeps that name. A value whose `str()`
/// cannot be rendered returns [`PYTHON_STR_UNREPRESENTABLE`].
///
/// The next statement is `from sesslint.repair.recipes_conservative import
/// register_all`. This crate returns
/// [`RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE`]. Salvage registration,
/// SL002 registration, SL203 blocking, recipe matching, and the plan
/// fingerprint are not run.
///
/// `findings` are not read. `acknowledge_side_effects` and `input_format`
/// are not validated. Python keyword defaults are supplied by the caller:
/// `profile` `"neutral"`, `source_hash` `None`, `policy` `"conservative"`,
/// `acknowledge_side_effects` `False`, `input_format` `None`.
///
/// # Errors
///
/// Returns [`PlanError`]. This function does not panic. Success is
/// [`Infallible`], so no [`RepairPlan`] is returned.
pub fn plan(
    findings: &[Finding],
    events: &[SourceHashEvent],
    profile: &PlanProfile,
    source_hash: Option<&str>,
    policy: &PlanPolicy,
    acknowledge_side_effects: bool,
    input_format: Option<&str>,
) -> Result<Infallible, PlanError> {
    let policy = require_policy(policy)?;
    let resolved_source_hash = match source_hash {
        Some(hash) => hash.to_owned(),
        None => compute_events_source_hash(events).map_err(PlanError::SourceHash)?,
    };
    let profile_name = resolve_profile_name(profile)?;
    Err(conservative_register_all_unavailable(
        findings,
        &resolved_source_hash,
        &profile_name,
        policy,
        acknowledge_side_effects,
        input_format,
    ))
}

fn require_policy(policy: &PlanPolicy) -> Result<&str, PlanError> {
    match policy {
        PlanPolicy::Str(text) if text == "conservative" || text == "salvage" => Ok(text.as_str()),
        other => Err(PlanError::invalid_policy(other)),
    }
}

fn resolve_profile_name(profile: &PlanProfile) -> Result<String, PlanError> {
    match profile {
        PlanProfile::Str(text) => Ok(text.clone()),
        PlanProfile::Named(name) => Ok(name.clone()),
        PlanProfile::Bool(true) => Ok("True".to_owned()),
        PlanProfile::Bool(false) => Ok("False".to_owned()),
        PlanProfile::None => Ok("None".to_owned()),
        PlanProfile::Int(number) => Ok(number.to_string()),
        PlanProfile::Unrenderable => Err(PlanError::ProfileStr),
    }
}

fn policy_repr(policy: &PlanPolicy) -> String {
    match policy {
        PlanPolicy::Str(text) => python_str_repr(text),
        PlanPolicy::Bool(true) => "True".to_owned(),
        PlanPolicy::Bool(false) => "False".to_owned(),
        PlanPolicy::None => "None".to_owned(),
        PlanPolicy::Int(number) => number.to_string(),
    }
}

/// The conservative `register_all` import is not available.
///
/// The arguments are the values `plan` has already stored or accepted.
/// They are not read. No [`RepairPlan`] is built.
fn conservative_register_all_unavailable(
    findings: &[Finding],
    resolved_source_hash: &str,
    profile_name: &str,
    policy: &str,
    acknowledge_side_effects: bool,
    input_format: Option<&str>,
) -> PlanError {
    let _ = (
        findings,
        resolved_source_hash,
        profile_name,
        policy,
        acknowledge_side_effects,
        input_format,
    );
    PlanError::RegisterAll
}

fn dicts_as_list(items: impl IntoIterator<Item = Vec<(String, PlanValue)>>) -> PlanValue {
    PlanValue::list(items.into_iter().map(PlanValue::string_map).collect())
}

fn loss_dict_pairs(loss: &Loss, reveal_totals: bool) -> Vec<(PlanKey, PlanValue)> {
    let mut pairs = loss
        .to_dict()
        .into_iter()
        .map(|(key, value)| (PlanKey::Str(key), value))
        .collect::<Vec<_>>();
    if reveal_totals {
        pairs.push((
            PlanKey::str_key("total_lost"),
            PlanValue::int(loss.total_lost()),
        ));
        pairs.push((
            PlanKey::str_key("total_kept"),
            PlanValue::int(loss.total_kept()),
        ));
    }
    pairs
}

fn plan_text(
    entries: &[(PlanKey, PlanValue)],
    name: &str,
    default: &str,
) -> Result<String, PlannerError> {
    match lookup(entries, name) {
        None => Ok(default.to_owned()),
        Some(PlanValue::Str(text)) => Ok(text.clone()),
        Some(_) => Err(PlannerError::new(format!("Plan {name} must be a string"))),
    }
}

fn plan_array(
    entries: &[(PlanKey, PlanValue)],
    name: &str,
) -> Result<Vec<PlanValue>, PlannerError> {
    match lookup(entries, name) {
        None => Ok(Vec::new()),
        Some(PlanValue::List(items) | PlanValue::Tuple(items)) => Ok(items.clone()),
        Some(_) => Err(PlannerError::new(format!("Plan {name} must be an array"))),
    }
}

fn plan_fingerprint(entries: &[(PlanKey, PlanValue)]) -> Result<String, PlanParseError> {
    if let Some(PlanValue::Str(text)) = lookup(entries, "fingerprint") {
        if !text.is_empty() {
            return Ok(text.clone());
        }
    }
    let value = codec_plan(entries);
    Ok(compute_plan_fingerprint(&value, None)?)
}

fn codec_plan(entries: &[(PlanKey, PlanValue)]) -> Value {
    Value::object(
        entries
            .iter()
            .map(|(key, value)| (codec_key(key), codec_value(value)))
            .collect(),
    )
}

fn codec_key(key: &PlanKey) -> ObjectKey {
    match key {
        PlanKey::Str(text) => ObjectKey::string(text.clone()),
        PlanKey::Int(number) => ObjectKey::non_string(number.to_string()),
        PlanKey::Bool(true) => ObjectKey::non_string("True"),
        PlanKey::Bool(false) => ObjectKey::non_string("False"),
        PlanKey::None => ObjectKey::non_string("None"),
        PlanKey::Float(_) => ObjectKey::non_string("<float>"),
        PlanKey::Bytes(_) => ObjectKey::non_string("<bytes>"),
        PlanKey::Other { type_name } => ObjectKey::non_string((*type_name).to_owned()),
    }
}

fn codec_value(value: &PlanValue) -> Value {
    match value {
        PlanValue::None => Value::null(),
        PlanValue::Bool(flag) => Value::bool(*flag),
        PlanValue::Int(number) => Value::int_i128(*number),
        PlanValue::Float(bits) => Value::float(f64::from_bits(*bits)),
        PlanValue::Str(text) => Value::string(text.clone()),
        PlanValue::Bytes(_) => Value::foreign("bytes"),
        PlanValue::List(items) | PlanValue::Tuple(items) => {
            Value::array(items.iter().map(codec_value).collect())
        }
        PlanValue::Map(entries) => codec_plan(entries),
        PlanValue::Other { type_name } => Value::foreign(type_name),
    }
}

fn source_hash_seam(event: &SourceHashEvent) -> SourceHashError {
    match event {
        SourceHashEvent::Session(session) => match session.to_canonical_bytes() {
            Ok(_bytes) => SourceHashError::Hashlib,
            Err(error) => SourceHashError::Canonical(error),
        },
        SourceHashEvent::Mapping(mapping) => match canonical_bytes(mapping) {
            Ok(_bytes) => SourceHashError::Hashlib,
            Err(error) => SourceHashError::Canonical(error),
        },
        SourceHashEvent::Rendered(_text) => SourceHashError::Hashlib,
        SourceHashEvent::Unrenderable => SourceHashError::Unrenderable,
    }
}

fn finding_evidence(finding: &Finding) -> Option<Vec<(String, DictValue)>> {
    let mut found = None;
    for (key, value) in finding.to_dict() {
        if key == "evidence" {
            found = Some(value);
        }
    }
    match found {
        Some(DictValue::Map(entries)) if !entries.is_empty() => Some(entries),
        _ => None,
    }
}

fn evidence_get<'a>(entries: &'a [(String, DictValue)], name: &str) -> Option<&'a DictValue> {
    entries
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
}

fn dict_truthy(value: &DictValue) -> bool {
    match value {
        DictValue::None => false,
        DictValue::Bool(flag) => *flag,
        DictValue::Int(number) => *number != 0,
        DictValue::Str(text) => !text.is_empty(),
        DictValue::Bytes(bytes) => !bytes.is_empty(),
        DictValue::List(items)
        | DictValue::Tuple(items)
        | DictValue::Set(items)
        | DictValue::FrozenSet(items) => !items.is_empty(),
        DictValue::Map(entries) => !entries.is_empty(),
    }
}

fn evidence_or<'a>(
    entries: &'a [(String, DictValue)],
    first: &str,
    second: &str,
) -> Option<&'a DictValue> {
    let left = evidence_get(entries, first);
    if left.is_some_and(dict_truthy) {
        return left;
    }
    evidence_get(entries, second)
}

fn explicit_index(entries: &[(String, DictValue)]) -> Option<i64> {
    for name in EVIDENCE_INDEX_KEYS {
        if let Some(DictValue::Int(number)) = evidence_get(entries, name) {
            return Some(*number);
        }
    }
    for name in EVIDENCE_INDEX_LIST_KEYS {
        let Some(value) = evidence_get(entries, name) else {
            continue;
        };
        let items = match value {
            DictValue::List(items) | DictValue::Tuple(items) => items.as_slice(),
            _ => continue,
        };
        for item in items {
            if let DictValue::Int(number) = item {
                return Some(*number);
            }
        }
    }
    None
}

fn record_needle(
    finding: &Finding,
    evidence: Option<&[(String, DictValue)]>,
) -> Result<Option<String>, EventError> {
    if let Some(entries) = evidence {
        if let Some(value) = evidence_or(entries, "root_id", "event_id") {
            if !matches!(value, DictValue::None) {
                return Ok(Some(scalar_id(value)?));
            }
        }
    }
    match finding.source().record_id() {
        Some(record_id) if !record_id.is_empty() => Ok(Some(record_id.to_owned())),
        _ => Ok(None),
    }
}

fn scalar_id(value: &DictValue) -> Result<String, EventError> {
    match value {
        DictValue::Str(text) => Ok(text.clone()),
        DictValue::Int(number) => Ok(number.to_string()),
        DictValue::Bool(true) => Ok("True".to_owned()),
        DictValue::Bool(false) => Ok("False".to_owned()),
        DictValue::None => Ok("None".to_owned()),
        _ => Err(EventError::PythonStr),
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

/// `from sesslint._resources import schema_path` cannot run in this crate.
pub const SCHEMA_PATH_UNAVAILABLE: &str = "sesslint._resources.schema_path is not available";

/// Failure from [`get_plan_schema_path`] and [`load_plan_schema`].
///
/// [`Display`](fmt::Display) is [`SCHEMA_PATH_UNAVAILABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct PlanSchemaError;

impl fmt::Display for PlanSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SCHEMA_PATH_UNAVAILABLE)
    }
}

impl Error for PlanSchemaError {}

/// Python: `get_plan_schema_path`.
///
/// The first statement is `from sesslint._resources import schema_path`.
/// That function is not in this crate. This does not build `Path(__file__)`,
/// does not return a filesystem path, and does not read
/// `schemas/sesslint.plan.v1.json`.
pub const fn get_plan_schema_path() -> PlanSchemaError {
    PlanSchemaError
}

/// Python: `load_plan_schema`.
///
/// Calls [`get_plan_schema_path`] first and stops on that same display.
/// This does not check `is_file`, call `json.loads`, or invent a mapping.
pub const fn load_plan_schema() -> PlanSchemaError {
    get_plan_schema_path()
}

/// Python `__all__` (`planner.py` lines 1011–1024), in that order.
pub const ALL: [&str; 12] = [
    "ALLOWED_LOSS_CLASSES",
    "EMPTY_EVENTS_HASH",
    "MAX_STEPS",
    "PLAN_VERSION",
    "Blocked",
    "Loss",
    "PlanStep",
    "RepairPlan",
    "compute_events_source_hash",
    "get_plan_schema_path",
    "load_plan_schema",
    "plan",
];

#[cfg(test)]
mod tests {
    use std::error::Error;

    use codec::canonical_codec::{ObjectKey, Value};
    use model::canonical::{canonical_bytes, SessionEvent};
    use model::codes::{Repairability, Severity};
    use model::events::{
        EventError, EventField, EventMapping, EventValue, PYTHON_FLOAT_STR_UNREPRESENTABLE,
        PYTHON_STR_UNREPRESENTABLE,
    };
    use model::finding::{Finding, FindingInput, PyValue, SourceRef, SCHEMA_VERSION};

    use crate::fingerprint::compute_plan_fingerprint;
    use crate::preconditions::{PreconditionError, _find_torn_compaction_dropped_indices};

    use super::{
        _compute_torn_compaction_loss, _counts, _object, _resolve_target_index, _strings,
        compute_events_source_hash, get_plan_schema_path, load_plan_schema, plan, Blocked, Loss,
        PlanError, PlanKey, PlanPolicy, PlanProfile, PlanSchemaError, PlanStep, PlanStepFields,
        PlanValue, PlannerError, RepairPlan, RepairPlanFields, SourceHashError, SourceHashEvent,
        ALL, ALLOWED_LOSS_CLASSES, EMPTY_EVENTS_HASH, EVENT_DROP_RECIPES,
        HASHLIB_SHA256_UNAVAILABLE, MAX_STEPS, NON_EVENT_LOSS_CLASSES, PLAN_VERSION,
        RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE, SCHEMA_PATH_UNAVAILABLE, SYNTHETIC_STEP_FP,
        UNDECODED_RECORD_CODES,
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

    fn plan_err(data: &PlanValue) -> String {
        RepairPlan::from_dict(data)
            .expect_err("rejected plan")
            .to_string()
    }

    fn is_digest(text: &str) -> bool {
        text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    fn manual_plan(pairs: Vec<(&str, Value)>) -> Value {
        Value::object(
            pairs
                .into_iter()
                .map(|(key, value)| (ObjectKey::string(key), value))
                .collect(),
        )
    }

    fn keyed<'a>(value: &'a PlanValue, name: &str) -> &'a PlanValue {
        let PlanValue::Map(entries) = value else {
            panic!("map");
        };
        entries
            .iter()
            .find_map(|(key, child)| match key {
                PlanKey::Str(text) if text == name => Some(child),
                _ => None,
            })
            .expect(name)
    }

    fn sample_plan(policy: &str, loss: Loss) -> RepairPlan {
        let mut fields = PlanStepFields::new(0, "recipe-alpha", "fp-alpha", Some(0));
        fields.params = vec![
            ("z-param".to_owned(), PlanValue::int(1)),
            ("a-param".to_owned(), PlanValue::bool_value(false)),
        ];
        let step = PlanStep::try_new(fields).expect("step");
        RepairPlan::new(RepairPlanFields {
            source_hash: "abc".to_owned(),
            profile: " ".to_owned(),
            steps: vec![step],
            blocked: vec![Blocked::new("fp-alpha", "SL001", "cap-overflow")],
            loss_accounting: loss,
            fingerprint: "kept-fp".to_owned(),
            version: "custom-version".to_owned(),
            policy: policy.to_owned(),
        })
    }

    fn loss_sample() -> Loss {
        Loss::new(
            vec![("z-class".to_owned(), 2), ("a-class".to_owned(), 0)],
            4,
            5,
        )
    }

    #[test]
    fn repair_plan_to_dict_omits_conservative_totals_and_appends_other_policy() {
        let conservative = sample_plan("conservative", loss_sample());
        let encoded = conservative.to_dict();
        assert_eq!(
            dict_keys(&encoded),
            [
                "blocked",
                "fingerprint",
                "loss_accounting",
                "profile",
                "source_hash",
                "steps",
                "version",
            ]
        );
        assert_eq!(nested_keys(&encoded[2].1), ["preview"]);
        assert_eq!(
            nested_keys(keyed(&encoded[2].1, "preview")),
            ["z-class", "a-class"]
        );
        assert_eq!(
            dict_keys(&conservative.loss_accounting().to_dict()),
            ["preview"]
        );
        assert_eq!(conservative.total_lost(), 4);
        assert_eq!(conservative.total_kept(), 5);
        assert_eq!(conservative.profile(), " ");

        let salvage = sample_plan("salvage", loss_sample());
        let encoded = salvage.to_dict();
        assert_eq!(
            dict_keys(&encoded),
            [
                "blocked",
                "fingerprint",
                "loss_accounting",
                "profile",
                "source_hash",
                "steps",
                "version",
                "policy",
            ]
        );
        assert_eq!(encoded[7].1, text("salvage"));
        assert_eq!(
            nested_keys(&encoded[2].1),
            ["preview", "total_lost", "total_kept"]
        );
        assert_eq!(keyed(&encoded[2].1, "total_lost"), &PlanValue::int(4));
        assert_eq!(keyed(&encoded[2].1, "total_kept"), &PlanValue::int(5));
        assert_eq!(dict_keys(&salvage.loss_accounting().to_dict()), ["preview"]);

        let other = sample_plan("other", loss_sample());
        assert_eq!(other.to_dict()[7].1, text("other"));
        assert_eq!(
            keyed(&other.to_dict()[2].1, "total_lost"),
            &PlanValue::int(4)
        );
    }

    #[test]
    fn repair_plan_from_dict_round_trip_preserves_space_and_drops_conservative_totals() {
        let conservative = sample_plan("conservative", loss_sample());
        let again = RepairPlan::from_dict(&PlanValue::string_map(conservative.to_dict()))
            .expect("conservative");
        assert_eq!(again.fingerprint(), "kept-fp");
        assert_eq!(again.profile(), " ");
        assert_eq!(again.policy(), "conservative");
        assert_eq!(again.version(), "custom-version");
        assert_eq!(again.source_hash(), "abc");
        assert_eq!(again.steps(), conservative.steps());
        assert_eq!(again.blocked(), conservative.blocked());
        assert_eq!(again.loss_accounting().preview(), loss_sample().preview());
        assert_eq!(again.total_lost(), 0);
        assert_eq!(again.total_kept(), 0);

        let salvage = sample_plan("salvage", loss_sample());
        let again =
            RepairPlan::from_dict(&PlanValue::string_map(salvage.to_dict())).expect("salvage");
        assert_eq!(again, salvage);

        let tuple_steps = RepairPlan::from_dict(&obj([
            ("fingerprint", text("kept")),
            ("steps", PlanValue::tuple(vec![required([])])),
            ("blocked", PlanValue::tuple(vec![])),
            ("profile", text(" ")),
        ]))
        .expect("tuple");
        assert_eq!(tuple_steps.steps().len(), 1);
        assert_eq!(tuple_steps.profile(), " ");
        assert!(tuple_steps.blocked().is_empty());
    }

    #[test]
    fn repair_plan_from_dict_first_failure_order() {
        assert_eq!(plan_err(&PlanValue::list(vec![])), "Plan must be an object");
        let bad_key = PlanValue::map(vec![(
            PlanKey::bool_value(true),
            PlanValue::bytes(b"echo-me".to_vec()),
        )]);
        let err = plan_err(&bad_key);
        assert_eq!(err, "Plan must be an object");
        assert!(!err.contains("echo-me"));

        assert_eq!(
            plan_err(&obj([
                ("source_hash", PlanValue::bytes(b"echo-me".to_vec())),
                ("profile", PlanValue::int(2)),
                ("policy", text("nope")),
            ])),
            "Plan source_hash must be a string"
        );
        assert!(!plan_err(&obj([(
            "source_hash",
            PlanValue::bytes(b"echo-me".to_vec())
        )]))
        .contains("echo-me"));
        assert_eq!(
            plan_err(&obj([
                ("profile", PlanValue::int(2)),
                ("version", PlanValue::bool_value(true)),
            ])),
            "Plan profile must be a string"
        );
        assert_eq!(
            plan_err(&obj([
                ("version", PlanValue::int(3)),
                ("policy", PlanValue::int(4)),
            ])),
            "Plan version must be a string"
        );
        assert_eq!(
            plan_err(&obj([
                ("policy", PlanValue::bool_value(true)),
                ("fingerprint", PlanValue::int(5)),
            ])),
            "Plan policy must be a string"
        );
        assert_eq!(
            plan_err(&obj([
                ("fingerprint", PlanValue::bool_value(false)),
                ("policy", text("nope")),
                ("profile", text("")),
            ])),
            "Plan fingerprint must be a string"
        );
        assert_eq!(
            plan_err(&obj([("policy", text("")), ("profile", text("")),])),
            "Plan policy is unsupported"
        );
        assert_eq!(
            plan_err(&obj([("policy", text(" conservative"))])),
            "Plan policy is unsupported"
        );
        assert_eq!(
            plan_err(&obj([
                ("policy", text("conservative")),
                ("profile", text("")),
                ("steps", PlanValue::int(1)),
            ])),
            "Plan profile must not be empty"
        );
        assert_eq!(
            plan_err(&obj([
                ("fingerprint", text("kept")),
                ("steps", PlanValue::int(1)),
                ("blocked", text("no")),
            ])),
            "Plan steps must be an array"
        );
        assert_eq!(
            plan_err(&obj([
                ("fingerprint", text("kept")),
                ("steps", PlanValue::list(vec![PlanValue::int(1)])),
                ("blocked", PlanValue::bool_value(true)),
            ])),
            "Plan blocked must be an array"
        );
        assert_eq!(
            plan_err(&obj([
                ("fingerprint", text("kept")),
                (
                    "steps",
                    PlanValue::list(vec![required([("seq", PlanValue::bool_value(true))])]),
                ),
            ])),
            "Plan step seq must be a nonnegative integer"
        );
        assert_eq!(
            plan_err(&obj([
                ("fingerprint", text("kept")),
                (
                    "blocked",
                    PlanValue::list(vec![obj([("code", PlanValue::int(1))])]),
                ),
            ])),
            "Blocked entry code must be a string"
        );
        assert_eq!(
            plan_err(&obj([
                ("fingerprint", text("kept")),
                ("loss_accounting", PlanValue::int(1)),
            ])),
            "Loss accounting must be an object"
        );
        assert_eq!(
            plan_err(&obj([
                ("fingerprint", text("kept")),
                (
                    "loss_accounting",
                    obj([("total_lost", PlanValue::bool_value(true))]),
                ),
            ])),
            "Loss total_lost must be a nonnegative integer"
        );
    }

    #[test]
    fn repair_plan_fingerprint_uses_none_policy_or_stores_a_present_string() {
        let spaced = RepairPlan::from_dict(&obj([
            ("fingerprint", text(" ")),
            ("profile", text("neutral")),
            ("spike", PlanValue::float(f64::NAN)),
        ]))
        .expect("space fingerprint skips the hasher");
        assert_eq!(spaced.fingerprint(), " ");
        assert!(!is_digest(spaced.fingerprint()));

        let data = obj([
            ("fingerprint", text("")),
            ("profile", text("neutral")),
            ("source_hash", text("abc")),
        ]);
        let loaded = RepairPlan::from_dict(&data).expect("recompute");
        let manual = manual_plan(vec![
            ("source_hash", Value::string("abc")),
            ("profile", Value::string("neutral")),
            ("fingerprint", Value::string("")),
        ]);
        let omitted = compute_plan_fingerprint(&manual, None).expect("none policy");
        let bound = compute_plan_fingerprint(&manual, Some("conservative")).expect("bound");
        assert_eq!(loaded.fingerprint(), omitted);
        assert_ne!(loaded.fingerprint(), bound);
        assert!(is_digest(&omitted));
        assert_ne!(omitted, EMPTY_EVENTS_HASH);

        let missing = RepairPlan::from_dict(&obj([
            ("profile", text("neutral")),
            ("source_hash", text("abc")),
        ]))
        .expect("missing fingerprint");
        assert_eq!(missing.fingerprint(), omitted);

        let nan = obj([
            ("profile", text("neutral")),
            ("spike", PlanValue::float(f64::NAN)),
        ]);
        let err = RepairPlan::from_dict(&nan).expect_err("nan");
        let direct = compute_plan_fingerprint(
            &manual_plan(vec![
                ("profile", Value::string("neutral")),
                ("spike", Value::float(f64::NAN)),
            ]),
            None,
        )
        .expect_err("direct nan");
        assert_eq!(err.to_string(), direct.to_string());
        assert!(err.source().is_some());
        assert!(!is_digest(&err.to_string()));
        assert_ne!(err.to_string(), EMPTY_EVENTS_HASH);
    }

    #[test]
    fn repair_plan_unwraps_one_expected_plan_mapping() {
        let inner = obj([
            ("profile", text("middle")),
            ("fingerprint", text("inner-fp")),
            ("policy", text("salvage")),
            (
                "expected_plan",
                obj([("profile", text("deeper")), ("fingerprint", text("deep"))]),
            ),
        ]);
        let outer = obj([
            ("expected_plan", inner),
            ("profile", text("outer")),
            ("fingerprint", text("outer-fp")),
        ]);
        let plan = RepairPlan::from_dict(&outer).expect("unwrap");
        assert_eq!(plan.profile(), "middle");
        assert_eq!(plan.fingerprint(), "inner-fp");
        assert_eq!(plan.policy(), "salvage");

        let text_wrapper = obj([("expected_plan", text("nope"))]);
        let plan = RepairPlan::from_dict(&text_wrapper).expect("not a mapping");
        assert_eq!(plan.profile(), "neutral");
        assert_eq!(plan.policy(), "conservative");
        assert_eq!(plan.version(), PLAN_VERSION);
        assert_eq!(plan.source_hash(), "");
        let manual = manual_plan(vec![("expected_plan", Value::string("nope"))]);
        assert_eq!(
            plan.fingerprint(),
            compute_plan_fingerprint(&manual, None).expect("outer hash")
        );
    }

    #[test]
    fn compute_events_source_hash_returns_seams_for_non_empty_input() {
        assert_eq!(
            compute_events_source_hash(&[]).expect("empty"),
            EMPTY_EVENTS_HASH
        );

        let rendered = compute_events_source_hash(&[
            SourceHashEvent::Rendered("echo-me".to_owned()),
            SourceHashEvent::Mapping(EventMapping::new(Vec::new())),
        ])
        .expect_err("rendered first");
        assert_eq!(rendered, SourceHashError::Hashlib);
        assert_eq!(rendered.to_string(), HASHLIB_SHA256_UNAVAILABLE);
        assert!(!rendered.to_string().contains("echo-me"));
        assert!(rendered.source().is_none());
        assert!(!is_digest(&rendered.to_string()));

        let unrendered = compute_events_source_hash(&[
            SourceHashEvent::Unrenderable,
            SourceHashEvent::Rendered("echo-me".to_owned()),
        ])
        .expect_err("str fails first");
        assert_eq!(unrendered, SourceHashError::Unrenderable);
        assert_eq!(unrendered.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert_ne!(unrendered.to_string(), HASHLIB_SHA256_UNAVAILABLE);

        let mapping =
            EventMapping::new(vec![("id".to_owned(), EventField::Str("evt-a".to_owned()))]);
        let mapped = compute_events_source_hash(&[
            SourceHashEvent::Mapping(mapping.clone()),
            SourceHashEvent::Rendered("later".to_owned()),
        ])
        .expect_err("mapping");
        assert_eq!(
            mapped,
            SourceHashError::Canonical(canonical_bytes(&mapping).expect_err("canonical seam"))
        );
        assert_eq!(
            mapped.to_string(),
            "sesslint._canonical_codec.canonical_json_bytes is not available"
        );
        assert!(!mapped.to_string().contains("evt-a"));
        assert!(mapped.source().is_some());
        assert_ne!(mapped.to_string(), EMPTY_EVENTS_HASH);
        assert!(!is_digest(&mapped.to_string()));

        let session = SessionEvent::new(
            "evt-synthetic",
            None,
            0,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        );
        let bytes = session.to_canonical_bytes().expect_err("session bytes");
        let hashed = compute_events_source_hash(&[SourceHashEvent::Session(Box::new(session))])
            .expect_err("session");
        assert_eq!(hashed, SourceHashError::Canonical(bytes));
        assert_ne!(hashed.to_string(), HASHLIB_SHA256_UNAVAILABLE);
    }

    fn target_finding(code: &str, record_id: Option<&str>, evidence: PyValue) -> Finding {
        let source = SourceRef::try_new("<canonical>", None, record_id).expect("source");
        Finding::try_new(FindingInput {
            code: PyValue::string(code),
            severity: PyValue::severity(Severity::Error),
            repairability: PyValue::repairability(Repairability::Manual),
            message: PyValue::string("synthetic target marker"),
            source: PyValue::source(source),
            related_ids: PyValue::tuple(Vec::new()),
            fingerprint: PyValue::string("0123456789abcdef"),
            schema_version: PyValue::string(SCHEMA_VERSION),
            message_template: PyValue::None,
            evidence,
        })
        .expect("finding")
    }

    fn ev_map(entries: Vec<(&str, PyValue)>) -> PyValue {
        PyValue::map(
            entries
                .into_iter()
                .map(|(key, value)| (PyValue::string(key), value))
                .collect(),
        )
    }

    fn id_event(id: EventField) -> EventValue {
        EventValue::Mapping(EventMapping::new(vec![("id".to_owned(), id)]))
    }

    #[test]
    fn resolve_target_index_prefers_real_ints_then_ids() {
        let events = [
            id_event(EventField::Str("evt-a".to_owned())),
            id_event(EventField::Str("evt-b".to_owned())),
            id_event(EventField::Int(7)),
            id_event(EventField::Bool(true)),
        ];
        let at = target_finding(
            "SL005",
            Some("evt-a"),
            ev_map(vec![
                ("at_index", PyValue::bool_value(true)),
                ("index", PyValue::int(0)),
                ("record_indexes", PyValue::list(vec![PyValue::int(3)])),
            ]),
        );
        assert_eq!(_resolve_target_index(&at, None).expect("index"), Some(0));

        let negative = target_finding("SL001", None, ev_map(vec![("at_index", PyValue::int(-2))]));
        assert_eq!(
            _resolve_target_index(&negative, Some(&events)).expect("negative"),
            Some(-2)
        );

        let listed = target_finding(
            "SL005",
            Some("evt-a"),
            ev_map(vec![
                ("record_indexes", PyValue::string("01")),
                (
                    "result_indexes",
                    PyValue::list(vec![PyValue::bool_value(true), PyValue::int(6)]),
                ),
            ]),
        );
        assert_eq!(
            _resolve_target_index(&listed, Some(&events)).expect("list"),
            Some(6)
        );

        let tuple_index = target_finding(
            "SL005",
            None,
            ev_map(vec![(
                "record_indexes",
                PyValue::tuple(vec![PyValue::bool_value(false), PyValue::int(4)]),
            )]),
        );
        assert_eq!(
            _resolve_target_index(&tuple_index, None).expect("tuple"),
            Some(4)
        );

        let set_skipped = target_finding(
            "SL005",
            Some("evt-a"),
            ev_map(vec![(
                "record_indexes",
                PyValue::set(vec![PyValue::int(3)]),
            )]),
        );
        assert_eq!(
            _resolve_target_index(&set_skipped, Some(&events)).expect("set"),
            Some(0)
        );

        let zero_root = target_finding(
            "SL005",
            Some("evt-a"),
            ev_map(vec![("root_id", PyValue::int(0))]),
        );
        let zero_events = [
            id_event(EventField::Str("0".to_owned())),
            id_event(EventField::Str("evt-a".to_owned())),
        ];
        assert_eq!(
            _resolve_target_index(&zero_root, Some(&zero_events)).expect("zero"),
            Some(1)
        );

        let root = target_finding(
            "SL005",
            Some("evt-a"),
            ev_map(vec![
                ("root_id", PyValue::string("evt-b")),
                ("event_id", PyValue::string("evt-a")),
            ]),
        );
        assert_eq!(
            _resolve_target_index(&root, Some(&events)).expect("root"),
            Some(1)
        );

        let empty_root = target_finding(
            "SL005",
            Some("evt-a"),
            ev_map(vec![
                ("root_id", PyValue::string("")),
                ("event_id", PyValue::int(7)),
            ]),
        );
        assert_eq!(
            _resolve_target_index(&empty_root, Some(&events)).expect("event id"),
            Some(2)
        );

        let flag = target_finding(
            "SL005",
            Some("evt-a"),
            ev_map(vec![("event_id", PyValue::bool_value(true))]),
        );
        assert_eq!(
            _resolve_target_index(&flag, Some(&events)).expect("true"),
            Some(3)
        );

        let by_record = target_finding("SL005", Some("evt-b"), PyValue::None);
        assert_eq!(
            _resolve_target_index(&by_record, Some(&events)).expect("record"),
            Some(1)
        );
        assert_eq!(
            _resolve_target_index(&by_record, None).expect("no events"),
            None
        );

        let undecoded = target_finding("SL001", Some("evt-a"), PyValue::None);
        let float_events = [id_event(EventField::Float(1.0))];
        assert_eq!(
            _resolve_target_index(&undecoded, Some(&float_events)).expect("sl001"),
            None
        );
        let sl002 = target_finding("SL002", Some("evt-a"), PyValue::None);
        assert_eq!(
            _resolve_target_index(&sl002, Some(&events)).expect("sl002"),
            None
        );

        let float_before = [
            id_event(EventField::Float(1.0)),
            id_event(EventField::Str("evt-a".to_owned())),
        ];
        let err = _resolve_target_index(&by_record, Some(&float_before)).expect_err("float id");
        assert_eq!(err, EventError::PythonFloatStr);
        assert_eq!(err.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);

        let no_needle = target_finding("SL005", None, PyValue::None);
        assert_eq!(
            _resolve_target_index(&no_needle, Some(&float_events)).expect("no id"),
            None
        );

        let listed_id = target_finding(
            "SL005",
            Some("evt-a"),
            ev_map(vec![(
                "root_id",
                PyValue::list(vec![PyValue::string("evt-a")]),
            )]),
        );
        let err = _resolve_target_index(&listed_id, Some(&events)).expect_err("list id");
        assert_eq!(err, EventError::PythonStr);
        assert_eq!(err.to_string(), PYTHON_STR_UNREPRESENTABLE);
    }

    fn kind_event(kind: &str, corr: Option<&str>) -> EventValue {
        let mut entries = vec![("kind".to_owned(), EventField::Str(kind.to_owned()))];
        if let Some(corr) = corr {
            entries.push((
                "correlation_id".to_owned(),
                EventField::Str(corr.to_owned()),
            ));
        }
        EventValue::Mapping(EventMapping::new(entries))
    }

    #[test]
    fn torn_compaction_loss_returns_helper_length_or_one() {
        let float_boundary = [EventValue::Mapping(EventMapping::new(vec![(
            "kind".to_owned(),
            EventField::Float(1.0),
        )]))];
        assert_eq!(
            _compute_torn_compaction_loss(&float_boundary, -1).expect("low"),
            1
        );
        assert_eq!(
            _compute_torn_compaction_loss(&float_boundary, i64::MIN).expect("min"),
            1
        );
        assert_eq!(
            _compute_torn_compaction_loss(&float_boundary, 1).expect("high"),
            1
        );
        assert_eq!(_compute_torn_compaction_loss(&[], 0).expect("empty"), 1);
        let propagated = _compute_torn_compaction_loss(&float_boundary, 0).expect_err("event");
        let direct = _find_torn_compaction_dropped_indices(&float_boundary, 0).expect_err("direct");
        assert_eq!(propagated, direct);
        assert_eq!(propagated.to_string(), PYTHON_FLOAT_STR_UNREPRESENTABLE);
        assert!(matches!(propagated, PreconditionError::Event(_)));

        let message = [kind_event("message", None)];
        assert_eq!(
            _compute_torn_compaction_loss(&message, 0).expect("value"),
            1
        );
        assert!(matches!(
            _find_torn_compaction_dropped_indices(&message, 0).expect_err("value error"),
            PreconditionError::Value(_)
        ));

        let split = [
            kind_event("tool_call", Some("corr-synthetic")),
            kind_event("compaction_boundary", None),
            kind_event("tool_result", Some("corr-synthetic")),
        ];
        let dropped = _find_torn_compaction_dropped_indices(&split, 1).expect("dropped");
        let count = _compute_torn_compaction_loss(&split, 1).expect("count");
        assert_eq!(count, i64::try_from(dropped.len()).expect("len"));
        assert_eq!(count, 2);
    }

    fn plan_error(
        findings: &[Finding],
        events: &[SourceHashEvent],
        profile: &PlanProfile,
        source_hash: Option<&str>,
        policy: &PlanPolicy,
        acknowledge_side_effects: bool,
        input_format: Option<&str>,
    ) -> PlanError {
        plan(
            findings,
            events,
            profile,
            source_hash,
            policy,
            acknowledge_side_effects,
            input_format,
        )
        .expect_err("plan stops")
    }

    fn policy_text(policy: &PlanPolicy) -> String {
        let err = plan_error(
            &[],
            &[SourceHashEvent::Unrenderable],
            &PlanProfile::unrenderable(),
            None,
            policy,
            true,
            Some("not-a-format"),
        );
        assert!(err.source().is_none());
        assert!(!matches!(
            err,
            PlanError::SourceHash(_) | PlanError::ProfileStr | PlanError::RegisterAll
        ));
        err.to_string()
    }

    #[test]
    fn plan_rejects_policy_before_hash_profile_or_import() {
        assert_eq!(
            policy_text(&PlanPolicy::str_value("Aggressive")),
            "Invalid repair policy: 'Aggressive'. Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::str_value("")),
            "Invalid repair policy: ''. Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::str_value("it's")),
            "Invalid repair policy: \"it's\". Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::str_value("a\nb")),
            "Invalid repair policy: 'a\\nb'. Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::str_value("True")),
            "Invalid repair policy: 'True'. Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::str_value("conservative ")),
            "Invalid repair policy: 'conservative '. Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::bool_value(true)),
            "Invalid repair policy: True. Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::bool_value(false)),
            "Invalid repair policy: False. Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::none()),
            "Invalid repair policy: None. Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::int(1)),
            "Invalid repair policy: 1. Must be 'conservative' or 'salvage'"
        );
        assert_eq!(
            policy_text(&PlanPolicy::int(-2)),
            "Invalid repair policy: -2. Must be 'conservative' or 'salvage'"
        );
    }

    #[test]
    fn plan_propagates_source_hash_without_a_recipe_import() {
        let rendered = [SourceHashEvent::Rendered("echo-me".to_owned())];
        let direct = compute_events_source_hash(&rendered).expect_err("rendered");
        let via = plan_error(
            &[],
            &rendered,
            &PlanProfile::unrenderable(),
            None,
            &PlanPolicy::str_value("conservative"),
            false,
            None,
        );
        assert_eq!(via, PlanError::SourceHash(direct));
        assert_eq!(via.to_string(), HASHLIB_SHA256_UNAVAILABLE);
        assert_eq!(via.to_string(), direct.to_string());
        assert!(via.source().is_some());
        assert!(!via.to_string().contains("echo-me"));

        let unrendered = [SourceHashEvent::Unrenderable];
        let direct = compute_events_source_hash(&unrendered).expect_err("str");
        let via = plan_error(
            &[],
            &unrendered,
            &PlanProfile::str_value("neutral"),
            None,
            &PlanPolicy::str_value("salvage"),
            false,
            None,
        );
        assert_eq!(via, PlanError::SourceHash(direct));
        assert_eq!(via.to_string(), PYTHON_STR_UNREPRESENTABLE);
        assert_ne!(
            via.to_string(),
            RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
        );

        let mapping =
            EventMapping::new(vec![("id".to_owned(), EventField::Str("evt-a".to_owned()))]);
        let mapped = [SourceHashEvent::Mapping(mapping.clone())];
        let direct = compute_events_source_hash(&mapped).expect_err("mapping");
        let via = plan_error(
            &[],
            &mapped,
            &PlanProfile::unrenderable(),
            None,
            &PlanPolicy::str_value("conservative"),
            true,
            Some("canonical"),
        );
        assert_eq!(via, PlanError::SourceHash(direct));
        assert_eq!(
            via.to_string(),
            "sesslint._canonical_codec.canonical_json_bytes is not available"
        );
        assert_eq!(
            direct,
            SourceHashError::Canonical(canonical_bytes(&mapping).expect_err("canonical seam"))
        );
        assert!(!via.to_string().contains("evt-a"));
        assert!(via.source().is_some());

        let session = SessionEvent::new(
            "evt-synthetic",
            None,
            0,
            "2024-02-29T00:00:00Z",
            "assistant",
            "message",
        );
        let bytes = session.to_canonical_bytes().expect_err("session bytes");
        let session_events = [SourceHashEvent::Session(Box::new(session))];
        let direct = compute_events_source_hash(&session_events).expect_err("session");
        let via = plan_error(
            &[],
            &session_events,
            &PlanProfile::named("strict"),
            None,
            &PlanPolicy::str_value("conservative"),
            false,
            None,
        );
        assert_eq!(via, PlanError::SourceHash(direct));
        assert_eq!(direct, SourceHashError::Canonical(bytes));
        assert_ne!(via.to_string(), HASHLIB_SHA256_UNAVAILABLE);

        let stored = plan_error(
            &[],
            &unrendered,
            &PlanProfile::str_value("neutral"),
            Some(""),
            &PlanPolicy::str_value("conservative"),
            false,
            None,
        );
        assert_eq!(stored, PlanError::RegisterAll);
        assert_eq!(
            compute_events_source_hash(&[]).expect("empty"),
            EMPTY_EVENTS_HASH
        );
        let continued = plan_error(
            &[],
            &[],
            &PlanProfile::str_value("neutral"),
            None,
            &PlanPolicy::str_value("conservative"),
            false,
            None,
        );
        assert_eq!(continued, PlanError::RegisterAll);
    }

    #[test]
    fn plan_resolves_profile_then_stops_at_conservative_register_all() {
        assert_eq!(
            RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE,
            "sesslint.repair.recipes_conservative.register_all is not available"
        );
        assert_eq!(
            PlanError::RegisterAll.to_string(),
            RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
        );
        assert_eq!(
            PlanError::ProfileStr.to_string(),
            PYTHON_STR_UNREPRESENTABLE
        );
        assert!(PlanError::RegisterAll.source().is_none());
        assert!(PlanError::ProfileStr.source().is_none());

        let blocked = plan_error(
            &[],
            &[],
            &PlanProfile::unrenderable(),
            None,
            &PlanPolicy::str_value("conservative"),
            false,
            None,
        );
        assert_eq!(blocked, PlanError::ProfileStr);
        let blocked_salvage = plan_error(
            &[],
            &[SourceHashEvent::Unrenderable],
            &PlanProfile::unrenderable(),
            Some("abc"),
            &PlanPolicy::str_value("salvage"),
            true,
            Some("not-a-format"),
        );
        assert_eq!(blocked_salvage, PlanError::ProfileStr);

        let sl203 = target_finding("SL203", Some("rec-sl203"), PyValue::None);
        let bad_events = [SourceHashEvent::Unrenderable];
        let profiles = [
            PlanProfile::str_value("neutral"),
            PlanProfile::str_value(""),
            PlanProfile::named("strict"),
            PlanProfile::named(""),
            PlanProfile::bool_value(true),
            PlanProfile::bool_value(false),
            PlanProfile::none(),
            PlanProfile::int(0),
            PlanProfile::int(-2),
        ];
        for profile in &profiles {
            let err = plan_error(
                std::slice::from_ref(&sl203),
                &bad_events,
                profile,
                Some(""),
                &PlanPolicy::str_value("conservative"),
                true,
                Some("not-a-format"),
            );
            assert_eq!(err, PlanError::RegisterAll, "{profile:?}");
            assert_eq!(
                err.to_string(),
                RECIPES_CONSERVATIVE_REGISTER_ALL_UNAVAILABLE
            );
            assert!(!err.to_string().contains("SL203"));
            assert!(!err.to_string().contains("salvage"));
            assert!(!err.to_string().contains("SL002"));
        }
        let present = plan_error(
            &[],
            &bad_events,
            &PlanProfile::str_value("neutral"),
            Some("deadbeef"),
            &PlanPolicy::str_value("salvage"),
            false,
            None,
        );
        assert_eq!(present, PlanError::RegisterAll);
    }

    #[test]
    fn schema_helpers_stop_at_the_resource_seam() {
        assert_eq!(
            SCHEMA_PATH_UNAVAILABLE,
            "sesslint._resources.schema_path is not available"
        );
        let path_error = get_plan_schema_path();
        assert_eq!(path_error, PlanSchemaError);
        assert_eq!(path_error.to_string(), SCHEMA_PATH_UNAVAILABLE);
        assert!(path_error.source().is_none());
        assert!(!path_error.to_string().contains("schemas"));
        assert!(!path_error.to_string().contains("sesslint.plan.v1.json"));

        let loaded = load_plan_schema();
        assert_eq!(loaded, path_error);
        assert_eq!(loaded.to_string(), SCHEMA_PATH_UNAVAILABLE);
        assert!(!loaded.to_string().contains("Repair plan schema not found"));
        assert!(loaded.source().is_none());

        assert_eq!(
            ALL,
            [
                "ALLOWED_LOSS_CLASSES",
                "EMPTY_EVENTS_HASH",
                "MAX_STEPS",
                "PLAN_VERSION",
                "Blocked",
                "Loss",
                "PlanStep",
                "RepairPlan",
                "compute_events_source_hash",
                "get_plan_schema_path",
                "load_plan_schema",
                "plan",
            ]
        );
    }
}
