//! SL002 torn terminal record discard (RVW-002, TASK-2.1).
//!
//! Port of `src/sesslint/repair/recipes_sl002.py` lines 1-129
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`apply_torn_terminal_record_discard`] copies with
//! [`copy_events_as_dicts`](model::events::copy_events_as_dicts) and discards
//! the last event only when `params` is a mapping, `cut_index` is an int and
//! not a bool, and `target_index == cut_index == len(events) - 1` after the
//! copy. A copy error is propagated. The input events are not returned as a
//! successful discard. A reader-minted step names no event. An event that only
//! shares an id stays. Preceding events stay.
//!
//! [`affected_region_torn_terminal_record_discard`] would return
//! `sesslint.policy.abstention.AffectedRegion`. That type lives in the checks
//! crate. This crate does not depend on checks and does not construct that
//! type. Every path that would construct it, including empty, invalid,
//! exception, and success, returns [`AffectedRegionUnavailable`]. Index and id
//! checks still run, in pin order, before that error. A bool is not an int.
//!
//! Registration stores the two callables on the repair [`Recipe`] registry and
//! does not call them. No I/O.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::error::Error;
use std::fmt;

use model::events::{
    copy_events_as_dicts, event_id, EventError, EventField, EventMapping, EventValue,
};

use crate::registry::{get_recipe, register_recipe, CallableId, Recipe, RecipeSpec, RegistryError};

/// Python `__all__`, in that order.
pub const ALL: [&str; 4] = [
    "RECIPE_TORN_TERMINAL_RECORD_DISCARD",
    "affected_region_torn_terminal_record_discard",
    "apply_torn_terminal_record_discard",
    "register_all",
];

/// `sesslint.policy.abstention.AffectedRegion` is not available in this crate.
pub const AFFECTED_REGION_UNAVAILABLE: &str =
    "sesslint.policy.abstention.AffectedRegion is not available";

const RECIPE_NAME: &str = "torn-terminal-record-discard";
const HANDLES: [&str; 1] = [model::codes::SL002];
const PRECONDITIONS: [&str; 2] = ["no_sl203", "torn_terminal_record"];

/// Python `IndexError` from `list.pop` on an empty list.
const EMPTY_POP: &str = "pop from empty list";

/// Value read from `target_index`.
///
/// `None` is Python `None`, including a missing attribute. [`StepScalar::Bool`]
/// is not an int. [`StepScalar::Other`] is present and is neither `None`,
/// `bool`, nor `int`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepScalar {
    /// Python `None`.
    None,
    /// Python `int`. Not a bool.
    Int(i64),
    /// Python `bool`. Not an int.
    Bool(bool),
    /// Present, and not `None`, `bool`, or `int`.
    Other,
}

/// `params` as this recipe reads it.
///
/// [`StepParams::NotMapping`] is any non-mapping, including `None` and a
/// missing attribute.
#[derive(Debug, Clone, PartialEq)]
pub enum StepParams {
    /// Python `collections.abc.Mapping`.
    Mapping(EventMapping),
    /// Not a mapping.
    NotMapping,
}

/// Step fields this recipe reads.
///
/// This is not the planner `PlanStep`. The planner module is still empty.
/// `apply` reads `params["cut_index"]` and `target_index`. `affected_region`
/// reads `target_index`, then `cut_index`, `first_unsafe_index`, and
/// `target_index` inside `params`.
#[derive(Debug, Clone, PartialEq)]
pub struct TornTerminalStep {
    pub target_index: StepScalar,
    pub params: StepParams,
}

/// Failure from [`apply_torn_terminal_record_discard`].
///
/// [`Display`](fmt::Display) is the message only. A copy failure displays the
/// [`EventError`] text. An empty `pop` displays [`EMPTY_POP`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TornDiscardError {
    /// [`copy_events_as_dicts`](model::events::copy_events_as_dicts) failed.
    Copy(EventError),
    /// The discard condition matched `len == 0` and `pop` cannot run.
    EmptyPop,
}

impl fmt::Display for TornDiscardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Copy(error) => error.fmt(formatter),
            Self::EmptyPop => formatter.write_str(EMPTY_POP),
        }
    }
}

impl Error for TornDiscardError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Copy(error) => Some(error),
            Self::EmptyPop => None,
        }
    }
}

impl From<EventError> for TornDiscardError {
    fn from(error: EventError) -> Self {
        Self::Copy(error)
    }
}

/// `sesslint.policy.abstention.AffectedRegion` cannot be constructed here.
///
/// [`Display`](fmt::Display) is [`AFFECTED_REGION_UNAVAILABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffectedRegionUnavailable;

impl AffectedRegionUnavailable {
    /// Seam sentence. This is the Display text.
    pub const fn message(self) -> &'static str {
        AFFECTED_REGION_UNAVAILABLE
    }
}

impl fmt::Display for AffectedRegionUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(AFFECTED_REGION_UNAVAILABLE)
    }
}

impl Error for AffectedRegionUnavailable {}

/// Discard the torn terminal event when the step names that last index twice.
///
/// Python: `apply_torn_terminal_record_discard`. The copy runs first and has
/// no `try`/`except`. [`StepScalar::Bool`] as `cut_index` is not an int.
/// A bool `target_index` still uses Python `==` (`True == 1`, `False == 0`).
///
/// The arguments are owned because [`CallableId::from_fn`] stores
/// `fn(A, B) -> C`. A reference signature is higher-ranked and does not match
/// that constructor.
///
/// # Errors
///
/// Returns [`TornDiscardError::Copy`] when the copy fails. The input events
/// are not returned as `Ok`. Returns [`TornDiscardError::EmptyPop`] when the
/// index condition matches an empty list. This function does not panic.
#[allow(clippy::needless_pass_by_value)]
pub fn apply_torn_terminal_record_discard(
    events: Vec<EventValue>,
    step: TornTerminalStep,
) -> Result<Vec<EventMapping>, TornDiscardError> {
    let mut out = copy_events_as_dicts(&events)?;
    let Some(cut) = strict_cut_index(&step) else {
        return Ok(out);
    };
    let Some(last) = len_minus_one(out.len()) else {
        return Ok(out);
    };
    // `pop` runs only after the index match. `Some` discards the last event.
    // `None` is the empty-list `IndexError`.
    if target_equals_int(step.target_index, cut) && cut == last && out.pop().is_none() {
        return Err(TornDiscardError::EmptyPop);
    }
    Ok(out)
}

/// Declare the affected region, then refuse to construct it.
///
/// Python: `affected_region_torn_terminal_record_discard`. Empty input, a
/// non-int cut, an out-of-range cut, an `_event_id` failure, and a proven
/// index set all return [`AffectedRegionUnavailable`]. This is not `true` and
/// not an unproven region value.
///
/// Owned arguments match [`CallableId::from_fn`]. See
/// [`apply_torn_terminal_record_discard`].
///
/// # Errors
///
/// Always returns [`AffectedRegionUnavailable`] after the checks that apply.
/// Display is [`AFFECTED_REGION_UNAVAILABLE`]. This function does not panic.
#[allow(clippy::needless_pass_by_value)]
pub fn affected_region_torn_terminal_record_discard(
    step: TornTerminalStep,
    events: Vec<EventValue>,
) -> Result<Infallible, AffectedRegionUnavailable> {
    let error = match region_parts(&step, &events) {
        Ok(parts) => refuse_region(parts),
        Err(RegionFailure::Unproven | RegionFailure::Exception(_)) => AffectedRegionUnavailable,
    };
    Err(error)
}

/// Python `RECIPE_TORN_TERMINAL_RECORD_DISCARD`.
///
/// [`Recipe::try_new`] is fallible, so this is a function. The name is a
/// non-empty literal. Callables are stored and not called.
///
/// # Errors
///
/// Returns [`RegistryError`] when the name is empty. This literal is not empty.
pub fn recipe_torn_terminal_record_discard() -> Result<Recipe, RegistryError> {
    let spec = RecipeSpec {
        name: RECIPE_NAME,
        handles: &HANDLES,
        preconditions: &PRECONDITIONS,
        lossy: false,
        salvage_only: false,
        apply: Some(CallableId::from_fn(apply_torn_terminal_record_discard)),
        min_policy: "conservative",
        version: "1.0.0",
        affected_region: Some(CallableId::from_fn(
            affected_region_torn_terminal_record_discard,
        )),
        excludes_execution_dependence: false,
    };
    Recipe::try_new(spec)
}

/// Python constant `RECIPE_TORN_TERMINAL_RECORD_DISCARD`.
pub use recipe_torn_terminal_record_discard as RECIPE_TORN_TERMINAL_RECORD_DISCARD;

/// Register the SL002 recipe when its name is absent.
///
/// Python: `register_all`. [`get_recipe`] runs first. An absent name is
/// registered through [`register_recipe`]. `apply` and `affected_region` are
/// not called. This does not build a second registry.
///
/// # Errors
///
/// Returns [`RegistryError`] when construction or registration fails. A name
/// that appears between the check and the insert is the duplicate-name
/// `ValueError`.
pub fn register_all() -> Result<(), RegistryError> {
    if get_recipe(RECIPE_NAME).is_none() {
        register_recipe(&recipe_torn_terminal_record_discard()?)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolved {
    Int(i64),
    NotInt,
}

#[derive(Debug, PartialEq, Eq)]
enum RegionFailure {
    Unproven,
    Exception(Option<EventError>),
}

#[derive(Debug, PartialEq, Eq)]
struct RegionParts {
    indices: BTreeSet<i64>,
    ids: BTreeSet<String>,
    ranges: [(i64, i64); 1],
}

fn strict_cut_index(step: &TornTerminalStep) -> Option<i64> {
    let StepParams::Mapping(params) = &step.params else {
        return None;
    };
    match params.get("cut_index") {
        Some(EventField::Int(value)) => Some(*value),
        _ => None,
    }
}

fn target_equals_int(target: StepScalar, cut: i64) -> bool {
    match target {
        StepScalar::Int(value) => value == cut,
        StepScalar::Bool(true) => cut == 1,
        StepScalar::Bool(false) => cut == 0,
        StepScalar::None | StepScalar::Other => false,
    }
}

/// Python `len(events) - 1`.
///
/// An empty list is `-1`. A length that does not fit in `i64` is `None`; the
/// caller then keeps the copy because equality cannot be proved.
fn len_minus_one(len: usize) -> Option<i64> {
    if len == 0 {
        return Some(-1);
    }
    i64::try_from(len - 1).ok()
}

fn field_is_none(value: Option<&EventField>) -> bool {
    matches!(value, None | Some(EventField::Null))
}

/// Pin order: `cut_index`, then `first_unsafe_index`, then `target_index`.
///
/// A present non-`None` value stops the walk. A bool is present. It is not
/// skipped, and it is not an int.
fn chosen_param(params: &EventMapping) -> Option<&EventField> {
    let mut chosen = params.get("cut_index");
    if field_is_none(chosen) {
        chosen = params.get("first_unsafe_index");
    }
    if field_is_none(chosen) {
        chosen = params.get("target_index");
    }
    match chosen {
        None | Some(EventField::Null) => None,
        Some(value) => Some(value),
    }
}

fn param_cut(params: &StepParams) -> Option<Resolved> {
    let StepParams::Mapping(mapping) = params else {
        return None;
    };
    match chosen_param(mapping) {
        Some(EventField::Int(value)) => Some(Resolved::Int(*value)),
        _ => None,
    }
}

fn region_parts(
    step: &TornTerminalStep,
    events: &[EventValue],
) -> Result<RegionParts, RegionFailure> {
    let num_events = events.len();
    if num_events == 0 {
        return Err(RegionFailure::Unproven);
    }

    let mut cut = match step.target_index {
        StepScalar::None => None,
        StepScalar::Int(value) => Some(Resolved::Int(value)),
        StepScalar::Bool(_) | StepScalar::Other => Some(Resolved::NotInt),
    };
    if cut.is_none() {
        cut = param_cut(&step.params);
    }

    if let Some(resolved) = cut {
        let Resolved::Int(cut) = resolved else {
            return Err(RegionFailure::Unproven);
        };
        if cut < 0 {
            return Err(RegionFailure::Unproven);
        }
        let Ok(cut_index) = usize::try_from(cut) else {
            return Err(RegionFailure::Unproven);
        };
        if cut_index >= num_events {
            return Err(RegionFailure::Unproven);
        }

        let mut indices = BTreeSet::new();
        for index in cut_index..num_events {
            let Ok(index) = i64::try_from(index) else {
                return Err(RegionFailure::Exception(None));
            };
            indices.insert(index);
        }
        if cut > 0 {
            indices.insert(cut - 1);
        }
        let start_ord = if cut == 0 { 0 } else { cut - 1 };
        let Ok(end_ord) = i64::try_from(num_events - 1) else {
            return Err(RegionFailure::Exception(None));
        };
        let ids = ids_for(events, &indices)?;
        return Ok(RegionParts {
            indices,
            ids,
            ranges: [(start_ord, end_ord)],
        });
    }

    let boundary_idx = num_events - 1;
    let Ok(boundary) = i64::try_from(boundary_idx) else {
        return Err(RegionFailure::Exception(None));
    };
    let Some(event) = events.get(boundary_idx) else {
        return Err(RegionFailure::Exception(None));
    };
    let boundary_id = match event_id(event) {
        Ok(id) => id,
        Err(error) => return Err(RegionFailure::Exception(Some(error))),
    };
    let mut ids = BTreeSet::new();
    if let Some(id) = boundary_id {
        ids.insert(id);
    }
    let mut indices = BTreeSet::new();
    indices.insert(boundary);
    Ok(RegionParts {
        indices,
        ids,
        ranges: [(boundary, boundary)],
    })
}

fn ids_for(
    events: &[EventValue],
    indices: &BTreeSet<i64>,
) -> Result<BTreeSet<String>, RegionFailure> {
    let mut ids = BTreeSet::new();
    for index in indices {
        let Some(index) = usize::try_from(*index).ok() else {
            return Err(RegionFailure::Exception(None));
        };
        let Some(event) = events.get(index) else {
            return Err(RegionFailure::Exception(None));
        };
        match event_id(event) {
            Ok(Some(id)) => {
                ids.insert(id);
            }
            Ok(None) => {}
            Err(error) => return Err(RegionFailure::Exception(Some(error))),
        }
    }
    Ok(ids)
}

fn refuse_region(parts: RegionParts) -> AffectedRegionUnavailable {
    let _checked = (
        parts.indices.len(),
        parts.ids.len(),
        parts.ranges[0].0,
        parts.ranges[0].1,
    );
    AffectedRegionUnavailable
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error;

    use model::canonical::SessionEvent;
    use model::events::{copy_events_as_dicts, EventError, EventField, EventMapping, EventValue};

    use super::{
        affected_region_torn_terminal_record_discard, apply_torn_terminal_record_discard,
        chosen_param, recipe_torn_terminal_record_discard, region_parts, RegionFailure,
        RegionParts, StepParams, StepScalar, TornDiscardError, TornTerminalStep, ALL,
        RECIPE_TORN_TERMINAL_RECORD_DISCARD,
    };
    use crate::registry::CallableId;

    fn bare(entries: Vec<(&str, EventField)>) -> EventMapping {
        EventMapping::new(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    fn params(entries: Vec<(&str, EventField)>) -> StepParams {
        StepParams::Mapping(bare(entries))
    }

    fn step(target_index: StepScalar, params: StepParams) -> TornTerminalStep {
        TornTerminalStep {
            target_index,
            params,
        }
    }

    fn named(id: &str) -> EventValue {
        EventValue::Mapping(bare(vec![("id", EventField::Str(id.to_owned()))]))
    }

    fn id_text(mapping: &EventMapping) -> Option<&str> {
        match mapping.get("id") {
            Some(EventField::Str(text)) => Some(text.as_str()),
            _ => None,
        }
    }

    fn ids(mappings: &[EventMapping]) -> Vec<Option<&str>> {
        mappings.iter().map(id_text).collect()
    }

    fn seam(step: TornTerminalStep, events: Vec<EventValue>) -> String {
        affected_region_torn_terminal_record_discard(step, events)
            .expect_err("AffectedRegion is not available")
            .to_string()
    }

    #[test]
    fn discards_only_the_named_last_event_and_keeps_the_prefix() {
        let events = vec![named("a"), named("b"), named("c")];
        let kept = step(
            StepScalar::Int(2),
            params(vec![("cut_index", EventField::Int(2))]),
        );
        let out = apply_torn_terminal_record_discard(events, kept).expect("copy");
        assert_eq!(ids(&out), vec![Some("a"), Some("b")]);
    }

    #[test]
    fn reader_minted_step_names_no_event() {
        let events = vec![named("a"), named("torn")];
        let minted = step(
            StepScalar::None,
            params(vec![("cut_index", EventField::Int(1))]),
        );
        let out = apply_torn_terminal_record_discard(events, minted).expect("copy");
        assert_eq!(ids(&out), vec![Some("a"), Some("torn")]);
    }

    #[test]
    fn shared_id_on_a_preceding_event_stays() {
        let events = vec![named("same"), named("same")];
        let named_last = step(
            StepScalar::Int(1),
            params(vec![("cut_index", EventField::Int(1))]),
        );
        let out = apply_torn_terminal_record_discard(events, named_last).expect("copy");
        assert_eq!(ids(&out), vec![Some("same")]);

        let events = vec![named("same"), named("same")];
        let id_only = step(
            StepScalar::Int(0),
            params(vec![("cut_index", EventField::Int(0))]),
        );
        let out = apply_torn_terminal_record_discard(events, id_only).expect("copy");
        assert_eq!(ids(&out), vec![Some("same"), Some("same")]);
    }

    #[test]
    fn bool_cut_index_is_not_an_int() {
        let events = vec![named("a"), named("b")];
        let bool_cut = step(
            StepScalar::Int(1),
            params(vec![("cut_index", EventField::Bool(true))]),
        );
        let out = apply_torn_terminal_record_discard(events, bool_cut).expect("copy");
        assert_eq!(ids(&out), vec![Some("a"), Some("b")]);
    }

    #[test]
    fn bool_target_uses_python_equality() {
        let true_target = step(
            StepScalar::Bool(true),
            params(vec![("cut_index", EventField::Int(1))]),
        );
        let out = apply_torn_terminal_record_discard(vec![named("a"), named("b")], true_target)
            .expect("copy");
        assert_eq!(ids(&out), vec![Some("a")]);

        let false_target = step(
            StepScalar::Bool(false),
            params(vec![("cut_index", EventField::Int(0))]),
        );
        let out =
            apply_torn_terminal_record_discard(vec![named("only")], false_target).expect("copy");
        assert!(out.is_empty());

        let true_is_not_zero = step(
            StepScalar::Bool(true),
            params(vec![("cut_index", EventField::Int(0))]),
        );
        let out = apply_torn_terminal_record_discard(vec![named("only")], true_is_not_zero)
            .expect("copy");
        assert_eq!(ids(&out), vec![Some("only")]);
    }

    #[test]
    fn non_mapping_params_and_other_target_keep_events() {
        let events = vec![named("a"), named("b")];
        let not_mapping = step(StepScalar::Int(1), StepParams::NotMapping);
        let out = apply_torn_terminal_record_discard(events, not_mapping).expect("copy");
        assert_eq!(ids(&out), vec![Some("a"), Some("b")]);

        let other = step(
            StepScalar::Other,
            params(vec![("cut_index", EventField::Int(1))]),
        );
        let out =
            apply_torn_terminal_record_discard(vec![named("a"), named("b")], other).expect("copy");
        assert_eq!(ids(&out), vec![Some("a"), Some("b")]);
    }

    #[test]
    fn apply_does_not_read_the_region_fallback_keys() {
        let fallback = step(
            StepScalar::Int(1),
            params(vec![("first_unsafe_index", EventField::Int(1))]),
        );
        let out = apply_torn_terminal_record_discard(vec![named("a"), named("b")], fallback)
            .expect("copy");
        assert_eq!(ids(&out), vec![Some("a"), Some("b")]);
    }

    #[test]
    fn last_cut_index_wins_and_the_copy_is_independent() {
        let original = bare(vec![
            ("id", EventField::Str("a".to_owned())),
            ("kind", EventField::Str("message".to_owned())),
        ]);
        let events = vec![EventValue::Mapping(original.clone()), named("b")];
        let duplicated_keys = step(
            StepScalar::Int(1),
            StepParams::Mapping(EventMapping::new(vec![
                ("cut_index".to_owned(), EventField::Int(0)),
                ("cut_index".to_owned(), EventField::Int(1)),
            ])),
        );
        let mut out = apply_torn_terminal_record_discard(events, duplicated_keys).expect("copy");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], original);
        out[0].push("extra", EventField::Null);
        assert_eq!(original.entries().len(), 2);
        assert!(original.get("extra").is_none());
    }

    #[test]
    fn copy_error_is_propagated_and_is_not_a_successful_discard() {
        let events = vec![
            named("keep"),
            EventValue::from_session(SessionEvent::new(
                "evt-synthetic",
                None,
                1,
                "2026-01-01T00:00:00Z",
                "assistant",
                "message",
            )),
        ];
        let direct = copy_events_as_dicts(&events).expect_err("session copy");
        let step = step(
            StepScalar::Int(1),
            params(vec![("cut_index", EventField::Int(1))]),
        );
        let err = apply_torn_terminal_record_discard(events, step).expect_err("propagated");
        assert_eq!(err.to_string(), direct.to_string());
        assert!(matches!(err, TornDiscardError::Copy(copy) if copy == direct));
        assert_eq!(
            Error::source(&err).map(ToString::to_string).as_deref(),
            Some(direct.to_string().as_str())
        );
        assert!(!err.to_string().contains("keep"));
    }

    #[test]
    fn empty_list_pop_is_an_error_and_a_missing_cut_stays_empty() {
        let pop = step(
            StepScalar::Int(-1),
            params(vec![("cut_index", EventField::Int(-1))]),
        );
        let err = apply_torn_terminal_record_discard(Vec::new(), pop).expect_err("empty pop");
        assert_eq!(err.to_string(), "pop from empty list");
        assert!(matches!(err, TornDiscardError::EmptyPop));
        assert!(Error::source(&err).is_none());

        let missing = step(StepScalar::None, StepParams::NotMapping);
        let out = apply_torn_terminal_record_discard(Vec::new(), missing).expect("copy");
        assert!(out.is_empty());
    }

    #[test]
    fn param_walk_stops_on_a_bool_and_prefers_cut_index() {
        let bool_stops = bare(vec![
            ("cut_index", EventField::Bool(true)),
            ("first_unsafe_index", EventField::Int(2)),
        ]);
        assert_eq!(chosen_param(&bool_stops), Some(&EventField::Bool(true)));

        let null_then_unsafe = bare(vec![
            ("cut_index", EventField::Null),
            ("first_unsafe_index", EventField::Int(2)),
            ("target_index", EventField::Int(0)),
        ]);
        assert_eq!(chosen_param(&null_then_unsafe), Some(&EventField::Int(2)));

        let unsafe_null = bare(vec![
            ("first_unsafe_index", EventField::Null),
            ("target_index", EventField::Int(0)),
        ]);
        assert_eq!(chosen_param(&unsafe_null), Some(&EventField::Int(0)));
    }

    #[test]
    fn empty_invalid_and_bool_targets_do_not_build_ids() {
        let events = vec![named("a")];
        assert_eq!(
            region_parts(&step(StepScalar::Int(0), StepParams::NotMapping), &[]),
            Err(RegionFailure::Unproven)
        );
        assert_eq!(
            region_parts(&step(StepScalar::Int(3), StepParams::NotMapping), &events),
            Err(RegionFailure::Unproven)
        );
        assert_eq!(
            region_parts(&step(StepScalar::Int(-1), StepParams::NotMapping), &events),
            Err(RegionFailure::Unproven)
        );
        assert_eq!(
            region_parts(
                &step(
                    StepScalar::Bool(true),
                    params(vec![("cut_index", EventField::Int(0))])
                ),
                &events
            ),
            Err(RegionFailure::Unproven)
        );
        assert_eq!(
            region_parts(
                &step(
                    StepScalar::Other,
                    params(vec![("cut_index", EventField::Int(0))])
                ),
                &events
            ),
            Err(RegionFailure::Unproven)
        );
    }

    #[test]
    fn bool_param_stays_on_the_boundary_path() {
        let events = vec![named("a"), named("b"), named("c")];
        let bool_cut = step(
            StepScalar::None,
            params(vec![
                ("cut_index", EventField::Bool(false)),
                ("first_unsafe_index", EventField::Int(0)),
            ]),
        );
        assert_eq!(
            region_parts(&bool_cut, &events),
            Ok(RegionParts {
                indices: BTreeSet::from([2]),
                ids: BTreeSet::from(["c".to_owned()]),
                ranges: [(2, 2)],
            })
        );
    }

    #[test]
    fn cut_index_wins_and_includes_the_preceding_boundary() {
        let events = vec![named("a"), named("b"), named("c")];
        let cut = step(
            StepScalar::None,
            params(vec![
                ("cut_index", EventField::Int(2)),
                ("first_unsafe_index", EventField::Int(0)),
            ]),
        );
        assert_eq!(
            region_parts(&cut, &events),
            Ok(RegionParts {
                indices: BTreeSet::from([1, 2]),
                ids: BTreeSet::from(["b".to_owned(), "c".to_owned()]),
                ranges: [(1, 2)],
            })
        );
    }

    #[test]
    fn missing_id_is_omitted_and_a_float_id_is_the_exception_path() {
        let events = vec![
            EventValue::Mapping(EventMapping::new(Vec::new())),
            named("b"),
        ];
        let whole = step(StepScalar::Int(0), StepParams::NotMapping);
        assert_eq!(
            region_parts(&whole, &events),
            Ok(RegionParts {
                indices: BTreeSet::from([0, 1]),
                ids: BTreeSet::from(["b".to_owned()]),
                ranges: [(0, 1)],
            })
        );

        let float_id = EventValue::Mapping(bare(vec![("id", EventField::Float(1.0))]));
        let events = vec![float_id, named("b")];
        assert_eq!(
            region_parts(&step(StepScalar::Int(0), StepParams::NotMapping), &events),
            Err(RegionFailure::Exception(Some(EventError::PythonFloatStr)))
        );
    }

    #[test]
    fn session_boundary_id_is_read_before_the_seam() {
        let events = vec![EventValue::from_session(SessionEvent::new(
            "evt-boundary",
            None,
            0,
            "2026-01-01T00:00:00Z",
            "user",
            "message",
        ))];
        let dropped = step(StepScalar::None, StepParams::NotMapping);
        assert_eq!(
            region_parts(&dropped, &events),
            Ok(RegionParts {
                indices: BTreeSet::from([0]),
                ids: BTreeSet::from(["evt-boundary".to_owned()]),
                ranges: [(0, 0)],
            })
        );
        assert_eq!(
            seam(dropped, events),
            "sesslint.policy.abstention.AffectedRegion is not available"
        );
    }

    #[test]
    fn every_region_path_displays_the_checks_seam() {
        let proven = step(
            StepScalar::Int(2),
            params(vec![("cut_index", EventField::Int(2))]),
        );
        let events = vec![named("a"), named("b"), named("c")];
        let error = affected_region_torn_terminal_record_discard(proven, events).expect_err("seam");
        assert_eq!(
            error.to_string(),
            "sesslint.policy.abstention.AffectedRegion is not available"
        );
        assert_eq!(error.message(), error.to_string());
        assert!(Error::source(&error).is_none());

        let cases = [
            seam(step(StepScalar::Int(0), StepParams::NotMapping), Vec::new()),
            seam(
                step(StepScalar::Int(4), StepParams::NotMapping),
                vec![named("a")],
            ),
            seam(
                step(StepScalar::Bool(true), StepParams::NotMapping),
                vec![named("a"), named("b")],
            ),
            seam(
                step(StepScalar::None, StepParams::NotMapping),
                vec![EventValue::Mapping(bare(vec![(
                    "id",
                    EventField::Float(1.5),
                )]))],
            ),
        ];
        for text in cases {
            assert_eq!(
                text,
                "sesslint.policy.abstention.AffectedRegion is not available"
            );
            assert!(!text.contains("float"));
            assert!(!text.contains("representable"));
            assert!(!text.contains("unproven"));
            assert_ne!(text, "true");
        }
    }

    #[test]
    fn recipe_fields_match_the_pin_and_store_distinct_callables() {
        let recipe = recipe_torn_terminal_record_discard().expect("recipe");
        let alias = RECIPE_TORN_TERMINAL_RECORD_DISCARD().expect("alias");
        assert_eq!(recipe, alias);
        assert_eq!(recipe.name(), "torn-terminal-record-discard");
        assert_eq!(
            recipe
                .handles()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![model::codes::SL002]
        );
        assert_eq!(
            recipe
                .preconditions()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["no_sl203", "torn_terminal_record"]
        );
        assert!(!recipe.lossy());
        assert!(!recipe.salvage_only());
        assert_eq!(recipe.min_policy(), "conservative");
        assert_eq!(recipe.version(), "1.0.0");
        assert!(!recipe.excludes_execution_dependence());
        assert_eq!(
            recipe.apply(),
            Some(CallableId::from_fn(apply_torn_terminal_record_discard))
        );
        assert_eq!(
            recipe.affected_region(),
            Some(CallableId::from_fn(
                affected_region_torn_terminal_record_discard
            ))
        );
        assert_ne!(recipe.apply(), recipe.affected_region());
        assert_eq!(
            ALL,
            [
                "RECIPE_TORN_TERMINAL_RECORD_DISCARD",
                "affected_region_torn_terminal_record_discard",
                "apply_torn_terminal_record_discard",
                "register_all",
            ]
        );
    }
}
