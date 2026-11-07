//! Repair recipe registry and metadata definitions (TASK-018).
//!
//! Port of `src/sesslint/repair/registry.py` lines 1-97
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! No I/O and no file writes. A duplicate name or an unknown precondition is
//! a Python `ValueError`. [`list_recipes`] is insertion order. Handles are
//! sorted because the pin sorts them. Preconditions are not sorted.
//!
//! This table has its own mutex. It does not lock the precondition registry.
//! After the duplicate-name check, a non-empty precondition list is tested
//! against [`precondition_func_names`](crate::preconditions::precondition_func_names).
//! An empty list does not read that table. `apply` and `affected_region` are
//! stored and are not called.

use std::error::Error;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use crate::preconditions::precondition_func_names;

/// Python `__all__`, in that order. Not sorted.
///
/// `REGISTRY` is the live map. This port does not hand the map out. Lookup is
/// [`get_recipe`]. The values in insertion order are [`list_recipes`].
pub const ALL: [&str; 7] = [
    "REGISTRY",
    "Recipe",
    "clear_registry",
    "get_recipe",
    "list_recipes",
    "recipes_for",
    "register_recipe",
];

/// A non-string recipe name is not representable in `&str`.
///
/// Python `__post_init__` raises `ValueError` when `name` is not a `str`.
/// This constructor does not panic to imitate that branch.
pub const NON_STRING_NAME_UNREPRESENTABLE: &str = "A non-string recipe name is not representable in &str. Python __post_init__ raises ValueError when name is not a str. This constructor does not panic to imitate that branch.";

/// Python `ValueError` from recipe construction or registration.
///
/// [`Display`](fmt::Display) is the message only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError {
    message: String,
}

impl RegistryError {
    fn value(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Python exception message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for RegistryError {}

/// Identity of a callable stored on [`Recipe`].
///
/// Python types `apply` and `affected_region` as `Any`. This module stores the
/// pointer and does not call it. `None` is Python `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallableId {
    address: usize,
}

impl CallableId {
    /// Capture `pointer` without calling it.
    pub fn from_fn<A, B, C>(pointer: fn(A, B) -> C) -> Self {
        Self {
            address: pointer as *const () as usize,
        }
    }
}

/// Inputs for [`Recipe::try_new`].
///
/// Field order matches the Python dataclass. Omitted callables are `None`.
#[derive(Debug, Clone, Copy)]
pub struct RecipeSpec<'a> {
    pub name: &'a str,
    pub handles: &'a [&'a str],
    pub preconditions: &'a [&'a str],
    pub lossy: bool,
    pub salvage_only: bool,
    pub apply: Option<CallableId>,
    pub min_policy: &'a str,
    pub version: &'a str,
    pub affected_region: Option<CallableId>,
    pub excludes_execution_dependence: bool,
}

impl<'a> RecipeSpec<'a> {
    /// Python dataclass defaults.
    ///
    /// `min_policy` is `"conservative"`, `version` is `"1.0.0"`, both callables
    /// are absent, and `excludes_execution_dependence` is false.
    pub fn new(
        name: &'a str,
        handles: &'a [&'a str],
        preconditions: &'a [&'a str],
        lossy: bool,
        salvage_only: bool,
    ) -> Self {
        Self {
            name,
            handles,
            preconditions,
            lossy,
            salvage_only,
            apply: None,
            min_policy: "conservative",
            version: "1.0.0",
            affected_region: None,
            excludes_execution_dependence: false,
        }
    }
}

/// Specification of a deterministic repair recipe.
///
/// Python: `Recipe` (`frozen=True`, `slots=True`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipe {
    name: String,
    handles: Vec<String>,
    preconditions: Vec<String>,
    lossy: bool,
    salvage_only: bool,
    apply: Option<CallableId>,
    min_policy: String,
    version: String,
    affected_region: Option<CallableId>,
    excludes_execution_dependence: bool,
}

impl Recipe {
    /// Build a recipe.
    ///
    /// Python: `Recipe.__post_init__`. Check order is fixed: non-empty name,
    /// then sort `handles`, then maybe rewrite `min_policy`, then maybe set
    /// `salvage_only`. A non-string name is not representable
    /// ([`NON_STRING_NAME_UNREPRESENTABLE`]).
    ///
    /// Handles use Python `sorted` order for `str`: Unicode scalar order.
    /// Preconditions keep the caller's order.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] when `name` is empty. Display is
    /// `Recipe name must be a non-empty string`. This function does not panic
    /// and does not register the recipe.
    pub fn try_new(spec: RecipeSpec<'_>) -> Result<Self, RegistryError> {
        if spec.name.is_empty() {
            return Err(RegistryError::value(
                "Recipe name must be a non-empty string",
            ));
        }
        let mut handles: Vec<String> = spec.handles.iter().copied().map(str::to_owned).collect();
        // Python `sorted` is stable. Equal strings keep their relative order.
        handles.sort();
        let mut min_policy = spec.min_policy.to_owned();
        let mut salvage_only = spec.salvage_only;
        if (salvage_only || spec.lossy) && min_policy == "conservative" {
            min_policy = "salvage".to_owned();
        }
        if spec.lossy && !spec.salvage_only {
            salvage_only = true;
        }
        Ok(Self {
            name: spec.name.to_owned(),
            handles,
            preconditions: spec
                .preconditions
                .iter()
                .copied()
                .map(str::to_owned)
                .collect(),
            lossy: spec.lossy,
            salvage_only,
            apply: spec.apply,
            min_policy,
            version: spec.version.to_owned(),
            affected_region: spec.affected_region,
            excludes_execution_dependence: spec.excludes_execution_dependence,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn handles(&self) -> &[String] {
        &self.handles
    }

    pub fn preconditions(&self) -> &[String] {
        &self.preconditions
    }

    pub fn lossy(&self) -> bool {
        self.lossy
    }

    pub fn salvage_only(&self) -> bool {
        self.salvage_only
    }

    pub fn apply(&self) -> Option<CallableId> {
        self.apply
    }

    pub fn min_policy(&self) -> &str {
        &self.min_policy
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn affected_region(&self) -> Option<CallableId> {
        self.affected_region
    }

    pub fn excludes_execution_dependence(&self) -> bool {
        self.excludes_execution_dependence
    }
}

/// Register `recipe`.
///
/// Python: `register_recipe`. The duplicate-name check runs before any
/// precondition name is read. Each precondition is then tested in list order.
/// The first unknown name fails. The recipe is inserted only after both checks
/// pass. Insertion order is the order of successful registration.
///
/// # Errors
///
/// Returns [`RegistryError`] for a duplicate name or an unknown precondition.
/// Display is the Python `ValueError` message. This function does not panic
/// and does not insert on error.
pub fn register_recipe(recipe: &Recipe) -> Result<(), RegistryError> {
    if name_present(recipe.name()) {
        return Err(duplicate_name(recipe.name()));
    }
    if let Some(unknown) = unknown_precondition(recipe) {
        return Err(unknown_precondition_error(recipe.name(), &unknown));
    }
    with_registry(|registry| {
        if registry
            .iter()
            .any(|existing| existing.name() == recipe.name())
        {
            return Err(duplicate_name(recipe.name()));
        }
        registry.push(recipe.clone());
        Ok(())
    })
}

/// Python: `get_recipe`. `None` when the name is absent.
pub fn get_recipe(name: &str) -> Option<Recipe> {
    with_registry(|registry| {
        registry
            .iter()
            .find(|recipe| recipe.name() == name)
            .cloned()
    })
}

/// Python: `recipes_for`. Registration order. A code matches a handle exactly.
pub fn recipes_for(code: &str) -> Vec<Recipe> {
    with_registry(|registry| {
        registry
            .iter()
            .filter(|recipe| recipe.handles().iter().any(|handle| handle == code))
            .cloned()
            .collect()
    })
}

/// Python: `list_recipes`. Insertion order. This is not sorted.
pub fn list_recipes() -> Vec<Recipe> {
    with_registry(|registry| registry.clone())
}

/// Python: `clear_registry`. Drops every recipe. Precondition names stay.
pub fn clear_registry() {
    with_registry(|registry| registry.clear());
}

fn duplicate_name(name: &str) -> RegistryError {
    RegistryError::value(format!(
        "Duplicate recipe name: '{name}' is already registered"
    ))
}

fn unknown_precondition_error(recipe: &str, precondition: &str) -> RegistryError {
    RegistryError::value(format!(
        "Recipe '{recipe}' references unknown precondition: '{precondition}'"
    ))
}

/// `None` when every name is known. An empty list does not read the table.
fn unknown_precondition(recipe: &Recipe) -> Option<String> {
    if recipe.preconditions.is_empty() {
        return None;
    }
    let known = precondition_func_names();
    recipe
        .preconditions
        .iter()
        .find(|name| !known.iter().any(|known_name| known_name == *name))
        .cloned()
}

fn name_present(name: &str) -> bool {
    with_registry(|registry| registry.iter().any(|existing| existing.name() == name))
}

/// Recipe table. Not the precondition registry mutex.
fn registry() -> &'static Mutex<Vec<Recipe>> {
    static REGISTRY: OnceLock<Mutex<Vec<Recipe>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

fn with_registry<T>(body: impl FnOnce(&mut Vec<Recipe>) -> T) -> T {
    let mut guard = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    body(&mut guard)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::{Mutex, MutexGuard};

    use crate::preconditions::precondition_func_names;

    use super::{
        clear_registry, get_recipe, list_recipes, recipes_for, register_recipe, CallableId, Recipe,
        RecipeSpec, RegistryError, ALL, NON_STRING_NAME_UNREPRESENTABLE,
    };

    fn isolate() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        clear_registry();
        guard
    }

    fn must(result: Result<Recipe, RegistryError>) -> Recipe {
        match result {
            Ok(recipe) => recipe,
            Err(error) => panic!("{error}"),
        }
    }

    fn must_register(result: Result<(), RegistryError>) {
        if let Err(error) = result {
            panic!("{error}");
        }
    }

    fn strings(values: &[String]) -> Vec<&str> {
        values.iter().map(String::as_str).collect()
    }

    fn must_not_run(_left: u8, _right: u8) -> u8 {
        panic!("recipe callable must not be invoked");
    }

    #[test]
    fn empty_name_is_value_error_and_registers_nothing() {
        let _guard = isolate();
        let error =
            match Recipe::try_new(RecipeSpec::new("", &["SL101"], &["no_sl203"], false, false)) {
                Ok(_) => panic!("expected ValueError"),
                Err(error) => error,
            };
        assert_eq!(error.to_string(), "Recipe name must be a non-empty string");
        assert_eq!(error.message(), "Recipe name must be a non-empty string");
        assert!(Error::source(&error).is_none());
        assert!(list_recipes().is_empty());
        assert!(NON_STRING_NAME_UNREPRESENTABLE.contains("not representable"));
        assert!(NON_STRING_NAME_UNREPRESENTABLE.contains("ValueError"));
        assert!(NON_STRING_NAME_UNREPRESENTABLE.contains("does not panic"));
    }

    #[test]
    fn normalization_matches_post_init() {
        let _guard = isolate();
        let conservative = must(Recipe::try_new(RecipeSpec::new(
            "plain",
            &["m", "a", "m"],
            &[],
            false,
            false,
        )));
        assert_eq!(strings(conservative.handles()), ["a", "m", "m"]);
        assert_eq!(conservative.min_policy(), "conservative");
        assert!(!conservative.lossy());
        assert!(!conservative.salvage_only());
        assert_eq!(conservative.version(), "1.0.0");
        assert!(!conservative.excludes_execution_dependence());
        assert!(conservative.apply().is_none());
        assert!(conservative.affected_region().is_none());

        let lossy = must(Recipe::try_new(RecipeSpec::new(
            "lossy-conservative",
            &["SL005"],
            &[],
            true,
            false,
        )));
        assert_eq!(lossy.min_policy(), "salvage");
        assert!(lossy.lossy());
        assert!(lossy.salvage_only());

        let salvage_only = must(Recipe::try_new(RecipeSpec::new(
            "salvage-flag",
            &[],
            &[],
            false,
            true,
        )));
        assert_eq!(salvage_only.min_policy(), "salvage");
        assert!(!salvage_only.lossy());
        assert!(salvage_only.salvage_only());

        let both = must(Recipe::try_new(RecipeSpec::new(
            "both-flags",
            &[],
            &[],
            true,
            true,
        )));
        assert_eq!(both.min_policy(), "salvage");
        assert!(both.salvage_only());

        let mut strict = RecipeSpec::new("lossy-strict", &[], &[], true, false);
        strict.min_policy = "strict";
        let strict = must(Recipe::try_new(strict));
        assert_eq!(strict.min_policy(), "strict");
        assert!(strict.salvage_only());

        let mut mixed_case = RecipeSpec::new("lossy-mixed-case", &[], &[], true, false);
        mixed_case.min_policy = "Conservative";
        let mixed_case = must(Recipe::try_new(mixed_case));
        assert_eq!(mixed_case.min_policy(), "Conservative");
        assert!(mixed_case.salvage_only());

        let mut custom = RecipeSpec::new(" ", &[], &[], false, false);
        custom.version = "9.9.9";
        custom.excludes_execution_dependence = true;
        let custom = must(Recipe::try_new(custom));
        assert_eq!(custom.name(), " ");
        assert_eq!(custom.version(), "9.9.9");
        assert!(custom.excludes_execution_dependence());
        assert!(custom.handles().is_empty());

        must_register(register_recipe(&lossy));
        assert_eq!(get_recipe("lossy-conservative"), Some(lossy));
    }

    #[test]
    fn happy_registration_preserves_insertion_order() {
        let _guard = isolate();
        assert_eq!(
            ALL,
            [
                "REGISTRY",
                "Recipe",
                "clear_registry",
                "get_recipe",
                "list_recipes",
                "recipes_for",
                "register_recipe",
            ]
        );
        let mut spec = RecipeSpec::new(
            "synthetic-clean",
            &["SL201", "SL10", "SL101"],
            &["source_hash_pinned", "no_sl203"],
            false,
            false,
        );
        let callable = CallableId::from_fn(must_not_run);
        spec.apply = Some(callable);
        spec.affected_region = Some(callable);
        let first = must(Recipe::try_new(spec));
        assert_eq!(strings(first.handles()), ["SL10", "SL101", "SL201"]);
        assert_eq!(
            strings(first.preconditions()),
            ["source_hash_pinned", "no_sl203"]
        );
        assert_eq!(first.min_policy(), "conservative");
        assert!(!first.salvage_only());
        assert_eq!(first.apply(), Some(callable));
        assert_eq!(first.affected_region(), Some(callable));
        must_register(register_recipe(&first));

        assert_eq!(get_recipe("synthetic-clean"), Some(first.clone()));
        assert!(get_recipe("non-existent").is_none());
        assert_eq!(recipes_for("SL1"), Vec::<Recipe>::new());
        assert_eq!(recipes_for("SL10"), vec![first.clone()]);
        assert_eq!(recipes_for("SL101"), vec![first.clone()]);
        assert_eq!(recipes_for("SL201"), vec![first.clone()]);
        assert_eq!(list_recipes(), vec![first.clone()]);

        let second = must(Recipe::try_new(RecipeSpec::new(
            "aaa-later",
            &["SL101"],
            &[],
            false,
            false,
        )));
        must_register(register_recipe(&second));
        assert_eq!(list_recipes(), vec![first.clone(), second.clone()]);
        assert_eq!(recipes_for("SL101"), vec![first, second]);
        assert_eq!(
            list_recipes().iter().map(Recipe::name).collect::<Vec<_>>(),
            ["synthetic-clean", "aaa-later"]
        );
    }

    #[test]
    fn duplicate_name_is_reported_before_unknown_precondition() {
        let _guard = isolate();
        let first = must(Recipe::try_new(RecipeSpec::new(
            "duplicate-stub",
            &["SL101"],
            &["no_sl203"],
            false,
            false,
        )));
        must_register(register_recipe(&first));
        let second = must(Recipe::try_new(RecipeSpec::new(
            "duplicate-stub",
            &["SL201"],
            &["non_existent_precondition"],
            true,
            true,
        )));
        let error = match register_recipe(&second) {
            Ok(()) => panic!("duplicate must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "Duplicate recipe name: 'duplicate-stub' is already registered"
        );
        assert_eq!(list_recipes(), vec![first]);
        assert_eq!(strings(list_recipes()[0].handles()), ["SL101"]);
    }

    #[test]
    fn unknown_precondition_is_not_registered() {
        let _guard = isolate();
        let recipe = must(Recipe::try_new(RecipeSpec::new(
            "bad-precondition-stub",
            &["SL101"],
            &["no_sl203", "non_existent_precondition", "also_missing"],
            false,
            false,
        )));
        let error = match register_recipe(&recipe) {
            Ok(()) => panic!("unknown precondition must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "Recipe 'bad-precondition-stub' references unknown precondition: 'non_existent_precondition'"
        );
        assert_eq!(
            strings(recipe.preconditions()),
            ["no_sl203", "non_existent_precondition", "also_missing"]
        );
        assert!(list_recipes().is_empty());
        assert!(get_recipe("bad-precondition-stub").is_none());
    }

    #[test]
    fn clear_registry_drops_recipes_and_leaves_preconditions() {
        let _guard = isolate();
        let recipe = must(Recipe::try_new(RecipeSpec::new(
            "synthetic-clear",
            &["SL101"],
            &["no_sl203"],
            false,
            false,
        )));
        must_register(register_recipe(&recipe));
        assert_eq!(list_recipes().len(), 1);
        assert!(precondition_func_names()
            .iter()
            .any(|name| name == "no_sl203"));
        clear_registry();
        assert!(list_recipes().is_empty());
        assert!(get_recipe("synthetic-clear").is_none());
        assert!(recipes_for("SL101").is_empty());
        assert!(precondition_func_names()
            .iter()
            .any(|name| name == "no_sl203"));
        must_register(register_recipe(&recipe));
        assert_eq!(list_recipes(), vec![recipe]);
    }
}
