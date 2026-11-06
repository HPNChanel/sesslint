//! Empty scaffold for the `checks` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::ChecksError;

pub mod context;
pub mod hygiene {}
pub mod indexes;
pub mod checkpoint;
pub mod accounting;
pub mod compaction_snapshot;
pub mod context_pressure;
pub mod durable_prefix;
pub mod foreign_shape;
pub mod graph;
pub mod identity;
pub mod ordering;
pub mod size;
pub mod tool_pairing_1;
pub mod tool_pairing_2;
pub mod writers;
pub mod abstention;
// `sesslint.policy` package surface. Order is `policy/__init__.py` `__all__`
// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
#[rustfmt::skip]
pub use abstention::{SAFE_SIDE_EFFECT, TOOL_KINDS, Abstention, must_abstain};
pub mod profile;
pub mod config {}
pub mod builtin;
pub mod assessment {}
pub mod runner {}

// `sesslint.profiles` package surface. Order is `profiles/__init__.py` `__all__`
// @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
#[rustfmt::skip]
pub use builtin::{
    ALL_RULES,
    CLAUDE_STRICT_PROFILE,
    NEUTRAL_PROFILE,
    OPENAI_STRICT_PROFILE,
    REGISTRY,
};
#[rustfmt::skip]
pub use profile::{
    EffectiveConfig,
    Profile,
    apply_rule_selection,
    deselected_rules,
    get_profile,
    list_profiles,
    require_canonical,
    resolve_effective_config,
    stamp_source_profile,
};

pub const PROFILES_ALL: [&str; 14] = [
    "ALL_RULES",
    "CLAUDE_STRICT_PROFILE",
    "EffectiveConfig",
    "NEUTRAL_PROFILE",
    "OPENAI_STRICT_PROFILE",
    "Profile",
    "REGISTRY",
    "apply_rule_selection",
    "deselected_rules",
    "get_profile",
    "list_profiles",
    "require_canonical",
    "resolve_effective_config",
    "stamp_source_profile",
];

#[cfg(test)]
mod tests {
    #[test]
    fn policy_reexport_list_is_exactly_the_package_names() {
        let src = include_str!("lib.rs");
        let marker = concat!("pub use ", "abstention::{");
        assert_eq!(src.matches(marker).count(), 1);
        let body = src
            .split_once(marker)
            .expect("policy re-export")
            .1
            .split_once("};")
            .expect("policy re-export end")
            .0;
        let names: Vec<&str> = body
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect();
        assert_eq!(
            names,
            [
                "SAFE_SIDE_EFFECT",
                "TOOL_KINDS",
                "Abstention",
                "must_abstain",
            ]
        );
        assert_eq!(super::SAFE_SIDE_EFFECT, super::abstention::SAFE_SIDE_EFFECT);
        assert_eq!(super::TOOL_KINDS, super::abstention::TOOL_KINDS);
        same_item(super::must_abstain, super::abstention::must_abstain);
        let item = super::abstention::Abstention::new(false, std::iter::empty::<&str>());
        let reexported: super::Abstention = item.clone();
        assert_eq!(reexported, item);
    }

    /// Same function item: a re-export does not create a second `must_abstain`.
    fn same_item<T>(left: T, right: T) {
        let _ = (left, right);
    }

    #[test]
    fn profiles_reexport_list_is_exactly_the_package_names() {
        assert_eq!(
            super::PROFILES_ALL,
            [
                "ALL_RULES",
                "CLAUDE_STRICT_PROFILE",
                "EffectiveConfig",
                "NEUTRAL_PROFILE",
                "OPENAI_STRICT_PROFILE",
                "Profile",
                "REGISTRY",
                "apply_rule_selection",
                "deselected_rules",
                "get_profile",
                "list_profiles",
                "require_canonical",
                "resolve_effective_config",
                "stamp_source_profile",
            ]
        );
        assert!(!super::PROFILES_ALL.contains(&"VALID_FORMATS"));
        assert_eq!(super::ALL_RULES, super::builtin::ALL_RULES);
        let registry_names: Vec<&str> = super::REGISTRY
            .entries()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(
            registry_names,
            ["neutral", "claude-strict", "openai-strict"]
        );
        assert_eq!(
            super::get_profile("neutral").unwrap_err().to_string(),
            "sesslint.profiles.builtin is not available"
        );
    }
}
