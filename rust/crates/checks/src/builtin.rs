//! Built-in replay profiles as pure data.
//!
//! Port of `src/sesslint/profiles/builtin.py` lines 1–141
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`NEUTRAL_PROFILE`], [`CLAUDE_STRICT_PROFILE`], and [`OPENAI_STRICT_PROFILE`]
//! are the three profiles. [`REGISTRY`] stores them in insertion order:
//! `neutral`, then `claude-strict`, then `openai-strict`.
//! [`OrderedMap::get`] matches the name exactly. A missing name is absence.
//! This module does not build a close-match suggestion and does not wire
//! [`crate::profile::get_profile`].
//!
//! [`Profile`] owns its strings, so each profile is a [`std::sync::LazyLock`]
//! rather than a `const`.

use std::sync::LazyLock;

use model::codes::{
    Severity, SL001, SL002, SL003, SL004, SL005, SL006, SL007, SL008, SL009, SL010, SL011, SL101,
    SL102, SL103, SL104, SL105, SL106, SL107, SL108, SL201, SL202, SL203, SL204, SL205, SL206,
    SL207, SL208, SL301, SL302, SL303, SL304, SL305, SL306, SL401, SL402,
};

use crate::profile::{OrderedMap, Profile};

/// Python: `ALL_RULES`, source order.
///
/// This list is not sorted.
pub const ALL_RULES: [&str; 35] = [
    SL001, SL002, SL003, SL004, SL005, SL006, SL007, SL008, SL009, SL010, SL011, SL101, SL102,
    SL103, SL104, SL105, SL106, SL107, SL108, SL201, SL202, SL203, SL204, SL205, SL206, SL207,
    SL208, SL301, SL302, SL303, SL304, SL305, SL306, SL401, SL402,
];

/// [`Profile::new`] sets `version` to `"1.0.0"` and `timestamp_skew_ms` to `2000`.
fn build_profile(
    name: &str,
    description: &str,
    allowed_adapters: &[&str],
    margin_min: f64,
    checkpoint_sensitivity: &str,
    severity: Severity,
) -> Profile {
    let mut thresholds = OrderedMap::new();
    thresholds.insert("confidence_min", 0.55);
    thresholds.insert("margin_min", margin_min);
    let mut profile = Profile::new(
        name,
        description,
        allowed_adapters.iter().copied(),
        ALL_RULES,
        thresholds,
        checkpoint_sensitivity,
    );
    profile.rule_severities.insert(SL107, severity);
    profile.rule_severities.insert(SL108, severity);
    profile
}

fn neutral_profile() -> Profile {
    build_profile(
        "neutral",
        "Vendor-neutral baseline profile using standard generic rules and default thresholds.",
        &["canonical", "claude", "openai", "codex", "auto"],
        0.15,
        "default",
        Severity::Warning,
    )
}

/// Python: `NEUTRAL_PROFILE`.
pub static NEUTRAL_PROFILE: LazyLock<Profile> = LazyLock::new(neutral_profile);

fn claude_strict_profile() -> Profile {
    build_profile(
        "claude-strict",
        "Strict profile for Claude Code sessions with tight format margins \
         and strict version checks.",
        &["claude", "canonical", "auto"],
        0.20,
        "default",
        Severity::Error,
    )
}

/// Python: `CLAUDE_STRICT_PROFILE`.
pub static CLAUDE_STRICT_PROFILE: LazyLock<Profile> = LazyLock::new(claude_strict_profile);

fn openai_strict_profile() -> Profile {
    build_profile(
        "openai-strict",
        "Strict profile for OpenAI Agents SDK sessions with high checkpoint sensitivity.",
        &["openai", "codex", "canonical", "auto"],
        0.15,
        "high",
        Severity::Error,
    )
}

/// Python: `OPENAI_STRICT_PROFILE`.
pub static OPENAI_STRICT_PROFILE: LazyLock<Profile> = LazyLock::new(openai_strict_profile);

fn registry() -> OrderedMap<Profile> {
    let mut registry = OrderedMap::new();
    registry.insert(
        NEUTRAL_PROFILE.name.clone(),
        Profile::clone(&*NEUTRAL_PROFILE),
    );
    registry.insert(
        CLAUDE_STRICT_PROFILE.name.clone(),
        Profile::clone(&*CLAUDE_STRICT_PROFILE),
    );
    registry.insert(
        OPENAI_STRICT_PROFILE.name.clone(),
        Profile::clone(&*OPENAI_STRICT_PROFILE),
    );
    registry
}

/// Python: `REGISTRY`.
///
/// Key order is the insertion order. [`OrderedMap::get`] is exact. A missing
/// name is [`None`]. Keys are not sorted, and this is not a [`std::collections::BTreeMap`].
pub static REGISTRY: LazyLock<OrderedMap<Profile>> = LazyLock::new(registry);

/// Python `__all__`, in that order. Not sorted.
pub const ALL: [&str; 5] = [
    "ALL_RULES",
    "CLAUDE_STRICT_PROFILE",
    "NEUTRAL_PROFILE",
    "OPENAI_STRICT_PROFILE",
    "REGISTRY",
];

#[cfg(test)]
mod tests {
    use model::codes::{
        Severity, SL001, SL002, SL003, SL004, SL005, SL006, SL007, SL008, SL009, SL010, SL011,
        SL101, SL102, SL103, SL104, SL105, SL106, SL107, SL108, SL201, SL202, SL203, SL204, SL205,
        SL206, SL207, SL208, SL301, SL302, SL303, SL304, SL305, SL306, SL401, SL402,
    };

    use super::{
        ALL, ALL_RULES, CLAUDE_STRICT_PROFILE, NEUTRAL_PROFILE, OPENAI_STRICT_PROFILE, REGISTRY,
    };
    use crate::profile::Profile;

    const SOURCE_ORDER: [&str; 35] = [
        SL001, SL002, SL003, SL004, SL005, SL006, SL007, SL008, SL009, SL010, SL011, SL101, SL102,
        SL103, SL104, SL105, SL106, SL107, SL108, SL201, SL202, SL203, SL204, SL205, SL206, SL207,
        SL208, SL301, SL302, SL303, SL304, SL305, SL306, SL401, SL402,
    ];

    fn as_strs(values: &[String]) -> Vec<&str> {
        values.iter().map(String::as_str).collect()
    }

    fn assert_thresholds(profile: &Profile, margin_bits: u64) {
        let entries = profile.thresholds.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries.first().map(|(key, _)| key.as_str()),
            Some("confidence_min")
        );
        assert_eq!(
            entries.first().map(|(_, value)| value.to_bits()),
            Some(0.55_f64.to_bits())
        );
        assert_eq!(
            entries.get(1).map(|(key, _)| key.as_str()),
            Some("margin_min")
        );
        assert_eq!(
            entries.get(1).map(|(_, value)| value.to_bits()),
            Some(margin_bits)
        );
    }

    fn assert_severities(profile: &Profile, severity: Severity) {
        let entries = profile.rule_severities.entries();
        assert_eq!(
            entries.first().map(|(key, value)| (key.as_str(), *value)),
            Some((SL107, severity))
        );
        assert_eq!(
            entries.get(1).map(|(key, value)| (key.as_str(), *value)),
            Some((SL108, severity))
        );
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn all_rules_keeps_source_order() {
        assert_eq!(ALL_RULES.len(), 35);
        assert_eq!(ALL_RULES, SOURCE_ORDER);
        assert_eq!(
            as_strs(&NEUTRAL_PROFILE.enabled_rules).as_slice(),
            ALL_RULES
        );
        assert_eq!(
            as_strs(&CLAUDE_STRICT_PROFILE.enabled_rules).as_slice(),
            ALL_RULES
        );
        assert_eq!(
            as_strs(&OPENAI_STRICT_PROFILE.enabled_rules).as_slice(),
            ALL_RULES
        );
    }

    #[test]
    fn profiles_use_the_three_names_and_descriptions() {
        assert_eq!(NEUTRAL_PROFILE.name, "neutral");
        assert_eq!(NEUTRAL_PROFILE.version, "1.0.0");
        assert_eq!(
            NEUTRAL_PROFILE.description,
            "Vendor-neutral baseline profile using standard generic rules and default thresholds."
        );
        assert_eq!(CLAUDE_STRICT_PROFILE.name, "claude-strict");
        assert_eq!(CLAUDE_STRICT_PROFILE.version, "1.0.0");
        assert_eq!(
            CLAUDE_STRICT_PROFILE.description,
            "Strict profile for Claude Code sessions with tight format margins and strict version checks."
        );
        assert_eq!(OPENAI_STRICT_PROFILE.name, "openai-strict");
        assert_eq!(OPENAI_STRICT_PROFILE.version, "1.0.0");
        assert_eq!(
            OPENAI_STRICT_PROFILE.description,
            "Strict profile for OpenAI Agents SDK sessions with high checkpoint sensitivity."
        );
    }

    #[test]
    fn adapters_keep_profile_order() {
        assert_eq!(
            as_strs(&NEUTRAL_PROFILE.allowed_adapters).as_slice(),
            ["canonical", "claude", "openai", "codex", "auto"]
        );
        assert_eq!(
            as_strs(&CLAUDE_STRICT_PROFILE.allowed_adapters).as_slice(),
            ["claude", "canonical", "auto"]
        );
        assert_eq!(
            as_strs(&OPENAI_STRICT_PROFILE.allowed_adapters).as_slice(),
            ["openai", "codex", "canonical", "auto"]
        );
    }

    #[test]
    fn claude_strict_margin_is_tighter() {
        assert_thresholds(&NEUTRAL_PROFILE, 0.15_f64.to_bits());
        assert_thresholds(&CLAUDE_STRICT_PROFILE, 0.20_f64.to_bits());
        assert_thresholds(&OPENAI_STRICT_PROFILE, 0.15_f64.to_bits());
    }

    #[test]
    fn openai_strict_checkpoint_sensitivity_is_high() {
        assert_eq!(NEUTRAL_PROFILE.checkpoint_sensitivity, "default");
        assert_eq!(CLAUDE_STRICT_PROFILE.checkpoint_sensitivity, "default");
        assert_eq!(OPENAI_STRICT_PROFILE.checkpoint_sensitivity, "high");
    }

    #[test]
    fn rule_severities_match_each_profile() {
        assert_severities(&NEUTRAL_PROFILE, Severity::Warning);
        assert_severities(&CLAUDE_STRICT_PROFILE, Severity::Error);
        assert_severities(&OPENAI_STRICT_PROFILE, Severity::Error);
    }

    #[test]
    fn timestamp_skew_is_2000() {
        assert_eq!(NEUTRAL_PROFILE.timestamp_skew_ms, 2000);
        assert_eq!(CLAUDE_STRICT_PROFILE.timestamp_skew_ms, 2000);
        assert_eq!(OPENAI_STRICT_PROFILE.timestamp_skew_ms, 2000);
    }

    #[test]
    fn registry_keeps_insertion_order_and_unknown_names_are_absent() {
        let names: Vec<&str> = REGISTRY
            .entries()
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(names, ["neutral", "claude-strict", "openai-strict"]);
        assert_eq!(REGISTRY.get("neutral"), Some(&*NEUTRAL_PROFILE));
        assert_eq!(REGISTRY.get("claude-strict"), Some(&*CLAUDE_STRICT_PROFILE));
        assert_eq!(REGISTRY.get("openai-strict"), Some(&*OPENAI_STRICT_PROFILE));
        assert_eq!(REGISTRY.get("not-a-profile"), None);
        assert_eq!(REGISTRY.get("Neutral"), None);
    }

    #[test]
    fn all_matches_python_export_order() {
        assert_eq!(
            ALL,
            [
                "ALL_RULES",
                "CLAUDE_STRICT_PROFILE",
                "NEUTRAL_PROFILE",
                "OPENAI_STRICT_PROFILE",
                "REGISTRY",
            ]
        );
    }
}
