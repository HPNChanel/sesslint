//! Version declarations for SessLint CLI, schemas, adapters, and profiles.
//!
//! Port of `src/sesslint/_version.py` lines 1–36
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Every version string is a compile-time literal. This module does not read
//! `pyproject.toml`, the environment, or the wall clock.

use std::collections::BTreeMap;

/// Python: `__version__`.
pub const VERSION: &str = "0.5.0";

/// Python: `CLI_VERSION` (assigned from `__version__`).
pub const CLI_VERSION: &str = VERSION;

pub const SESSION_SCHEMA_VERSION: &str = "sesslint.session/v1";
pub const REPORT_SCHEMA_VERSION: &str = "sesslint.report/v1";
pub const MANIFEST_SCHEMA_VERSION: &str = "sesslint.repair-manifest/v1";

/// Python: `ADAPTER_VERSIONS` (pairs listed in source insertion order).
pub const ADAPTER_VERSIONS: &[(&str, &str)] = &[
    ("canonical", "1.0.0"),
    ("claude-code-jsonl", "1.0.0"),
    ("codex-rollout", "1.0.0"),
    ("openai-agents", "1.0.0"),
];

/// Python: `PROFILE_VERSIONS` (pairs listed in source insertion order).
pub const PROFILE_VERSIONS: &[(&str, &str)] = &[
    ("neutral", "1.0.0"),
    ("claude-strict", "1.0.0"),
    ("openai-strict", "1.0.0"),
];

/// JSON-safe value in [`get_version_info`] (`str` or nested str→str map).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionValue {
    String(&'static str),
    Map(BTreeMap<&'static str, &'static str>),
}

/// Python: `ADAPTER_VERSIONS` as an output map (sorted keys).
pub fn adapter_versions() -> BTreeMap<&'static str, &'static str> {
    ADAPTER_VERSIONS.iter().copied().collect()
}

/// Python: `PROFILE_VERSIONS` as an output map (sorted keys).
pub fn profile_versions() -> BTreeMap<&'static str, &'static str> {
    PROFILE_VERSIONS.iter().copied().collect()
}

/// Return structured version dictionary for CLI version command.
///
/// Construction follows Python insertion order; the returned [`BTreeMap`]
/// iterates in alphabetical key order, matching `json.dumps(..., sort_keys=True)`.
pub fn get_version_info() -> BTreeMap<&'static str, VersionValue> {
    let mut info = BTreeMap::new();
    info.insert("cli", VersionValue::String(CLI_VERSION));
    info.insert(
        "schema_session",
        VersionValue::String(SESSION_SCHEMA_VERSION),
    );
    info.insert("schema_report", VersionValue::String(REPORT_SCHEMA_VERSION));
    info.insert(
        "schema_manifest",
        VersionValue::String(MANIFEST_SCHEMA_VERSION),
    );
    info.insert("adapters", VersionValue::Map(adapter_versions()));
    info.insert("profiles", VersionValue::Map(profile_versions()));
    info
}

#[cfg(test)]
mod tests {
    use super::{
        adapter_versions, get_version_info, profile_versions, VersionValue, ADAPTER_VERSIONS,
        CLI_VERSION, MANIFEST_SCHEMA_VERSION, PROFILE_VERSIONS, REPORT_SCHEMA_VERSION,
        SESSION_SCHEMA_VERSION, VERSION,
    };

    fn expect_string(value: Option<&VersionValue>) -> &str {
        match value {
            Some(VersionValue::String(text)) => text,
            other => panic!("expected string version value, got {other:?}"),
        }
    }

    fn expect_map(
        value: Option<&VersionValue>,
    ) -> &std::collections::BTreeMap<&'static str, &'static str> {
        match value {
            Some(VersionValue::Map(map)) => map,
            other => panic!("expected map version value, got {other:?}"),
        }
    }

    #[test]
    fn constants_match_pinned_literals() {
        assert_eq!(VERSION, "0.5.0");
        assert_eq!(CLI_VERSION, "0.5.0");
        assert_eq!(SESSION_SCHEMA_VERSION, "sesslint.session/v1");
        assert_eq!(REPORT_SCHEMA_VERSION, "sesslint.report/v1");
        assert_eq!(MANIFEST_SCHEMA_VERSION, "sesslint.repair-manifest/v1");
        assert_eq!(
            ADAPTER_VERSIONS,
            &[
                ("canonical", "1.0.0"),
                ("claude-code-jsonl", "1.0.0"),
                ("codex-rollout", "1.0.0"),
                ("openai-agents", "1.0.0"),
            ]
        );
        assert_eq!(
            PROFILE_VERSIONS,
            &[
                ("neutral", "1.0.0"),
                ("claude-strict", "1.0.0"),
                ("openai-strict", "1.0.0"),
            ]
        );
    }

    #[test]
    fn get_version_info_matches_pinned_literals() {
        let info = get_version_info();
        assert_eq!(expect_string(info.get("cli")), "0.5.0");
        assert_eq!(
            expect_string(info.get("schema_session")),
            "sesslint.session/v1"
        );
        assert_eq!(
            expect_string(info.get("schema_report")),
            "sesslint.report/v1"
        );
        assert_eq!(
            expect_string(info.get("schema_manifest")),
            "sesslint.repair-manifest/v1"
        );

        let adapters = expect_map(info.get("adapters"));
        assert_eq!(adapters.get("canonical"), Some(&"1.0.0"));
        assert_eq!(adapters.get("claude-code-jsonl"), Some(&"1.0.0"));
        assert_eq!(adapters.get("codex-rollout"), Some(&"1.0.0"));
        assert_eq!(adapters.get("openai-agents"), Some(&"1.0.0"));

        let profiles = expect_map(info.get("profiles"));
        assert_eq!(profiles.get("neutral"), Some(&"1.0.0"));
        assert_eq!(profiles.get("claude-strict"), Some(&"1.0.0"));
        assert_eq!(profiles.get("openai-strict"), Some(&"1.0.0"));
    }

    #[test]
    fn get_version_info_sorted_json_keys_are_alphabetical() {
        let info = get_version_info();
        let keys: Vec<&str> = info.keys().copied().collect();
        assert_eq!(
            keys,
            [
                "adapters",
                "cli",
                "profiles",
                "schema_manifest",
                "schema_report",
                "schema_session",
            ]
        );
        assert_eq!(info.len(), 6);
    }

    #[test]
    fn nested_output_maps_iterate_alphabetically() {
        let adapters: Vec<&str> = adapter_versions().keys().copied().collect();
        assert_eq!(
            adapters,
            [
                "canonical",
                "claude-code-jsonl",
                "codex-rollout",
                "openai-agents",
            ]
        );

        let profiles: Vec<&str> = profile_versions().keys().copied().collect();
        assert_eq!(profiles, ["claude-strict", "neutral", "openai-strict"]);
    }

    #[test]
    fn closed_world_unknown_ids_are_absent() {
        assert_eq!(adapter_versions().get("unknown"), None);
        assert_eq!(profile_versions().get("unknown"), None);
        assert!(!get_version_info().contains_key("schema_scan"));
        assert!(!get_version_info().contains_key("$schema"));
    }
}
