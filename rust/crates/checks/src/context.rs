//! Check execution context and version metadata (DEV-004, FR-046).
//!
//! This module defines CheckContext, which threads adapter and profile identity and version
//! information through check runners into finding fingerprint computations.
//!
//! Port of `src/sesslint/context.py` lines 1–169
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.

use std::collections::BTreeMap;

use serde_json::Value;

use model::version::{ADAPTER_VERSIONS, PROFILE_VERSIONS};

use crate::ChecksError;

const UNKNOWN: &str = "unknown";
const DEFAULT_TIMESTAMP_SKEW_MS: i64 = 2000;

/// Sentinel for [`CheckContext::with_overrides`] `source_metadata`.
///
/// Python uses `_UNSET = object()` so omitted metadata is distinct from
/// explicit `None` and from a non-mapping value.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum SourceMetadataOverride {
    /// Python `_UNSET` — keep the previous metadata.
    #[default]
    Unset,
    /// Explicit mapping or `None`.
    Explicit(Option<BTreeMap<String, Value>>),
    /// Explicit non-mapping; stored as `None`.
    NonMapping,
}

/// Context carrying adapter and profile version metadata into checks (FR-046).
///
/// Per FR-046, every finding fingerprint is derived from rule ID + adapter/profile
/// versions + structural coords.
/// When a version coordinate is unavailable or omitted, it MUST be explicit "unknown"
/// (never empty string) so absence is visible in the fingerprint preimage.
/// Also threads preserved source metadata / projections into checks (DEV-011).
#[derive(Clone, Debug, PartialEq)]
pub struct CheckContext {
    adapter_id: String,
    adapter_version: String,
    profile_id: String,
    profile_version: String,
    source_metadata: Option<BTreeMap<String, Value>>,
    timestamp_skew_ms: i64,
}

impl Default for CheckContext {
    fn default() -> Self {
        Self::new(
            UNKNOWN,
            UNKNOWN,
            UNKNOWN,
            UNKNOWN,
            None,
            DEFAULT_TIMESTAMP_SKEW_MS,
        )
    }
}

impl CheckContext {
    /// Construct a context, replacing blank or whitespace-only coordinates with `"unknown"`.
    pub fn new(
        adapter_id: impl AsRef<str>,
        adapter_version: impl AsRef<str>,
        profile_id: impl AsRef<str>,
        profile_version: impl AsRef<str>,
        source_metadata: Option<BTreeMap<String, Value>>,
        timestamp_skew_ms: i64,
    ) -> Self {
        Self {
            adapter_id: unknown_if_blank(adapter_id.as_ref()),
            adapter_version: unknown_if_blank(adapter_version.as_ref()),
            profile_id: unknown_if_blank(profile_id.as_ref()),
            profile_version: unknown_if_blank(profile_version.as_ref()),
            source_metadata,
            timestamp_skew_ms,
        }
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn profile_version(&self) -> &str {
        &self.profile_version
    }

    pub fn source_metadata(&self) -> Option<&BTreeMap<String, Value>> {
        self.source_metadata.as_ref()
    }

    pub fn timestamp_skew_ms(&self) -> i64 {
        self.timestamp_skew_ms
    }

    /// Whether the adapter can expose checkpoints after a native compaction.
    ///
    /// This is adapter capability, not a claim that any checkpoint exists.
    /// Canonical/unknown contexts retain conservative checkpoint semantics.
    pub fn compaction_checkpoint_capable(&self) -> bool {
        self.adapter_id != "claude-code-jsonl" && self.adapter_id != "codex-rollout"
    }

    /// Create a CheckContext, looking up registered version strings when unspecified.
    pub fn create(
        adapter_id: Option<&str>,
        adapter_version: Option<&str>,
        profile_id: Option<&str>,
        profile_version: Option<&str>,
        source_metadata: Option<BTreeMap<String, Value>>,
    ) -> Self {
        let clean_ad_id = clean_coord(adapter_id);
        let clean_ad_ver = resolve_version(adapter_version, &clean_ad_id, ADAPTER_VERSIONS);
        let clean_prof_id = clean_coord(profile_id);
        let clean_prof_ver = resolve_version(profile_version, &clean_prof_id, PROFILE_VERSIONS);
        Self::new(
            clean_ad_id,
            clean_ad_ver,
            clean_prof_id,
            clean_prof_ver,
            source_metadata,
            DEFAULT_TIMESTAMP_SKEW_MS,
        )
    }

    /// Construct CheckContext by resolving a Profile (or profile name) and adapter name.
    ///
    /// Python imports `sesslint.profiles`, which is not ported. This method
    /// fails closed rather than inventing `NEUTRAL_PROFILE` or `get_profile`.
    pub fn from_profile_and_adapter() -> Result<Self, ChecksError> {
        Err(ChecksError::Unsupported)
    }

    /// Return a mapping of context fields.
    pub fn to_dict(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert("adapter_id".to_owned(), self.adapter_id.clone());
        fields.insert("adapter_version".to_owned(), self.adapter_version.clone());
        fields.insert("profile_id".to_owned(), self.profile_id.clone());
        fields.insert("profile_version".to_owned(), self.profile_version.clone());
        fields
    }

    /// Return a copy of CheckContext with overridden fields.
    pub fn with_overrides(
        &self,
        adapter_id: Option<&str>,
        adapter_version: Option<&str>,
        profile_id: Option<&str>,
        profile_version: Option<&str>,
        source_metadata: SourceMetadataOverride,
    ) -> Self {
        let metadata = match source_metadata {
            SourceMetadataOverride::Unset => self.source_metadata.clone(),
            SourceMetadataOverride::Explicit(value) => value,
            SourceMetadataOverride::NonMapping => None,
        };
        Self::new(
            adapter_id.unwrap_or(&self.adapter_id),
            adapter_version.unwrap_or(&self.adapter_version),
            profile_id.unwrap_or(&self.profile_id),
            profile_version.unwrap_or(&self.profile_version),
            metadata,
            self.timestamp_skew_ms,
        )
    }
}

fn unknown_if_blank(value: &str) -> String {
    if value.trim().is_empty() {
        UNKNOWN.to_owned()
    } else {
        value.to_owned()
    }
}

fn clean_coord(value: Option<&str>) -> String {
    match value {
        Some(raw) => {
            let stripped = raw.trim();
            if stripped.is_empty() {
                UNKNOWN.to_owned()
            } else {
                stripped.to_owned()
            }
        }
        None => UNKNOWN.to_owned(),
    }
}

fn resolve_version(
    explicit: Option<&str>,
    id: &str,
    table: &[(&'static str, &'static str)],
) -> String {
    if let Some(raw) = explicit {
        let stripped = raw.trim();
        if !stripped.is_empty() {
            return stripped.to_owned();
        }
    }
    match registered_version(table, id) {
        Some(version) => version.to_owned(),
        None => UNKNOWN.to_owned(),
    }
}

fn registered_version<'a>(table: &[(&'a str, &'a str)], id: &str) -> Option<&'a str> {
    table
        .iter()
        .find_map(|(key, version)| (*key == id).then_some(*version))
}

#[cfg(test)]
mod tests {
    use super::{CheckContext, SourceMetadataOverride, DEFAULT_TIMESTAMP_SKEW_MS, UNKNOWN};
    use crate::ChecksError;
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn marker_metadata() -> BTreeMap<String, Value> {
        let mut metadata = BTreeMap::new();
        metadata.insert("k".to_owned(), Value::from(1));
        metadata
    }

    #[test]
    fn defaults_are_unknown_and_skew_is_2000() {
        let ctx = CheckContext::default();
        assert_eq!(ctx.adapter_id(), UNKNOWN);
        assert_eq!(ctx.adapter_version(), UNKNOWN);
        assert_eq!(ctx.profile_id(), UNKNOWN);
        assert_eq!(ctx.profile_version(), UNKNOWN);
        assert_eq!(ctx.source_metadata(), None);
        assert_eq!(ctx.timestamp_skew_ms(), DEFAULT_TIMESTAMP_SKEW_MS);
        assert!(ctx.compaction_checkpoint_capable());
    }

    #[test]
    fn blank_and_whitespace_coords_become_unknown() {
        let ctx = CheckContext::new("", "  ", "\n", "\t", None, 2000);
        assert_eq!(ctx.adapter_id(), UNKNOWN);
        assert_eq!(ctx.adapter_version(), UNKNOWN);
        assert_eq!(ctx.profile_id(), UNKNOWN);
        assert_eq!(ctx.profile_version(), UNKNOWN);
        assert_ne!(ctx.adapter_id(), "");
        assert_ne!(ctx.adapter_version(), "");
    }

    #[test]
    fn non_blank_coords_keep_surrounding_whitespace() {
        let ctx = CheckContext::new(
            " synth-adapter-01 ",
            " 9.9.9 ",
            " synth-profile-01 ",
            " 2026.01 ",
            None,
            2000,
        );
        assert_eq!(ctx.adapter_id(), " synth-adapter-01 ");
        assert_eq!(ctx.adapter_version(), " 9.9.9 ");
        assert_eq!(ctx.profile_id(), " synth-profile-01 ");
        assert_eq!(ctx.profile_version(), " 2026.01 ");
    }

    #[test]
    fn create_looks_up_registered_versions_when_omitted() {
        let ctx = CheckContext::create(Some("canonical"), None, Some("neutral"), None, None);
        assert_eq!(ctx.adapter_id(), "canonical");
        assert_eq!(ctx.adapter_version(), "1.0.0");
        assert_eq!(ctx.profile_id(), "neutral");
        assert_eq!(ctx.profile_version(), "1.0.0");
        assert_eq!(ctx.timestamp_skew_ms(), DEFAULT_TIMESTAMP_SKEW_MS);
    }

    #[test]
    fn create_does_not_lookup_when_version_is_explicit() {
        let ctx = CheckContext::create(
            Some("canonical"),
            Some("9.9.9-synth"),
            Some("neutral"),
            Some("2026.01-synth"),
            None,
        );
        assert_eq!(ctx.adapter_version(), "9.9.9-synth");
        assert_eq!(ctx.profile_version(), "2026.01-synth");
    }

    #[test]
    fn create_treats_whitespace_version_as_omitted() {
        let ctx = CheckContext::create(
            Some("canonical"),
            Some("  \t  "),
            Some("neutral"),
            Some("\n"),
            None,
        );
        assert_eq!(ctx.adapter_version(), "1.0.0");
        assert_eq!(ctx.profile_version(), "1.0.0");
    }

    #[test]
    fn create_unregistered_id_does_not_invent_a_version() {
        let ctx = CheckContext::create(
            Some("synth-adapter-01"),
            None,
            Some("synth-profile-01"),
            None,
            None,
        );
        assert_eq!(ctx.adapter_id(), "synth-adapter-01");
        assert_eq!(ctx.adapter_version(), UNKNOWN);
        assert_eq!(ctx.profile_id(), "synth-profile-01");
        assert_eq!(ctx.profile_version(), UNKNOWN);
    }

    #[test]
    fn create_strips_ids_and_rejects_blank() {
        let ctx = CheckContext::create(Some(" canonical "), None, Some("   "), Some("  "), None);
        assert_eq!(ctx.adapter_id(), "canonical");
        assert_eq!(ctx.adapter_version(), "1.0.0");
        assert_eq!(ctx.profile_id(), UNKNOWN);
        assert_eq!(ctx.profile_version(), UNKNOWN);
    }

    #[test]
    fn compaction_checkpoint_capable_false_only_for_two_adapters() {
        let claude = CheckContext::new("claude-code-jsonl", "1.0.0", UNKNOWN, UNKNOWN, None, 2000);
        let codex = CheckContext::new("codex-rollout", "1.0.0", UNKNOWN, UNKNOWN, None, 2000);
        let canonical = CheckContext::new("canonical", "1.0.0", UNKNOWN, UNKNOWN, None, 2000);
        let openai = CheckContext::new("openai-agents", "1.0.0", UNKNOWN, UNKNOWN, None, 2000);
        let synth = CheckContext::new("synth-adapter-01", "1.0.0", UNKNOWN, UNKNOWN, None, 2000);
        assert!(!claude.compaction_checkpoint_capable());
        assert!(!codex.compaction_checkpoint_capable());
        assert!(canonical.compaction_checkpoint_capable());
        assert!(openai.compaction_checkpoint_capable());
        assert!(synth.compaction_checkpoint_capable());
        assert!(CheckContext::default().compaction_checkpoint_capable());
    }

    #[test]
    fn to_dict_returns_only_four_id_version_strings() {
        let ctx = CheckContext::new(
            "synth-adapter-01",
            "9.9.9-synth",
            "synth-profile-01",
            "2026.01-synth",
            Some(marker_metadata()),
            4321,
        );
        let dict = ctx.to_dict();
        let keys: Vec<&str> = dict.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "adapter_id",
                "adapter_version",
                "profile_id",
                "profile_version",
            ]
        );
        assert_eq!(
            dict.get("adapter_id").map(String::as_str),
            Some("synth-adapter-01")
        );
        assert_eq!(
            dict.get("adapter_version").map(String::as_str),
            Some("9.9.9-synth")
        );
        assert_eq!(
            dict.get("profile_id").map(String::as_str),
            Some("synth-profile-01")
        );
        assert_eq!(
            dict.get("profile_version").map(String::as_str),
            Some("2026.01-synth")
        );
        assert_eq!(dict.len(), 4);
        assert!(!dict.contains_key("source_metadata"));
        assert!(!dict.contains_key("timestamp_skew_ms"));
    }

    #[test]
    fn with_overrides_copies_fields_and_preserves_skew() {
        let ctx = CheckContext::new(
            "synth-adapter-01",
            "9.9.9-synth",
            "synth-profile-01",
            "2026.01-synth",
            Some(marker_metadata()),
            4321,
        );
        let out = ctx.with_overrides(
            Some("synth-adapter-02"),
            None,
            Some("synth-profile-02"),
            None,
            SourceMetadataOverride::Unset,
        );
        assert_eq!(out.adapter_id(), "synth-adapter-02");
        assert_eq!(out.adapter_version(), "9.9.9-synth");
        assert_eq!(out.profile_id(), "synth-profile-02");
        assert_eq!(out.profile_version(), "2026.01-synth");
        assert_eq!(out.timestamp_skew_ms(), 4321);
        assert_eq!(out.source_metadata(), Some(&marker_metadata()));
    }

    #[test]
    fn with_overrides_unset_keeps_previous_metadata() {
        let ctx = CheckContext::new(
            "synth-adapter-01",
            UNKNOWN,
            UNKNOWN,
            UNKNOWN,
            Some(marker_metadata()),
            2000,
        );
        let out = ctx.with_overrides(None, None, None, None, SourceMetadataOverride::Unset);
        assert_eq!(out.source_metadata(), Some(&marker_metadata()));
    }

    #[test]
    fn with_overrides_explicit_none_clears_metadata() {
        let ctx = CheckContext::new(
            "synth-adapter-01",
            UNKNOWN,
            UNKNOWN,
            UNKNOWN,
            Some(marker_metadata()),
            2000,
        );
        let out = ctx.with_overrides(
            None,
            None,
            None,
            None,
            SourceMetadataOverride::Explicit(None),
        );
        assert_eq!(out.source_metadata(), None);
    }

    #[test]
    fn with_overrides_non_mapping_becomes_none() {
        let ctx = CheckContext::new(
            "synth-adapter-01",
            UNKNOWN,
            UNKNOWN,
            UNKNOWN,
            Some(marker_metadata()),
            2000,
        );
        let out = ctx.with_overrides(None, None, None, None, SourceMetadataOverride::NonMapping);
        assert_eq!(out.source_metadata(), None);
    }

    #[test]
    fn with_overrides_blank_id_becomes_unknown() {
        let ctx = CheckContext::new(
            "synth-adapter-01",
            "9.9.9-synth",
            "synth-profile-01",
            "2026.01-synth",
            None,
            2000,
        );
        let out = ctx.with_overrides(
            Some(""),
            Some("  "),
            Some("\t"),
            Some("\n"),
            SourceMetadataOverride::Unset,
        );
        assert_eq!(out.adapter_id(), UNKNOWN);
        assert_eq!(out.adapter_version(), UNKNOWN);
        assert_eq!(out.profile_id(), UNKNOWN);
        assert_eq!(out.profile_version(), UNKNOWN);
    }

    #[test]
    fn from_profile_and_adapter_returns_unsupported() {
        let err = CheckContext::from_profile_and_adapter();
        assert!(matches!(err, Err(ChecksError::Unsupported)));
    }
}
