//! Empty scaffold for the `adapters` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::AdaptersError;

pub mod links;
pub mod synthetic;
pub mod safe_value;
pub mod drift;
pub mod metadata;
pub mod canonical;
pub mod claude_code;
pub mod openai_agents;
pub mod codex_rollout;
pub mod detect;
pub mod load {}
pub mod source;

/// One supported-adapter metadata row.
///
/// Python dict keys from `supported_adapters`: `name`, `default_profile`,
/// `description`, and `versions_supported`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportedAdapter {
    pub name: &'static str,
    pub default_profile: &'static str,
    pub description: &'static str,
    pub versions_supported: Vec<String>,
}

/// Return supported-adapter metadata rows (name, profile, description, versions).
///
/// Python: `supported_adapters` in `src/sesslint/adapters/__init__.py`
/// lines 64–98 @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
///
/// The rows stay in pin order. Each `versions_supported` list is a sorted
/// copy of that adapter's version set (`sorted()`, ordinary string order).
/// This function has no failure branch.
pub fn supported_adapters() -> Vec<SupportedAdapter> {
    vec![
        SupportedAdapter {
            name: "canonical",
            default_profile: "neutral",
            description: "sesslint.session/v1 canonical JSONL (SessLint's own interchange format)",
            versions_supported: sorted_version_copy(&canonical::SUPPORTED_CANONICAL_VERSIONS),
        },
        SupportedAdapter {
            name: "claude-code-jsonl",
            default_profile: "claude-strict",
            description: "Claude Code JSONL (per-turn records incl. snapshots/hooks)",
            versions_supported: sorted_version_copy(&claude_code::SUPPORTED_CLAUDE_VERSIONS),
        },
        SupportedAdapter {
            name: "codex-rollout",
            default_profile: "openai-strict",
            description: "Codex rollout/session_meta + response_item records",
            versions_supported: sorted_version_copy(
                &codex_rollout::SUPPORTED_CODEX_ROLLOUT_VERSIONS,
            ),
        },
        SupportedAdapter {
            name: "openai-agents",
            default_profile: "openai-strict",
            description: "OpenAI Agents SDK session export (session + item arrays)",
            versions_supported: sorted_version_copy(
                &openai_agents::SUPPORTED_OPENAI_AGENTS_VERSIONS,
            ),
        },
    ]
}

/// Sorted copy of a version set. Python `sorted()` uses ordinary string order.
fn sorted_version_copy<const N: usize>(versions: &[&str; N]) -> Vec<String> {
    let mut copy: Vec<String> = versions.iter().copied().map(str::to_owned).collect();
    copy.sort();
    copy
}

#[cfg(test)]
mod tests {
    use super::{supported_adapters, SupportedAdapter};

    #[test]
    fn supported_adapters_matches_the_pin() {
        let rows = supported_adapters();
        assert_eq!(rows, supported_adapters());
        assert_eq!(
            rows,
            vec![
                SupportedAdapter {
                    name: "canonical",
                    default_profile: "neutral",
                    description: "sesslint.session/v1 canonical JSONL (SessLint's own interchange format)",
                    versions_supported: vec![
                        "1".to_owned(),
                        "1.0".to_owned(),
                        "1.0.0".to_owned(),
                    ],
                },
                SupportedAdapter {
                    name: "claude-code-jsonl",
                    default_profile: "claude-strict",
                    description: "Claude Code JSONL (per-turn records incl. snapshots/hooks)",
                    versions_supported: vec![
                        "0.1".to_owned(),
                        "0.1.0".to_owned(),
                        "1".to_owned(),
                        "1.0".to_owned(),
                        "1.0.0".to_owned(),
                        "claude-code-v1".to_owned(),
                    ],
                },
                SupportedAdapter {
                    name: "codex-rollout",
                    default_profile: "openai-strict",
                    description: "Codex rollout/session_meta + response_item records",
                    versions_supported: vec![
                        "1".to_owned(),
                        "1.0".to_owned(),
                        "1.0.0".to_owned(),
                        "codex-rollout-v1".to_owned(),
                    ],
                },
                SupportedAdapter {
                    name: "openai-agents",
                    default_profile: "openai-strict",
                    description: "OpenAI Agents SDK session export (session + item arrays)",
                    versions_supported: vec![
                        "0.1".to_owned(),
                        "0.1.0".to_owned(),
                        "0.2".to_owned(),
                        "0.2.0".to_owned(),
                        "1".to_owned(),
                        "1.0".to_owned(),
                        "1.0.0".to_owned(),
                        "openai-agents-v1".to_owned(),
                    ],
                },
            ]
        );
        assert_ne!(
            rows[1].versions_supported,
            [
                "1".to_owned(),
                "1.0".to_owned(),
                "1.0.0".to_owned(),
                "0.1".to_owned(),
                "0.1.0".to_owned(),
                "claude-code-v1".to_owned(),
            ]
        );
    }
}
