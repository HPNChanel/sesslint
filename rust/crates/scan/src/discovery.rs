//! TRIAGE-002: shared vendor layout filters and bounded latest-session discovery.
//!
//! Port of `src/sesslint/discovery.py` lines 1–65
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.

use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::ScanError;

/// Python: `MAX_DISCOVERY_ENTRIES = 100_000`.
///
/// The bounded walk in `latest_session` is not ported; the cap stays as the
/// published constant so later ports keep the same refusal threshold.
pub const MAX_DISCOVERY_ENTRIES: usize = 100_000;

/// Python keyword default for `candidate_in_layout(..., *, subagents=True)`.
pub const DEFAULT_SUBAGENTS: bool = true;

/// Typed failure for layout recognition (`ValueError` in Python).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// Python `ValueError` from `Path.relative_to` when `path` is not under `root`.
    NotUnderRoot,
    /// Python `ValueError("agent must be claude or codex")`.
    InvalidAgent,
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUnderRoot => formatter.write_str(
                "path is not in the subpath of root OR one path is relative and the other is absolute.",
            ),
            Self::InvalidAgent => formatter.write_str("agent must be claude or codex"),
        }
    }
}

impl Error for DiscoveryError {}

/// Recognize ledger positions, excluding auxiliary files before selection.
///
/// `subagents` matches the Python keyword-only argument; pass
/// [`DEFAULT_SUBAGENTS`] (`true`) when the caller would omit it.
pub fn candidate_in_layout(
    path: &Path,
    root: &Path,
    agent: &str,
    subagents: bool,
) -> Result<bool, DiscoveryError> {
    let parts = relative_parts(path, root)?;
    if agent == "claude" {
        let two_part_jsonl = parts.len() == 2 && python_suffix(path) == ".jsonl";
        let subagent_jsonl = subagents
            && parts.len() == 4
            && parts.get(2) == Some(&OsStr::new("subagents"))
            && python_name(path).starts_with("agent-")
            && python_suffix(path) == ".jsonl";
        return Ok(two_part_jsonl || subagent_jsonl);
    }
    if agent == "codex" {
        return Ok(python_name(path).starts_with("rollout-") && python_suffix(path) == ".jsonl");
    }
    Err(DiscoveryError::InvalidAgent)
}

/// Select the newest primary ledger; refuse incomplete enumeration.
///
/// Python imports `sesslint.api.discover_session_roots` here. That symbol is
/// not ported, so this function does not invent a root list, does not walk a
/// home directory, and does not follow symlinks. Callers receive the crate
/// [`ScanError::Unsupported`].
pub fn latest_session(_agent: &str) -> Result<PathBuf, ScanError> {
    Err(ScanError::Unsupported)
}

fn relative_parts<'a>(path: &'a Path, root: &Path) -> Result<Vec<&'a OsStr>, DiscoveryError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| DiscoveryError::NotUnderRoot)?;
    Ok(relative
        .components()
        .map(|component| component.as_os_str())
        .collect())
}

fn python_name(path: &Path) -> &str {
    path.file_name().and_then(OsStr::to_str).unwrap_or("")
}

fn python_suffix(path: &Path) -> &str {
    let name = python_name(path);
    match name.rfind('.') {
        Some(index) if index > 0 && index < name.len().saturating_sub(1) => &name[index..],
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_in_layout, latest_session, DiscoveryError, DEFAULT_SUBAGENTS,
        MAX_DISCOVERY_ENTRIES,
    };
    use crate::ScanError;
    use std::path::{Path, PathBuf};

    fn root() -> PathBuf {
        PathBuf::from("synthetic-store")
    }

    fn under_root(parts: &[&str]) -> PathBuf {
        let mut path = root();
        for part in parts {
            path.push(part);
        }
        path
    }

    #[test]
    fn max_discovery_entries_is_one_hundred_thousand() {
        assert_eq!(MAX_DISCOVERY_ENTRIES, 100_000);
    }

    #[test]
    fn claude_two_part_jsonl_is_primary() {
        let path = under_root(&["projects", "sess.jsonl"]);
        assert!(candidate_in_layout(&path, &root(), "claude", DEFAULT_SUBAGENTS).expect("layout"));
    }

    #[test]
    fn claude_two_part_non_jsonl_is_rejected() {
        let path = under_root(&["projects", "sess.json"]);
        assert!(!candidate_in_layout(&path, &root(), "claude", true).expect("layout"));
    }

    #[test]
    fn claude_four_part_subagent_is_accepted_when_enabled() {
        let path = under_root(&["projects", "proj", "subagents", "agent-child.jsonl"]);
        assert!(candidate_in_layout(&path, &root(), "claude", true).expect("layout"));
    }

    #[test]
    fn claude_four_part_subagent_is_rejected_when_disabled() {
        let path = under_root(&["projects", "proj", "subagents", "agent-child.jsonl"]);
        assert!(!candidate_in_layout(&path, &root(), "claude", false).expect("layout"));
    }

    #[test]
    fn claude_four_part_requires_third_component_subagents() {
        let path = under_root(&["projects", "proj", "other", "agent-child.jsonl"]);
        assert!(!candidate_in_layout(&path, &root(), "claude", true).expect("layout"));
    }

    #[test]
    fn claude_four_part_requires_agent_prefix() {
        let path = under_root(&["projects", "proj", "subagents", "child.jsonl"]);
        assert!(!candidate_in_layout(&path, &root(), "claude", true).expect("layout"));
    }

    #[test]
    fn claude_three_part_is_rejected() {
        let path = under_root(&["projects", "proj", "sess.jsonl"]);
        assert!(!candidate_in_layout(&path, &root(), "claude", true).expect("layout"));
    }

    #[test]
    fn codex_rollout_jsonl_is_accepted_at_any_depth() {
        let shallow = under_root(&["rollout-a.jsonl"]);
        let nested = under_root(&["sessions", "2026", "10", "rollout-b.jsonl"]);
        assert!(candidate_in_layout(&shallow, &root(), "codex", true).expect("layout"));
        assert!(candidate_in_layout(&nested, &root(), "codex", false).expect("layout"));
    }

    #[test]
    fn codex_requires_rollout_prefix_and_jsonl_suffix() {
        let no_prefix = under_root(&["session-a.jsonl"]);
        let no_suffix = under_root(&["rollout-a.json"]);
        assert!(!candidate_in_layout(&no_prefix, &root(), "codex", true).expect("layout"));
        assert!(!candidate_in_layout(&no_suffix, &root(), "codex", true).expect("layout"));
    }

    #[test]
    fn unknown_agent_is_typed_value_error() {
        let path = under_root(&["projects", "sess.jsonl"]);
        let error = candidate_in_layout(&path, &root(), "gemini", true)
            .expect_err("unknown agent must not panic");
        assert_eq!(error, DiscoveryError::InvalidAgent);
        assert_eq!(error.to_string(), "agent must be claude or codex");
    }

    #[test]
    fn relative_to_runs_before_agent_check() {
        let path = Path::new("other-store").join("projects").join("sess.jsonl");
        let error = candidate_in_layout(&path, &root(), "gemini", true)
            .expect_err("not-under-root must win");
        assert_eq!(error, DiscoveryError::NotUnderRoot);
    }

    #[test]
    fn latest_session_returns_crate_unsupported() {
        let error = latest_session("claude").expect_err("api not ported");
        assert!(matches!(error, ScanError::Unsupported));
        assert_eq!(error.to_string(), "scan error");
        let also = latest_session("codex").expect_err("api not ported");
        assert!(matches!(also, ScanError::Unsupported));
        let unknown = latest_session("gemini").expect_err("must not invent roots");
        assert!(matches!(unknown, ScanError::Unsupported));
    }
}
