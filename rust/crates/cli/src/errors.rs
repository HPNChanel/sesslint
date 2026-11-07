//! CLI error type carrying an exit code through the dispatch layer.

use std::error::Error;
use std::fmt;

/// A user-facing CLI failure: message printed to stderr, exit_code returned.
///
/// Raised anywhere below `main()` — inside `build_context` or a command's
/// `run` — and converted to `print(stderr) + return exit_code` by the
/// dispatch layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    exit_code: i32,
    message: String,
}

impl CliError {
    /// Python: `CliError(exit_code, message)`.
    pub fn new(exit_code: i32, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CliError {}

#[cfg(test)]
mod tests {
    use super::CliError;
    use std::error::Error;

    const SYNTHETIC: &str = "synthetic-check-ok";

    #[test]
    fn happy_path_stores_exit_code_and_displays_message() {
        let error = CliError::new(0, SYNTHETIC);
        assert_eq!(error.exit_code(), 0);
        assert_eq!(error.message(), SYNTHETIC);
        assert_eq!(error.to_string(), SYNTHETIC);
        assert!(error.source().is_none());
    }

    #[test]
    fn typical_usage_failure_preserves_exit_code_two() {
        let error = CliError::new(2, SYNTHETIC);
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.to_string(), SYNTHETIC);
    }

    #[test]
    fn empty_message_displays_empty_and_keeps_exit_code() {
        let error = CliError::new(2, "");
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.message(), "");
        assert_eq!(error.to_string(), "");
    }

    #[test]
    fn unicode_message_is_preserved_verbatim() {
        let message = "synthetic-phiên-bản-không-hỗ-trợ";
        let error = CliError::new(2, message);
        assert_eq!(error.message(), message);
        assert_eq!(error.to_string(), message);
    }

    #[test]
    fn display_is_the_message_only() {
        let error = CliError::new(2, SYNTHETIC);
        let text = error.to_string();
        assert_eq!(text, SYNTHETIC);
        assert!(!text.contains('2'));
        assert!(!text.contains("exit"));
    }

    #[test]
    fn negative_and_nonzero_exit_codes_are_stored_as_given() {
        let negative = CliError::new(-1, SYNTHETIC);
        let large = CliError::new(130, SYNTHETIC);
        assert_eq!(negative.exit_code(), -1);
        assert_eq!(large.exit_code(), 130);
        assert_eq!(negative.to_string(), SYNTHETIC);
        assert_eq!(large.to_string(), SYNTHETIC);
    }

    #[test]
    fn equality_is_by_exit_code_and_message() {
        let left = CliError::new(2, SYNTHETIC);
        let right = CliError::new(2, SYNTHETIC);
        let different_code = CliError::new(1, SYNTHETIC);
        let different_message = CliError::new(2, "synthetic-other");
        assert_eq!(left, right);
        assert_ne!(left, different_code);
        assert_ne!(left, different_message);
    }
}
