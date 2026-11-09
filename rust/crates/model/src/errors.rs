//! Typed error hierarchy for SessLint.

use std::error::Error;
use std::fmt;

/// Python class order in `sesslint.errors` (most-specific kind for an instance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorKind {
    Sesslint,
    Schema,
    Version,
    UnknownField,
    Finding,
    Assurance,
    ContentLeak,
    FileTooLarge,
    MaxRecordsExceeded,
    HeaderMissing,
    SourceChanged,
    AtomicWrite,
    Operational,
    Adapter,
}

/// Base exception for all SessLint errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SesslintError {
    Generic { message: String, code: String },
    Schema(SchemaError),
    Finding(FindingError),
    Assurance(AssuranceError),
    ContentLeak(ContentLeakError),
    FileTooLarge(FileTooLargeError),
    MaxRecordsExceeded(MaxRecordsExceededError),
    SourceChanged(SourceChangedError),
    AtomicWrite(AtomicWriteError),
    Operational(OperationalError),
    Adapter(AdapterError),
}

impl SesslintError {
    pub const DEFAULT_CODE: &'static str = "ERROR";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Generic {
            message: message.into(),
            code: code.into(),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Generic { .. } => ErrorKind::Sesslint,
            Self::Schema(error) => error.kind(),
            Self::Finding(_) => ErrorKind::Finding,
            Self::Assurance(_) => ErrorKind::Assurance,
            Self::ContentLeak(_) => ErrorKind::ContentLeak,
            Self::FileTooLarge(_) => ErrorKind::FileTooLarge,
            Self::MaxRecordsExceeded(_) => ErrorKind::MaxRecordsExceeded,
            Self::SourceChanged(_) => ErrorKind::SourceChanged,
            Self::AtomicWrite(_) => ErrorKind::AtomicWrite,
            Self::Operational(_) => ErrorKind::Operational,
            Self::Adapter(_) => ErrorKind::Adapter,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Generic { message, .. } => message,
            Self::Schema(error) => error.message(),
            Self::Finding(error) => error.message(),
            Self::Assurance(error) => error.message(),
            Self::ContentLeak(error) => error.message(),
            Self::FileTooLarge(error) => error.message(),
            Self::MaxRecordsExceeded(error) => error.message(),
            Self::SourceChanged(error) => error.message(),
            Self::AtomicWrite(error) => error.message(),
            Self::Operational(error) => error.message(),
            Self::Adapter(error) => error.message(),
        }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Generic { code, .. } => code,
            Self::Schema(error) => error.code(),
            Self::Finding(error) => error.code(),
            Self::Assurance(error) => error.code(),
            Self::ContentLeak(error) => error.code(),
            Self::FileTooLarge(error) => error.code(),
            Self::MaxRecordsExceeded(error) => error.code(),
            Self::SourceChanged(error) => error.code(),
            Self::AtomicWrite(error) => error.code(),
            Self::Operational(error) => error.code(),
            Self::Adapter(error) => error.code(),
        }
    }

    pub fn reason_code(&self) -> Option<&str> {
        match self {
            Self::Schema(error) => error.reason_code(),
            _ => None,
        }
    }

    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Schema(error) => error.version(),
            _ => None,
        }
    }

    pub fn field_name(&self) -> Option<&str> {
        match self {
            Self::Schema(error) => error.field_name(),
            _ => None,
        }
    }

    /// Python: `isinstance(err, SchemaError)`.
    pub fn is_schema(&self) -> bool {
        matches!(self, Self::Schema(_))
    }

    /// Python: `FindingError` / `AssuranceError` / `ContentLeakError` also subclass `ValueError`.
    pub fn is_value_error(&self) -> bool {
        matches!(
            self,
            Self::Finding(_) | Self::Assurance(_) | Self::ContentLeak(_)
        )
    }

    /// Python: `AtomicWriteError` also subclasses `OSError`.
    pub fn is_os_error(&self) -> bool {
        matches!(self, Self::AtomicWrite(_))
    }
}

impl fmt::Display for SesslintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for SesslintError {}

/// Raised when an artifact violates canonical schema or structural constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    Generic { message: String, code: String },
    Version(VersionError),
    UnknownField(UnknownFieldError),
    HeaderMissing(HeaderMissingError),
}

impl SchemaError {
    pub const DEFAULT_CODE: &'static str = "SCHEMA";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Generic {
            message: message.into(),
            code: code.into(),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Generic { .. } => ErrorKind::Schema,
            Self::Version(_) => ErrorKind::Version,
            Self::UnknownField(_) => ErrorKind::UnknownField,
            Self::HeaderMissing(_) => ErrorKind::HeaderMissing,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Generic { message, .. } => message,
            Self::Version(error) => error.message(),
            Self::UnknownField(error) => error.message(),
            Self::HeaderMissing(error) => error.message(),
        }
    }

    pub fn code(&self) -> &str {
        match self {
            Self::Generic { code, .. } => code,
            Self::Version(error) => error.code(),
            Self::UnknownField(error) => error.code(),
            Self::HeaderMissing(error) => error.code(),
        }
    }

    pub fn reason_code(&self) -> Option<&str> {
        match self {
            Self::Version(error) => Some(error.reason_code()),
            Self::UnknownField(error) => Some(error.reason_code()),
            Self::Generic { .. } | Self::HeaderMissing(_) => None,
        }
    }

    pub fn version(&self) -> Option<&str> {
        match self {
            Self::Version(error) => error.version(),
            _ => None,
        }
    }

    pub fn field_name(&self) -> Option<&str> {
        match self {
            Self::UnknownField(error) => error.field_name(),
            _ => None,
        }
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for SchemaError {}

impl From<SchemaError> for SesslintError {
    fn from(value: SchemaError) -> Self {
        Self::Schema(value)
    }
}

/// Raised when an unsupported schema version is encountered (SL301 hook).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionError {
    message: String,
    version: Option<String>,
}

impl VersionError {
    pub const CODE: &'static str = "VERSION";
    pub const REASON_CODE: &'static str = "SL301";

    pub fn new(message: impl Into<String>, version: Option<String>) -> Self {
        let message = format_reason_message(message.into(), Self::REASON_CODE, Self::CODE);
        Self { message, version }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn code(&self) -> &'static str {
        Self::CODE
    }

    pub fn reason_code(&self) -> &'static str {
        Self::REASON_CODE
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

impl fmt::Display for VersionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for VersionError {}

impl From<VersionError> for SchemaError {
    fn from(value: VersionError) -> Self {
        Self::Version(value)
    }
}

impl From<VersionError> for SesslintError {
    fn from(value: VersionError) -> Self {
        SchemaError::from(value).into()
    }
}

/// Raised when an unrecognized top-level field is encountered (SL302 hook).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownFieldError {
    message: String,
    field_name: Option<String>,
}

impl UnknownFieldError {
    pub const CODE: &'static str = "UNKNOWN_FIELD";
    pub const REASON_CODE: &'static str = "SL302";

    pub fn new(message: impl Into<String>, field_name: Option<String>) -> Self {
        let message = format_reason_message(message.into(), Self::REASON_CODE, Self::CODE);
        Self {
            message,
            field_name,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn code(&self) -> &'static str {
        Self::CODE
    }

    pub fn reason_code(&self) -> &'static str {
        Self::REASON_CODE
    }

    pub fn field_name(&self) -> Option<&str> {
        self.field_name.as_deref()
    }
}

impl fmt::Display for UnknownFieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for UnknownFieldError {}

impl From<UnknownFieldError> for SchemaError {
    fn from(value: UnknownFieldError) -> Self {
        Self::UnknownField(value)
    }
}

impl From<UnknownFieldError> for SesslintError {
    fn from(value: UnknownFieldError) -> Self {
        SchemaError::from(value).into()
    }
}

/// Raised when finding construction, validation, or contract enforcement fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingError {
    inner: CodedMessage,
}

impl FindingError {
    pub const DEFAULT_CODE: &'static str = "FINDING";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for FindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for FindingError {}

impl From<FindingError> for SesslintError {
    fn from(value: FindingError) -> Self {
        Self::Finding(value)
    }
}

/// Raised when assurance level validation or mandatory limitation constraint fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssuranceError {
    inner: CodedMessage,
}

impl AssuranceError {
    pub const DEFAULT_CODE: &'static str = "ASSURANCE";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for AssuranceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for AssuranceError {}

impl From<AssuranceError> for SesslintError {
    fn from(value: AssuranceError) -> Self {
        Self::Assurance(value)
    }
}

/// Raised when forbidden content, credentials, or payload text leaks into artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentLeakError {
    inner: CodedMessage,
}

impl ContentLeakError {
    pub const DEFAULT_CODE: &'static str = "CONTENT_LEAK";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for ContentLeakError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for ContentLeakError {}

impl From<ContentLeakError> for SesslintError {
    fn from(value: ContentLeakError) -> Self {
        Self::ContentLeak(value)
    }
}

/// Raised when file or stream size exceeds configured byte limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTooLargeError {
    inner: CodedMessage,
}

impl FileTooLargeError {
    pub const DEFAULT_CODE: &'static str = "LIMIT_EXCEEDED";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for FileTooLargeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for FileTooLargeError {}

impl From<FileTooLargeError> for SesslintError {
    fn from(value: FileTooLargeError) -> Self {
        Self::FileTooLarge(value)
    }
}

/// Raised when record count exceeds configured limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxRecordsExceededError {
    inner: CodedMessage,
}

impl MaxRecordsExceededError {
    pub const DEFAULT_CODE: &'static str = "LIMIT_EXCEEDED";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for MaxRecordsExceededError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for MaxRecordsExceededError {}

impl From<MaxRecordsExceededError> for SesslintError {
    fn from(value: MaxRecordsExceededError) -> Self {
        Self::MaxRecordsExceeded(value)
    }
}

/// Raised when a required session header is absent, empty, or unreadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMissingError {
    inner: CodedMessage,
}

impl HeaderMissingError {
    pub const DEFAULT_CODE: &'static str = "HEADER_MISSING";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for HeaderMissingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for HeaderMissingError {}

impl From<HeaderMissingError> for SchemaError {
    fn from(value: HeaderMissingError) -> Self {
        Self::HeaderMissing(value)
    }
}

impl From<HeaderMissingError> for SesslintError {
    fn from(value: HeaderMissingError) -> Self {
        SchemaError::from(value).into()
    }
}

/// Raised when an input source file is modified concurrently during inspection or repair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceChangedError {
    inner: CodedMessage,
}

impl SourceChangedError {
    pub const DEFAULT_CODE: &'static str = "SOURCE_CHANGED";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for SourceChangedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for SourceChangedError {}

impl From<SourceChangedError> for SesslintError {
    fn from(value: SourceChangedError) -> Self {
        Self::SourceChanged(value)
    }
}

/// Raised when an atomic write or replace operation fails, or an unsafe path is requested.
///
/// Python sets `self.code` after `SesslintError.__init__(message)` without passing
/// `code=` into the base; the public result is still the supplied (or default) code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicWriteError {
    inner: CodedMessage,
}

impl AtomicWriteError {
    pub const DEFAULT_CODE: &'static str = "ATOMIC_WRITE_ERROR";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for AtomicWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for AtomicWriteError {}

impl From<AtomicWriteError> for SesslintError {
    fn from(value: AtomicWriteError) -> Self {
        Self::AtomicWrite(value)
    }
}

/// Raised when an internal operational invariant or renderer validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalError {
    inner: CodedMessage,
}

impl OperationalError {
    pub const DEFAULT_CODE: &'static str = "OPERATIONAL_ERROR";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for OperationalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for OperationalError {}

impl From<OperationalError> for SesslintError {
    fn from(value: OperationalError) -> Self {
        Self::Operational(value)
    }
}

/// Raised when an adapter invariant or parsing constraint fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterError {
    inner: CodedMessage,
}

impl AdapterError {
    pub const DEFAULT_CODE: &'static str = "ADAPTER_ERROR";

    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    pub fn message(&self) -> &str {
        self.inner.message()
    }

    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for AdapterError {}

impl From<AdapterError> for SesslintError {
    fn from(value: AdapterError) -> Self {
        Self::Adapter(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CodedMessage {
    message: String,
    code: String,
}

impl CodedMessage {
    fn new(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: code.into(),
        }
    }

    fn message(&self) -> &str {
        &self.message
    }

    fn code(&self) -> &str {
        &self.code
    }
}

impl fmt::Display for CodedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn format_reason_message(message: String, reason_code: &str, code: &str) -> String {
    if message.contains(reason_code) {
        message
    } else {
        format!("{message} (code: {code} / {reason_code})")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterError, AssuranceError, AtomicWriteError, ContentLeakError, ErrorKind,
        FileTooLargeError, FindingError, HeaderMissingError, MaxRecordsExceededError,
        OperationalError, SchemaError, SesslintError, SourceChangedError, UnknownFieldError,
        VersionError,
    };
    use std::error::Error;

    const SYNTHETIC: &str = "synthetic-check-ok";

    #[test]
    fn happy_path_constructs_base_error_with_default_code() {
        let error = SesslintError::new(SYNTHETIC);
        assert_eq!(error.kind(), ErrorKind::Sesslint);
        assert_eq!(error.code(), "ERROR");
        assert_eq!(error.to_string(), SYNTHETIC);
        assert!(!error.is_schema());
        assert!(!error.is_value_error());
        assert!(!error.is_os_error());
        assert!(error.source().is_none());
    }

    #[test]
    fn default_codes_match_python_class_attributes() {
        assert_eq!(SesslintError::new(SYNTHETIC).code(), "ERROR");
        assert_eq!(SchemaError::new(SYNTHETIC).code(), "SCHEMA");
        assert_eq!(VersionError::new(SYNTHETIC, None).code(), "VERSION");
        assert_eq!(
            UnknownFieldError::new(SYNTHETIC, None).code(),
            "UNKNOWN_FIELD"
        );
        assert_eq!(FindingError::new(SYNTHETIC).code(), "FINDING");
        assert_eq!(AssuranceError::new(SYNTHETIC).code(), "ASSURANCE");
        assert_eq!(ContentLeakError::new(SYNTHETIC).code(), "CONTENT_LEAK");
        assert_eq!(FileTooLargeError::new(SYNTHETIC).code(), "LIMIT_EXCEEDED");
        assert_eq!(
            MaxRecordsExceededError::new(SYNTHETIC).code(),
            "LIMIT_EXCEEDED"
        );
        assert_eq!(HeaderMissingError::new(SYNTHETIC).code(), "HEADER_MISSING");
        assert_eq!(SourceChangedError::new(SYNTHETIC).code(), "SOURCE_CHANGED");
        assert_eq!(
            AtomicWriteError::new(SYNTHETIC).code(),
            "ATOMIC_WRITE_ERROR"
        );
        assert_eq!(OperationalError::new(SYNTHETIC).code(), "OPERATIONAL_ERROR");
        assert_eq!(AdapterError::new(SYNTHETIC).code(), "ADAPTER_ERROR");
    }

    #[test]
    fn version_error_appends_sl301_when_absent() {
        let error = VersionError::new("unsupported schema version", None);
        assert_eq!(
            error.to_string(),
            "unsupported schema version (code: VERSION / SL301)"
        );
        assert_eq!(error.reason_code(), "SL301");
        assert_eq!(error.version(), None);
    }

    #[test]
    fn version_error_keeps_message_when_sl301_already_present() {
        let error = VersionError::new("already cites SL301", Some("sesslint.session/9.9".into()));
        assert_eq!(error.to_string(), "already cites SL301");
        assert_eq!(error.version(), Some("sesslint.session/9.9"));
        assert!(
            !error.to_string().contains("sesslint.session/9.9"),
            "Display must not interpolate version"
        );
    }

    #[test]
    fn version_error_empty_message_still_gets_suffix() {
        let error = VersionError::new("", None);
        assert_eq!(error.to_string(), " (code: VERSION / SL301)");
    }

    #[test]
    fn version_error_substring_sl301_suppresses_suffix() {
        let error = VersionError::new("prefix-SL301-suffix", None);
        assert_eq!(error.to_string(), "prefix-SL301-suffix");
    }

    #[test]
    fn unknown_field_error_appends_sl302_when_absent() {
        let error = UnknownFieldError::new("Unknown field in session header", Some("evil".into()));
        assert_eq!(
            error.to_string(),
            "Unknown field in session header (code: UNKNOWN_FIELD / SL302)"
        );
        assert_eq!(error.reason_code(), "SL302");
        assert_eq!(error.field_name(), Some("evil"));
    }

    #[test]
    fn unknown_field_error_keeps_message_when_sl302_already_present() {
        let error = UnknownFieldError::new("Unknown field (SL302)", Some("rogue".into()));
        assert_eq!(error.to_string(), "Unknown field (SL302)");
        assert_eq!(error.field_name(), Some("rogue"));
        assert!(
            !error.to_string().contains("rogue"),
            "Display must not interpolate field_name"
        );
    }

    #[test]
    fn custom_codes_override_defaults() {
        assert_eq!(
            SesslintError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(SchemaError::with_code(SYNTHETIC, "CUSTOM").code(), "CUSTOM");
        assert_eq!(
            FindingError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(
            AssuranceError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(
            ContentLeakError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(
            FileTooLargeError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(
            MaxRecordsExceededError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(
            HeaderMissingError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(
            SourceChangedError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(
            AtomicWriteError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(
            OperationalError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
        assert_eq!(
            AdapterError::with_code(SYNTHETIC, "CUSTOM").code(),
            "CUSTOM"
        );
    }

    #[test]
    fn hierarchy_matches_python_isinstance() {
        let version: SesslintError = VersionError::new("unsupported schema version", None).into();
        assert!(version.is_schema());
        assert!(!version.is_value_error());
        assert_eq!(version.kind(), ErrorKind::Version);
        assert_eq!(version.reason_code(), Some("SL301"));

        let unknown: SesslintError = UnknownFieldError::new("unknown", None).into();
        assert!(unknown.is_schema());
        assert_eq!(unknown.kind(), ErrorKind::UnknownField);

        let header: SesslintError = HeaderMissingError::new("missing header").into();
        assert!(header.is_schema());
        assert_eq!(header.kind(), ErrorKind::HeaderMissing);

        let schema: SesslintError = SchemaError::new("missing field").into();
        assert!(schema.is_schema());
        assert_eq!(schema.kind(), ErrorKind::Schema);

        let finding: SesslintError = FindingError::new("bad finding").into();
        assert!(finding.is_value_error());
        assert!(!finding.is_schema());
        assert_eq!(finding.kind(), ErrorKind::Finding);

        let assurance: SesslintError = AssuranceError::new("bad assurance").into();
        assert!(assurance.is_value_error());

        let leak: SesslintError = ContentLeakError::new("intrinsic content leak").into();
        assert!(leak.is_value_error());
        assert_eq!(leak.kind(), ErrorKind::ContentLeak);

        let atomic: SesslintError = AtomicWriteError::new("refusing protected path").into();
        assert!(atomic.is_os_error());
        assert!(!atomic.is_value_error());
        assert_eq!(atomic.kind(), ErrorKind::AtomicWrite);
    }

    #[test]
    fn limit_errors_share_code_but_remain_distinct_kinds() {
        let too_large: SesslintError = FileTooLargeError::new("byte limit").into();
        let too_many: SesslintError = MaxRecordsExceededError::new("record limit").into();
        assert_eq!(too_large.code(), too_many.code());
        assert_eq!(too_large.code(), "LIMIT_EXCEEDED");
        assert_ne!(too_large.kind(), too_many.kind());
        assert_eq!(too_large.kind(), ErrorKind::FileTooLarge);
        assert_eq!(too_many.kind(), ErrorKind::MaxRecordsExceeded);
    }

    #[test]
    fn kind_sequence_preserves_construction_order() {
        let errors: [SesslintError; 14] = [
            SesslintError::new(SYNTHETIC),
            SchemaError::new(SYNTHETIC).into(),
            VersionError::new(SYNTHETIC, None).into(),
            UnknownFieldError::new(SYNTHETIC, None).into(),
            FindingError::new(SYNTHETIC).into(),
            AssuranceError::new(SYNTHETIC).into(),
            ContentLeakError::new(SYNTHETIC).into(),
            FileTooLargeError::new(SYNTHETIC).into(),
            MaxRecordsExceededError::new(SYNTHETIC).into(),
            HeaderMissingError::new(SYNTHETIC).into(),
            SourceChangedError::new(SYNTHETIC).into(),
            AtomicWriteError::new(SYNTHETIC).into(),
            OperationalError::new(SYNTHETIC).into(),
            AdapterError::new(SYNTHETIC).into(),
        ];
        let kinds = errors.map(|error| error.kind());

        assert_eq!(
            kinds,
            [
                ErrorKind::Sesslint,
                ErrorKind::Schema,
                ErrorKind::Version,
                ErrorKind::UnknownField,
                ErrorKind::Finding,
                ErrorKind::Assurance,
                ErrorKind::ContentLeak,
                ErrorKind::FileTooLarge,
                ErrorKind::MaxRecordsExceeded,
                ErrorKind::HeaderMissing,
                ErrorKind::SourceChanged,
                ErrorKind::AtomicWrite,
                ErrorKind::Operational,
                ErrorKind::Adapter,
            ]
        );
    }

    #[test]
    fn display_is_content_free_for_structural_messages() {
        let error = VersionError::new(
            "unsupported schema version",
            Some("sesslint.session/9.9".into()),
        );
        let text = error.to_string();
        assert_eq!(text, "unsupported schema version (code: VERSION / SL301)");
        assert!(!text.contains('{'));
        assert!(!text.contains('}'));
        assert!(!text.contains("payload"));
        assert!(!text.contains("transcript"));
    }

    #[test]
    fn unicode_message_without_reason_gets_suffix() {
        let error = VersionError::new("phiên bản không hỗ trợ", None);
        assert_eq!(
            error.to_string(),
            "phiên bản không hỗ trợ (code: VERSION / SL301)"
        );
    }
}
