//! Typed error hierarchy for repair execution (TASK-021).
//!
//! Port of `src/sesslint/repair/errors.py` lines 1-96
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! Every value subclasses `SesslintError` and `ValueError`. Display is the
//! exception message only. The class `code` is separate and is not appended.
//! `Abstained` stays fail-closed: its code remains `ABSTAINED`, and this
//! module has no success path that turns an abstention into a repair.
//!
//! `sesslint.errors.SesslintError` is ported as [`model::errors::SesslintError`].
//! That enum's generic variant is not a `ValueError`, so this hierarchy stays
//! in this module. [`RepairError::is_sesslint_error`] and
//! [`RepairError::is_value_error`] report the two Python bases.
//!
//! No I/O. Constructors do not panic.

use std::error::Error;
use std::fmt;

/// Python `__all__`, in that order.
pub const ALL: [&str; 10] = [
    "Abstained",
    "ManifestCollision",
    "OutputInvalid",
    "PlanSourceMismatch",
    "PlanTampered",
    "PolicyMismatch",
    "RepairError",
    "RepairRefused",
    "VendorProjectionRefused",
    "VendorRepairRefused",
];

/// Most-specific Python class.
///
/// Variant order is the class order in `sesslint.repair.errors`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RepairKind {
    /// `RepairError`.
    Repair,
    /// `PlanTampered`.
    PlanTampered,
    /// `Abstained`.
    Abstained,
    /// `PolicyMismatch`.
    PolicyMismatch,
    /// `OutputInvalid`.
    OutputInvalid,
    /// `RepairRefused` itself, not a subclass.
    RepairRefused,
    /// `VendorRepairRefused`.
    VendorRepairRefused,
    /// `ManifestCollision`.
    ManifestCollision,
    /// `VendorProjectionRefused`.
    VendorProjectionRefused,
    /// `PlanSourceMismatch`.
    PlanSourceMismatch,
}

/// Base exception for all repair execution failures and refusals.
///
/// Python: `RepairError(SesslintError, ValueError)` with code `REPAIR_ERROR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairError {
    /// A `RepairError` instance that is not a subclass.
    Generic { message: String, code: String },
    /// `PlanTampered`.
    PlanTampered(PlanTampered),
    /// `Abstained`.
    Abstained(Abstained),
    /// `PolicyMismatch`.
    PolicyMismatch(PolicyMismatch),
    /// `OutputInvalid`.
    OutputInvalid(OutputInvalid),
    /// `RepairRefused` or one of its subclasses.
    RepairRefused(RepairRefused),
    /// `PlanSourceMismatch`.
    PlanSourceMismatch(PlanSourceMismatch),
}

impl RepairError {
    /// Python class attribute `RepairError.code`.
    pub const DEFAULT_CODE: &'static str = "REPAIR_ERROR";

    /// Python: `RepairError(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python: `RepairError(message, code=code)`.
    ///
    /// Display stays `message`. Passing `code` does not change the class.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Generic {
            message: message.into(),
            code: code.into(),
        }
    }

    /// Python: `isinstance(err, SesslintError)`.
    ///
    /// The ported base is [`model::errors::SesslintError`]. Its default code is
    /// the Python class attribute `ERROR`. This method does not convert into
    /// `SesslintError::Generic`, because that variant is not a `ValueError`.
    pub fn is_sesslint_error(&self) -> bool {
        self.matches_hierarchy() && model::errors::SesslintError::DEFAULT_CODE == "ERROR"
    }

    /// Python: `isinstance(err, ValueError)`.
    ///
    /// The whole repair hierarchy subclasses `ValueError`.
    pub fn is_value_error(&self) -> bool {
        self.matches_hierarchy()
    }

    /// Python: `isinstance(err, PlanTampered)`.
    pub fn is_plan_tampered(&self) -> bool {
        matches!(self, Self::PlanTampered(_))
    }

    /// Python: `isinstance(err, Abstained)`.
    pub fn is_abstained(&self) -> bool {
        matches!(self, Self::Abstained(_))
    }

    /// Python: `isinstance(err, PolicyMismatch)`.
    pub fn is_policy_mismatch(&self) -> bool {
        matches!(self, Self::PolicyMismatch(_))
    }

    /// Python: `isinstance(err, OutputInvalid)`.
    pub fn is_output_invalid(&self) -> bool {
        matches!(self, Self::OutputInvalid(_))
    }

    /// Python: `isinstance(err, RepairRefused)`.
    ///
    /// True for `RepairRefused` and for `VendorRepairRefused`,
    /// `ManifestCollision`, and `VendorProjectionRefused`.
    pub fn is_repair_refused(&self) -> bool {
        matches!(self, Self::RepairRefused(_))
    }

    /// Python: `isinstance(err, VendorRepairRefused)`.
    pub fn is_vendor_repair_refused(&self) -> bool {
        matches!(
            self,
            Self::RepairRefused(RepairRefused::VendorRepairRefused(_))
        )
    }

    /// Python: `isinstance(err, ManifestCollision)`.
    pub fn is_manifest_collision(&self) -> bool {
        matches!(
            self,
            Self::RepairRefused(RepairRefused::ManifestCollision(_))
        )
    }

    /// Python: `isinstance(err, VendorProjectionRefused)`.
    pub fn is_vendor_projection_refused(&self) -> bool {
        matches!(
            self,
            Self::RepairRefused(RepairRefused::VendorProjectionRefused(_))
        )
    }

    /// Python: `isinstance(err, PlanSourceMismatch)`.
    pub fn is_plan_source_mismatch(&self) -> bool {
        matches!(self, Self::PlanSourceMismatch(_))
    }

    /// Most-specific Python class.
    pub fn kind(&self) -> RepairKind {
        match self {
            Self::Generic { .. } => RepairKind::Repair,
            Self::PlanTampered(_) => RepairKind::PlanTampered,
            Self::Abstained(_) => RepairKind::Abstained,
            Self::PolicyMismatch(_) => RepairKind::PolicyMismatch,
            Self::OutputInvalid(_) => RepairKind::OutputInvalid,
            Self::RepairRefused(error) => error.kind(),
            Self::PlanSourceMismatch(_) => RepairKind::PlanSourceMismatch,
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        match self {
            Self::Generic { message, .. } => message,
            Self::PlanTampered(error) => error.message(),
            Self::Abstained(error) => error.message(),
            Self::PolicyMismatch(error) => error.message(),
            Self::OutputInvalid(error) => error.message(),
            Self::RepairRefused(error) => error.message(),
            Self::PlanSourceMismatch(error) => error.message(),
        }
    }

    /// Python: `err.code`.
    pub fn code(&self) -> &str {
        match self {
            Self::Generic { code, .. } => code,
            Self::PlanTampered(error) => error.code(),
            Self::Abstained(error) => error.code(),
            Self::PolicyMismatch(error) => error.code(),
            Self::OutputInvalid(error) => error.code(),
            Self::RepairRefused(error) => error.code(),
            Self::PlanSourceMismatch(error) => error.code(),
        }
    }

    /// Python: `VendorProjectionRefused.reason`.
    ///
    /// `Some("")` is the default reason. `None` means this class has no
    /// `reason` attribute.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::RepairRefused(error) => error.reason(),
            Self::Generic { .. }
            | Self::PlanTampered(_)
            | Self::Abstained(_)
            | Self::PolicyMismatch(_)
            | Self::OutputInvalid(_)
            | Self::PlanSourceMismatch(_) => None,
        }
    }

    fn matches_hierarchy(&self) -> bool {
        matches!(
            self,
            Self::Generic { .. }
                | Self::PlanTampered(_)
                | Self::Abstained(_)
                | Self::PolicyMismatch(_)
                | Self::OutputInvalid(_)
                | Self::RepairRefused(_)
                | Self::PlanSourceMismatch(_)
        )
    }
}

impl fmt::Display for RepairError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for RepairError {}

/// Raised when recomputed plan fingerprint does not match declared plan fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanTampered {
    inner: CodedMessage,
}

impl PlanTampered {
    /// Python class attribute `PlanTampered.code`.
    pub const DEFAULT_CODE: &'static str = "PLAN_TAMPERED";

    /// Python: `PlanTampered(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python: `PlanTampered(message, code=code)`.
    ///
    /// Display stays `message`.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Python: `err.code`.
    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for PlanTampered {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for PlanTampered {}

/// Raised when repair execution must abstain due to SL203 or side-effects.
///
/// Code stays `ABSTAINED`. Constructing this error is a refusal. This module
/// does not turn an abstention into a repaired plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abstained {
    inner: CodedMessage,
}

impl Abstained {
    /// Python class attribute `Abstained.code`.
    pub const DEFAULT_CODE: &'static str = "ABSTAINED";

    /// Python: `Abstained(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python: `Abstained(message, code=code)`.
    ///
    /// Display stays `message`. The default code stays available as
    /// [`Self::DEFAULT_CODE`] and is not replaced by a detector code.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Python: `err.code`.
    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for Abstained {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for Abstained {}

/// Raised when plan policy does not match the execution policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMismatch {
    inner: CodedMessage,
}

impl PolicyMismatch {
    /// Python class attribute `PolicyMismatch.code`.
    pub const DEFAULT_CODE: &'static str = "POLICY_MISMATCH";

    /// Python: `PolicyMismatch(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python: `PolicyMismatch(message, code=code)`.
    ///
    /// Display stays `message`.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Python: `err.code`.
    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for PolicyMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for PolicyMismatch {}

/// Raised when repaired output fails schema, multiset, revalidation, or cap checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputInvalid {
    inner: CodedMessage,
}

impl OutputInvalid {
    /// Python class attribute `OutputInvalid.code`.
    pub const DEFAULT_CODE: &'static str = "OUTPUT_INVALID";

    /// Python: `OutputInvalid(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python: `OutputInvalid(message, code=code)`.
    ///
    /// Display stays `message`.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Python: `err.code`.
    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for OutputInvalid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for OutputInvalid {}

/// Raised when repair is refused due to invalid destination, live-store, etc.
///
/// Python: `RepairRefused(RepairError)` with code `REPAIR_REFUSED`.
/// `VendorRepairRefused`, `ManifestCollision`, and `VendorProjectionRefused`
/// are subclasses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairRefused {
    /// A `RepairRefused` instance that is not a subclass.
    Generic { message: String, code: String },
    /// `VendorRepairRefused`.
    VendorRepairRefused(VendorRepairRefused),
    /// `ManifestCollision`.
    ManifestCollision(ManifestCollision),
    /// `VendorProjectionRefused`.
    VendorProjectionRefused(VendorProjectionRefused),
}

impl RepairRefused {
    /// Python class attribute `RepairRefused.code`.
    pub const DEFAULT_CODE: &'static str = "REPAIR_REFUSED";

    /// Python: `RepairRefused(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python: `RepairRefused(message, code=code)`.
    ///
    /// Display stays `message`.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self::Generic {
            message: message.into(),
            code: code.into(),
        }
    }

    /// Python: `isinstance(err, SesslintError)`.
    pub fn is_sesslint_error(&self) -> bool {
        self.matches_hierarchy() && model::errors::SesslintError::DEFAULT_CODE == "ERROR"
    }

    /// Python: `isinstance(err, ValueError)`.
    pub fn is_value_error(&self) -> bool {
        self.matches_hierarchy()
    }

    /// Python: `isinstance(err, VendorRepairRefused)`.
    pub fn is_vendor_repair_refused(&self) -> bool {
        matches!(self, Self::VendorRepairRefused(_))
    }

    /// Python: `isinstance(err, ManifestCollision)`.
    pub fn is_manifest_collision(&self) -> bool {
        matches!(self, Self::ManifestCollision(_))
    }

    /// Python: `isinstance(err, VendorProjectionRefused)`.
    pub fn is_vendor_projection_refused(&self) -> bool {
        matches!(self, Self::VendorProjectionRefused(_))
    }

    /// Most-specific Python class.
    pub fn kind(&self) -> RepairKind {
        match self {
            Self::Generic { .. } => RepairKind::RepairRefused,
            Self::VendorRepairRefused(_) => RepairKind::VendorRepairRefused,
            Self::ManifestCollision(_) => RepairKind::ManifestCollision,
            Self::VendorProjectionRefused(_) => RepairKind::VendorProjectionRefused,
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        match self {
            Self::Generic { message, .. } => message,
            Self::VendorRepairRefused(error) => error.message(),
            Self::ManifestCollision(error) => error.message(),
            Self::VendorProjectionRefused(error) => error.message(),
        }
    }

    /// Python: `err.code`.
    pub fn code(&self) -> &str {
        match self {
            Self::Generic { code, .. } => code,
            Self::VendorRepairRefused(error) => error.code(),
            Self::ManifestCollision(error) => error.code(),
            Self::VendorProjectionRefused(error) => error.code(),
        }
    }

    /// Python: `VendorProjectionRefused.reason`.
    ///
    /// `Some("")` is the default reason. `None` means this class has no
    /// `reason` attribute.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::VendorProjectionRefused(error) => Some(error.reason()),
            Self::Generic { .. } | Self::VendorRepairRefused(_) | Self::ManifestCollision(_) => {
                None
            }
        }
    }

    fn matches_hierarchy(&self) -> bool {
        matches!(
            self,
            Self::Generic { .. }
                | Self::VendorRepairRefused(_)
                | Self::ManifestCollision(_)
                | Self::VendorProjectionRefused(_)
        )
    }
}

impl fmt::Display for RepairRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for RepairRefused {}

/// Raised when repair targets a vendor (non-canonical) format, explicitly or detected.
///
/// Repair operates exclusively on canonical session streams. Callers map this
/// refusal to the usage-error exit path (CLI exit 2), distinct from generic
/// repair refusals.
///
/// Python: `VendorRepairRefused(RepairRefused)` with code `VENDOR_FORMAT_REFUSED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorRepairRefused {
    inner: CodedMessage,
}

impl VendorRepairRefused {
    /// Python class attribute `VendorRepairRefused.code`.
    pub const DEFAULT_CODE: &'static str = "VENDOR_FORMAT_REFUSED";

    /// Python: `VendorRepairRefused(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python: `VendorRepairRefused(message, code=code)`.
    ///
    /// Display stays `message`. The value remains a `VendorRepairRefused`.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Python: `err.code`.
    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for VendorRepairRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for VendorRepairRefused {}

/// Raised when destination repair manifest already exists (refusing to overwrite receipt).
///
/// Python: `ManifestCollision(RepairRefused)` with code `MANIFEST_COLLISION`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestCollision {
    inner: CodedMessage,
}

impl ManifestCollision {
    /// Python class attribute `ManifestCollision.code`.
    pub const DEFAULT_CODE: &'static str = "MANIFEST_COLLISION";

    /// Python: `ManifestCollision(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python: `ManifestCollision(message, code=code)`.
    ///
    /// Display stays `message`.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Python: `err.code`.
    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for ManifestCollision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for ManifestCollision {}

/// Raised when a vendor write-back projection cannot be proven safe.
///
/// Carries a machine-readable `reason` tag (R1-R6) identifying which
/// fail-closed condition fired. See `sesslint.repair.writeback`.
///
/// Python: `VendorProjectionRefused(message, reason="")`. Display is
/// `message` only. `reason` is not interpolated. The code is always
/// `VENDOR_PROJECTION_REFUSED`; this constructor does not take a code override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorProjectionRefused {
    message: String,
    reason: String,
}

impl VendorProjectionRefused {
    /// Python class attribute `VendorProjectionRefused.code`.
    pub const DEFAULT_CODE: &'static str = "VENDOR_PROJECTION_REFUSED";

    /// Python: `VendorProjectionRefused(message)` (`reason=""`).
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_reason(message, "")
    }

    /// Python: `VendorProjectionRefused(message, reason=reason)`.
    ///
    /// Display stays `message`. An empty `reason` is `""`, not absence.
    pub fn with_reason(message: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            reason: reason.into(),
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Python: `err.code`. Always `VENDOR_PROJECTION_REFUSED`.
    pub fn code(&self) -> &'static str {
        Self::DEFAULT_CODE
    }

    /// Python: `err.reason`.
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl fmt::Display for VendorProjectionRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for VendorProjectionRefused {}

/// Raised when plan.source_hash does not match the source file bytes SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSourceMismatch {
    inner: CodedMessage,
}

impl PlanSourceMismatch {
    /// Python class attribute `PlanSourceMismatch.code`.
    pub const DEFAULT_CODE: &'static str = "PLAN_SOURCE_MISMATCH";

    /// Python: `PlanSourceMismatch(message)`.
    pub fn new(message: impl Into<String>) -> Self {
        Self::with_code(message, Self::DEFAULT_CODE)
    }

    /// Python: `PlanSourceMismatch(message, code=code)`.
    ///
    /// Display stays `message`.
    pub fn with_code(message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            inner: CodedMessage::new(message, code),
        }
    }

    /// Exception message. This is the Display text.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// Python: `err.code`.
    pub fn code(&self) -> &str {
        self.inner.code()
    }
}

impl fmt::Display for PlanSourceMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl Error for PlanSourceMismatch {}

impl From<PlanTampered> for RepairError {
    fn from(value: PlanTampered) -> Self {
        Self::PlanTampered(value)
    }
}

impl From<Abstained> for RepairError {
    fn from(value: Abstained) -> Self {
        Self::Abstained(value)
    }
}

impl From<PolicyMismatch> for RepairError {
    fn from(value: PolicyMismatch) -> Self {
        Self::PolicyMismatch(value)
    }
}

impl From<OutputInvalid> for RepairError {
    fn from(value: OutputInvalid) -> Self {
        Self::OutputInvalid(value)
    }
}

impl From<RepairRefused> for RepairError {
    fn from(value: RepairRefused) -> Self {
        Self::RepairRefused(value)
    }
}

impl From<PlanSourceMismatch> for RepairError {
    fn from(value: PlanSourceMismatch) -> Self {
        Self::PlanSourceMismatch(value)
    }
}

impl From<VendorRepairRefused> for RepairRefused {
    fn from(value: VendorRepairRefused) -> Self {
        Self::VendorRepairRefused(value)
    }
}

impl From<ManifestCollision> for RepairRefused {
    fn from(value: ManifestCollision) -> Self {
        Self::ManifestCollision(value)
    }
}

impl From<VendorProjectionRefused> for RepairRefused {
    fn from(value: VendorProjectionRefused) -> Self {
        Self::VendorProjectionRefused(value)
    }
}

impl From<VendorRepairRefused> for RepairError {
    fn from(value: VendorRepairRefused) -> Self {
        Self::from(RepairRefused::from(value))
    }
}

impl From<ManifestCollision> for RepairError {
    fn from(value: ManifestCollision) -> Self {
        Self::from(RepairRefused::from(value))
    }
}

impl From<VendorProjectionRefused> for RepairError {
    fn from(value: VendorProjectionRefused) -> Self {
        Self::from(RepairRefused::from(value))
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

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::errors::{
        Abstained, ManifestCollision, OutputInvalid, PlanSourceMismatch, PlanTampered,
        PolicyMismatch, RepairError, RepairKind, RepairRefused, VendorProjectionRefused,
        VendorRepairRefused, ALL,
    };

    #[test]
    fn constructs_repair_error_with_default_code() {
        let error = RepairError::new("synthetic-repair-error");
        assert_eq!(error.to_string(), "synthetic-repair-error");
        assert_eq!(error.message(), "synthetic-repair-error");
        assert_eq!(error.code(), "REPAIR_ERROR");
        assert_eq!(error.kind(), RepairKind::Repair);
        assert!(error.is_sesslint_error());
        assert!(error.is_value_error());
        assert!(!error.is_repair_refused());
        assert!(!error.is_abstained());
        assert_eq!(error.reason(), None);
        assert!(error.source().is_none());
        assert!(!error.to_string().contains("REPAIR_ERROR"));
    }

    #[test]
    fn hierarchy_type_is_not_the_scaffold_repair_error() {
        let hierarchy = RepairError::new("synthetic-repair-error");
        let scaffold = crate::RepairError::Unsupported;
        assert_eq!(hierarchy.to_string(), "synthetic-repair-error");
        assert_eq!(hierarchy.code(), "REPAIR_ERROR");
        assert_eq!(scaffold.to_string(), "repair error");
    }

    #[test]
    fn each_class_keeps_pin_code_and_message_display() {
        let errors = [
            RepairError::new("synthetic-repair-error"),
            RepairError::from(PlanTampered::new("synthetic-plan-tampered")),
            RepairError::from(Abstained::new("synthetic-abstained")),
            RepairError::from(PolicyMismatch::new("synthetic-policy-mismatch")),
            RepairError::from(OutputInvalid::new("synthetic-output-invalid")),
            RepairError::from(RepairRefused::new("synthetic-repair-refused")),
            RepairError::from(VendorRepairRefused::new("synthetic-vendor-repair-refused")),
            RepairError::from(ManifestCollision::new("synthetic-manifest-collision")),
            RepairError::from(VendorProjectionRefused::new(
                "synthetic-vendor-projection-refused",
            )),
            RepairError::from(PlanSourceMismatch::new("synthetic-plan-source-mismatch")),
        ];
        let kinds = errors.clone().map(|error| error.kind());
        let messages = errors.clone().map(|error| error.to_string());
        let codes = errors.clone().map(|error| error.code().to_owned());

        assert_eq!(
            kinds,
            [
                RepairKind::Repair,
                RepairKind::PlanTampered,
                RepairKind::Abstained,
                RepairKind::PolicyMismatch,
                RepairKind::OutputInvalid,
                RepairKind::RepairRefused,
                RepairKind::VendorRepairRefused,
                RepairKind::ManifestCollision,
                RepairKind::VendorProjectionRefused,
                RepairKind::PlanSourceMismatch,
            ]
        );
        assert_eq!(
            messages,
            [
                "synthetic-repair-error".to_owned(),
                "synthetic-plan-tampered".to_owned(),
                "synthetic-abstained".to_owned(),
                "synthetic-policy-mismatch".to_owned(),
                "synthetic-output-invalid".to_owned(),
                "synthetic-repair-refused".to_owned(),
                "synthetic-vendor-repair-refused".to_owned(),
                "synthetic-manifest-collision".to_owned(),
                "synthetic-vendor-projection-refused".to_owned(),
                "synthetic-plan-source-mismatch".to_owned(),
            ]
        );
        assert_eq!(
            codes,
            [
                "REPAIR_ERROR".to_owned(),
                "PLAN_TAMPERED".to_owned(),
                "ABSTAINED".to_owned(),
                "POLICY_MISMATCH".to_owned(),
                "OUTPUT_INVALID".to_owned(),
                "REPAIR_REFUSED".to_owned(),
                "VENDOR_FORMAT_REFUSED".to_owned(),
                "MANIFEST_COLLISION".to_owned(),
                "VENDOR_PROJECTION_REFUSED".to_owned(),
                "PLAN_SOURCE_MISMATCH".to_owned(),
            ]
        );
        for error in &errors {
            assert!(error.is_sesslint_error());
            assert!(error.is_value_error());
            assert!(error.source().is_none());
            assert_eq!(error.to_string(), error.message());
        }
    }

    #[test]
    fn kind_order_follows_class_declaration_not_name_order() {
        assert!(RepairKind::Repair < RepairKind::PlanTampered);
        assert!(RepairKind::PlanTampered < RepairKind::Abstained);
        assert!(RepairKind::Abstained < RepairKind::PolicyMismatch);
        assert!(RepairKind::VendorRepairRefused < RepairKind::ManifestCollision);
        assert!(RepairKind::ManifestCollision < RepairKind::VendorProjectionRefused);
        assert!(RepairKind::VendorProjectionRefused < RepairKind::PlanSourceMismatch);
    }

    #[test]
    fn abstained_stays_fail_closed() {
        let error = Abstained::new("synthetic abstain SL203");
        assert_eq!(error.to_string(), "synthetic abstain SL203");
        assert_eq!(error.code(), "ABSTAINED");
        assert_eq!(Abstained::DEFAULT_CODE, "ABSTAINED");
        let as_repair = RepairError::from(error);
        assert!(as_repair.is_abstained());
        assert!(!as_repair.is_repair_refused());
        assert_eq!(as_repair.kind(), RepairKind::Abstained);
        assert!(as_repair.is_sesslint_error());
        assert!(as_repair.is_value_error());
        let outcome: Result<(), RepairError> = Err(as_repair);
        assert_eq!(
            outcome.as_ref().err().map(ToString::to_string),
            Some("synthetic abstain SL203".to_owned())
        );
    }

    #[test]
    fn empty_message_display_stays_empty() {
        let error = RepairError::new("");
        assert_eq!(error.to_string(), "");
        assert_eq!(error.code(), "REPAIR_ERROR");
        let abstained = Abstained::new("");
        assert_eq!(abstained.to_string(), "");
        assert_eq!(abstained.code(), "ABSTAINED");
    }

    #[test]
    fn code_override_keeps_display_and_kind() {
        let cases = [
            (
                RepairError::with_code("synthetic-repair-error", "CUSTOM"),
                RepairKind::Repair,
            ),
            (
                RepairError::from(PlanTampered::with_code("synthetic-plan-tampered", "CUSTOM")),
                RepairKind::PlanTampered,
            ),
            (
                RepairError::from(Abstained::with_code("synthetic-abstained", "CUSTOM")),
                RepairKind::Abstained,
            ),
            (
                RepairError::from(PolicyMismatch::with_code(
                    "synthetic-policy-mismatch",
                    "CUSTOM",
                )),
                RepairKind::PolicyMismatch,
            ),
            (
                RepairError::from(OutputInvalid::with_code(
                    "synthetic-output-invalid",
                    "CUSTOM",
                )),
                RepairKind::OutputInvalid,
            ),
            (
                RepairError::from(RepairRefused::with_code(
                    "synthetic-repair-refused",
                    "CUSTOM",
                )),
                RepairKind::RepairRefused,
            ),
            (
                RepairError::from(VendorRepairRefused::with_code(
                    "synthetic-vendor-repair-refused",
                    "CUSTOM",
                )),
                RepairKind::VendorRepairRefused,
            ),
            (
                RepairError::from(ManifestCollision::with_code(
                    "synthetic-manifest-collision",
                    "CUSTOM",
                )),
                RepairKind::ManifestCollision,
            ),
            (
                RepairError::from(PlanSourceMismatch::with_code(
                    "synthetic-plan-source-mismatch",
                    "CUSTOM",
                )),
                RepairKind::PlanSourceMismatch,
            ),
        ];
        for (error, kind) in cases {
            assert_eq!(error.code(), "CUSTOM");
            assert_eq!(error.kind(), kind);
            assert!(!error.to_string().contains("CUSTOM"));
            assert!(error.is_value_error());
            assert!(error.is_sesslint_error());
        }
    }

    #[test]
    fn repair_refused_subclasses_keep_their_classes() {
        let vendor = VendorRepairRefused::new("synthetic-vendor-repair-refused");
        assert_eq!(vendor.to_string(), "synthetic-vendor-repair-refused");
        assert_eq!(vendor.code(), "VENDOR_FORMAT_REFUSED");
        let vendor_refused = RepairRefused::from(vendor);
        assert!(vendor_refused.is_vendor_repair_refused());
        assert!(!vendor_refused.is_manifest_collision());
        assert!(!vendor_refused.is_vendor_projection_refused());
        assert!(vendor_refused.is_value_error());
        assert!(vendor_refused.is_sesslint_error());
        assert_eq!(vendor_refused.reason(), None);
        let vendor_repair = RepairError::from(vendor_refused);
        assert!(vendor_repair.is_repair_refused());
        assert!(vendor_repair.is_vendor_repair_refused());
        assert!(!vendor_repair.is_manifest_collision());
        assert_eq!(vendor_repair.kind(), RepairKind::VendorRepairRefused);
        assert_eq!(vendor_repair.to_string(), "synthetic-vendor-repair-refused");

        let collision = ManifestCollision::new("synthetic-manifest-collision");
        assert_eq!(collision.code(), "MANIFEST_COLLISION");
        let collision_repair = RepairError::from(collision);
        assert!(collision_repair.is_repair_refused());
        assert!(collision_repair.is_manifest_collision());
        assert!(!collision_repair.is_vendor_repair_refused());
        assert!(!collision_repair.is_vendor_projection_refused());
        assert_eq!(collision_repair.reason(), None);
        assert_eq!(collision_repair.to_string(), "synthetic-manifest-collision");

        let generic = RepairRefused::new("synthetic-repair-refused");
        assert!(!generic.is_vendor_repair_refused());
        assert!(!generic.is_manifest_collision());
        assert!(!generic.is_vendor_projection_refused());
        assert_eq!(generic.reason(), None);
        let generic_repair = RepairError::from(generic);
        assert!(generic_repair.is_repair_refused());
        assert!(!generic_repair.is_vendor_repair_refused());
        assert_eq!(generic_repair.kind(), RepairKind::RepairRefused);
    }

    #[test]
    fn vendor_projection_refused_keeps_reason_off_display() {
        let defaulted = VendorProjectionRefused::new("synthetic-vendor-projection-refused");
        assert_eq!(defaulted.reason(), "");
        assert_eq!(defaulted.code(), "VENDOR_PROJECTION_REFUSED");
        assert_eq!(defaulted.to_string(), "synthetic-vendor-projection-refused");
        assert_eq!(
            defaulted,
            VendorProjectionRefused::with_reason("synthetic-vendor-projection-refused", "")
        );

        let tagged =
            VendorProjectionRefused::with_reason("synthetic-vendor-projection-refused", "R1");
        assert_eq!(tagged.reason(), "R1");
        assert_eq!(tagged.code(), "VENDOR_PROJECTION_REFUSED");
        assert_eq!(tagged.to_string(), "synthetic-vendor-projection-refused");
        assert!(!tagged.to_string().contains("R1"));
        assert!(!tagged.to_string().contains("VENDOR_PROJECTION_REFUSED"));
        assert!(tagged.source().is_none());

        let refused = RepairRefused::from(tagged);
        assert!(refused.is_vendor_projection_refused());
        assert!(!refused.is_vendor_repair_refused());
        assert!(!refused.is_manifest_collision());
        assert_eq!(refused.reason(), Some("R1"));
        assert_eq!(refused.to_string(), "synthetic-vendor-projection-refused");
        assert_eq!(refused.code(), "VENDOR_PROJECTION_REFUSED");
        assert!(refused.is_sesslint_error());
        assert!(refused.is_value_error());

        let repair = RepairError::from(refused);
        assert!(repair.is_repair_refused());
        assert!(repair.is_vendor_projection_refused());
        assert!(!repair.is_manifest_collision());
        assert_eq!(repair.kind(), RepairKind::VendorProjectionRefused);
        assert_eq!(repair.reason(), Some("R1"));
        assert_eq!(repair.code(), "VENDOR_PROJECTION_REFUSED");
        assert_eq!(repair.to_string(), "synthetic-vendor-projection-refused");
        assert!(!repair.to_string().contains("R1"));

        let empty_reason = RepairError::from(VendorProjectionRefused::new(
            "synthetic-vendor-projection-refused",
        ));
        assert_eq!(empty_reason.reason(), Some(""));
        assert_ne!(
            RepairError::new("synthetic-repair-error").reason(),
            Some("")
        );
    }

    #[test]
    fn sibling_classes_are_not_repair_refusals() {
        let plan = RepairError::from(PlanTampered::new("synthetic-plan-tampered"));
        assert!(plan.is_plan_tampered());
        assert!(!plan.is_repair_refused());
        assert!(!plan.is_policy_mismatch());
        assert!(!plan.is_output_invalid());
        assert!(!plan.is_plan_source_mismatch());
        assert_eq!(plan.reason(), None);
        assert_eq!(plan.to_string(), "synthetic-plan-tampered");
        assert_eq!(plan.code(), "PLAN_TAMPERED");

        let policy = RepairError::from(PolicyMismatch::new("synthetic-policy-mismatch"));
        assert!(policy.is_policy_mismatch());
        assert!(!policy.is_plan_tampered());
        assert_eq!(policy.code(), "POLICY_MISMATCH");
        assert_eq!(policy.to_string(), "synthetic-policy-mismatch");

        let output = RepairError::from(OutputInvalid::new("synthetic-output-invalid"));
        assert!(output.is_output_invalid());
        assert!(!output.is_plan_source_mismatch());
        assert_eq!(output.code(), "OUTPUT_INVALID");
        assert_eq!(output.to_string(), "synthetic-output-invalid");

        let source = RepairError::from(PlanSourceMismatch::new("synthetic-plan-source-mismatch"));
        assert!(source.is_plan_source_mismatch());
        assert!(!source.is_plan_tampered());
        assert!(!source.is_repair_refused());
        assert_eq!(source.code(), "PLAN_SOURCE_MISMATCH");
        assert_eq!(source.to_string(), "synthetic-plan-source-mismatch");
    }

    #[test]
    fn all_exports_match_python_order() {
        assert_eq!(
            ALL,
            [
                "Abstained",
                "ManifestCollision",
                "OutputInvalid",
                "PlanSourceMismatch",
                "PlanTampered",
                "PolicyMismatch",
                "RepairError",
                "RepairRefused",
                "VendorProjectionRefused",
                "VendorRepairRefused",
            ]
        );
    }
}
