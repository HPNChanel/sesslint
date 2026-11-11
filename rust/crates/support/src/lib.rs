//! Barrel for `src/sesslint/__init__.py` lines 1–263
//! @ `02694d537104659df66cdd084354739f3cccc440`.
//!
//! The pin re-exports implementation modules. This crate has no dependency
//! on those crates, so only the version constants copied from the pin are
//! values. Every other public name fails closed with [`SupportError::Unsupported`].

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::SupportError;

#[path = "schema/sesslint-config.schema.rs"]
pub mod config_schema;

/// Pinned `sesslint._version.CLI_VERSION`.
pub const CLI_VERSION: &str = "0.5.0";
/// Pinned `sesslint._version.MANIFEST_SCHEMA_VERSION`.
pub const MANIFEST_SCHEMA_VERSION: &str = "sesslint.repair-manifest/v1";
/// Pinned `sesslint._version.REPORT_SCHEMA_VERSION`.
pub const REPORT_SCHEMA_VERSION: &str = "sesslint.report/v1";
/// Pinned `sesslint._version.SESSION_SCHEMA_VERSION`.
pub const SESSION_SCHEMA_VERSION: &str = "sesslint.session/v1";
/// Pinned `sesslint.__version__`, which is `CLI_VERSION`.
pub const VERSION: &str = CLI_VERSION;

/// Pinned `__all__`, in source order.
pub const ALL: &[&str] = &[
    "CLI_VERSION",
    "MANIFEST_SCHEMA_VERSION",
    "REPORT_SCHEMA_VERSION",
    "SESSION_SCHEMA_VERSION",
    "__version__",
    "ALL_CODES",
    "AdapterError",
    "Assurance",
    "AssuranceError",
    "AtomicWriteError",
    "Bundle",
    "CanonicalEvent",
    "CheckContext",
    "Code",
    "CodeInfo",
    "ContentLeakError",
    "Counts",
    "DiscoveredRoot",
    "FileResult",
    "FileTooLargeError",
    "Finding",
    "FindingError",
    "HeaderMissingError",
    "MAX_IDENTITY_FINDINGS",
    "MaxRecordsExceededError",
    "OperationalError",
    "Policy",
    "PrecheckReason",
    "PrecheckResult",
    "ReaderLimits",
    "RepairAction",
    "RepairManifest",
    "Repairability",
    "Report",
    "ReproMetadata",
    "RevalidationSummary",
    "ScanReport",
    "ScanTotals",
    "SchemaError",
    "SesslintError",
    "Session",
    "SessionEvent",
    "SessionHeader",
    "Severity",
    "SourceChangedError",
    "SourceGuard",
    "SourceRef",
    "UnknownFieldError",
    "VersionError",
    "atomic_write_bytes",
    "atomic_write_text",
    "build_bundle",
    "build_manifest",
    "build_report",
    "build_repro_metadata",
    "canonical_bytes",
    "canonical_json_bytes",
    "check_dir",
    "check_file",
    "check_identities",
    "scan_path",
    "check_nesting_depth",
    "compute_content_hash",
    "compute_finding_fingerprint",
    "compute_fingerprint",
    "compute_manifest_idempotency_key",
    "discover_session_roots",
    "dump_manifest",
    "dump_report",
    "dump_session",
    "enforce_content_free",
    "enforce_content_free_text",
    "extract_record_id",
    "fingerprint_file",
    "fingerprint_finding",
    "get_bundle_schema_path",
    "get_code_info",
    "get_finding_schema_path",
    "get_manifest_schema_path",
    "get_plan_schema_path",
    "get_report_schema_path",
    "get_session_schema_path",
    "guard",
    "guarded",
    "guarded_iter_events",
    "is_valid_code",
    "iter_events",
    "load_bundle_schema",
    "load_finding_schema",
    "load_manifest_schema",
    "load_plan_schema",
    "load_report_schema",
    "load_session_file",
    "load_session_schema",
    "make_finding",
    "minimize_id",
    "minimize_path",
    "parse_finding_dict",
    "parse_manifest",
    "parse_report",
    "parse_session",
    "precheck",
    "read_header",
    "render_human",
    "render_json",
    "repeat_hash",
    "sort_findings",
    "stable_sort_findings",
    "to_canonical_dict",
    "to_canonical_json",
    "verify",
    "verify_source_guard",
];

/// Return a pinned version constant.
///
/// Any other name, including the rest of [`ALL`], is [`SupportError::Unsupported`].
pub fn require_symbol(name: &str) -> Result<&'static str, SupportError> {
    match name {
        "CLI_VERSION" | "__version__" => Ok(CLI_VERSION),
        "MANIFEST_SCHEMA_VERSION" => Ok(MANIFEST_SCHEMA_VERSION),
        "REPORT_SCHEMA_VERSION" => Ok(REPORT_SCHEMA_VERSION),
        "SESSION_SCHEMA_VERSION" => Ok(SESSION_SCHEMA_VERSION),
        _ => Err(SupportError::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        require_symbol, ALL, CLI_VERSION, MANIFEST_SCHEMA_VERSION, REPORT_SCHEMA_VERSION,
        SESSION_SCHEMA_VERSION, VERSION,
    };

    #[test]
    fn version_constants_match_the_pin() {
        assert_eq!(CLI_VERSION, "0.5.0");
        assert_eq!(VERSION, CLI_VERSION);
        assert_eq!(SESSION_SCHEMA_VERSION, "sesslint.session/v1");
        assert_eq!(REPORT_SCHEMA_VERSION, "sesslint.report/v1");
        assert_eq!(MANIFEST_SCHEMA_VERSION, "sesslint.repair-manifest/v1");
        assert_eq!(require_symbol("CLI_VERSION").unwrap(), CLI_VERSION);
        assert_eq!(require_symbol("__version__").unwrap(), VERSION);
        assert_eq!(
            require_symbol("MANIFEST_SCHEMA_VERSION").unwrap(),
            MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(
            require_symbol("REPORT_SCHEMA_VERSION").unwrap(),
            REPORT_SCHEMA_VERSION
        );
        assert_eq!(
            require_symbol("SESSION_SCHEMA_VERSION").unwrap(),
            SESSION_SCHEMA_VERSION
        );
    }

    #[test]
    fn other_public_names_fail_closed() {
        assert_eq!(ALL.len(), 112);
        assert_eq!(ALL[0], "CLI_VERSION");
        assert_eq!(ALL[111], "verify_source_guard");
        for name in ALL {
            let value = require_symbol(name);
            if matches!(
                *name,
                "CLI_VERSION"
                    | "__version__"
                    | "MANIFEST_SCHEMA_VERSION"
                    | "REPORT_SCHEMA_VERSION"
                    | "SESSION_SCHEMA_VERSION"
            ) {
                assert!(value.is_ok(), "{name}");
            } else {
                assert!(value.is_err(), "{name}");
            }
        }
        assert!(require_symbol("").is_err());
        assert!(require_symbol("not_a_symbol").is_err());
    }
}
