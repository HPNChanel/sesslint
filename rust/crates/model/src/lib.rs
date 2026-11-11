//! Empty scaffold for the `model` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::ModelError;

pub mod canonical;
pub mod codes;
pub mod errors;
pub mod events;
pub mod finding;
#[path = "schema/sesslint.finding.v1.rs"]
pub mod finding_schema;
pub mod reference;
#[path = "schema/sesslint.repair-manifest.v1.rs"]
pub mod repair_manifest_schema;
#[path = "schema/sesslint.report.v1.rs"]
pub mod report_schema;
pub mod resources;
pub mod secret_families;
#[path = "schema/sesslint.session.v1.rs"]
pub mod session_schema;
pub mod version;
