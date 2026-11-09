//! Empty scaffold for the `evidence` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::EvidenceError;

pub mod bundle;
#[path = "schema/sesslint.bundle.v1.rs"]
pub mod bundle_schema;
pub mod diff;
pub mod doctor;
pub mod exporter;
pub mod precheck;
pub mod preview;
pub mod seal;
#[path = "schema/sesslint.seal-ledger.v1.rs"]
pub mod seal_ledger_schema;
pub mod stats;
pub mod verify;
