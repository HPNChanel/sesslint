//! Empty scaffold for the `scan` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::ScanError;

pub mod atomic;
pub mod batch;
#[path = "schema/sesslint.batch-repair.v1.rs"]
pub mod batch_repair_schema;
pub mod cache;
pub mod discovery;
pub mod io;
pub mod scan;
#[path = "schema/sesslint.scan-report.v1.rs"]
pub mod scan_report_schema;
pub mod state_db;
