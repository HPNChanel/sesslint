//! Empty scaffold for the `report` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::ReportError;

pub mod baseline;
pub mod progress;
pub mod report;
pub mod html_report;
pub mod sarif;
pub mod triage;
