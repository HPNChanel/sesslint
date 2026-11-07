//! Empty scaffold for the `evidence` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::EvidenceError;

pub mod stats {}
pub mod bundle {}
pub mod diff {}
pub mod doctor;
pub mod precheck;
pub mod seal {}
pub mod verify {}
pub mod exporter {}
pub mod preview;
