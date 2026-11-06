//! Empty scaffold for the `checks` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::ChecksError;

pub mod context {}
pub mod hygiene {}
pub mod indexes;
pub mod checkpoint {}
pub mod graph {}
pub mod accounting {}
pub mod compaction_snapshot {}
pub mod context_pressure {}
pub mod durable_prefix {}
pub mod foreign_shape {}
pub mod identity {}
pub mod ordering {}
pub mod size {}
pub mod tool_pairing_1 {}
pub mod tool_pairing_2 {}
pub mod writers {}
pub mod abstention {}
pub mod profile {}
pub mod config {}
pub mod builtin {}
pub mod assessment {}
pub mod runner {}
