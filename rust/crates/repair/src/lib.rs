//! Empty scaffold for the `repair` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::RepairError;

pub mod assurance;
pub mod fingerprint;
pub mod preconditions {}
pub mod refusals;
pub mod registry {}
pub mod recipes_sl002 {}
pub mod planner {}
pub mod errors;
pub mod recipes_conservative {}
pub mod recipes_salvage {}
pub mod vetting {}
pub mod writeback {}
pub mod executor {}
