//! Empty scaffold for the `outcome` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::OutcomeError;

pub mod contract {}
pub mod snapshot {}
pub mod engine {}
pub mod report {}
