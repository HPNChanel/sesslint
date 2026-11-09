//! Declarative outcome contracts and validation (CON-01, CON-02, CON-05, CON-07).
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::OutcomeError;

pub mod contract;
pub mod engine;
pub mod snapshot;
pub mod report {}
