//! Empty scaffold for the `scan` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::ScanError;

pub mod atomic;
pub mod cache {}
pub mod discovery;
pub mod io {}
pub mod state_db {}
pub mod scan {}
pub mod batch {}
