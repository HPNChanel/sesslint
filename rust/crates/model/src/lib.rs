//! Empty scaffold for the `model` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::ModelError;

pub mod resources {}
pub mod errors;
pub mod version;
pub mod codes {}
pub mod secret_families {}
pub mod finding {}
pub mod canonical {}
pub mod events {}
pub mod reference {}
