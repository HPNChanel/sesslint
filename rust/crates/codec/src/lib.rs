//! Empty scaffold for the `codec` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::CodecError;

pub mod canonical_codec;
pub mod determinism;
