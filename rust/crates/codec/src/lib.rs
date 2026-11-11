//! Canonical codec, determinism, and the low-level session IO kernel.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::CodecError;

pub mod atomic;
pub mod canonical_codec;
pub mod determinism;
pub mod io_raw;
