//! Empty scaffold for the `cli` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::CliError;

pub mod context;
pub mod errors;
pub mod json_errors;
pub mod options;
pub mod output;
pub mod progress;
pub mod seal;
pub mod version;
pub mod api {}
pub mod common;
pub mod render;
pub mod scan_args;
pub mod check {}
pub mod triage {}
pub mod bundle {}
pub mod completion;
pub mod diff {}
pub mod doctor {}
pub mod export {}
pub mod hook;
pub mod mcp {}
pub mod outcome {}
pub mod repair {}
pub mod stats {}
pub mod verify {}
pub mod watch;
pub mod registry {}
pub mod main__ {}
