//! Empty scaffold for the `integrations` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::IntegrationsError;

pub mod hook_event;
pub mod hooks;
pub mod mcp_server {}
pub mod watch;

#[path = "schema/sesslint.hook-result.v1.rs"]
pub mod hook_result_schema;
