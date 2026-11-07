//! Empty scaffold for the `adapters` crate.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;

pub use error::AdaptersError;

pub mod links;
pub mod synthetic;
pub mod safe_value;
pub mod drift;
pub mod metadata;
pub mod canonical;
pub mod claude_code;
pub mod openai_agents;
pub mod codex_rollout;
pub mod detect;
pub mod load {}
pub mod source;
