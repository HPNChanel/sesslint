//! The `sesslint mcp` subcommand (RX-P4.5-cli-cli.mcp-01).
//!
//! Source: `src/sesslint/cli/mcp.py` at
//! `02694d537104659df66cdd084354739f3cccc440`, lines 1–25.
//! `configure` records the exact argparse declaration, like other CLI modules.
//! The late `sesslint.mcp_server.serve` dependency is not ported yet: `run`
//! returns a typed unavailable error before consulting stdin/stdout. No server
//! is started, no protocol response is fabricated, and no success is returned.

use std::error::Error;
use std::fmt;

pub const NAME: &str = "mcp";
pub const HELP: &str = "[read-only] Run a Model Context Protocol server over stdio.";
pub const DESCRIPTION: &str = concat!(
    "[read-only] MCP stdio server (protocol 2025-06-18, newline-",
    "delimited JSON-RPC): exposes sesslint_check / sesslint_precheck / ",
    "sesslint_scan tools so agents can call checks natively. ",
    "Long-running process — EOF or Ctrl+C exits cleanly."
);
pub const SERVE_UNAVAILABLE: &str = "sesslint.mcp_server.serve is not available";

/// Exact declaration made by Python `subparsers.add_parser`. There are no
/// aliases, custom arguments, shared options or parser defaults in this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McpSpec {
    pub name: &'static str,
    pub help: &'static str,
    pub description: &'static str,
}

#[must_use]
pub fn configure() -> McpSpec {
    McpSpec {
        name: NAME,
        help: HELP,
        description: DESCRIPTION,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServeUnavailable;

impl fmt::Display for ServeUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(SERVE_UNAVAILABLE)
    }
}

impl Error for ServeUnavailable {}

/// Python ignores `ctx`, `args` and `parser`. Its first action is the late import
/// of `serve`; fail here before acquiring stream buffers while that import is
/// unavailable. This seam must be replaced when the server module is integrated.
pub fn run() -> Result<i32, ServeUnavailable> {
    Err(ServeUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_preserves_pinned_protocol_and_tool_contract() {
        let spec = configure();
        assert_eq!(spec.name, "mcp");
        assert_eq!(
            spec.help,
            "[read-only] Run a Model Context Protocol server over stdio."
        );
        assert_eq!(
            spec.description,
            "[read-only] MCP stdio server (protocol 2025-06-18, newline-delimited JSON-RPC): exposes sesslint_check / sesslint_precheck / sesslint_scan tools so agents can call checks natively. Long-running process — EOF or Ctrl+C exits cleanly."
        );
        assert_eq!(spec.description.matches('—').count(), 1);
    }

    #[test]
    fn unported_server_never_returns_a_success_code() {
        let error = run().expect_err("unported serve cannot return success");
        assert_eq!(error, ServeUnavailable);
        assert_eq!(
            error.to_string(),
            "sesslint.mcp_server.serve is not available"
        );
        assert!(error.source().is_none());
    }
}
