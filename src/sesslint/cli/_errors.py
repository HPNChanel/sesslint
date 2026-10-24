"""CLI error type carrying an exit code through the dispatch layer."""

from __future__ import annotations


class CliError(Exception):
    """A user-facing CLI failure: message printed to stderr, exit_code returned.

    Raised anywhere below ``main()`` — inside ``build_context`` or a command's
    ``run`` — and converted to ``print(stderr) + return exit_code`` by the
    dispatch layer.
    """

    def __init__(self, exit_code: int, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message
