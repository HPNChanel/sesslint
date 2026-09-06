"""Typed error hierarchy for SessLint."""

from __future__ import annotations


class SesslintError(Exception):
    """Base exception for all SessLint errors."""

    code: str = "ERROR"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class SchemaError(SesslintError):
    """Raised when an artifact violates canonical schema or structural constraints."""

    code: str = "SCHEMA"

    def __init__(self, message: str, *, code: str = "SCHEMA") -> None:
        super().__init__(message, code=code)


class VersionError(SchemaError):
    """Raised when an unsupported schema version is encountered (SL301 hook)."""

    code: str = "VERSION"
    reason_code: str = "SL301"

    def __init__(self, message: str, *, version: str | None = None) -> None:
        formatted = message if "SL301" in message else f"{message} (code: VERSION / SL301)"
        super().__init__(formatted, code="VERSION")
        self.version = version


class UnknownFieldError(SchemaError):
    """Raised when an unrecognized top-level field is encountered (SL302 hook)."""

    code: str = "UNKNOWN_FIELD"
    reason_code: str = "SL302"

    def __init__(self, message: str, *, field_name: str | None = None) -> None:
        formatted = message if "SL302" in message else f"{message} (code: UNKNOWN_FIELD / SL302)"
        super().__init__(formatted, code="UNKNOWN_FIELD")
        self.field_name = field_name


class FindingError(SesslintError, ValueError):
    """Raised when finding construction, validation, or contract enforcement fails."""

    code: str = "FINDING"

    def __init__(self, message: str, *, code: str = "FINDING") -> None:
        super().__init__(message, code=code)


class AssuranceError(SesslintError, ValueError):
    """Raised when assurance level validation or mandatory limitation constraint fails."""

    code: str = "ASSURANCE"

    def __init__(self, message: str, *, code: str = "ASSURANCE") -> None:
        super().__init__(message, code=code)


class ContentLeakError(SesslintError, ValueError):
    """Raised when forbidden content, credentials, or payload text leaks into artifacts."""

    code: str = "CONTENT_LEAK"

    def __init__(self, message: str, *, code: str = "CONTENT_LEAK") -> None:
        super().__init__(message, code=code)


class FileTooLargeError(SesslintError):
    """Raised when file or stream size exceeds configured byte limits."""

    code: str = "LIMIT_EXCEEDED"

    def __init__(self, message: str, *, code: str = "LIMIT_EXCEEDED") -> None:
        super().__init__(message, code=code)


class MaxRecordsExceededError(SesslintError):
    """Raised when record count exceeds configured limits."""

    code: str = "LIMIT_EXCEEDED"

    def __init__(self, message: str, *, code: str = "LIMIT_EXCEEDED") -> None:
        super().__init__(message, code=code)


class HeaderMissingError(SchemaError):
    """Raised when a required session header is absent, empty, or unreadable."""

    code: str = "HEADER_MISSING"

    def __init__(self, message: str, *, code: str = "HEADER_MISSING") -> None:
        super().__init__(message, code=code)


class SourceChangedError(SesslintError):
    """Raised when an input source file is modified concurrently during inspection or repair."""

    code: str = "SOURCE_CHANGED"

    def __init__(self, message: str, *, code: str = "SOURCE_CHANGED") -> None:
        super().__init__(message, code=code)


class AtomicWriteError(SesslintError, OSError):
    """Raised when an atomic write or replace operation fails, or an unsafe path is requested."""

    code: str = "ATOMIC_WRITE_ERROR"

    def __init__(self, message: str, *, code: str = "ATOMIC_WRITE_ERROR") -> None:
        super().__init__(message)
        self.code = code
