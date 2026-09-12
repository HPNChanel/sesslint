"""Safe value formatting and bounded discriminator echo for adapter findings (DEV-008, FR-081).

Provides centralized helpers for formatting finding evidence without leaking sensitive
field values or unconstrained hostile type strings into diagnostic reports.
"""

from __future__ import annotations

import re
from typing import Any, Final

from sesslint.errors import FindingError
from sesslint.finding import enforce_content_free_text

# Allowlist: 1 to 64 chars of alphanumeric, underscore, dot, hyphen
_DISCRIMINATOR_ALLOWLIST: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# Delimiter-bounded or prefix patterns for API keys and secrets that match the allowlist charset
_SENSITIVE_DISCRIMINATOR_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?i)"
    r"(?:^|[_\-.])"
    r"(?:"
    r"(?:sk|rk)[_\-]"  # OpenAI / Stripe secret or restricted key
    r"|gh[pousr]_[A-Za-z0-9]"  # GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_
    r"|glpat-[A-Za-z0-9]"  # GitLab personal access token
    r"|(?:akia|asia)[0-9a-z]{16}"  # AWS Access Key ID (permanent or temporary session)
    r"|aiza[0-9a-z_\-]{20,}"  # Google API key
    r"|xox[baprs]-[0-9a-z]"  # Slack tokens: xoxb-, xoxp-, xapp-, xoxa-, xoxr-
    r"|slack[_\-]token[_\-]"  # Generic slack token marker
    r"|bearer[_\-]"  # Bearer token indicator
    r")"
)
_CREDENTIAL_PREFIXES: Final[tuple[str, ...]] = (
    "sk-",
    "sk_",
    "rk-",
    "rk_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "akia",
    "asia",
    "aiza",
    "xoxb-",
    "xoxp-",
    "xapp-",
    "xoxa-",
    "xoxr-",
    "slack_token_",
    "bearer-",
    "bearer_",
)


def safe_type_value(val: Any) -> str:
    """Return safe type and size descriptor without leaking field content (FR-081, FR-082)."""
    t_name = type(val).__name__
    if isinstance(val, (str, bytes, list, dict, set, tuple)):
        return f"<{t_name}:len={len(val)}>"
    return f"<{t_name}>"


def safe_discriminator(val: Any) -> tuple[str, bool]:
    """Echo discriminator verbatim if allowlisted and content-free, else safe shape.

    Rule: Echo verbatim ONLY if ^[A-Za-z0-9_.-]{1,64}$ and free of sensitive patterns.
    Otherwise return (safe_type_value(val), True).

    Returns:
        tuple[str, bool]: (type_value, is_truncated)
    """
    if isinstance(val, str) and _DISCRIMINATOR_ALLOWLIST.fullmatch(val):
        try:
            enforce_content_free_text(val, context="safe_discriminator")
        except FindingError:
            return (safe_type_value(val), True)
        lower_val = val.lower()
        if any(lower_val.startswith(p) for p in _CREDENTIAL_PREFIXES) or bool(
            _SENSITIVE_DISCRIMINATOR_PATTERN.search(val)
        ):
            return (safe_type_value(val), True)
        return (val, False)
    return (safe_type_value(val), True)


__all__ = [
    "safe_discriminator",
    "safe_type_value",
]
