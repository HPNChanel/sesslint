"""Shared secret-shape registry for detection and adapter minimization (B14).

Detectors require complete token shapes. Adapter minimization additionally
rejects suspicious partial prefixes, so truncation cannot reveal a credential.
"""

from __future__ import annotations

import re
from typing import Final

_TOKEN_BOUNDARY: Final[bytes] = rb"(?<![A-Za-z0-9_-])"
SECRET_FAMILIES: Final[tuple[tuple[str, re.Pattern[bytes], int], ...]] = (
    (
        "anthropic-api-key",
        re.compile(_TOKEN_BOUNDARY + rb"sk-ant-[A-Za-z0-9_-]{20,}"),
        0,
    ),
    (
        "openai-api-key",
        re.compile(_TOKEN_BOUNDARY + rb"sk-[A-Za-z0-9]{20,}"),
        0,
    ),
    (
        "openrouter-api-key",
        re.compile(_TOKEN_BOUNDARY + rb"sk-or-v1-[0-9a-f]{48,}"),
        0,
    ),
    (
        "github-pat-classic",
        re.compile(_TOKEN_BOUNDARY + rb"ghp_[A-Za-z0-9]{36,}"),
        0,
    ),
    (
        "github-pat-fine-grained",
        re.compile(_TOKEN_BOUNDARY + rb"github_pat_[A-Za-z0-9_]{22,}"),
        0,
    ),
    (
        "github-oauth-token",
        re.compile(_TOKEN_BOUNDARY + rb"gh[osru]_[A-Za-z0-9]{36,}"),
        0,
    ),
    (
        "stripe-webhook-secret",
        re.compile(_TOKEN_BOUNDARY + rb"whsec_[A-Za-z0-9]{24,}"),
        0,
    ),
    (
        "stripe-key",
        re.compile(_TOKEN_BOUNDARY + rb"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
        0,
    ),
    (
        "aws-access-key",
        re.compile(_TOKEN_BOUNDARY + rb"(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        0,
    ),
    (
        "google-api-key",
        re.compile(_TOKEN_BOUNDARY + rb"AIza[A-Za-z0-9_-]{20,}"),
        0,
    ),
    (
        "slack-token",
        re.compile(_TOKEN_BOUNDARY + rb"xox[a-z]-[A-Za-z0-9-]{16,}"),
        0,
    ),
    (
        "gitlab-pat",
        re.compile(_TOKEN_BOUNDARY + rb"glpat-[A-Za-z0-9_-]{20,}"),
        0,
    ),
    (
        "bearer-token",
        re.compile(_TOKEN_BOUNDARY + rb"(?i:bearer)[ \t]+[A-Za-z0-9._~+/=\\-]{16,}"),
        0,
    ),
    (
        "npm-token",
        re.compile(_TOKEN_BOUNDARY + rb"npm_[A-Za-z0-9]{20,}"),
        0,
    ),
    (
        "huggingface-token",
        re.compile(_TOKEN_BOUNDARY + rb"hf_[A-Za-z0-9]{20,}"),
        0,
    ),
    (
        "supabase-pat",
        re.compile(_TOKEN_BOUNDARY + rb"sbp_[0-9a-f]{40,}"),
        0,
    ),
    (
        "telegram-bot-token",
        re.compile(_TOKEN_BOUNDARY + rb"\d{8,10}:[A-Za-z0-9_-]{35}\b"),
        0,
    ),
    (
        "jwt",
        re.compile(
            _TOKEN_BOUNDARY + rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ),
        0,
    ),
    (
        # The digest covers the header plus the first base64 fragment when
        # adjacent (JSON-escaped ``\n`` or real newline both count), so two
        # different keys hash differently while the marker alone still flags.
        "private-key-block",
        re.compile(
            _TOKEN_BOUNDARY
            + rb"-----BEGIN [A-Z ]*PRIVATE KEY-----((?:\\n|\s)+[A-Za-z0-9+/=_-]{8,})?"
        ),
        0,
    ),
    (
        # Keyword must end the key token (modulo quotes/dots) immediately
        # before ':' or '=' — so `token_count`, `token_endpoint`,
        # `secretary`, and `id_token_hint` never match, while
        # `aws_secret_access_key` (ends in access_key) does. Punctuation
        # between keyword and separator may be backslash-escaped (`\"` inside
        # JSON string payloads), as may the opening quote of the value; the
        # value group 1 stops at whitespace, quotes, commas, closing
        # brackets, and backslashes so a trailing `\"` is never captured.
        "generic-credential-assignment",
        re.compile(
            rb"(?:password|passwd|api[_-]?key|access[_-]?key|account[_-]?key|client[_-]?secret"
            rb"|private[_-]?key|auth[_-]?token|secret|token)(?:\\?[\"'.-])*\s*[:=]\s*"
            rb"(?:\\?[\"'`])?\s*([^\s\"'`,)\]}\\]{8,})",
            re.IGNORECASE,
        ),
        1,
    ),
)

FAMILY_LITERALS: Final[dict[str, tuple[bytes, ...]]] = {
    "anthropic-api-key": (b"sk-ant-",),
    "openai-api-key": (b"sk-",),
    "openrouter-api-key": (b"sk-or-v1-",),
    "github-pat-classic": (b"ghp_",),
    "github-pat-fine-grained": (b"github_pat_",),
    "github-oauth-token": (b"gho_", b"ghs_", b"ghr_", b"ghu_"),
    "stripe-webhook-secret": (b"whsec_",),
    "stripe-key": (b"sk_live_", b"sk_test_", b"rk_live_", b"rk_test_"),
    "aws-access-key": (b"AKIA", b"ASIA"),
    "google-api-key": (b"AIza",),
    "slack-token": (b"xox",),
    "gitlab-pat": (b"glpat-",),
    "bearer-token": (b"bearer",),
    "npm-token": (b"npm_",),
    "huggingface-token": (b"hf_",),
    "supabase-pat": (b"sbp_",),
    "jwt": (b"eyJ",),
    "private-key-block": (b"PRIVATE KEY-----",),
}
