"""Shared secret-family registry: SL009 detection and discriminator redaction (B14, B24).

Single source of truth for credential token shapes. Two consumers read it:

- ``sesslint.checks.hygiene`` (SL009, transcript-hygiene T-01) scans raw
  persisted record bytes with every family's exact ``pattern``;
- ``sesslint.adapters.safe_value`` (DEV-008, FR-081) refuses to echo a
  discriminator verbatim when any family matches it, or when it carries one
  of a family's ``echo_prefixes`` / delimiter-bounded ``echo_markers``.

Keeping both on one table is the B14 fix: a token shape the redaction layer
knows is never invisible to SL009, and a token SL009 flags is never echoed
verbatim into finding evidence.

Token boundary (B24): vendor-prefix families must start at a token boundary
— the preceding byte is not ``[A-Za-z0-9_-]`` — because the same prefix deep
inside a longer random blob is substring noise. Detection runs on *raw* JSON
bytes, where a string escape (``\\n``, ``\\t``, ``\\r``, ``\\b``, ``\\f``,
``\\uXXXX``) ends in a word character although the decoded text has a
separator there. :func:`token_boundary_ok` therefore also accepts a start
right after a *real* JSON escape: an odd-length backslash run followed by one
of ``bfnrt``, or a ``\\uXXXX`` escape whose code point is not itself a token
character. ``\\\\n`` (escaped backslash + literal ``n``) and ``\\u0041``
(``A``) stay mid-token, exactly like ``xghp_…``.

Pure, stdlib-only and deterministic. Every pattern is linear-time: no nested
quantifiers over overlapping classes, every unbounded run is followed by a
disjoint literal or class, and escape-quote runs are bounded (``\\{0,3}``).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Final

# Bump on every family addition/tightening so evidence stays self-describing.
# v3: B14 families (gitlab, google, slack, npm, hugging face, azure, gcp,
# bearer) plus JSON-escape-aware token boundaries (B24).
SECRET_FAMILY_SET_VERSION: Final[int] = 3

_TOKEN_CHARS: Final[frozenset[int]] = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)
_ESCAPE_LETTERS: Final[frozenset[int]] = frozenset(b"bfnrt")
_HEX_DIGITS: Final[frozenset[int]] = frozenset(b"0123456789abcdefABCDEF")
_BACKSLASH: Final[int] = 0x5C
_LOWER_U: Final[int] = 0x75

# Permissive regex half of the token boundary: a non-token byte, or the tail
# of something shaped like a JSON escape. ``token_boundary_ok`` arbitrates
# the escape shapes exactly (backslash parity, ``\\u`` code point).
TOKEN_BOUNDARY: Final[bytes] = rb"(?:(?<![A-Za-z0-9_-])|(?<=\\[bfnrt])|(?<=\\u[0-9A-Fa-f]{4}))"


def token_boundary_ok(data: bytes, start: int) -> bool:
    """Return True when a token starting at ``start`` begins at a token boundary.

    A boundary is the start of the buffer, a preceding non-token byte, or the
    end of a genuine JSON string escape (B24). Backslash-run counting is
    bounded by the run itself, so total work stays linear in ``data``.
    """
    if start <= 0 or data[start - 1] not in _TOKEN_CHARS:
        return True
    if data[start - 1] in _ESCAPE_LETTERS and start >= 2 and data[start - 2] == _BACKSLASH:
        escape_at = start - 2
    elif (
        start >= 6
        and data[start - 6] == _BACKSLASH
        and data[start - 5] == _LOWER_U
        and all(b in _HEX_DIGITS for b in data[start - 4 : start])
    ):
        if int(data[start - 4 : start], 16) in _TOKEN_CHARS:
            return False  # ``Aghp_…`` decodes to ``Aghp_…``: mid-token.
        escape_at = start - 6
    else:
        return False
    run = 0
    i = escape_at
    while i >= 0 and data[i] == _BACKSLASH:
        run += 1
        i -= 1
    return run % 2 == 1


# Assigned values that are documentation placeholders, not credentials.
# Uniform-character values (``xxxxxxxx``, ``********``) and wrapper forms
# (``<VAR>``, ``${VAR}``, ``{VAR}``) are excluded separately by shape.
_PLACEHOLDER_VALUES: Final[frozenset[bytes]] = frozenset(
    {
        b"redacted",
        b"example",
        b"placeholder",
        b"changeme",
        b"change-me",
        b"password",
        b"passwd",
        b"secret",
        b"token",
        b"none",
        b"null",
        b"true",
        b"false",
        b"undefined",
        b"unknown",
        b"tbd",
        b"n/a",
    }
)


def looks_like_placeholder(value: bytes) -> bool:
    """Best-effort exclusion of documentation placeholders in assignments.

    ``token: null`` / ``api_key = "xxxxxxxx"`` / ``password: ${VAR}`` are
    configuration *shapes*, not leaked credentials. Precision beats recall:
    when unsure, the value still counts as a hit.
    """
    v = value.lower().strip(b"\"'`")
    if len(v) < 8:
        return True
    if len(set(v)) <= 2:
        return True
    if v[:1] in (b"<", b"{", b"[") or v.startswith(b"${"):
        return True
    if v.startswith((b"your-", b"your_", b"your.")):
        return True
    return v in _PLACEHOLDER_VALUES


def _not_placeholder(value: bytes) -> bool:
    return not looks_like_placeholder(value)


_HAS_DIGIT: Final[re.Pattern[bytes]] = re.compile(rb"[0-9]")
_HAS_LETTER: Final[re.Pattern[bytes]] = re.compile(rb"[A-Za-z]")


def _bearer_value_ok(value: bytes) -> bool:
    """Opaque bearer credentials mix letters and digits; prose and
    ``REPLACE_WITH_ACCESS_TOKEN``-style placeholders do not."""
    if looks_like_placeholder(value):
        return False
    return _HAS_DIGIT.search(value) is not None and _HAS_LETTER.search(value) is not None


@dataclass(frozen=True, slots=True)
class SecretFamily:
    """One documented credential shape.

    ``pattern`` is the reference detector (boundary-prefixed, IGNORECASE when
    ``casefold``); ``scan_pattern`` is what runs — identical, or for
    ``casefold`` families the same source compiled case-sensitively and
    matched against ASCII-lowered bytes (T-10). ``anchors`` are literals every
    match necessarily contains (record prefilter); ``gate_literals`` and
    ``gate_pattern`` form the cheap window-gate superset. ``requires`` is a
    co-occurrence marker that must appear in the same record. ``value_check``
    vetoes non-credential values of the ``value_group`` span.
    """

    family_id: str
    pattern: re.Pattern[bytes]
    scan_pattern: re.Pattern[bytes]
    value_group: int
    boundary: bool
    casefold: bool
    anchors: tuple[bytes, ...]
    gate_literals: tuple[bytes, ...]
    gate_pattern: re.Pattern[bytes] | None
    requires: re.Pattern[bytes] | None
    value_check: Callable[[bytes], bool] | None
    echo_prefixes: tuple[str, ...]
    echo_markers: tuple[str, ...]


def _family(
    family_id: str,
    shape: bytes,
    *,
    boundary: bool = True,
    value_group: int = 0,
    casefold: bool = False,
    anchors: tuple[bytes, ...] = (),
    gate: tuple[bytes, ...] | None = None,
    gate_pattern: bytes | None = None,
    requires: bytes | None = None,
    value_check: Callable[[bytes], bool] | None = None,
    echo_prefixes: tuple[str, ...] = (),
    echo_markers: tuple[str, ...] = (),
) -> SecretFamily:
    source = (TOKEN_BOUNDARY if boundary else b"") + shape
    pattern = re.compile(source, re.IGNORECASE if casefold else 0)
    if gate is None:
        gate = () if gate_pattern is not None else anchors
    return SecretFamily(
        family_id=family_id,
        pattern=pattern,
        scan_pattern=re.compile(source) if casefold else pattern,
        value_group=value_group,
        boundary=boundary,
        casefold=casefold,
        anchors=anchors,
        gate_literals=gate,
        gate_pattern=re.compile(gate_pattern) if gate_pattern is not None else None,
        requires=re.compile(requires) if requires is not None else None,
        value_check=value_check,
        echo_prefixes=echo_prefixes,
        echo_markers=echo_markers,
    )


_PEM_HEADER: Final[bytes] = rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"

# Ordered data, not a dict: iteration order is contract. ``echo_markers`` are
# case-insensitive ``str`` regex fragments searched after ``^`` or a
# ``_``/``-``/``.`` delimiter; ``echo_prefixes`` are lowercase literals.
SECRET_FAMILIES: Final[tuple[SecretFamily, ...]] = (
    _family(
        "anthropic-api-key",
        rb"sk-ant-[A-Za-z0-9_-]{20,}",
        anchors=(b"sk-ant-",),
        gate=(b"sk-",),
        echo_prefixes=("sk-ant-",),
    ),
    _family(
        "openai-api-key",
        rb"sk-[A-Za-z0-9]{20,}",
        anchors=(b"sk-",),
        echo_prefixes=("sk-",),
        echo_markers=(r"sk-",),
    ),
    _family(
        "openrouter-api-key",
        rb"sk-or-v1-[0-9a-f]{48,}",
        anchors=(b"sk-or-v1-",),
        gate=(b"sk-",),
        echo_prefixes=("sk-or-",),
    ),
    _family(
        "github-pat-classic",
        rb"ghp_[A-Za-z0-9]{36,}",
        anchors=(b"ghp_",),
        echo_prefixes=("ghp_",),
        echo_markers=(r"ghp_[a-z0-9]",),
    ),
    _family(
        "github-pat-fine-grained",
        rb"github_pat_[A-Za-z0-9_]{22,}",
        anchors=(b"github_pat_",),
        echo_prefixes=("github_pat_",),
        echo_markers=(r"github_pat_[a-z0-9]",),
    ),
    _family(
        "github-oauth-token",
        rb"gh[osru]_[A-Za-z0-9]{36,}",
        anchors=(b"gho_", b"ghs_", b"ghr_", b"ghu_"),
        echo_prefixes=("gho_", "ghu_", "ghs_", "ghr_"),
        echo_markers=(r"gh[ousr]_[a-z0-9]",),
    ),
    _family(
        "stripe-webhook-secret",
        rb"whsec_[A-Za-z0-9]{24,}",
        anchors=(b"whsec_",),
        echo_prefixes=("whsec_",),
    ),
    _family(
        "stripe-key",
        rb"[sr]k_(?:live|test)_[A-Za-z0-9]{16,}",
        anchors=(b"sk_live_", b"sk_test_", b"rk_live_", b"rk_test_"),
        gate=(b"k_live_", b"k_test_"),
        echo_prefixes=("sk_", "rk_", "rk-"),
        echo_markers=(r"(?:sk|rk)_", r"rk-"),
    ),
    _family(
        "aws-access-key",
        rb"(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        anchors=(b"AKIA", b"ASIA"),
        echo_prefixes=("akia", "asia"),
        echo_markers=(r"(?:akia|asia)[0-9a-z]{16}",),
    ),
    _family(
        "supabase-pat",
        rb"sbp_[0-9a-f]{40,}",
        anchors=(b"sbp_",),
        echo_prefixes=("sbp_",),
    ),
    _family(
        # Anchorless: every match carries ``:`` + 35 token chars, which is
        # the gate superset (the digit prefix stays in the family pattern).
        "telegram-bot-token",
        rb"\d{8,10}:[A-Za-z0-9_-]{35}\b",
        gate_pattern=rb":[A-Za-z0-9_-]{35}",
    ),
    _family(
        "jwt",
        rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        anchors=(b"eyJ",),
        echo_prefixes=("eyj",),
    ),
    _family(
        # The digest covers the header plus the first base64 fragment when
        # adjacent (JSON-escaped ``\n`` or real newline both count), so two
        # different keys hash differently while the marker alone still flags.
        "private-key-block",
        _PEM_HEADER + rb"((?:\\n|\s)+[A-Za-z0-9+/=_-]{8,})?",
        anchors=(b"PRIVATE KEY-----",),
        gate=(b"-----BEGIN",),
    ),
    _family(
        # glpat- + 20 token chars (newer routable tokens are longer).
        "gitlab-pat",
        rb"glpat-[A-Za-z0-9_-]{20,}",
        anchors=(b"glpat-",),
        echo_prefixes=("glpat-",),
        echo_markers=(r"glpat-[a-z0-9]",),
    ),
    _family(
        # AIza + exactly 35 token chars (39 total), not continued.
        "google-api-key",
        rb"AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])",
        anchors=(b"AIza",),
        echo_prefixes=("aiza",),
        echo_markers=(r"aiza[0-9a-z_\-]{20,}",),
    ),
    _family(
        # xox[abeoprs]-<numeric id>-… (bot/user/app/refresh/legacy/config)
        # and app-level xapp-<n>-<ID>-<numeric>-…; the numeric segment keeps
        # ``xoxo-hugs``-style prose out.
        "slack-token",
        rb"(?:xox[abeoprs]-[0-9]{8,}|xapp-[0-9]-[A-Z0-9]{8,}-[0-9]{8,})-[A-Za-z0-9-]{8,}",
        anchors=(b"xox", b"xapp-"),
        gate_pattern=rb"x(?:ox[abeoprs]|app)-[0-9]",
        echo_prefixes=(
            "xoxa-",
            "xoxb-",
            "xoxe-",
            "xoxo-",
            "xoxp-",
            "xoxr-",
            "xoxs-",
            "xapp-",
            "slack_token_",
        ),
        echo_markers=(r"xox[abeoprs]-[0-9a-z]", r"xapp-[0-9a-z]", r"slack[_\-]token[_\-]"),
    ),
    _family(
        # npm_ + exactly 36 alphanumerics (30 random + 6 checksum).
        "npm-token",
        rb"npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_-])",
        anchors=(b"npm_",),
        gate_pattern=rb"npm_[A-Za-z0-9]{36}",
        echo_prefixes=("npm_",),
    ),
    _family(
        # hf_ + exactly 34 ASCII letters.
        "huggingface-token",
        rb"hf_[A-Za-z]{34}(?![A-Za-z0-9_-])",
        anchors=(b"hf_",),
        gate_pattern=rb"hf_[A-Za-z]{34}",
        echo_prefixes=("hf_",),
    ),
    _family(
        # Connection-string account key: 64 bytes -> 86 base64 chars + ``==``.
        "azure-storage-key",
        rb"AccountKey=([A-Za-z0-9+/]{86}==)(?![A-Za-z0-9+/=])",
        value_group=1,
        anchors=(b"AccountKey=",),
        value_check=_not_placeholder,
    ),
    _family(
        # SAS ``sig=``: base64 HMAC-SHA256 = 43 base64 units + one pad,
        # optionally percent-encoded (%2B, %2F, %3D).
        "azure-sas-signature",
        rb"sig=((?:[A-Za-z0-9+/]|%2[BbFf]){43}(?:=|%3[Dd]))(?![A-Za-z0-9+/=%])",
        value_group=1,
        anchors=(b"sig=",),
        value_check=_not_placeholder,
    ),
    _family(
        # Service-account JSON: a PEM ``private_key`` value in a record that
        # also declares ``"type": "service_account"`` (raw or JSON-escaped).
        # Starts at the literal key, quote escapes bounded, so linear-time.
        "gcp-service-account-key",
        rb'private_key\\{0,3}"[ \t]*:[ \t]*\\{0,3}"('
        + _PEM_HEADER
        + rb"(?:\\{1,3}[nr]|\s)+[A-Za-z0-9+/=]{8,})",
        boundary=False,
        value_group=1,
        anchors=(b"private_key",),
        gate=(b"service_account",),
        requires=rb'type\\{0,3}"[ \t]*:[ \t]*\\{0,3}"service_account\\{0,3}"',
    ),
    _family(
        # RFC 6750 b64token after ``Bearer``; the digest covers the token only.
        "bearer-token",
        rb"[Bb]earer[ \t]+([A-Za-z0-9._~+/-]{20,}=*)",
        value_group=1,
        anchors=(b"Bearer", b"bearer"),
        gate=(b"earer",),
        value_check=_bearer_value_ok,
        echo_prefixes=("bearer-", "bearer_"),
        echo_markers=(r"bearer[_\-]",),
    ),
    _family(
        # Keyword must end the key token (modulo quotes/dots) immediately
        # before ':' or '=' — so `token_count`, `token_endpoint`,
        # `secretary`, and `id_token_hint` never match, while
        # `aws_secret_access_key` (ends in access_key) does. Punctuation
        # between keyword and separator may be backslash-escaped (`\"` inside
        # JSON string payloads), as may the opening quote of the value; the
        # value group 1 stops at whitespace, quotes, commas, closing
        # brackets, and backslashes so a trailing `\"` is never captured.
        # Anchorless: gated by the keyword+separator finder in hygiene.
        "generic-credential-assignment",
        rb"(?:password|passwd|api[_-]?key|access[_-]?key|client[_-]?secret"
        rb"|private[_-]?key|auth[_-]?token|secret|token)(?:\\?[\"'.-])*\s*[:=]\s*"
        rb"(?:\\?[\"'`])?([^\s\"'`,)\]}\\]{8,})",
        boundary=False,
        value_group=1,
        casefold=True,
        value_check=_not_placeholder,
    ),
)

SECRET_FAMILY_IDS: Final[tuple[str, ...]] = tuple(f.family_id for f in SECRET_FAMILIES)

# Redaction view (safe_value): ordered, de-duplicated unions over the table.
ECHO_PREFIXES: Final[tuple[str, ...]] = tuple(
    dict.fromkeys(p for f in SECRET_FAMILIES for p in f.echo_prefixes)
)
ECHO_MARKERS: Final[tuple[str, ...]] = tuple(
    dict.fromkeys(m for f in SECRET_FAMILIES for m in f.echo_markers)
)


def iter_family_spans(family: SecretFamily, data: bytes) -> Iterator[tuple[int, int]]:
    """Yield ``(start, end)`` of each accepted value span of ``family`` in ``data``.

    Leftmost, non-overlapping like ``finditer``. A candidate rejected by the
    exact token boundary resumes the search one byte later — exactly what a
    strict lookbehind would do — while a candidate rejected by
    ``value_check`` is consumed, matching the pre-v3 placeholder semantics.
    """
    if family.requires is not None and family.requires.search(data) is None:
        return
    haystack = data.lower() if family.casefold else data
    search = family.scan_pattern.search
    group = family.value_group
    check = family.value_check
    pos = 0
    while True:
        match = search(haystack, pos)
        if match is None:
            return
        start, end = match.span()
        if family.boundary and not token_boundary_ok(data, start):
            pos = start + 1
            continue
        pos = end if end > start else start + 1
        value_start, value_end = match.span(group)
        if value_start < 0:
            continue
        if check is not None and not check(data[value_start:value_end]):
            continue
        yield value_start, value_end


def first_secret_family(data: bytes) -> str | None:
    """Return the first family with an accepted match in ``data``, else None."""
    for family in SECRET_FAMILIES:
        if family.anchors and not any(anchor in data for anchor in family.anchors):
            continue
        for _span in iter_family_spans(family, data):
            return family.family_id
    return None


__all__ = [
    "ECHO_MARKERS",
    "ECHO_PREFIXES",
    "SECRET_FAMILIES",
    "SECRET_FAMILY_IDS",
    "SECRET_FAMILY_SET_VERSION",
    "TOKEN_BOUNDARY",
    "SecretFamily",
    "first_secret_family",
    "iter_family_spans",
    "looks_like_placeholder",
    "token_boundary_ok",
]
