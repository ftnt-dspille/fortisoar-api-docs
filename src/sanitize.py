"""Credential / PII scrubber for spec inputs.

Run on every request body, header set, query string, and response body
before it lands in the spec. Conservative — when in doubt, redact.
"""
from __future__ import annotations

import re
from typing import Any

# Headers we never include — they often carry creds or session state
DROP_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "x-csrftoken",
    "x-fortisoar-csrf-token",
    "x-api-key",
    "apikey",
    "api-key",
}

# JSON keys whose values get replaced with REDACTED. Match is case-
# insensitive and substring-based to catch "user_password", "apiKey",
# "client_secret", etc.
REDACT_KEY_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"password",
        r"passwd",
        r"secret",
        r"token",
        r"api[_-]?key",
        r"apikey",
        r"private[_-]?key",
        r"credential",
        r"\bauth\b",
        r"client[_-]?secret",
        r"client[_-]?id",
        r"refresh[_-]?token",
        r"access[_-]?token",
        r"bearer",
        r"hmac",
    ]
]

REDACTED = "REDACTED"

# Operator identity tokens that show up in captured response data
# (contributor fields, audit user fields, hostnames). Scrubbed wherever
# they appear in strings. Extend as needed.
OPERATOR_IDENTITY_RE = re.compile(
    r"\b(?:Dylan\s+Spille|dspille)\b",
    re.IGNORECASE,
)

# Replace any IPv4 address with the placeholder host. Conservative — even
# 8.8.8.8 in an example payload becomes the placeholder, since we can't
# tell intent.
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOSTNAME_PLACEHOLDER = "your-soar.example.com"

# Internal hostnames seen in evidence — extend as needed.
INTERNAL_HOST_RE = re.compile(
    r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:fortinet\.com|fortinetcloud\.com|"
    r"forticloud\.com|fortisoc\.forticloud\.com|fortisoar\.local)\b",
    re.IGNORECASE,
)

# Email addresses — scrubbed unless they look like generic test fixtures
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SAFE_EMAIL_DOMAINS = {"example.com", "example.org", "test.com"}

# JWT-like tokens (three base64url segments separated by dots)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# Long bearer-token-like strings: 32+ contiguous base64-ish chars
LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}\b")


def _scrub_string(s: str, *, allow_long_tokens: bool = False) -> str:
    s = JWT_RE.sub(REDACTED, s)
    s = OPERATOR_IDENTITY_RE.sub("user", s)
    s = INTERNAL_HOST_RE.sub(HOSTNAME_PLACEHOLDER, s)
    s = IPV4_RE.sub(HOSTNAME_PLACEHOLDER, s)

    def _email_repl(m: re.Match[str]) -> str:
        addr = m.group(0)
        domain = addr.split("@", 1)[1].lower()
        return addr if domain in SAFE_EMAIL_DOMAINS else "user@example.com"

    s = EMAIL_RE.sub(_email_repl, s)
    if not allow_long_tokens:
        s = LONG_TOKEN_RE.sub(REDACTED, s)
    return s


def _key_should_redact(key: str) -> bool:
    return any(p.search(key) for p in REDACT_KEY_PATTERNS)


def scrub_value(v: Any, parent_key: str = "") -> Any:
    if isinstance(v, dict):
        return {k: (REDACTED if _key_should_redact(k) else scrub_value(val, k))
                for k, val in v.items()}
    if isinstance(v, list):
        return [scrub_value(item, parent_key) for item in v]
    if isinstance(v, str):
        return _scrub_string(v)
    return v


def scrub_headers(headers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for h in headers:
        name = (h.get("name") or "").lower()
        if name in DROP_HEADERS:
            continue
        value = h.get("value", "")
        out.append({"name": h.get("name"), "value": _scrub_string(str(value))})
    return out


def scrub_url(url: str) -> str:
    # URL path segments — base64 IDs, long UUIDs, file slugs — are not
    # secrets and must not be eaten by the LONG_TOKEN_RE pass.
    return _scrub_string(url, allow_long_tokens=True)
