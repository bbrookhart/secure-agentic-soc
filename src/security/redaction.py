"""Secret redaction.

Two complementary strategies:

1. **Known-value redaction** -- exact secret strings pulled from configuration
   are registered at start-up and scrubbed wherever they appear.  This is the
   reliable half: if we know the secret, we can always find it.
2. **Pattern redaction** -- regexes for common credential shapes (API keys,
   bearer tokens, private keys, AWS keys).  This is best-effort defence in
   depth for secrets that leak in from log lines or tool output.

Applied at two chokepoints: everything written to the audit log, and everything
returned from a tool before it can reach an LLM prompt.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

# Ordered patterns: more specific first so they win the first match.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private_key",
        re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----.*?-----END[A-Z ]*PRIVATE KEY-----", re.S),
    ),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}")),
    (
        "assigned_secret",
        # key = value / "key": "value" for anything that looks credential-ish.
        re.compile(
            r"(?i)\b(api[_-]?key|apikey|secret|password|passwd|token|credential)\b"
            r"(\s*[:=]\s*)"
            r"(\"[^\"]{4,}\"|'[^']{4,}'|[^\s,;}'\"]{4,})"
        ),
    ),
)

# Exact secret values registered at start-up.
_known_secrets: set[str] = set()


def register_secret(value: str) -> None:
    """Register an exact secret value for scrubbing.

    Very short values are ignored: redacting a 3-character string would mangle
    unrelated text without meaningfully protecting anything.
    """
    if value and len(value) >= 6:
        _known_secrets.add(value)


def register_secrets(values: list[str]) -> None:
    for value in values:
        register_secret(value)


def clear_registered_secrets() -> None:
    """Test hook -- drops all registered exact secrets."""
    _known_secrets.clear()


def redact_text(text: str) -> str:
    """Scrub known secrets and credential-shaped patterns from ``text``."""
    if not text:
        return text

    for secret in _known_secrets:
        if secret in text:
            text = text.replace(secret, REDACTED)

    for name, pattern in _PATTERNS:
        if name == "assigned_secret":
            text = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
        else:
            text = pattern.sub(REDACTED, text)

    return text


def redact_obj(obj: Any) -> Any:
    """Recursively redact strings inside dicts / lists / tuples.

    Dict *keys* whose name implies a credential have their value dropped
    entirely rather than pattern-matched -- cheaper and more reliable.
    """
    sensitive_key = re.compile(r"(?i)(api[_-]?key|secret|password|passwd|token|credential|authorization)")

    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for key, value in obj.items():
            if isinstance(key, str) and sensitive_key.search(key):
                out[key] = REDACTED
            else:
                out[key] = redact_obj(value)
        return out
    if isinstance(obj, list):
        return [redact_obj(item) for item in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(item) for item in obj)
    return obj
