"""Opt-in request and response logging.

Enabled with ``PANW_AI_SEC_DEBUG``. Credential header values are replaced with a
non-reversible ``sha256:<prefix>`` digest, so debug output can be pasted into an issue or
a support ticket while still letting you confirm which key a request actually used.

When disabled this costs one environment read and nothing else.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Final

from prisma_airs.constants import ENV_AI_SEC_DEBUG, HEADER_API_KEY, HEADER_AUTH_TOKEN

logger: Final = logging.getLogger("prisma_airs")

_TRUTHY: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})

#: Compared case-insensitively, because header casing is not guaranteed.
_SENSITIVE_HEADERS: Final[frozenset[str]] = frozenset(
    {HEADER_AUTH_TOKEN.lower(), HEADER_API_KEY.lower()}
)


def is_debug_enabled() -> bool:
    """Report whether ``PANW_AI_SEC_DEBUG`` is set to a truthy value."""
    raw = os.environ.get(ENV_AI_SEC_DEBUG)
    return raw is not None and raw.strip().lower() in _TRUTHY


def hash_token(value: str) -> str:
    """Reduce a secret to a stable, non-reversible ``sha256:<12 hex>`` token."""
    digest = hashlib.sha256(value.encode()).hexdigest()[:12]
    return f"sha256:{digest}"


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``headers`` with credential values digested.

    The input is not mutated. Non-sensitive headers pass through unchanged.
    """
    return {
        key: hash_token(value) if key.lower() in _SENSITIVE_HEADERS else value
        for key, value in headers.items()
    }


def log_request(method: str, url: str, headers: dict[str, str], body: str | None) -> None:
    """Log an outbound request.

    Headers are sanitised here rather than by the caller, so there is no path through
    which a raw credential reaches the log.
    """
    logger.debug("→ %s %s", method, url)
    logger.debug("  headers %s", sanitize_headers(headers))
    if body is not None:
        logger.debug("  body %s", body)


def log_response(status: int, elapsed_ms: float, body: str | None) -> None:
    """Log a response status, elapsed time, and body when available."""
    logger.debug("← %d (%.0fms)%s", status, elapsed_ms, f" {body}" if body is not None else "")
