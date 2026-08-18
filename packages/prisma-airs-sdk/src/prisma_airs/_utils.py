"""Small helpers shared across clients."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Final

from prisma_airs.errors import AISecPayloadError

_UUID_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def is_valid_uuid(value: str) -> bool:
    """Report whether ``value`` is a canonically formatted RFC 4122 UUID.

    Deliberately a regex rather than :class:`uuid.UUID`, which accepts braced, URN, and
    unhyphenated spellings the API rejects.
    """
    return _UUID_RE.match(value) is not None


def validate_job_id(job_id: str) -> None:
    """Raise if ``job_id`` is not a valid UUID.

    Args:
        job_id: Identifier to check.

    Raises:
        AISecPayloadError: If the identifier is malformed.
    """
    if not is_valid_uuid(job_id):
        raise AISecPayloadError(f"Invalid job id: {job_id}")


def generate_payload_hash(payload: str, secret: str) -> str:
    """Return the hex HMAC-SHA256 of ``payload`` keyed by ``secret``.

    Sent as the ``x-payload-hash`` header on scan requests so the service can verify the
    body was not altered in transit.

    Args:
        payload: The serialised request body, exactly as it will be sent.
        secret: The API key used as the HMAC key.

    Returns:
        Lowercase hex digest.
    """
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
