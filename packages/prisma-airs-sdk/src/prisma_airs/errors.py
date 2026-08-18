"""Exception hierarchy for the Prisma AIRS SDK.

Every error raised by this package derives from :class:`AISecSDKException` and carries an
:class:`ErrorType` classifying its origin. The string form is prefixed with that type --
``AISEC_CLIENT_SIDE_ERROR:Invalid API Key or OAuth Token`` -- matching what the service
and the reference implementations emit, so log lines stay greppable across languages.

Subclasses exist so callers can be selective with ``except``. They are a convenience over
the classification, not a separate taxonomy: each one simply fixes ``error_type``.
"""

from __future__ import annotations

from enum import Enum
from typing import ClassVar


class ErrorType(str, Enum):
    """Classification of SDK errors by origin."""

    SERVER_SIDE_ERROR = "AISEC_SERVER_SIDE_ERROR"
    """5xx response from the AIRS API."""

    CLIENT_SIDE_ERROR = "AISEC_CLIENT_SIDE_ERROR"
    """4xx response, or a failure at the network boundary."""

    USER_REQUEST_PAYLOAD_ERROR = "AISEC_USER_REQUEST_PAYLOAD_ERROR"
    """Invalid caller-supplied input, such as a malformed UUID or oversized content."""

    MISSING_VARIABLE = "AISEC_MISSING_VARIABLE"
    """A required configuration value was not supplied."""

    SDK_ERROR = "AISEC_SDK_ERROR"
    """Internal SDK error."""

    OAUTH_ERROR = "AISEC_OAUTH_ERROR"
    """OAuth2 token acquisition failed."""

    RESPONSE_VALIDATION = "AISEC_RESPONSE_VALIDATION"
    """A 2xx body was invalid JSON or did not match the declared response model."""


class FailureKind(str, Enum):
    """Whether a request reached the service or failed in transit."""

    HTTP = "http"
    """A response was received and carried an error status."""

    NETWORK = "network"
    """No response was received: DNS, connection, or timeout failure."""


# N818 wants an `Error` suffix. The name is kept deliberately: it matches both the
# official pan-aisecurity SDK and the TypeScript reference, so `except AISecSDKException`
# means the same thing in every Prisma AIRS client a team might have in play.
class AISecSDKException(Exception):  # noqa: N818
    """Base exception for all Prisma AIRS SDK errors.

    Attributes:
        raw_message: The message without the ``ErrorType`` prefix.
        error_type: Classification of the error, if known.
        failure_kind: Whether a response was received at all.
        status_code: HTTP status, when a response was received.
        retry_after_ms: Server-provided retry delay, normalised to milliseconds.
    """

    #: Fixed by subclasses so they need not repeat the classification at each raise site.
    default_error_type: ClassVar[ErrorType | None] = None

    def __init__(
        self,
        message: str,
        error_type: ErrorType | None = None,
        *,
        failure_kind: FailureKind | None = None,
        status_code: int | None = None,
        retry_after_ms: float | None = None,
    ) -> None:
        resolved = error_type if error_type is not None else self.default_error_type
        super().__init__(f"{resolved.value}:{message}" if resolved else message)
        self.raw_message = message
        self.error_type = resolved
        self.failure_kind = failure_kind
        self.status_code = status_code
        self.retry_after_ms = retry_after_ms

    @property
    def retry_after_seconds(self) -> float | None:
        """Retry delay in seconds, or ``None`` when the service did not supply one."""
        return None if self.retry_after_ms is None else self.retry_after_ms / 1000.0


class AISecServerError(AISecSDKException):
    """The API returned a 5xx status after the retry budget was exhausted."""

    default_error_type = ErrorType.SERVER_SIDE_ERROR


class AISecClientError(AISecSDKException):
    """The API returned a 4xx status, or the request failed in transit."""

    default_error_type = ErrorType.CLIENT_SIDE_ERROR


class AISecPayloadError(AISecSDKException):
    """Caller-supplied input was rejected before the request was sent."""

    default_error_type = ErrorType.USER_REQUEST_PAYLOAD_ERROR


class AISecMissingVariableError(AISecSDKException):
    """A required credential or configuration value was not supplied."""

    default_error_type = ErrorType.MISSING_VARIABLE


class AISecOAuthError(AISecSDKException):
    """Acquiring an OAuth2 access token failed."""

    default_error_type = ErrorType.OAUTH_ERROR


class AISecResponseValidationError(AISecSDKException):
    """A successful response did not match the declared model."""

    default_error_type = ErrorType.RESPONSE_VALIDATION


__all__ = [
    "AISecClientError",
    "AISecMissingVariableError",
    "AISecOAuthError",
    "AISecPayloadError",
    "AISecResponseValidationError",
    "AISecSDKException",
    "AISecServerError",
    "ErrorType",
    "FailureKind",
]
