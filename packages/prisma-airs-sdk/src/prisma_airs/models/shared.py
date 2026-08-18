"""Enums and cross-cutting payloads shared by every Prisma AIRS API.

Two kinds of thing live here. The enums catalogue the string vocabularies the services
use for verdicts, enforcement actions, and detection service names. The models cover the
two payloads that belong to no single API: the error body any endpoint can return, and
the OAuth2 token response the management planes authenticate with.

Response models elsewhere in this package type verdicts, actions, and categories as plain
``str`` rather than as these enums. A value the services add mid-release would otherwise
turn a parseable response into a ``ValidationError`` -- the same failure mode
``extra="allow"`` exists to prevent. Because every enum here subclasses ``str``,
comparing a raw response field against a member still works, as in
``scan_response.action == Action.BLOCK``.

The mixin covers comparison, not rendering. ``str(Action.BLOCK)`` and ``f"{Action.BLOCK}"``
both produce ``"Action.BLOCK"``, not ``"block"``, so reach for ``.value`` when
interpolating a member into a request payload or a log line. Serialisation is the
exception: ``json.dumps`` writes the underlying ``str``.
"""

from __future__ import annotations

from enum import Enum

from prisma_airs.models.base import AirsModel

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Verdict(str, Enum):
    """What a single detection service concluded about a piece of content.

    Carried on the per-service rows of a threat report, such as
    ``DetectionServiceResult.verdict`` in :mod:`prisma_airs.models.scan`.
    """

    BENIGN = "benign"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Action(str, Enum):
    """What the service instructs the caller to do with the scanned content."""

    ALLOW = "allow"
    BLOCK = "block"

    ALERT = "alert"
    """Record the finding and let the content through. An alert is not a block."""


class Category(str, Enum):
    """The scan's top-level classification, returned on ``ScanResponse.category``.

    The members duplicate :class:`Verdict` today. They stay separate types because the
    source treats them separately: a category is the roll-up across every detection
    service that ran, a verdict is one service's own opinion, and the two vocabularies
    are free to diverge.
    """

    BENIGN = "benign"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class DetectionServiceName(str, Enum):
    """Detection services that can report a finding.

    The values match the boolean flag names on ``PromptDetected``, ``ResponseDetected``,
    and ``ToolDetectionFlags`` in :mod:`prisma_airs.models.scan`, so a member doubles as
    the attribute name to read a flag by. One flag has no member here:
    ``PromptDetected.source_code`` is set by the services but absent from this
    vocabulary, so code that walks the enum to enumerate detections will miss it.
    """

    DLP = "dlp"
    """Data loss prevention: content matched a data pattern in a DLP profile."""

    INJECTION = "injection"
    """Prompt injection. Command injection is reported under :attr:`MALICIOUS_CODE`."""

    URL_CATS = "url_cats"
    """URL filtering: a URL in the content fell into a flagged category."""

    TOXIC_CONTENT = "toxic_content"

    MALICIOUS_CODE = "malicious_code"

    AGENT = "agent"
    """Agent-framework attack patterns; detail arrives in ``AgentReport``."""

    TOPIC_VIOLATION = "topic_violation"
    """Content strayed outside the topics a guardrail allows."""

    DB_SECURITY = "db_security"
    """Database security: a finding on a database query found in the content."""

    UNGROUNDED = "ungrounded"
    """Contextual grounding: the response was not supported by the supplied context."""


class ContentErrorType(str, Enum):
    """Which side of an exchange a per-content error came from.

    Populates ``ContentError.content_type`` in :mod:`prisma_airs.models.scan`.
    """

    PROMPT = "prompt"
    RESPONSE = "response"


class ErrorStatus(str, Enum):
    """How a detection service failed on one piece of content.

    Populates ``ContentError.status``. A timeout is not a clean bill of health: the
    service never finished, so the absence of a finding from it says nothing about the
    content.
    """

    ERROR = "error"
    TIMEOUT = "timeout"


# ---------------------------------------------------------------------------
# Error response
# ---------------------------------------------------------------------------


class ErrorDetail(AirsModel):
    """The nested error object some AIRS endpoints wrap their message in."""

    message: str | None = None


class RetryAfter(AirsModel):
    """Service-supplied retry guidance, as an interval plus the unit it is measured in.

    ``unit`` stays a free-form string rather than an enum because the spelling is not
    fixed: the transport layer accepts ``s``, ``sec``, and ``seconds`` as the same unit,
    and the minute and millisecond forms alongside them. It maps the spellings it knows
    to milliseconds and declines to guess at the rest, since reading minutes as
    milliseconds would hammer an endpoint that just asked for room.
    """

    interval: float | None = None
    unit: str | None = None


class ErrorResponse(AirsModel):
    """An error body returned by any AIRS endpoint.

    Every field is optional. A failure can arrive carrying only a status code, only a
    message, or -- from an overloaded endpoint -- only retry guidance.

    The transport layer does not route errors through this model. Four Palo Alto services
    front these APIs and each wraps errors differently, so raising is driven by a
    best-effort sweep of the raw body across every known envelope. Use this model when
    you want a typed view of a body you already hold.

    ``status_code`` is a ``float`` because the wire schema types it as a bare JSON number
    with no integer constraint. The services send whole numbers, and ``429.0 == 429``
    compares as expected.
    """

    status_code: float | None = None
    message: str | None = None
    error: ErrorDetail | None = None
    retry_after: RetryAfter | None = None

    @property
    def detail(self) -> str | None:
        """The human-readable message, from whichever of the two places carries it.

        Prefers the top-level ``message`` over the nested ``error.message``, and returns
        ``None`` when the body carried neither -- which is why the caller should keep the
        status code around as a fallback.
        """
        if self.message:
            return self.message
        if self.error is not None and self.error.message:
            return self.error.message
        return None


# ---------------------------------------------------------------------------
# OAuth2
# ---------------------------------------------------------------------------


class OAuthTokenResponse(AirsModel):
    """An OAuth2 client-credentials token response.

    Internal to the management, AI gateway, red team, and model security planes; callers
    hold an ``OAuthClient`` rather than this payload.

    Not to be confused with :class:`prisma_airs.models.management.Oauth2Token`, which is a
    *management API resource* describing a token record, and reports ``expires_in`` as a
    string. This one is what the auth endpoint returns, with ``expires_in`` as a number.

    ``expires_in`` is a lifetime in seconds measured from receipt, not an absolute
    timestamp. Add it to a monotonic clock reading rather than to wall time: these tokens
    live about fifteen minutes, comfortably inside the window where an NTP correction or
    a laptop resuming from sleep could make a live token look expired -- or, worse, an
    expired one look live.
    """

    access_token: str
    token_type: str | None = None
    expires_in: float
    scope: str | None = None
