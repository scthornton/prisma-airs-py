"""Retry policy, error classification, and ``Retry-After`` normalisation.

The behaviours here are matched deliberately against the reference implementation rather
than delegated to httpx's transport-level retries, because several are specific to how
the Prisma AIRS services behave:

* Only 500, 502, 503, and 504 are retried. A 429 is *not* retried automatically -- the
  service supplies retry guidance and the caller decides.
* Backoff uses full jitter, ``uniform(0, 2**attempt seconds)``, so a fleet of clients
  retrying after a shared outage spreads out instead of arriving in lockstep.
* An authentication failure gets one free retry that does not consume the retry budget,
  because a token expiring mid-run is an expected event rather than a fault.
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Final

import httpx

from prisma_airs.constants import HTTP_FORCE_RETRY_STATUS_CODES
from prisma_airs.errors import (
    AISecClientError,
    AISecSDKException,
    AISecServerError,
    ErrorType,
    FailureKind,
)


def backoff_delay_ms(attempt: int) -> float:
    """Return a full-jitter backoff delay in milliseconds for a zero-based attempt.

    Uniform over ``[0, 2**attempt * 1000]``. Not cryptographic: the randomness exists to
    decorrelate concurrent clients, not to be unpredictable.
    """
    max_delay = 2**attempt * 1000
    return random.uniform(0, max_delay)  # noqa: S311


def is_retryable_status(status: int) -> bool:
    """Report whether a status code should trigger an automatic retry."""
    return status in HTTP_FORCE_RETRY_STATUS_CODES


#: Statuses at or above this are the service's fault; below it, the request's.
_SERVER_ERROR_THRESHOLD: Final = 500


def classify_error_type(status: int) -> ErrorType:
    """Classify an HTTP status as a server-side or client-side error."""
    if status >= _SERVER_ERROR_THRESHOLD:
        return ErrorType.SERVER_SIDE_ERROR
    return ErrorType.CLIENT_SIDE_ERROR


def extract_error_message(body: str, status: int) -> str:
    """Pull a human-readable message out of an error response body.

    Four Palo Alto services front these APIs and each wraps errors differently, so this
    tries every known envelope in turn: ``error_message``, ``message``, ``data.message``
    (the AI Gateway app-RBAC shape), ``error.message``, and ``msg`` (the SCM OPA-denial
    shape). When the body carries an ``errorCode`` it is appended, so callers can
    distinguish AI Gateway's ``AB01``/``AB02``/``AB03`` without inspecting headers.

    Args:
        body: Raw response body.
        status: Status code, used to build a fallback message.

    Returns:
        A message suitable for surfacing to a user.
    """
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return f"API error {status}: {body}" if body else f"API error {status}"

    if not isinstance(parsed, dict):
        return f"API error {status}: {body}" if body else f"API error {status}"

    data = parsed.get("data")
    data = data if isinstance(data, dict) else {}
    error = parsed.get("error")
    error = error if isinstance(error, dict) else {}

    base = (
        parsed.get("error_message")
        or parsed.get("message")
        or data.get("message")
        or error.get("message")
        or parsed.get("msg")
        or f"API error {status}"
    )
    code = data.get("errorCode")
    return f"{base} (errorCode: {code})" if code else str(base)


#: Accepted ``Retry-After`` date spellings, per RFC 9110: IMF-fixdate, the obsolete
#: RFC 850 form, and asctime. Anything else is ignored rather than guessed at.
_HTTP_DATE_FORMATS: Final[tuple[str, ...]] = (
    "%a, %d %b %Y %H:%M:%S GMT",
    "%A, %d-%b-%y %H:%M:%S GMT",
    "%a %b %d %H:%M:%S %Y",
)

#: Unit spellings observed in AIRS ``retry_after`` bodies, mapped to milliseconds.
_UNIT_MULTIPLIERS: Final[dict[str, int]] = {
    "ms": 1,
    "msec": 1,
    "msecs": 1,
    "millisecond": 1,
    "milliseconds": 1,
    "s": 1_000,
    "sec": 1_000,
    "secs": 1_000,
    "second": 1_000,
    "seconds": 1_000,
    "m": 60_000,
    "min": 60_000,
    "mins": 60_000,
    "minute": 60_000,
    "minutes": 60_000,
}


def parse_retry_after_header(
    value: str | None,
    *,
    now: Callable[[], datetime] | None = None,
) -> float | None:
    """Normalise a ``Retry-After`` header to milliseconds.

    Accepts either delta-seconds or an HTTP date. Returns ``None`` when the header is
    absent or unparseable, so a malformed value degrades to the default backoff rather
    than to an accidental zero-second retry.

    Args:
        value: Raw header value.
        now: Clock override, for testing.

    Returns:
        Delay in milliseconds, or ``None``.
    """
    if value is None:
        return None
    normalized = value.strip()
    if not normalized:
        return None

    if normalized.isdigit():
        return float(normalized) * 1_000

    # Space-padded asctime days ("Sun Nov  6 ...") collapse so %d matches.
    collapsed = " ".join(normalized.split())
    for fmt in _HTTP_DATE_FORMATS:
        try:
            parsed = datetime.strptime(collapsed, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        current = now() if now is not None else datetime.now(timezone.utc)
        delta: timedelta = parsed - current
        return max(0.0, delta.total_seconds() * 1_000)
    return None


def parse_retry_after_body(body: str) -> float | None:
    """Normalise an AIRS ``retry_after`` JSON object to milliseconds.

    The service returns ``{"retry_after": {"interval": 30, "unit": "seconds"}}``. An
    unrecognised unit yields ``None`` rather than a guess, since treating minutes as
    milliseconds would hammer an already-struggling endpoint.
    """
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None

    retry_after = parsed.get("retry_after")
    if not isinstance(retry_after, dict):
        return None

    interval = retry_after.get("interval")
    unit = retry_after.get("unit")
    # bool is a subclass of int; a JSON `true` here is malformed, not an interval of 1.
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or interval < 0:
        return None
    if not isinstance(unit, str):
        return None

    multiplier = _UNIT_MULTIPLIERS.get(unit.lower())
    return None if multiplier is None else float(interval) * multiplier


def execute_with_retry(
    *,
    max_retries: int,
    execute: Callable[[int], httpx.Response],
    on_retryable_failure: Callable[[httpx.Response], bool] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    delay_ms: Callable[[int], float] = backoff_delay_ms,
) -> httpx.Response:
    """Run ``execute`` with backoff until it succeeds or the budget is spent.

    Args:
        max_retries: Maximum retries, not counting the initial attempt.
        execute: Performs one attempt, receiving the zero-based attempt number.
        on_retryable_failure: Called on a non-2xx response. Returning ``True`` retries
            without consuming the budget; the caller is responsible for bounding how
            often it may do so.
        sleep: Sleep function, injectable for testing.
        delay_ms: Backoff strategy, injectable for testing.

    Returns:
        The first successful response.

    Raises:
        AISecServerError: A 5xx survived the retry budget.
        AISecClientError: A 4xx response, or the request never reached the service.
    """
    attempt = 0
    last_error: Exception | None = None

    while attempt <= max_retries:
        try:
            response = execute(attempt)
        except AISecSDKException:
            raise
        except httpx.HTTPError as err:
            last_error = err
            if attempt < max_retries:
                sleep(delay_ms(attempt) / 1000.0)
                attempt += 1
                continue
            raise AISecClientError(
                str(err) or "Network error", failure_kind=FailureKind.NETWORK
            ) from err

        if response.is_success:
            return response

        # A free retry, typically an expired token being refreshed. Deliberately does not
        # advance `attempt`, matching the reference implementation.
        if on_retryable_failure is not None and on_retryable_failure(response):
            continue

        if is_retryable_status(response.status_code) and attempt < max_retries:
            sleep(delay_ms(attempt) / 1000.0)
            attempt += 1
            continue

        raise _error_for(response)

    raise AISecClientError(
        str(last_error) if last_error else "Max retries exceeded",
        failure_kind=FailureKind.NETWORK if last_error else None,
    )


def _error_for(response: httpx.Response) -> AISecSDKException:
    """Build the exception for a terminal non-2xx response."""
    body = response.text
    message = extract_error_message(body, response.status_code)
    retry_after = parse_retry_after_header(response.headers.get("Retry-After"))
    if retry_after is None:
        retry_after = parse_retry_after_body(body)

    error_class = (
        AISecServerError
        if classify_error_type(response.status_code) is ErrorType.SERVER_SIDE_ERROR
        else AISecClientError
    )
    return error_class(
        message,
        failure_kind=FailureKind.HTTP,
        status_code=response.status_code,
        retry_after_ms=retry_after,
    )
