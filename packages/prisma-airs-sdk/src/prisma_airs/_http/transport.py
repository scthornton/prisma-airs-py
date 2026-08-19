"""The request pipeline: build, authenticate, send, retry, validate.

Every client call funnels through :func:`request`, so behaviour that must be uniform --
the user agent, retry policy, error mapping, and debug redaction -- is defined once here.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

import httpx
from pydantic import BaseModel, TypeAdapter, ValidationError

from prisma_airs._http.debug import is_debug_enabled, log_request, log_response
from prisma_airs._http.retry import execute_with_retry
from prisma_airs._http.types import AuthAdapter, HttpMethod, PreparedRequest
from prisma_airs.constants import MAX_NUMBER_OF_RETRIES, USER_AGENT
from prisma_airs.errors import AISecResponseValidationError
from prisma_airs.serialization import dumps_compact

T = TypeVar("T")

#: Sent on every request. The services key some behaviour off it.
_BASE_HEADERS: Mapping[str, str] = {"User-Agent": USER_AGENT, "service-name": "api"}


def serialize_body(value: Any) -> str:
    """Serialise a request body the way ``JSON.stringify`` would.

    Delegates to :func:`prisma_airs.serialization.dumps_compact`, which the CLI's
    machine-readable output also uses, so the two cannot drift apart.
    """
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return dumps_compact(value)


@dataclass
class RequestSpec(Generic[T]):
    """A declarative description of one endpoint call."""

    method: HttpMethod
    base_url: str
    path: str
    auth: AuthAdapter
    params: Mapping[str, str | Sequence[str]] | None = None
    body: Any = None
    #: Overrides the JSON content type. Some DLP endpoints require merge-patch.
    content_type: str | None = None
    #: Multipart payload. Takes precedence over ``body``; httpx writes the boundary.
    files: Mapping[str, Any] | None = None
    #: Validated against the response body. ``None`` discards the body.
    response_model: Any = None
    #: Allow an empty 2xx body to resolve to ``None`` instead of validating ``{}``.
    allow_empty_body: bool = False
    num_retries: int = MAX_NUMBER_OF_RETRIES
    extra_headers: dict[str, str] = field(default_factory=dict)


def build_url(
    base_url: str,
    path: str,
    params: Mapping[str, str | Sequence[str]] | None,
) -> httpx.URL:
    """Join a base URL and path, then apply query parameters.

    Sequence values expand to repeated keys, which is what these APIs expect for
    multi-valued filters.
    """
    url = httpx.URL(f"{base_url.rstrip('/')}{path}")
    if not params:
        return url

    # Widened to httpx's own accepted value type: list is invariant, so a narrower
    # annotation here will not satisfy QueryParams.
    pairs: list[tuple[str, str | int | float | bool | None]] = []
    for key, value in params.items():
        if isinstance(value, str):
            pairs.append((key, value))
        else:
            pairs.extend((key, item) for item in value)
    return url.copy_merge_params(httpx.QueryParams(pairs))


def request(spec: RequestSpec[T], *, client: httpx.Client) -> T:
    """Execute one API call and return its validated response.

    Args:
        spec: The call to make.
        client: HTTP client to send through. Owned by the caller.

    Returns:
        The validated response body, or ``None`` when no model is declared.

    Raises:
        AISecResponseValidationError: A 2xx body was not valid JSON, or did not match
            ``response_model``.
        AISecClientError: A 4xx response, or a transport failure.
        AISecServerError: A 5xx response that outlived the retry budget.
    """
    debug = is_debug_enabled()
    # `on_unauthorized` fires at most once per request. Without this guard, an endpoint
    # that answers 403 for a non-auth reason would loop against the free-retry path.
    auth_retry_used = False

    def attempt(_attempt: int) -> httpx.Response:
        headers = dict(_BASE_HEADERS)
        headers.update(spec.extra_headers)

        body_text: str | None = None
        if spec.files is None and spec.body is not None:
            headers["Content-Type"] = spec.content_type or "application/json"
            body_text = serialize_body(spec.body)

        prepared = PreparedRequest(
            method=spec.method,
            url=build_url(spec.base_url, spec.path, spec.params),
            headers=headers,
            body_text=body_text,
        )
        final = spec.auth.prepare(prepared)

        started = time.monotonic()
        if debug:
            log_request(
                final.method,
                str(final.url),
                final.headers,
                "[multipart/form-data]" if spec.files is not None else final.body_text,
            )

        response = client.request(
            final.method,
            final.url,
            headers=final.headers,
            content=final.body_text.encode() if final.body_text is not None else None,
            files=spec.files,
        )

        if debug:
            log_response(response.status_code, (time.monotonic() - started) * 1000, response.text)
        return response

    def on_retryable_failure(response: httpx.Response) -> bool:
        nonlocal auth_retry_used
        if auth_retry_used:
            return False
        if spec.auth.on_unauthorized(response):
            auth_retry_used = True
            return True
        return False

    response = execute_with_retry(
        max_retries=spec.num_retries,
        execute=attempt,
        on_retryable_failure=on_retryable_failure,
    )

    return _parse_response(spec, response.text)


def _parse_response(spec: RequestSpec[T], text: str) -> T:
    """Validate a successful response body against the declared model."""
    if spec.response_model is None:
        return None  # type: ignore[return-value]

    # Some endpoints return 200 with no body and others 204, from the same call.
    if spec.allow_empty_body and not text:
        return None  # type: ignore[return-value]

    try:
        # An empty body hydrates to `{}` so all-optional models validate cleanly. The
        # AIRS API omits the body entirely when a query has no results, and failing on a
        # named field beats a root-level "expected object, received undefined".
        payload = json.loads(text) if text else {}
    except ValueError as err:
        raise AISecResponseValidationError("Response body is not valid JSON") from err

    try:
        return TypeAdapter(spec.response_model).validate_python(payload)  # type: ignore[no-any-return]
    except ValidationError as err:
        raise AISecResponseValidationError(f"Response did not match schema: {err}") from err
