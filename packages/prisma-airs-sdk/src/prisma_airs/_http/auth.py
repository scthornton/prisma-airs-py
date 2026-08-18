"""Authentication strategies for the request pipeline.

Three planes, three schemes: the scan service takes an API key plus an HMAC over the
body, the management planes take an OAuth2 bearer token, and the AI Gateway takes a
bearer token *and* a tenant header. The third composes over the second rather than
duplicating it.
"""

from __future__ import annotations

import httpx

from prisma_airs._http.types import AuthAdapter, PreparedRequest
from prisma_airs._utils import generate_payload_hash
from prisma_airs.auth.oauth import OAuthClient
from prisma_airs.constants import (
    BEARER_PREFIX,
    HEADER_API_KEY,
    HEADER_AUTH_TOKEN,
    HEADER_PAYLOAD_HASH,
    HEADER_TSG_ID,
)
from prisma_airs.errors import AISecMissingVariableError

#: Statuses that justify discarding a cached token and trying once more. 403 is included
#: because the management planes return it for an expired token, not only for a genuine
#: authorisation failure.
_AUTH_FAILURE_STATUSES = frozenset({401, 403})


class ApiKeyAuth:
    """Authenticates scan-service requests with an API key, token, or both."""

    def __init__(self, *, api_key: str | None = None, api_token: str | None = None) -> None:
        if not api_key and not api_token:
            raise AISecMissingVariableError("ApiKeyAuth requires either api_key or api_token")
        self._api_key = api_key
        self._api_token = api_token

    def prepare(self, request: PreparedRequest) -> PreparedRequest:
        """Attach the API key header, bearer token, and payload hash as configured."""
        headers: dict[str, str] = {}
        if self._api_token:
            headers[HEADER_AUTH_TOKEN] = f"{BEARER_PREFIX}{self._api_token}"
        if self._api_key:
            headers[HEADER_API_KEY] = self._api_key
            if request.body_text is not None:
                headers[HEADER_PAYLOAD_HASH] = generate_payload_hash(
                    request.body_text, self._api_key
                )
        return request.with_headers(headers)

    def on_unauthorized(self, response: httpx.Response) -> bool:
        """Never retry: a rejected API key will be rejected again."""
        del response
        return False


class OAuthAuth:
    """Authenticates management-plane requests with an OAuth2 bearer token."""

    def __init__(self, oauth_client: OAuthClient) -> None:
        self._oauth = oauth_client

    def prepare(self, request: PreparedRequest) -> PreparedRequest:
        """Attach a bearer token, fetching or refreshing it if necessary."""
        token = self._oauth.get_token()
        return request.with_headers({HEADER_AUTH_TOKEN: f"{BEARER_PREFIX}{token}"})

    def on_unauthorized(self, response: httpx.Response) -> bool:
        """Discard the cached token on an auth failure so the retry fetches a fresh one."""
        if response.status_code in _AUTH_FAILURE_STATUSES:
            self._oauth.clear_token()
            return True
        return False


class TsgHeaderAuth:
    """Adds the tenant header that every AI Gateway endpoint requires.

    Wraps another adapter rather than replacing it, so the token-refresh behaviour of
    :class:`OAuthAuth` carries through unchanged. Omitting ``x-tsg-id`` produces a 403
    OPA denial that looks exactly like an expired token, which is a memorable afternoon.
    """

    def __init__(self, inner: AuthAdapter, tsg_id: str) -> None:
        self._inner = inner
        self._tsg_id = tsg_id

    def prepare(self, request: PreparedRequest) -> PreparedRequest:
        """Apply the inner adapter, then add the tenant header."""
        return self._inner.prepare(request).with_headers({HEADER_TSG_ID: self._tsg_id})

    def on_unauthorized(self, response: httpx.Response) -> bool:
        """Delegate to the wrapped adapter."""
        return self._inner.on_unauthorized(response)
