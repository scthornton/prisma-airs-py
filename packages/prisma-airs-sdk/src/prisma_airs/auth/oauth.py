"""OAuth2 client-credentials token management for the Prisma AIRS management planes.

One service account drives the management, AI gateway, red team, and model security
clients. Each client may declare its own environment prefix and falls back to
``PANW_MGMT_*``, so a single set of credentials works everywhere without being repeated.

Token expiry is tracked on a monotonic clock rather than wall time. Access tokens live
about fifteen minutes, which is comfortably inside the window where an NTP correction or
a laptop resuming from sleep could otherwise make a live token look expired -- or worse,
an expired one look live.
"""

from __future__ import annotations

import base64
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final

import httpx

from prisma_airs.constants import (
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TOKEN_ENDPOINT,
    ENV_PREFIX_MGMT,
    USER_AGENT,
)
from prisma_airs.errors import AISecMissingVariableError, AISecOAuthError

#: Refresh this far ahead of expiry, so a token cannot lapse mid-flight.
DEFAULT_TOKEN_BUFFER_MS: Final = 30_000.0


@dataclass(frozen=True)
class TokenInfo:
    """A snapshot of token state, for diagnostics."""

    has_token: bool
    is_valid: bool
    is_expired: bool
    is_expiring_soon: bool
    expires_in_ms: float


@dataclass(frozen=True)
class ResolvedCredentials:
    """OAuth2 credentials resolved from arguments and the environment."""

    client_id: str
    client_secret: str
    tsg_id: str
    token_endpoint: str


def resolve_credentials(
    *,
    primary_env_prefix: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    tsg_id: str | None = None,
    token_endpoint: str | None = None,
    fallback_env_prefix: str | None = ENV_PREFIX_MGMT,
    env: Mapping[str, str] | None = None,
) -> ResolvedCredentials:
    """Resolve credentials from explicit arguments, then environment prefixes.

    Precedence is argument, then ``{primary_env_prefix}_*``, then
    ``{fallback_env_prefix}_*``. Each field resolves independently, so a service-specific
    client ID can be combined with a shared tenant ID.

    Args:
        primary_env_prefix: Service-specific prefix, e.g. ``PANW_RED_TEAM``.
        client_id: Explicit client ID.
        client_secret: Explicit client secret.
        tsg_id: Explicit Tenant Service Group ID.
        token_endpoint: Explicit token endpoint.
        fallback_env_prefix: Prefix consulted when the primary is unset.
        env: Environment mapping, for testing.

    Returns:
        Fully resolved credentials.

    Raises:
        AISecMissingVariableError: If any required field could not be resolved.
    """
    environ: Mapping[str, str] = env if env is not None else os.environ

    def lookup(suffix: str, explicit: str | None) -> str | None:
        if explicit:
            return explicit
        primary = environ.get(f"{primary_env_prefix}_{suffix}")
        if primary:
            return primary
        if fallback_env_prefix:
            return environ.get(f"{fallback_env_prefix}_{suffix}")
        return None

    resolved_id = lookup("CLIENT_ID", client_id)
    resolved_secret = lookup("CLIENT_SECRET", client_secret)
    resolved_tsg = lookup("TSG_ID", tsg_id)

    if not resolved_id or not resolved_secret or not resolved_tsg:
        missing = [
            name
            for name, value in (
                ("CLIENT_ID", resolved_id),
                ("CLIENT_SECRET", resolved_secret),
                ("TSG_ID", resolved_tsg),
            )
            if not value
        ]
        expected = ", ".join(f"{primary_env_prefix}_{name}" for name in missing)
        fallback_hint = (
            f" (or {', '.join(f'{fallback_env_prefix}_{name}' for name in missing)})"
            if fallback_env_prefix
            else ""
        )
        raise AISecMissingVariableError(f"Missing OAuth2 credentials: {expected}{fallback_hint}")

    return ResolvedCredentials(
        client_id=resolved_id,
        client_secret=resolved_secret,
        tsg_id=resolved_tsg,
        token_endpoint=(token_endpoint or lookup("TOKEN_ENDPOINT", None) or DEFAULT_TOKEN_ENDPOINT),
    )


class OAuthClient:
    """Fetches and caches an OAuth2 access token for one tenant.

    Instances are safe to share across threads: concurrent callers arriving on a cold or
    expired cache collapse into a single token request rather than stampeding the auth
    endpoint.
    """

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        tsg_id: str,
        token_endpoint: str = DEFAULT_TOKEN_ENDPOINT,
        token_buffer_ms: float = DEFAULT_TOKEN_BUFFER_MS,
        on_token_refresh: Callable[[TokenInfo], None] | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._tsg_id = tsg_id
        self._token_endpoint = token_endpoint
        self._token_buffer_ms = token_buffer_ms
        self._on_token_refresh = on_token_refresh
        self._monotonic = monotonic
        self._timeout = timeout

        self._owns_client = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)

        self._lock = threading.Lock()
        self._access_token: str | None = None
        self._expires_at: float = 0.0

    @property
    def tsg_id(self) -> str:
        """The tenant this client authenticates against."""
        return self._tsg_id

    def get_token(self) -> str:
        """Return a valid access token, fetching or refreshing as needed."""
        with self._lock:
            if self._access_token is not None and not self._needs_refresh():
                return self._access_token
            return self._fetch_token()

    def clear_token(self) -> None:
        """Discard the cached token so the next call fetches a fresh one."""
        with self._lock:
            self._access_token = None
            self._expires_at = 0.0

    def get_token_info(self) -> TokenInfo:
        """Return current token state without triggering a fetch."""
        with self._lock:
            if self._access_token is None:
                return TokenInfo(
                    has_token=False,
                    is_valid=False,
                    is_expired=False,
                    is_expiring_soon=False,
                    expires_in_ms=0.0,
                )
            remaining_ms = max(0.0, (self._expires_at - self._monotonic()) * 1000)
            return TokenInfo(
                has_token=True,
                is_valid=not self._needs_refresh(),
                is_expired=remaining_ms <= 0,
                is_expiring_soon=0 < remaining_ms <= self._token_buffer_ms,
                expires_in_ms=remaining_ms,
            )

    def close(self) -> None:
        """Close the underlying HTTP client, if this instance created it."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> OAuthClient:
        """Enter a context that closes the HTTP client on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the HTTP client if this instance owns it."""
        self.close()

    def _needs_refresh(self) -> bool:
        """Report whether the cached token is expired or inside the pre-expiry buffer."""
        remaining_ms = (self._expires_at - self._monotonic()) * 1000
        return remaining_ms <= self._token_buffer_ms

    def _fetch_token(self) -> str:
        """Request a new token. Callers must hold the lock."""
        credentials = base64.b64encode(f"{self._client_id}:{self._client_secret}".encode()).decode()

        try:
            response = self._http.post(
                self._token_endpoint,
                headers={
                    "Authorization": f"Basic {credentials}",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": USER_AGENT,
                },
                data={
                    "grant_type": "client_credentials",
                    "scope": f"tsg_id:{self._tsg_id}",
                },
                timeout=self._timeout,
            )
        except httpx.HTTPError as err:
            raise AISecOAuthError(f"Token request failed: {err}") from err

        if not response.is_success:
            raise AISecOAuthError(_token_error_message(response))

        try:
            payload = response.json()
        except ValueError as err:
            raise AISecOAuthError("Token response is not valid JSON") from err

        access_token = payload.get("access_token") if isinstance(payload, dict) else None
        expires_in = payload.get("expires_in") if isinstance(payload, dict) else None
        if not isinstance(access_token, str) or not access_token:
            raise AISecOAuthError("Token response did not contain an access_token")
        if not isinstance(expires_in, (int, float)) or isinstance(expires_in, bool):
            raise AISecOAuthError("Token response did not contain a numeric expires_in")

        self._access_token = access_token
        self._expires_at = self._monotonic() + float(expires_in)

        if self._on_token_refresh is not None:
            remaining_ms = max(0.0, (self._expires_at - self._monotonic()) * 1000)
            self._on_token_refresh(
                TokenInfo(
                    has_token=True,
                    is_valid=True,
                    is_expired=False,
                    is_expiring_soon=remaining_ms <= self._token_buffer_ms,
                    expires_in_ms=remaining_ms,
                )
            )

        return access_token


def _token_error_message(response: httpx.Response) -> str:
    """Extract an OAuth2 error message, falling back to the status code."""
    try:
        body = response.json()
    except ValueError:
        return f"Token request failed with status {response.status_code}"
    if not isinstance(body, dict):
        return f"Token request failed with status {response.status_code}"
    message = body.get("error_description") or body.get("error")
    return str(message) if message else f"Token request failed with status {response.status_code}"
