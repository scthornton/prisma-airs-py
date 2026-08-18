"""Shared types for the request pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Literal, Protocol, runtime_checkable

import httpx

HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]


@dataclass(frozen=True)
class PreparedRequest:
    """An outbound request as an :class:`AuthAdapter` sees it.

    The body is already serialised to ``body_text`` before adapters run, because the
    scan service's payload hash is computed over the exact bytes that go on the wire.
    Adapters add headers; by convention they do not touch the body.
    """

    method: HttpMethod
    url: httpx.URL
    headers: dict[str, str] = field(default_factory=dict)
    body_text: str | None = None

    def with_headers(self, extra: dict[str, str]) -> PreparedRequest:
        """Return a copy with ``extra`` merged over the existing headers."""
        return replace(self, headers={**self.headers, **extra})


@runtime_checkable
class AuthAdapter(Protocol):
    """Pluggable authentication strategy.

    ``prepare`` augments an outbound request, normally with credential headers.
    ``on_unauthorized`` is consulted at most once per request after an authentication
    failure; returning ``True`` grants a retry that does not consume the retry budget.
    """

    def prepare(self, request: PreparedRequest) -> PreparedRequest:
        """Return ``request`` with authentication applied."""
        ...

    def on_unauthorized(self, response: httpx.Response) -> bool:
        """Report whether ``response`` warrants a free authentication retry."""
        ...
