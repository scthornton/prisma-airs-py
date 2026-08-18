"""Authentication adapters for the three credential schemes."""

from __future__ import annotations

import httpx
import pytest

from prisma_airs._http.auth import ApiKeyAuth, OAuthAuth, TsgHeaderAuth
from prisma_airs._http.types import PreparedRequest
from prisma_airs._utils import generate_payload_hash
from prisma_airs.errors import AISecMissingVariableError

URL = httpx.URL("https://api.example.test/v1/scan")


def prepared(body: str | None = None) -> PreparedRequest:
    return PreparedRequest(method="POST", url=URL, headers={"User-Agent": "test"}, body_text=body)


class FakeOAuthClient:
    """Stands in for OAuthClient without touching the network."""

    def __init__(self, token: str = "tok-abc") -> None:
        self.token = token
        self.cleared = 0

    def get_token(self) -> str:
        return self.token

    def clear_token(self) -> None:
        self.cleared += 1


class TestApiKeyAuth:
    def test_requires_at_least_one_credential(self) -> None:
        with pytest.raises(AISecMissingVariableError, match="api_key or api_token"):
            ApiKeyAuth()

    def test_sets_the_api_key_header(self) -> None:
        result = ApiKeyAuth(api_key="k1").prepare(prepared())

        assert result.headers["x-pan-token"] == "k1"

    def test_sets_a_bearer_header_for_a_token(self) -> None:
        result = ApiKeyAuth(api_token="t1").prepare(prepared())

        assert result.headers["Authorization"] == "Bearer t1"

    def test_hashes_the_body_when_a_key_and_body_are_present(self) -> None:
        body = '{"prompt":"hi"}'

        result = ApiKeyAuth(api_key="k1").prepare(prepared(body))

        assert result.headers["x-payload-hash"] == generate_payload_hash(body, "k1")

    def test_omits_the_payload_hash_when_there_is_no_body(self) -> None:
        result = ApiKeyAuth(api_key="k1").prepare(prepared())

        assert "x-payload-hash" not in result.headers

    def test_omits_the_payload_hash_when_only_a_token_is_configured(self) -> None:
        """The hash is keyed by the API key, so a token alone cannot produce one."""
        result = ApiKeyAuth(api_token="t1").prepare(prepared('{"a":1}'))

        assert "x-payload-hash" not in result.headers

    def test_preserves_existing_headers(self) -> None:
        result = ApiKeyAuth(api_key="k1").prepare(prepared())

        assert result.headers["User-Agent"] == "test"

    def test_never_requests_a_retry(self) -> None:
        """A rejected API key will be rejected again; retrying only burns quota."""
        auth = ApiKeyAuth(api_key="k1")

        assert not auth.on_unauthorized(httpx.Response(401, request=httpx.Request("GET", URL)))


class TestOAuthAuth:
    def test_attaches_a_bearer_token(self) -> None:
        result = OAuthAuth(FakeOAuthClient()).prepare(prepared())  # type: ignore[arg-type]

        assert result.headers["Authorization"] == "Bearer tok-abc"

    @pytest.mark.parametrize("status", [401, 403])
    def test_clears_the_token_and_retries_on_auth_failure(self, status: int) -> None:
        """403 is included: the management planes use it for an expired token."""
        fake = FakeOAuthClient()
        auth = OAuthAuth(fake)  # type: ignore[arg-type]

        retried = auth.on_unauthorized(httpx.Response(status, request=httpx.Request("GET", URL)))

        assert retried
        assert fake.cleared == 1

    @pytest.mark.parametrize("status", [400, 404, 429, 500])
    def test_leaves_other_statuses_alone(self, status: int) -> None:
        fake = FakeOAuthClient()
        auth = OAuthAuth(fake)  # type: ignore[arg-type]

        assert not auth.on_unauthorized(httpx.Response(status, request=httpx.Request("GET", URL)))
        assert fake.cleared == 0


class TestTsgHeaderAuth:
    def test_adds_the_tenant_header(self) -> None:
        """Omitting x-tsg-id yields a 403 that looks exactly like an expired token."""
        inner = OAuthAuth(FakeOAuthClient())  # type: ignore[arg-type]

        result = TsgHeaderAuth(inner, "1016244978").prepare(prepared())

        assert result.headers["x-tsg-id"] == "1016244978"

    def test_preserves_the_wrapped_adapter_headers(self) -> None:
        inner = OAuthAuth(FakeOAuthClient())  # type: ignore[arg-type]

        result = TsgHeaderAuth(inner, "123").prepare(prepared())

        assert result.headers["Authorization"] == "Bearer tok-abc"

    def test_delegates_the_retry_decision(self) -> None:
        """Composition must not lose the token-refresh behaviour it wraps."""
        fake = FakeOAuthClient()
        auth = TsgHeaderAuth(OAuthAuth(fake), "123")  # type: ignore[arg-type]

        retried = auth.on_unauthorized(httpx.Response(401, request=httpx.Request("GET", URL)))

        assert retried
        assert fake.cleared == 1
