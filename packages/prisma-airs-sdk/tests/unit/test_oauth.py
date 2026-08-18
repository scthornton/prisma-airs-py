"""OAuth2 credential resolution and token lifecycle."""

from __future__ import annotations

import base64
import threading

import httpx
import pytest
import respx

from prisma_airs.auth.oauth import OAuthClient, resolve_credentials
from prisma_airs.constants import DEFAULT_TOKEN_ENDPOINT
from prisma_airs.errors import AISecMissingVariableError, AISecOAuthError

TOKEN_URL = DEFAULT_TOKEN_ENDPOINT


def token_response(access_token: str = "tok-1", expires_in: int = 900) -> httpx.Response:
    return httpx.Response(
        200,
        json={"access_token": access_token, "token_type": "Bearer", "expires_in": expires_in},
    )


class Clock:
    """A monotonic clock the test drives by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def build_client(clock: Clock, **kwargs: object) -> OAuthClient:
    defaults: dict[str, object] = {
        "client_id": "cid",
        "client_secret": "csecret",
        "tsg_id": "1016244978",
        "monotonic": clock,
    }
    return OAuthClient(**{**defaults, **kwargs})  # type: ignore[arg-type]


class TestResolveCredentials:
    def test_explicit_arguments_win(self) -> None:
        result = resolve_credentials(
            primary_env_prefix="PANW_RED_TEAM",
            client_id="explicit-id",
            client_secret="explicit-secret",
            tsg_id="explicit-tsg",
            env={"PANW_RED_TEAM_CLIENT_ID": "env-id"},
        )

        assert result.client_id == "explicit-id"

    def test_reads_the_service_specific_prefix(self) -> None:
        result = resolve_credentials(
            primary_env_prefix="PANW_RED_TEAM",
            env={
                "PANW_RED_TEAM_CLIENT_ID": "rt-id",
                "PANW_RED_TEAM_CLIENT_SECRET": "rt-secret",
                "PANW_RED_TEAM_TSG_ID": "rt-tsg",
            },
        )

        assert (result.client_id, result.tsg_id) == ("rt-id", "rt-tsg")

    def test_falls_back_to_the_shared_management_prefix(self) -> None:
        """One service account should drive every plane without being repeated."""
        result = resolve_credentials(
            primary_env_prefix="PANW_AI_GW",
            env={
                "PANW_MGMT_CLIENT_ID": "mgmt-id",
                "PANW_MGMT_CLIENT_SECRET": "mgmt-secret",
                "PANW_MGMT_TSG_ID": "mgmt-tsg",
            },
        )

        assert result.client_id == "mgmt-id"

    def test_resolves_each_field_independently(self) -> None:
        """A service-specific ID can combine with a shared tenant ID."""
        result = resolve_credentials(
            primary_env_prefix="PANW_MODEL_SEC",
            env={
                "PANW_MODEL_SEC_CLIENT_ID": "ms-id",
                "PANW_MODEL_SEC_CLIENT_SECRET": "ms-secret",
                "PANW_MGMT_TSG_ID": "shared-tsg",
            },
        )

        assert (result.client_id, result.tsg_id) == ("ms-id", "shared-tsg")

    def test_ignores_empty_environment_values(self) -> None:
        """An exported-but-blank variable should not shadow the fallback."""
        result = resolve_credentials(
            primary_env_prefix="PANW_AI_GW",
            env={
                "PANW_AI_GW_CLIENT_ID": "",
                "PANW_MGMT_CLIENT_ID": "mgmt-id",
                "PANW_MGMT_CLIENT_SECRET": "s",
                "PANW_MGMT_TSG_ID": "t",
            },
        )

        assert result.client_id == "mgmt-id"

    def test_names_every_missing_variable(self) -> None:
        with pytest.raises(AISecMissingVariableError) as caught:
            resolve_credentials(primary_env_prefix="PANW_MGMT", env={})

        message = str(caught.value)
        assert "PANW_MGMT_CLIENT_ID" in message
        assert "PANW_MGMT_CLIENT_SECRET" in message
        assert "PANW_MGMT_TSG_ID" in message

    def test_mentions_the_fallback_in_the_error(self) -> None:
        """The error should tell you both places the value could have come from."""
        with pytest.raises(AISecMissingVariableError, match="PANW_MGMT_CLIENT_ID"):
            resolve_credentials(primary_env_prefix="PANW_RED_TEAM", env={})

    def test_defaults_the_token_endpoint(self) -> None:
        result = resolve_credentials(
            primary_env_prefix="PANW_MGMT",
            env={
                "PANW_MGMT_CLIENT_ID": "i",
                "PANW_MGMT_CLIENT_SECRET": "s",
                "PANW_MGMT_TSG_ID": "t",
            },
        )

        assert result.token_endpoint == DEFAULT_TOKEN_ENDPOINT

    def test_token_endpoint_is_overridable_per_service(self) -> None:
        result = resolve_credentials(
            primary_env_prefix="PANW_RED_TEAM",
            env={
                "PANW_RED_TEAM_CLIENT_ID": "i",
                "PANW_RED_TEAM_CLIENT_SECRET": "s",
                "PANW_RED_TEAM_TSG_ID": "t",
                "PANW_RED_TEAM_TOKEN_ENDPOINT": "https://auth.example.test/token",
            },
        )

        assert result.token_endpoint == "https://auth.example.test/token"


class TestTokenRequestShape:
    @respx.mock
    def test_sends_basic_auth_and_the_tenant_scope(self) -> None:
        """Matches the reference exactly: Basic credentials, form body, tsg_id scope."""
        route = respx.post(TOKEN_URL).mock(return_value=token_response())
        clock = Clock()

        build_client(clock).get_token()

        sent = route.calls.last.request
        expected = base64.b64encode(b"cid:csecret").decode()
        assert sent.headers["authorization"] == f"Basic {expected}"
        assert sent.headers["content-type"] == "application/x-www-form-urlencoded"
        body = sent.content.decode()
        assert "grant_type=client_credentials" in body
        assert "scope=tsg_id%3A1016244978" in body


class TestTokenCaching:
    @respx.mock
    def test_returns_the_token(self) -> None:
        respx.post(TOKEN_URL).mock(return_value=token_response("abc"))

        assert build_client(Clock()).get_token() == "abc"

    @respx.mock
    def test_reuses_a_live_token(self) -> None:
        route = respx.post(TOKEN_URL).mock(return_value=token_response())
        client = build_client(Clock())

        client.get_token()
        client.get_token()

        assert route.call_count == 1

    @respx.mock
    def test_refreshes_once_inside_the_pre_expiry_buffer(self) -> None:
        """A token must not lapse mid-flight, so it is replaced before it expires."""
        route = respx.post(TOKEN_URL).mock(return_value=token_response(expires_in=900))
        clock = Clock()
        client = build_client(clock)

        client.get_token()
        clock.advance(880)  # 20s left, inside the 30s buffer
        client.get_token()

        assert route.call_count == 2

    @respx.mock
    def test_does_not_refresh_while_comfortably_valid(self) -> None:
        route = respx.post(TOKEN_URL).mock(return_value=token_response(expires_in=900))
        clock = Clock()
        client = build_client(clock)

        client.get_token()
        clock.advance(600)
        client.get_token()

        assert route.call_count == 1

    @respx.mock
    def test_clear_token_forces_a_refetch(self) -> None:
        route = respx.post(TOKEN_URL).mock(return_value=token_response())
        client = build_client(Clock())

        client.get_token()
        client.clear_token()
        client.get_token()

        assert route.call_count == 2

    @respx.mock
    def test_concurrent_callers_collapse_into_one_request(self) -> None:
        """A cold cache under load must not stampede the auth endpoint."""
        route = respx.post(TOKEN_URL).mock(return_value=token_response())
        client = build_client(Clock())
        barrier = threading.Barrier(8)

        def worker() -> None:
            barrier.wait()
            client.get_token()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert route.call_count == 1


class TestTokenInfo:
    @respx.mock
    def test_reports_no_token_before_the_first_fetch(self) -> None:
        info = build_client(Clock()).get_token_info()

        assert not info.has_token
        assert not info.is_valid

    @respx.mock
    def test_reports_a_live_token(self) -> None:
        respx.post(TOKEN_URL).mock(return_value=token_response(expires_in=900))
        client = build_client(Clock())

        client.get_token()
        info = client.get_token_info()

        assert info.has_token
        assert info.is_valid
        assert info.expires_in_ms == pytest.approx(900_000)

    @respx.mock
    def test_flags_a_token_that_is_expiring_soon(self) -> None:
        respx.post(TOKEN_URL).mock(return_value=token_response(expires_in=900))
        clock = Clock()
        client = build_client(clock)

        client.get_token()
        clock.advance(890)

        info = client.get_token_info()
        assert info.is_expiring_soon
        assert not info.is_valid

    @respx.mock
    def test_invokes_the_refresh_callback(self) -> None:
        respx.post(TOKEN_URL).mock(return_value=token_response())
        seen: list[float] = []

        client = build_client(
            Clock(), on_token_refresh=lambda info: seen.append(info.expires_in_ms)
        )
        client.get_token()

        assert seen == [pytest.approx(900_000)]


class TestTokenFailures:
    @respx.mock
    def test_surfaces_the_oauth_error_description(self) -> None:
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                401, json={"error": "invalid_client", "error_description": "Bad credentials"}
            )
        )

        with pytest.raises(AISecOAuthError, match="Bad credentials"):
            build_client(Clock()).get_token()

    @respx.mock
    def test_falls_back_to_the_error_code(self) -> None:
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_scope"})
        )

        with pytest.raises(AISecOAuthError, match="invalid_scope"):
            build_client(Clock()).get_token()

    @respx.mock
    def test_falls_back_to_the_status_for_an_opaque_failure(self) -> None:
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(503, text="<html/>"))

        with pytest.raises(AISecOAuthError, match="503"):
            build_client(Clock()).get_token()

    @respx.mock
    def test_rejects_a_non_json_success_body(self) -> None:
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, text="not json"))

        with pytest.raises(AISecOAuthError, match="not valid JSON"):
            build_client(Clock()).get_token()

    @respx.mock
    def test_rejects_a_response_without_an_access_token(self) -> None:
        respx.post(TOKEN_URL).mock(return_value=httpx.Response(200, json={"expires_in": 900}))

        with pytest.raises(AISecOAuthError, match="access_token"):
            build_client(Clock()).get_token()

    @respx.mock
    def test_rejects_a_non_numeric_expires_in(self) -> None:
        """Without a usable expiry the client cannot know when to refresh."""
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": "soon"})
        )

        with pytest.raises(AISecOAuthError, match="expires_in"):
            build_client(Clock()).get_token()

    @respx.mock
    def test_wraps_a_transport_failure(self) -> None:
        respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("no route to host"))

        with pytest.raises(AISecOAuthError, match="Token request failed"):
            build_client(Clock()).get_token()
