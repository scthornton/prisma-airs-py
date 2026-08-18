"""The request pipeline: URL assembly, body serialisation, headers, and validation."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

import httpx
import pytest
import respx
from pydantic import BaseModel

from prisma_airs._http.transport import RequestSpec, build_url, request, serialize_body
from prisma_airs._http.types import PreparedRequest
from prisma_airs.constants import USER_AGENT
from prisma_airs.errors import AISecClientError, AISecResponseValidationError, AISecServerError

BASE = "https://api.example.test"


class NullAuth:
    """An adapter that authenticates nothing, so tests can isolate the pipeline."""

    def prepare(self, request: PreparedRequest) -> PreparedRequest:
        return request

    def on_unauthorized(self, response: httpx.Response) -> bool:
        del response
        return False


class StampAuth:
    """Records what it saw and stamps a header, to prove ordering."""

    def __init__(self) -> None:
        self.seen: PreparedRequest | None = None

    def prepare(self, request: PreparedRequest) -> PreparedRequest:
        self.seen = request
        return request.with_headers({"x-stamped": "yes"})

    def on_unauthorized(self, response: httpx.Response) -> bool:
        del response
        return False


class Profile(BaseModel):
    name: str
    enabled: bool = True


@pytest.fixture
def client() -> httpx.Client:
    return httpx.Client()


def spec(**overrides: Any) -> RequestSpec[Any]:
    defaults: dict[str, Any] = {
        "method": "GET",
        "base_url": BASE,
        "path": "/v1/thing",
        "auth": NullAuth(),
        "num_retries": 0,
    }
    return RequestSpec(**{**defaults, **overrides})


class TestSerializeBody:
    def test_emits_compact_separators(self) -> None:
        """The payload HMAC is over these exact bytes; whitespace would break it."""
        assert serialize_body({"a": 1, "b": [1, 2]}) == '{"a":1,"b":[1,2]}'

    def test_emits_non_ascii_as_utf8_not_escapes(self) -> None:
        """Python defaults to \\uXXXX escapes, which would change the hashed bytes."""
        assert serialize_body({"prompt": "日本語"}) == '{"prompt":"日本語"}'

    def test_preserves_key_insertion_order(self) -> None:
        assert serialize_body({"z": 1, "a": 2}) == '{"z":1,"a":2}'

    def test_serialises_pydantic_models_by_alias_dropping_unset(self) -> None:
        assert serialize_body(Profile(name="prod")) == '{"name":"prod","enabled":true}'

    def test_preserves_explicit_nulls_in_plain_mappings(self) -> None:
        """JSON.stringify drops `undefined` but keeps `null`, and a dict has no undefined."""
        assert serialize_body({"a": 1, "b": None}) == '{"a":1,"b":null}'

    def test_drops_unset_model_fields(self) -> None:
        """On a model, `None` stands in for `undefined`: the API wants the key absent."""

        class Partial(BaseModel):
            name: str
            note: str | None = None

        assert serialize_body(Partial(name="prod")) == '{"name":"prod"}'


@pytest.mark.parity
class TestSerializationParityWithNode:
    """Differential check against the runtime the reference implementation uses."""

    @pytest.mark.parametrize(
        "value",
        [
            {"a": 1, "b": [1, 2]},
            {"prompt": "日本語 🔐"},
            {"nested": {"x": None, "y": True}},
            {"z": 1, "a": 2},
            {"empty": {}, "list": []},
            {"escaped": 'quote " backslash \\ newline \n'},
            [1, "two", {"three": 3}],
        ],
    )
    def test_matches_json_stringify(self, value: Any) -> None:
        node = shutil.which("node")
        if node is None:
            pytest.skip("node is not installed")

        payload = json.dumps(value)
        result = subprocess.run(  # noqa: S603
            [node, "-e", f"process.stdout.write(JSON.stringify({payload}))"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )

        assert serialize_body(value) == result.stdout


class TestBuildUrl:
    def test_joins_base_and_path(self) -> None:
        assert str(build_url(BASE, "/v1/thing", None)) == f"{BASE}/v1/thing"

    def test_strips_trailing_slashes_from_the_base(self) -> None:
        """Config files and environment variables routinely carry a trailing slash."""
        assert str(build_url(f"{BASE}///", "/v1/thing", None)) == f"{BASE}/v1/thing"

    def test_applies_scalar_parameters(self) -> None:
        url = build_url(BASE, "/v1/thing", {"limit": "10"})

        assert url.params["limit"] == "10"

    def test_expands_sequences_to_repeated_keys(self) -> None:
        """Multi-valued filters arrive as repeated keys, not comma-joined."""
        url = build_url(BASE, "/v1/thing", {"id": ["a", "b"]})

        assert str(url).endswith("id=a&id=b")


class TestRequestPipeline:
    @respx.mock
    def test_sends_the_sdk_user_agent_and_service_name(self, client: httpx.Client) -> None:
        route = respx.get(f"{BASE}/v1/thing").mock(return_value=httpx.Response(200, json={}))

        request(spec(), client=client)

        sent = route.calls.last.request
        assert sent.headers["user-agent"] == USER_AGENT
        assert sent.headers["service-name"] == "api"

    @respx.mock
    def test_applies_the_auth_adapter(self, client: httpx.Client) -> None:
        auth = StampAuth()
        route = respx.get(f"{BASE}/v1/thing").mock(return_value=httpx.Response(200, json={}))

        request(spec(auth=auth), client=client)

        assert route.calls.last.request.headers["x-stamped"] == "yes"

    @respx.mock
    def test_serialises_the_body_before_auth_sees_it(self, client: httpx.Client) -> None:
        """The scan service hashes the body, so adapters must see the final bytes."""
        auth = StampAuth()
        respx.post(f"{BASE}/v1/thing").mock(return_value=httpx.Response(200, json={}))

        request(spec(method="POST", auth=auth, body={"a": 1}), client=client)

        assert auth.seen is not None
        assert auth.seen.body_text == '{"a":1}'

    @respx.mock
    def test_defaults_the_json_content_type(self, client: httpx.Client) -> None:
        route = respx.post(f"{BASE}/v1/thing").mock(return_value=httpx.Response(200, json={}))

        request(spec(method="POST", body={"a": 1}), client=client)

        assert route.calls.last.request.headers["content-type"] == "application/json"

    @respx.mock
    def test_honours_a_content_type_override(self, client: httpx.Client) -> None:
        """Several DLP endpoints reject application/json and require merge-patch."""
        route = respx.patch(f"{BASE}/v1/thing").mock(return_value=httpx.Response(200, json={}))

        request(
            spec(method="PATCH", body={"a": 1}, content_type="application/merge-patch+json"),
            client=client,
        )

        assert route.calls.last.request.headers["content-type"] == "application/merge-patch+json"

    @respx.mock
    def test_validates_the_response_into_the_declared_model(self, client: httpx.Client) -> None:
        respx.get(f"{BASE}/v1/thing").mock(
            return_value=httpx.Response(200, json={"name": "prod", "enabled": False})
        )

        result = request(spec(response_model=Profile), client=client)

        assert result == Profile(name="prod", enabled=False)

    @respx.mock
    def test_returns_none_when_no_model_is_declared(self, client: httpx.Client) -> None:
        respx.get(f"{BASE}/v1/thing").mock(return_value=httpx.Response(200, json={"junk": 1}))

        assert request(spec(), client=client) is None

    @respx.mock
    def test_hydrates_an_empty_body_to_an_object(self, client: httpx.Client) -> None:
        """The API omits the body entirely when a query has no results."""

        class AllOptional(BaseModel):
            items: list[str] = []

        respx.get(f"{BASE}/v1/thing").mock(return_value=httpx.Response(200, text=""))

        assert request(spec(response_model=AllOptional), client=client) == AllOptional()

    @respx.mock
    def test_allow_empty_body_short_circuits_validation(self, client: httpx.Client) -> None:
        """Some endpoints answer 200+body or 204+nothing from the same call."""
        respx.put(f"{BASE}/v1/thing").mock(return_value=httpx.Response(204, text=""))

        result = request(
            spec(method="PUT", response_model=Profile, allow_empty_body=True), client=client
        )

        assert result is None

    @respx.mock
    def test_rejects_a_non_json_success_body(self, client: httpx.Client) -> None:
        respx.get(f"{BASE}/v1/thing").mock(return_value=httpx.Response(200, text="<html/>"))

        with pytest.raises(AISecResponseValidationError, match="not valid JSON"):
            request(spec(response_model=Profile), client=client)

    @respx.mock
    def test_rejects_a_body_that_does_not_match_the_model(self, client: httpx.Client) -> None:
        respx.get(f"{BASE}/v1/thing").mock(return_value=httpx.Response(200, json={"wrong": 1}))

        with pytest.raises(AISecResponseValidationError, match="did not match schema"):
            request(spec(response_model=Profile), client=client)

    @respx.mock
    def test_maps_a_client_error(self, client: httpx.Client) -> None:
        respx.get(f"{BASE}/v1/thing").mock(
            return_value=httpx.Response(404, json={"message": "no such profile"})
        )

        with pytest.raises(AISecClientError) as caught:
            request(spec(), client=client)

        assert caught.value.status_code == 404
        assert caught.value.raw_message == "no such profile"

    @respx.mock
    def test_maps_a_server_error(self, client: httpx.Client) -> None:
        respx.get(f"{BASE}/v1/thing").mock(return_value=httpx.Response(500, json={"msg": "boom"}))

        with pytest.raises(AISecServerError):
            request(spec(), client=client)

    @respx.mock
    def test_offers_the_auth_adapter_only_one_free_retry(self, client: httpx.Client) -> None:
        """Without the guard, a 403 for a non-auth reason would loop forever."""
        attempts = 0

        class AlwaysRetryAuth(NullAuth):
            def on_unauthorized(self, response: httpx.Response) -> bool:
                del response
                return True

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(403, json={"msg": "denied"})

        respx.get(f"{BASE}/v1/thing").mock(side_effect=handler)

        with pytest.raises(AISecClientError):
            request(spec(auth=AlwaysRetryAuth()), client=client)

        assert attempts == 2  # the original, plus exactly one free retry
