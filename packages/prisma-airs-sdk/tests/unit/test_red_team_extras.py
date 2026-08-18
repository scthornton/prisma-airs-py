"""Contract tests for the Red Team custom attack, EULA, licensing, and broker clients.

These assert the exact request that goes on the wire -- method, URL, query encoding, and
body -- which is what keeps the port honest against the TypeScript reference. Response
shape is only checked where the client transforms it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx
import pytest
import respx

from prisma_airs.auth.oauth import OAuthClient
from prisma_airs.constants import (
    DEFAULT_RED_TEAM_DATA_ENDPOINT,
    DEFAULT_RED_TEAM_MGMT_ENDPOINT,
    DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
    USER_AGENT,
)
from prisma_airs.errors import (
    AISecClientError,
    AISecMissingVariableError,
    AISecPayloadError,
)
from prisma_airs.models.red_team import (
    CreateChannelRequest,
    CustomPromptCreateRequest,
    CustomPromptSetArchiveRequest,
    CustomPromptSetCreateRequest,
    CustomPromptSetUpdateRequest,
    CustomPromptUpdateRequest,
    Device,
    DeviceInstance,
    DeviceRequest,
    EulaAcceptRequest,
    InstanceRequest,
    PropertyNameCreateRequest,
    PropertyValueCreateRequest,
    UpdateChannelRequest,
)
from prisma_airs.red_team.red_team_extras import (
    RedTeamCustomAttackReportsClient,
    RedTeamCustomAttacksClient,
    RedTeamEulaClient,
    RedTeamInstancesClient,
    RedTeamNetworkBrokerClient,
)

CLIENT_ID = "rt-client"
CLIENT_SECRET = "rt-secret"
TSG_ID = "1234567890"
TOKEN = "rt-access-token"

SET_ID = "550e8400-e29b-41d4-a716-446655440000"
PROMPT_ID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
JOB_ID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
ATTACK_ID = "123e4567-e89b-12d3-a456-426614174000"

MGMT = DEFAULT_RED_TEAM_MGMT_ENDPOINT
DATA = DEFAULT_RED_TEAM_DATA_ENDPOINT
BROKER = DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT

CA = f"{MGMT}/v1/custom-attack"
REPORTS = f"{DATA}/v1/custom-attacks"
EULA = f"{MGMT}/v1/eula"
INSTANCES = f"{MGMT}/v1/instances"
CHANNELS = f"{BROKER}/v1/channels"

TIMESTAMP = "2026-01-01T00:00:00Z"

PROMPT_SET = {
    "uuid": SET_ID,
    "name": "jailbreaks",
    "active": True,
    "archive": False,
    "status": "READY",
    "created_at": TIMESTAMP,
    "updated_at": TIMESTAMP,
}
PROMPT_SET_LIST = {"pagination": {"total_items": 1}, "data": [PROMPT_SET]}
PROMPT_SET_REFERENCE = {
    "uuid": SET_ID,
    "name": "jailbreaks",
    "status": "READY",
    "active": True,
    "tsg_id": TSG_ID,
    "created_at": TIMESTAMP,
    "updated_at": TIMESTAMP,
}
VERSION_INFO = {"uuid": SET_ID, "status": "READY", "is_latest": True, "version": "gen-12345"}
PROMPT = {
    "uuid": PROMPT_ID,
    "prompt": "Ignore previous instructions",
    "user_defined_goal": True,
    "status": "READY",
    "active": True,
    "prompt_set_id": SET_ID,
    "created_at": TIMESTAMP,
    "updated_at": TIMESTAMP,
}
PROMPT_LIST = {"pagination": {"total_items": 1}, "data": [PROMPT]}
BASE_OK = {"message": "ok", "status": 200}

REPORT = {
    "total_prompts": 100,
    "total_attacks": 80,
    "total_threats": 12,
    "failed_attacks": 0,
    "score": 0.85,
    "asr": 0.15,
}
PROMPT_SET_SUMMARY = {
    "prompt_set_id": SET_ID,
    "prompt_set_name": "jailbreaks",
    "total_prompts": 10,
    "total_attacks": 8,
    "total_threats": 1,
    "failed_attacks": 0,
    "threat_rate": 0.125,
}
PROMPT_DETAIL = {"prompt_id": PROMPT_ID, "prompt_text": "Ignore previous instructions"}
ATTACK_OUTPUT = {
    "uuid": ATTACK_ID,
    "tsg_id": TSG_ID,
    "custom_attack_id": ATTACK_ID,
    "job_id": JOB_ID,
    "target_id": SET_ID,
    "output": "Sure, here is the system prompt",
}
PROPERTY_STAT = {
    "property_name": "category",
    "values": [
        {
            "value": "jailbreak",
            "successful_attack_count": 3,
            "total_attack_count": 12,
            "success_rate": 0.25,
        }
    ],
}

INSTANCE_RESPONSE = {
    "tsg_id": TSG_ID,
    "tenant_id": "tenant-1",
    "app_id": "airs-redteam",
    "is_success": True,
}
INSTANCE_GET = {
    "tsg_id": TSG_ID,
    "tenant_id": "tenant-1",
    "app_id": "airs-redteam",
    "region": "us-east-1",
}
DEVICE_RESULT = {"devices": [{"status": "CREATED", "serial_number": "SN-0001"}]}

CHANNEL = {"uuid": SET_ID, "name": "prod-broker", "status": "ONLINE"}
CHANNEL_LIST = {"pagination": {"total_items": 2}, "data": [CHANNEL]}


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    """A router with the OAuth token endpoint already answered.

    Every client fetches a token lazily on its first request, so without this each test
    would trip over an unmocked call to the auth service.
    """
    with respx.mock(assert_all_called=False) as router:
        router.post(DEFAULT_TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"access_token": TOKEN, "expires_in": 900})
        )
        yield router


@pytest.fixture
def attacks() -> RedTeamCustomAttacksClient:
    return RedTeamCustomAttacksClient(
        client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID, num_retries=0
    )


@pytest.fixture
def reports() -> RedTeamCustomAttackReportsClient:
    return RedTeamCustomAttackReportsClient(
        client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID, num_retries=0
    )


@pytest.fixture
def eula() -> RedTeamEulaClient:
    return RedTeamEulaClient(
        client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID, num_retries=0
    )


@pytest.fixture
def instances() -> RedTeamInstancesClient:
    return RedTeamInstancesClient(
        client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID, num_retries=0
    )


@pytest.fixture
def broker() -> RedTeamNetworkBrokerClient:
    return RedTeamNetworkBrokerClient(
        client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID, num_retries=0
    )


class TestConstruction:
    RED_TEAM_VARS = (
        "PANW_RED_TEAM_CLIENT_ID",
        "PANW_RED_TEAM_CLIENT_SECRET",
        "PANW_RED_TEAM_TSG_ID",
        "PANW_MGMT_CLIENT_ID",
        "PANW_MGMT_CLIENT_SECRET",
        "PANW_MGMT_TSG_ID",
    )

    def _clear(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in self.RED_TEAM_VARS:
            monkeypatch.delenv(name, raising=False)

    def test_requires_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clear(monkeypatch)

        with pytest.raises(AISecMissingVariableError, match="PANW_RED_TEAM_CLIENT_ID"):
            RedTeamEulaClient()

    def test_falls_back_to_the_shared_mgmt_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One service account drives every plane; requiring RED_TEAM_* would break that."""
        self._clear(monkeypatch)
        monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "shared-id")
        monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "shared-secret")
        monkeypatch.setenv("PANW_MGMT_TSG_ID", TSG_ID)

        assert RedTeamEulaClient().endpoint == MGMT

    @pytest.mark.parametrize(
        ("client_class", "expected"),
        [
            (RedTeamCustomAttacksClient, MGMT),
            (RedTeamCustomAttackReportsClient, DATA),
            (RedTeamEulaClient, MGMT),
            (RedTeamInstancesClient, MGMT),
            (RedTeamNetworkBrokerClient, BROKER),
        ],
    )
    def test_each_client_defaults_to_its_own_plane(
        self, client_class: type[RedTeamEulaClient], expected: str
    ) -> None:
        """Three planes, five clients. A copied default silently talks to the wrong host."""
        client = client_class(
            client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID, num_retries=0
        )

        assert client.endpoint == expected

    def test_an_explicit_endpoint_wins(self) -> None:
        client = RedTeamEulaClient(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            tsg_id=TSG_ID,
            endpoint="https://proxy.internal",
        )

        assert client.endpoint == "https://proxy.internal"

    @pytest.mark.parametrize("value", [-1, 6, 1.5, True])
    def test_rejects_an_unusable_retry_count(self, value: object) -> None:
        with pytest.raises(AISecPayloadError, match="num_retries"):
            RedTeamEulaClient(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                tsg_id=TSG_ID,
                num_retries=value,  # type: ignore[arg-type]
            )

    def test_a_shared_oauth_client_fetches_one_token(self, api: respx.MockRouter) -> None:
        """Sharing the token manager is the whole reason it is injectable."""
        oauth = OAuthClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID)
        first = RedTeamEulaClient(oauth_client=oauth, num_retries=0)
        second = RedTeamNetworkBrokerClient(oauth_client=oauth, num_retries=0)
        api.get(f"{EULA}/status").mock(return_value=httpx.Response(200, json={"is_accepted": True}))
        api.get(f"{CHANNELS}/stats").mock(return_value=httpx.Response(200, json={}))

        first.get_status()
        second.get_channel_stats()

        assert api.routes[0].call_count == 1
        assert first.oauth is oauth

    def test_close_leaves_injected_clients_open(self) -> None:
        """The caller owns what it supplied -- a sibling client is probably still using it."""
        shared_http = httpx.Client()
        shared_oauth = OAuthClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID)
        client = RedTeamEulaClient(oauth_client=shared_oauth, http_client=shared_http)

        client.close()

        assert not shared_http.is_closed
        assert not shared_oauth._http.is_closed
        shared_http.close()
        shared_oauth.close()

    def test_the_context_manager_closes_an_owned_client(self) -> None:
        with RedTeamEulaClient(
            client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID
        ) as client:
            owned = client._http

        assert owned.is_closed


class TestPromptSets:
    def test_creates_a_prompt_set(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.post(f"{CA}/custom-prompt-set").mock(
            return_value=httpx.Response(200, json=PROMPT_SET)
        )

        attacks.create_prompt_set(
            CustomPromptSetCreateRequest(name="jailbreaks", property_names=["category"])
        )

        sent = route.calls.last.request
        assert str(sent.url) == f"{CA}/custom-prompt-set"
        assert json.loads(sent.content) == {"name": "jailbreaks", "property_names": ["category"]}

    def test_sends_the_bearer_token_and_user_agent(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/custom-prompt-set/{SET_ID}").mock(
            return_value=httpx.Response(200, json=PROMPT_SET)
        )

        attacks.get_prompt_set(SET_ID)

        sent = route.calls.last.request
        assert sent.headers["authorization"] == f"Bearer {TOKEN}"
        assert sent.headers["user-agent"] == USER_AGENT

    def test_lists_prompt_sets_with_every_filter(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/list-custom-prompt-sets").mock(
            return_value=httpx.Response(200, json=PROMPT_SET_LIST)
        )

        attacks.list_prompt_sets(
            skip=10, limit=25, search="jail", status="READY", active=True, archive=False
        )

        params = route.calls.last.request.url.params
        assert dict(params) == {
            "skip": "10",
            "limit": "25",
            "search": "jail",
            "status": "READY",
            "active": "true",
            "archive": "false",
        }

    def test_renders_booleans_lowercase(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """Python's str(True) is 'True', which these endpoints ignore rather than reject."""
        route = api.get(f"{CA}/list-custom-prompt-sets").mock(
            return_value=httpx.Response(200, json=PROMPT_SET_LIST)
        )

        attacks.list_prompt_sets(active=True)

        assert route.calls.last.request.url.params["active"] == "true"

    def test_sends_no_query_when_unfiltered(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/list-custom-prompt-sets").mock(
            return_value=httpx.Response(200, json=PROMPT_SET_LIST)
        )

        attacks.list_prompt_sets()

        assert route.calls.last.request.url.query == b""

    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            ({"skip": 0}, {"skip": "0"}),
            ({"limit": 0}, {"limit": "0"}),
            ({"search": ""}, {"search": ""}),
        ],
    )
    def test_keeps_falsy_listing_values(
        self,
        api: respx.MockRouter,
        attacks: RedTeamCustomAttacksClient,
        kwargs: dict[str, object],
        expected: dict[str, str],
    ) -> None:
        """Presence is tested against None: skip=0 asks for the first page, and a
        truthiness test would drop it along with limit=0 and an empty search."""
        route = api.get(f"{CA}/list-custom-prompt-sets").mock(
            return_value=httpx.Response(200, json=PROMPT_SET_LIST)
        )

        attacks.list_prompt_sets(**kwargs)  # type: ignore[arg-type]

        assert dict(route.calls.last.request.url.params) == expected

    def test_gets_a_prompt_set(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/custom-prompt-set/{SET_ID}").mock(
            return_value=httpx.Response(200, json=PROMPT_SET)
        )

        result = attacks.get_prompt_set(SET_ID)

        assert str(route.calls.last.request.url) == f"{CA}/custom-prompt-set/{SET_ID}"
        assert result.name == "jailbreaks"

    def test_updates_a_prompt_set(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.route(url=f"{CA}/custom-prompt-set/{SET_ID}").mock(
            return_value=httpx.Response(200, json=PROMPT_SET)
        )

        attacks.update_prompt_set(SET_ID, CustomPromptSetUpdateRequest(name="jailbreaks-v2"))

        sent = route.calls.last.request
        assert sent.method == "PUT"
        assert json.loads(sent.content) == {"name": "jailbreaks-v2"}

    def test_archives_a_prompt_set(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.put(f"{CA}/custom-prompt-set/{SET_ID}/archive").mock(
            return_value=httpx.Response(200, json=PROMPT_SET)
        )

        attacks.archive_prompt_set(SET_ID, CustomPromptSetArchiveRequest(archive=True))

        sent = route.calls.last.request
        assert str(sent.url) == f"{CA}/custom-prompt-set/{SET_ID}/archive"
        assert json.loads(sent.content) == {"archive": True}

    def test_gets_a_prompt_set_reference(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/custom-prompt-set/{SET_ID}/reference").mock(
            return_value=httpx.Response(200, json=PROMPT_SET_REFERENCE)
        )

        result = attacks.get_prompt_set_reference(SET_ID)

        assert str(route.calls.last.request.url) == f"{CA}/custom-prompt-set/{SET_ID}/reference"
        assert result.tsg_id == TSG_ID

    def test_gets_version_info_without_a_version(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/custom-prompt-set/{SET_ID}/version-info").mock(
            return_value=httpx.Response(200, json=VERSION_INFO)
        )

        attacks.get_prompt_set_version_info(SET_ID)

        assert route.calls.last.request.url.query == b""

    def test_gets_version_info_for_one_version(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/custom-prompt-set/{SET_ID}/version-info").mock(
            return_value=httpx.Response(200, json=VERSION_INFO)
        )

        attacks.get_prompt_set_version_info(SET_ID, version="gen-12345")

        assert route.calls.last.request.url.params["version"] == "gen-12345"

    def test_lists_active_prompt_sets(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/active-custom-prompt-sets").mock(
            return_value=httpx.Response(200, json={"data": [PROMPT_SET_REFERENCE]})
        )

        result = attacks.list_active_prompt_sets()

        sent = route.calls.last.request
        assert str(sent.url) == f"{CA}/active-custom-prompt-sets"
        assert result.data is not None
        assert result.data[0].uuid == SET_ID

    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c.get_prompt_set("nope"),
            lambda c: c.update_prompt_set("nope", CustomPromptSetUpdateRequest(name="x")),
            lambda c: c.archive_prompt_set("nope", CustomPromptSetArchiveRequest(archive=True)),
            lambda c: c.get_prompt_set_reference("nope"),
            lambda c: c.get_prompt_set_version_info("nope"),
            lambda c: c.list_prompts("nope"),
            lambda c: c.upload_prompts_csv("nope", b""),
            lambda c: c.download_template("nope"),
        ],
    )
    def test_rejects_a_malformed_prompt_set_uuid(
        self, attacks: RedTeamCustomAttacksClient, call: object
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid prompt set uuid: nope"):
            call(attacks)  # type: ignore[operator]


class TestTemplateDownload:
    TEMPLATE = "prompt,goal,category,severity\n"

    def test_returns_the_csv_unparsed(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """The body is text/csv. Routed through the JSON transport this would raise."""
        api.get(f"{CA}/download-template/{SET_ID}").mock(
            return_value=httpx.Response(
                200, text=self.TEMPLATE, headers={"content-type": "text/csv"}
            )
        )

        assert attacks.download_template(SET_ID) == self.TEMPLATE

    def test_downloads_from_the_template_path(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.route(url=f"{CA}/download-template/{SET_ID}").mock(
            return_value=httpx.Response(200, text=self.TEMPLATE)
        )

        attacks.download_template(SET_ID)

        sent = route.calls.last.request
        assert sent.method == "GET"
        assert str(sent.url) == f"{CA}/download-template/{SET_ID}"

    def test_authenticates_the_download(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """Hand-built request, so the bearer token is the part most easily dropped."""
        route = api.get(f"{CA}/download-template/{SET_ID}").mock(
            return_value=httpx.Response(200, text=self.TEMPLATE)
        )

        attacks.download_template(SET_ID)

        sent = route.calls.last.request
        assert sent.headers["authorization"] == f"Bearer {TOKEN}"
        assert sent.headers["user-agent"] == USER_AGENT
        assert "service-name" not in sent.headers

    def test_raises_the_usual_error_for_a_bad_status(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """Bypassing the transport must not also bypass its error mapping."""
        api.get(f"{CA}/download-template/{SET_ID}").mock(
            return_value=httpx.Response(404, json={"message": "prompt set not found"})
        )

        with pytest.raises(AISecClientError, match="prompt set not found"):
            attacks.download_template(SET_ID)

    def test_retries_once_after_an_expired_token(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """A 401 buys one free re-auth, as it does on every transport-routed call."""
        route = api.get(f"{CA}/download-template/{SET_ID}").mock(
            side_effect=[
                httpx.Response(401, json={"message": "expired"}),
                httpx.Response(200, text=self.TEMPLATE),
            ]
        )

        assert attacks.download_template(SET_ID) == self.TEMPLATE
        assert route.call_count == 2

    def test_gives_up_after_one_free_re_auth(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """An endpoint answering 403 for a non-auth reason must not loop forever."""
        route = api.get(f"{CA}/download-template/{SET_ID}").mock(
            return_value=httpx.Response(403, json={"message": "forbidden"})
        )

        with pytest.raises(AISecClientError, match="forbidden"):
            attacks.download_template(SET_ID)

        assert route.call_count == 2


class TestPromptCsvUpload:
    def test_names_the_set_in_the_query_string(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """The set is a query parameter here, unlike every other prompt-set route."""
        route = api.post(f"{CA}/upload-custom-prompts-csv").mock(
            return_value=httpx.Response(201, json={"message": "Uploaded 5 prompts", "status": 201})
        )

        attacks.upload_prompts_csv(SET_ID, b"prompt,goal\n")

        sent = route.calls.last.request
        assert sent.url.params["prompt_set_uuid"] == SET_ID
        assert sent.url.path.endswith("/upload-custom-prompts-csv")

    def test_sends_the_file_as_multipart(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.post(f"{CA}/upload-custom-prompts-csv").mock(
            return_value=httpx.Response(201, json={"message": "ok", "status": 201})
        )

        attacks.upload_prompts_csv(SET_ID, b"prompt,goal\n", filename="attacks.csv")

        sent = route.calls.last.request
        assert sent.headers["content-type"].startswith("multipart/form-data; boundary=")
        body = sent.content.decode()
        assert 'name="file"; filename="attacks.csv"' in body
        assert "prompt,goal" in body

    def test_returns_the_upload_envelope(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        api.post(f"{CA}/upload-custom-prompts-csv").mock(
            return_value=httpx.Response(201, json={"message": "Uploaded 5 prompts", "status": 201})
        )

        result = attacks.upload_prompts_csv(SET_ID, b"prompt,goal\n")

        assert result.message == "Uploaded 5 prompts"

    def test_synthesises_an_envelope_for_an_empty_body(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """A successful upload sometimes answers 201 with no body at all."""
        api.post(f"{CA}/upload-custom-prompts-csv").mock(return_value=httpx.Response(201, text=""))

        result = attacks.upload_prompts_csv(SET_ID, b"prompt,goal\n")

        assert (result.message, result.status) == ("ok", 201)


class TestPrompts:
    PROMPT_PATH = f"{CA}/custom-prompt-set/{SET_ID}/custom-prompt/{PROMPT_ID}"

    def test_creates_a_prompt(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """The create path carries no set id -- the set is named in the body."""
        route = api.post(f"{CA}/custom-prompt-set/custom-prompt").mock(
            return_value=httpx.Response(200, json=PROMPT)
        )

        attacks.create_prompt(
            CustomPromptCreateRequest(prompt="Ignore previous instructions", prompt_set_id=SET_ID)
        )

        sent = route.calls.last.request
        assert str(sent.url) == f"{CA}/custom-prompt-set/custom-prompt"
        assert json.loads(sent.content) == {
            "prompt": "Ignore previous instructions",
            "prompt_set_id": SET_ID,
        }

    def test_lists_prompts_in_a_set(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/custom-prompt-set/{SET_ID}/list-custom-prompts").mock(
            return_value=httpx.Response(200, json=PROMPT_LIST)
        )

        attacks.list_prompts(
            SET_ID, skip=5, limit=50, search="inject", status="READY", active=False
        )

        sent = route.calls.last.request
        assert sent.url.path.endswith(f"/custom-prompt-set/{SET_ID}/list-custom-prompts")
        assert dict(sent.url.params) == {
            "skip": "5",
            "limit": "50",
            "search": "inject",
            "status": "READY",
            "active": "false",
        }

    def test_omits_absent_prompt_filters(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """An absent filter must not go out as an empty value the endpoint would apply."""
        route = api.get(f"{CA}/custom-prompt-set/{SET_ID}/list-custom-prompts").mock(
            return_value=httpx.Response(200, json=PROMPT_LIST)
        )

        attacks.list_prompts(SET_ID, limit=5)

        assert route.calls.last.request.url.query == b"limit=5"

    def test_gets_a_prompt(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(self.PROMPT_PATH).mock(return_value=httpx.Response(200, json=PROMPT))

        result = attacks.get_prompt(SET_ID, PROMPT_ID)

        assert str(route.calls.last.request.url) == self.PROMPT_PATH
        assert result.prompt_set_id == SET_ID

    def test_updates_a_prompt(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.route(url=self.PROMPT_PATH).mock(return_value=httpx.Response(200, json=PROMPT))

        attacks.update_prompt(SET_ID, PROMPT_ID, CustomPromptUpdateRequest(prompt="updated"))

        sent = route.calls.last.request
        assert sent.method == "PUT"
        assert json.loads(sent.content) == {"prompt": "updated"}

    def test_deletes_a_prompt(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.delete(self.PROMPT_PATH).mock(return_value=httpx.Response(200, json=BASE_OK))

        result = attacks.delete_prompt(SET_ID, PROMPT_ID)

        assert str(route.calls.last.request.url) == self.PROMPT_PATH
        assert result is not None
        assert result.status == 200

    def test_delete_tolerates_an_empty_body(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """The same call answers 200-with-body or 204-with-none depending on timing."""
        api.delete(self.PROMPT_PATH).mock(return_value=httpx.Response(204, text=""))

        assert attacks.delete_prompt(SET_ID, PROMPT_ID) is None

    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c.get_prompt(SET_ID, "nope"),
            lambda c: c.update_prompt(SET_ID, "nope", CustomPromptUpdateRequest(prompt="x")),
            lambda c: c.delete_prompt(SET_ID, "nope"),
        ],
    )
    def test_rejects_a_malformed_prompt_uuid(
        self, attacks: RedTeamCustomAttacksClient, call: object
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid prompt uuid: nope"):
            call(attacks)  # type: ignore[operator]

    def test_checks_the_set_id_before_the_prompt_id(
        self, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """Both are bad here; the message must name the first argument, not the second."""
        with pytest.raises(AISecPayloadError, match="Invalid prompt set uuid"):
            attacks.get_prompt("bad-set", "bad-prompt")


class TestProperties:
    def test_gets_property_names(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/property-names").mock(
            return_value=httpx.Response(200, json={"data": ["category", "severity"]})
        )

        result = attacks.get_property_names()

        assert str(route.calls.last.request.url) == f"{CA}/property-names"
        assert result.data == ["category", "severity"]

    def test_creates_a_property_name(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.post(f"{CA}/property-names").mock(
            return_value=httpx.Response(200, json=BASE_OK)
        )

        attacks.create_property_name(PropertyNameCreateRequest(name="severity"))

        sent = route.calls.last.request
        assert str(sent.url) == f"{CA}/property-names"
        assert json.loads(sent.content) == {"name": "severity"}

    def test_create_property_name_tolerates_an_empty_body(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        api.post(f"{CA}/property-names").mock(return_value=httpx.Response(204, text=""))

        assert attacks.create_property_name(PropertyNameCreateRequest(name="severity")) is None

    def test_gets_values_for_one_property(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.get(f"{CA}/property-values/severity").mock(
            return_value=httpx.Response(200, json={"name": "severity", "values": ["low", "high"]})
        )

        result = attacks.get_property_values("severity")

        assert str(route.calls.last.request.url) == f"{CA}/property-values/severity"
        assert result.values == ["low", "high"]

    def test_percent_encodes_the_property_name(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """Names are tenant-authored; an unescaped slash would reshape the path."""
        route = api.get(f"{CA}/property-values/attack%2Ftype").mock(
            return_value=httpx.Response(200, json={"name": "attack/type", "values": []})
        )

        attacks.get_property_values("attack/type")

        assert route.calls.last.request.url.raw_path.endswith(b"/property-values/attack%2Ftype")

    def test_repeats_the_property_names_key(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        """Repeated keys, not a comma-joined value: a comma is legal inside a name."""
        route = api.get(f"{CA}/property-values").mock(
            return_value=httpx.Response(200, json={"data": {"category": ["jailbreak"]}})
        )

        attacks.get_property_values_multiple(["category", "severity"])

        params = route.calls.last.request.url.params
        assert params.get_list("property_names") == ["category", "severity"]

    def test_creates_a_property_value(
        self, api: respx.MockRouter, attacks: RedTeamCustomAttacksClient
    ) -> None:
        route = api.post(f"{CA}/property-values").mock(
            return_value=httpx.Response(200, json=BASE_OK)
        )

        attacks.create_property_value(
            PropertyValueCreateRequest(property_name="severity", property_value="critical")
        )

        sent = route.calls.last.request
        assert str(sent.url) == f"{CA}/property-values"
        assert json.loads(sent.content) == {
            "property_name": "severity",
            "property_value": "critical",
        }


class TestCustomAttackReports:
    def test_gets_the_report(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        route = api.get(f"{REPORTS}/report/{JOB_ID}").mock(
            return_value=httpx.Response(200, json=REPORT)
        )

        result = reports.get_report(JOB_ID)

        assert str(route.calls.last.request.url) == f"{REPORTS}/report/{JOB_ID}"
        assert result.asr == 0.15

    def test_reports_come_from_the_data_plane(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        """Custom attacks are managed on the mgmt plane but reported on the data plane."""
        route = api.get(f"{REPORTS}/report/{JOB_ID}").mock(
            return_value=httpx.Response(200, json=REPORT)
        )

        reports.get_report(JOB_ID)

        assert str(route.calls.last.request.url).startswith(DATA)

    def test_gets_prompt_sets(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        route = api.get(f"{REPORTS}/report/{JOB_ID}/prompt-sets").mock(
            return_value=httpx.Response(
                200, json={"prompt_sets": [PROMPT_SET_SUMMARY], "total_prompt_sets": 1}
            )
        )

        result = reports.get_prompt_sets(JOB_ID)

        assert str(route.calls.last.request.url) == f"{REPORTS}/report/{JOB_ID}/prompt-sets"
        assert result.total_prompt_sets == 1

    def test_gets_prompts_by_set(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        route = api.get(f"{REPORTS}/report/{JOB_ID}/prompt-set/{SET_ID}/prompts").mock(
            return_value=httpx.Response(200, json=[PROMPT_DETAIL])
        )

        result = reports.get_prompts_by_set(JOB_ID, SET_ID, skip=0, limit=20, is_threat=True)

        sent = route.calls.last.request
        assert dict(sent.url.params) == {"skip": "0", "limit": "20", "is_threat": "true"}
        assert [p.prompt_id for p in result] == [PROMPT_ID]

    def test_prompts_by_set_returns_a_bare_array(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        """No pagination envelope, despite the endpoint taking pagination parameters."""
        api.get(f"{REPORTS}/report/{JOB_ID}/prompt-set/{SET_ID}/prompts").mock(
            return_value=httpx.Response(200, json=[])
        )

        assert reports.get_prompts_by_set(JOB_ID, SET_ID) == []

    def test_gets_prompt_detail(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        route = api.get(f"{REPORTS}/report/{JOB_ID}/prompt/{PROMPT_ID}").mock(
            return_value=httpx.Response(200, json=PROMPT_DETAIL)
        )

        result = reports.get_prompt_detail(JOB_ID, PROMPT_ID)

        assert str(route.calls.last.request.url) == f"{REPORTS}/report/{JOB_ID}/prompt/{PROMPT_ID}"
        assert result.prompt_text == "Ignore previous instructions"

    def test_lists_custom_attacks_under_the_job_prefix(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        """Attack views hang off job/{id}; prompt views off report/{id}. Same UUID."""
        route = api.get(f"{REPORTS}/job/{JOB_ID}/list-custom-attacks").mock(
            return_value=httpx.Response(
                200,
                json={
                    "pagination": {"total_items": 3},
                    "data": [],
                    "total_attacks": 3,
                    "total_threats": 1,
                },
            )
        )

        reports.list_custom_attacks(
            JOB_ID,
            skip=0,
            limit=20,
            search="inject",
            threat=True,
            prompt_set_id=SET_ID,
            property_value="jailbreak",
        )

        sent = route.calls.last.request
        assert (
            sent.url.path
            == f"/ai-red-teaming/data-plane/v1/custom-attacks/job/{JOB_ID}/list-custom-attacks"
        )
        assert dict(sent.url.params) == {
            "skip": "0",
            "limit": "20",
            "search": "inject",
            "threat": "true",
            "prompt_set_id": SET_ID,
            "property_value": "jailbreak",
        }

    def test_omits_absent_attack_filters(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        route = api.get(f"{REPORTS}/job/{JOB_ID}/list-custom-attacks").mock(
            return_value=httpx.Response(
                200,
                json={
                    "pagination": {"total_items": 0},
                    "data": [],
                    "total_attacks": 0,
                    "total_threats": 0,
                },
            )
        )

        reports.list_custom_attacks(JOB_ID)

        assert route.calls.last.request.url.query == b""

    def test_gets_attack_outputs(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        route = api.get(f"{REPORTS}/job/{JOB_ID}/attack/{ATTACK_ID}/list-outputs").mock(
            return_value=httpx.Response(200, json=[ATTACK_OUTPUT])
        )

        result = reports.get_attack_outputs(JOB_ID, ATTACK_ID)

        assert (
            str(route.calls.last.request.url)
            == f"{REPORTS}/job/{JOB_ID}/attack/{ATTACK_ID}/list-outputs"
        )
        assert [o.target_id for o in result] == [SET_ID]

    def test_gets_property_stats(
        self, api: respx.MockRouter, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        route = api.get(f"{REPORTS}/job/{JOB_ID}/property-stats").mock(
            return_value=httpx.Response(200, json=[PROPERTY_STAT])
        )

        result = reports.get_property_stats(JOB_ID)

        assert str(route.calls.last.request.url) == f"{REPORTS}/job/{JOB_ID}/property-stats"
        assert result[0].values[0].success_rate == 0.25

    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c.get_report("nope"),
            lambda c: c.get_prompt_sets("nope"),
            lambda c: c.get_prompts_by_set("nope", SET_ID),
            lambda c: c.get_prompt_detail("nope", PROMPT_ID),
            lambda c: c.list_custom_attacks("nope"),
            lambda c: c.get_attack_outputs("nope", ATTACK_ID),
            lambda c: c.get_property_stats("nope"),
        ],
    )
    def test_rejects_a_malformed_job_id(
        self, reports: RedTeamCustomAttackReportsClient, call: object
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid job id: nope"):
            call(reports)  # type: ignore[operator]

    def test_rejects_a_malformed_prompt_set_id(
        self, reports: RedTeamCustomAttackReportsClient
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid prompt set id: nope"):
            reports.get_prompts_by_set(JOB_ID, "nope")

    def test_rejects_a_malformed_prompt_id(self, reports: RedTeamCustomAttackReportsClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid prompt id: nope"):
            reports.get_prompt_detail(JOB_ID, "nope")

    def test_rejects_a_malformed_attack_id(self, reports: RedTeamCustomAttackReportsClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid attack id: nope"):
            reports.get_attack_outputs(JOB_ID, "nope")


class TestEula:
    def test_gets_the_content(self, api: respx.MockRouter, eula: RedTeamEulaClient) -> None:
        route = api.get(f"{EULA}/content").mock(
            return_value=httpx.Response(200, json={"content": "END USER LICENSE AGREEMENT"})
        )

        result = eula.get_content()

        assert str(route.calls.last.request.url) == f"{EULA}/content"
        assert result.content == "END USER LICENSE AGREEMENT"

    def test_gets_the_status(self, api: respx.MockRouter, eula: RedTeamEulaClient) -> None:
        route = api.get(f"{EULA}/status").mock(
            return_value=httpx.Response(200, json={"is_accepted": True, "accepted_at": TIMESTAMP})
        )

        result = eula.get_status()

        assert str(route.calls.last.request.url) == f"{EULA}/status"
        assert result.is_accepted

    def test_accepts_the_eula(self, api: respx.MockRouter, eula: RedTeamEulaClient) -> None:
        route = api.post(f"{EULA}/accept").mock(
            return_value=httpx.Response(200, json={"is_accepted": True})
        )

        eula.accept(EulaAcceptRequest(eula_content="END USER LICENSE AGREEMENT"))

        sent = route.calls.last.request
        assert str(sent.url) == f"{EULA}/accept"
        assert json.loads(sent.content) == {"eula_content": "END USER LICENSE AGREEMENT"}


class TestInstances:
    INSTANCE_BODY = InstanceRequest(
        tsg_id=TSG_ID, tenant_id="tenant-1", app_id="airs-redteam", region="us-east-1"
    )
    DEVICE_BODY = DeviceRequest(
        instance=DeviceInstance(
            app_id="airs-redteam", region="us-east-1", tenant_id="tenant-1", tsg_id=TSG_ID
        ),
        devices=[Device(serial_number="SN-0001")],
    )

    def test_creates_an_instance(
        self, api: respx.MockRouter, instances: RedTeamInstancesClient
    ) -> None:
        route = api.post(INSTANCES).mock(return_value=httpx.Response(200, json=INSTANCE_RESPONSE))

        instances.create_instance(self.INSTANCE_BODY)

        sent = route.calls.last.request
        assert str(sent.url) == INSTANCES
        assert json.loads(sent.content) == {
            "tsg_id": TSG_ID,
            "tenant_id": "tenant-1",
            "app_id": "airs-redteam",
            "region": "us-east-1",
        }

    def test_gets_an_instance(
        self, api: respx.MockRouter, instances: RedTeamInstancesClient
    ) -> None:
        route = api.get(f"{INSTANCES}/tenant-1").mock(
            return_value=httpx.Response(200, json=INSTANCE_GET)
        )

        result = instances.get_instance("tenant-1")

        assert str(route.calls.last.request.url) == f"{INSTANCES}/tenant-1"
        assert result.region == "us-east-1"

    def test_does_not_require_a_uuid_tenant_id(
        self, api: respx.MockRouter, instances: RedTeamInstancesClient
    ) -> None:
        """Tenant IDs are licensing identifiers; UUID-checking them rejects valid input."""
        api.get(f"{INSTANCES}/acme-prod-042").mock(
            return_value=httpx.Response(200, json={**INSTANCE_GET, "tenant_id": "acme-prod-042"})
        )

        assert instances.get_instance("acme-prod-042").tenant_id == "acme-prod-042"

    def test_updates_an_instance_with_put(
        self, api: respx.MockRouter, instances: RedTeamInstancesClient
    ) -> None:
        """PUT replaces the whole instance; the body is not a patch."""
        route = api.route(url=f"{INSTANCES}/tenant-1").mock(
            return_value=httpx.Response(200, json=INSTANCE_RESPONSE)
        )

        instances.update_instance("tenant-1", self.INSTANCE_BODY)

        sent = route.calls.last.request
        assert sent.method == "PUT"
        assert json.loads(sent.content)["region"] == "us-east-1"

    def test_deletes_an_instance(
        self, api: respx.MockRouter, instances: RedTeamInstancesClient
    ) -> None:
        route = api.delete(f"{INSTANCES}/tenant-1").mock(
            return_value=httpx.Response(200, json=INSTANCE_RESPONSE)
        )

        result = instances.delete_instance("tenant-1")

        assert str(route.calls.last.request.url) == f"{INSTANCES}/tenant-1"
        assert result.is_success

    def test_creates_devices(
        self, api: respx.MockRouter, instances: RedTeamInstancesClient
    ) -> None:
        route = api.post(f"{INSTANCES}/tenant-1/devices").mock(
            return_value=httpx.Response(200, json=DEVICE_RESULT)
        )

        result = instances.create_devices("tenant-1", self.DEVICE_BODY)

        sent = route.calls.last.request
        assert str(sent.url) == f"{INSTANCES}/tenant-1/devices"
        assert json.loads(sent.content)["devices"] == [{"serial_number": "SN-0001"}]
        assert result.devices is not None
        assert result.devices[0].status == "CREATED"

    def test_updates_devices_with_patch(
        self, api: respx.MockRouter, instances: RedTeamInstancesClient
    ) -> None:
        """PATCH merges the device collection; PUT here would deregister omitted devices."""
        route = api.route(url=f"{INSTANCES}/tenant-1/devices").mock(
            return_value=httpx.Response(200, json=DEVICE_RESULT)
        )

        instances.update_devices("tenant-1", self.DEVICE_BODY)

        sent = route.calls.last.request
        assert sent.method == "PATCH"
        assert json.loads(sent.content)["devices"] == [{"serial_number": "SN-0001"}]

    def test_deletes_devices_with_one_comma_joined_parameter(
        self, api: respx.MockRouter, instances: RedTeamInstancesClient
    ) -> None:
        """One key holding a comma-joined list, not a repeated key."""
        route = api.delete(f"{INSTANCES}/tenant-1/devices").mock(
            return_value=httpx.Response(200, json=DEVICE_RESULT)
        )

        instances.delete_devices("tenant-1", "SN-0001,SN-0002")

        params = route.calls.last.request.url.params
        assert params.get_list("serial_numbers") == ["SN-0001,SN-0002"]

    def test_mints_registry_credentials_with_post(
        self, api: respx.MockRouter, instances: RedTeamInstancesClient
    ) -> None:
        """A POST despite reading like a getter: each call mints a fresh token."""
        route = api.route(url=f"{MGMT}/v1/registry-credentials").mock(
            return_value=httpx.Response(200, json={"token": "eyJ", "expiry": TIMESTAMP})
        )

        result = instances.get_registry_credentials()

        sent = route.calls.last.request
        assert sent.method == "POST"
        assert str(sent.url) == f"{MGMT}/v1/registry-credentials"
        assert result.token == "eyJ"


class TestNetworkBroker:
    def test_uses_the_broker_base_url(
        self, api: respx.MockRouter, broker: RedTeamNetworkBrokerClient
    ) -> None:
        """A sub-path of the data plane, not the data plane itself."""
        route = api.get(CHANNELS).mock(return_value=httpx.Response(200, json=CHANNEL_LIST))

        broker.list_channels()

        assert str(route.calls.last.request.url).startswith(f"{BROKER}/")

    def test_repeats_the_status_key_for_several_statuses(
        self, api: respx.MockRouter, broker: RedTeamNetworkBrokerClient
    ) -> None:
        route = api.get(CHANNELS).mock(return_value=httpx.Response(200, json=CHANNEL_LIST))

        broker.list_channels(status=["ONLINE", "DRAFT"], limit=10)

        params = route.calls.last.request.url.params
        assert params.get_list("status") == ["ONLINE", "DRAFT"]
        assert params["limit"] == "10"

    def test_wraps_a_single_status_in_the_same_repeated_form(
        self, api: respx.MockRouter, broker: RedTeamNetworkBrokerClient
    ) -> None:
        """A bare string must not leak through as a stringified list."""
        route = api.get(CHANNELS).mock(return_value=httpx.Response(200, json=CHANNEL_LIST))

        broker.list_channels(status="ONLINE")

        assert route.calls.last.request.url.query == b"status=ONLINE"

    def test_sends_include_all_if_empty_lowercase(
        self, api: respx.MockRouter, broker: RedTeamNetworkBrokerClient
    ) -> None:
        route = api.get(CHANNELS).mock(return_value=httpx.Response(200, json=CHANNEL_LIST))

        broker.list_channels(include_all_if_empty=False)

        assert route.calls.last.request.url.params["include_all_if_empty"] == "false"

    def test_defaults_data_to_an_empty_list(
        self, api: respx.MockRouter, broker: RedTeamNetworkBrokerClient
    ) -> None:
        """A tenant with no channels omits the key entirely rather than sending []."""
        api.get(CHANNELS).mock(return_value=httpx.Response(200, json={"pagination": {}}))

        assert broker.list_channels().data == []

    def test_creates_a_channel(
        self, api: respx.MockRouter, broker: RedTeamNetworkBrokerClient
    ) -> None:
        route = api.post(CHANNELS).mock(return_value=httpx.Response(200, json=CHANNEL))

        broker.create_channel(CreateChannelRequest(name="prod-broker", description="Production"))

        sent = route.calls.last.request
        assert str(sent.url) == CHANNELS
        assert json.loads(sent.content) == {"name": "prod-broker", "description": "Production"}

    def test_gets_channel_stats_from_its_own_path(
        self, api: respx.MockRouter, broker: RedTeamNetworkBrokerClient
    ) -> None:
        """`stats` is a sibling of the collection; the server would read it as an id."""
        route = api.get(f"{CHANNELS}/stats").mock(
            return_value=httpx.Response(
                200, json={"online_channels": 3, "total_channels": 5, "client_version": "1.4.0"}
            )
        )

        result = broker.get_channel_stats()

        assert str(route.calls.last.request.url) == f"{CHANNELS}/stats"
        assert result.client_version == "1.4.0"

    def test_gets_a_channel(
        self, api: respx.MockRouter, broker: RedTeamNetworkBrokerClient
    ) -> None:
        route = api.get(f"{CHANNELS}/{SET_ID}").mock(return_value=httpx.Response(200, json=CHANNEL))

        result = broker.get_channel(SET_ID)

        assert str(route.calls.last.request.url) == f"{CHANNELS}/{SET_ID}"
        assert result.status == "ONLINE"

    def test_updates_a_channel_with_patch(
        self, api: respx.MockRouter, broker: RedTeamNetworkBrokerClient
    ) -> None:
        """PATCH, not PUT: name and description are the only writable fields."""
        route = api.route(url=f"{CHANNELS}/{SET_ID}").mock(
            return_value=httpx.Response(200, json=CHANNEL)
        )

        broker.update_channel(SET_ID, UpdateChannelRequest(description="Updated"))

        sent = route.calls.last.request
        assert sent.method == "PATCH"
        assert json.loads(sent.content) == {"description": "Updated"}

    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c.get_channel("nope"),
            lambda c: c.update_channel("nope", UpdateChannelRequest(name="x")),
        ],
    )
    def test_rejects_a_malformed_channel_id(
        self, broker: RedTeamNetworkBrokerClient, call: object
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid channel id: nope"):
            call(broker)  # type: ignore[operator]
