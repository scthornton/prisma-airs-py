"""Contract tests for the management API clients.

These assert the exact request that goes on the wire -- method, URL, query string,
headers, and body -- which is what keeps the port honest against the reference
implementation. The paths are transcribed literally rather than imported from
``prisma_airs.constants``, so a typo in a constant fails here instead of in production.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator

import httpx
import pytest
import respx

from prisma_airs.constants import (
    DEFAULT_DLP_ENDPOINT,
    DEFAULT_MGMT_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
)
from prisma_airs.errors import AISecMissingVariableError, AISecPayloadError, AISecServerError
from prisma_airs.management.management import ManagementClient, resolve_management_endpoint
from prisma_airs.models.management import (
    ApiKeyCreateRequest,
    ApiKeyRegenerateRequest,
    ClientIdAndCustomerApp,
    CreateCustomTopicRequest,
    CreateSecurityProfileRequest,
    CustomerApp,
    Policy,
)

BASE = DEFAULT_MGMT_ENDPOINT
TSG_ID = "1234567890"
ACCESS_TOKEN = "mgmt-access-token"

UUID = "550e8400-e29b-41d4-a716-446655440000"
OTHER_UUID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

PROFILE_URL = f"{BASE}/v1/mgmt/profile"
PROFILES_TSG_URL = f"{BASE}/v1/mgmt/profiles/tsg/{TSG_ID}"
TOPIC_URL = f"{BASE}/v1/mgmt/topic"
TOPICS_TSG_URL = f"{BASE}/v1/mgmt/topics/tsg/{TSG_ID}"
TOPIC_FORCE_URL = f"{BASE}/v1/mgmt/topic/force"
API_KEY_URL = f"{BASE}/v1/mgmt/apikey"
API_KEYS_TSG_URL = f"{BASE}/v1/mgmt/apikeys/tsg/{TSG_ID}"
CUSTOMER_APP_URL = f"{BASE}/v1/mgmt/customerapp"
CUSTOMER_APPS_TSG_URL = f"{BASE}/v1/mgmt/customerapp/tsg/{TSG_ID}"
DLP_PROFILES_URL = f"{BASE}/v1/mgmt/dlpprofiles"
DEPLOYMENT_PROFILES_URL = f"{BASE}/v1/mgmt/deploymentprofiles"
SCAN_LOGS_URL = f"{BASE}/v1/mgmt/scanlogs"
OAUTH_INVALIDATE_URL = f"{BASE}/v1/mgmt/oauth/invalidateToken"
OAUTH_TOKEN_URL = f"{BASE}/v1/mgmt/oauth/client_credential/accesstoken"
DASHBOARD_APP_URL = f"{BASE}/v1/mgmt/dashboard/v2/apps/application"
DASHBOARD_BREAKDOWN_URL = f"{BASE}/v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown"
DASHBOARD_OVERVIEW_URL = f"{BASE}/v1/mgmt/dashboard/v2/apps/applicationsoverview"

#: DLP lives on its own host, reached through ``mgmt.dlp``.
DLP_DATA_PATTERNS_URL = f"{DEFAULT_DLP_ENDPOINT}/v2/api/data-patterns"

PROFILE = {"profile_id": UUID, "profile_name": "prod", "revision": 1, "active": True}
TOPIC = {
    "topic_id": UUID,
    "topic_name": "credit-cards",
    "revision": 1,
    "active": True,
    "description": "Detects credit card numbers",
    "examples": ["4111-1111-1111-1111"],
}
API_KEY = {
    "api_key_id": "k1",
    "api_key_last8": "12345678",
    "auth_code": "ac",
    "expiration": "2026-12-31",
    "revoked": False,
}
CUSTOMER_APP = {
    "tsg_id": TSG_ID,
    "app_name": "myapp",
    "cloud_provider": "aws",
    "environment": "prod",
}
DEPLOYMENT_PROFILES = {
    "deployment_profiles": [{"dp_name": "prod-dp", "auth_code": "ac"}],
    "status": "ok",
}


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer's real PANW_MGMT_* variables from steering these tests."""
    for suffix in ("CLIENT_ID", "CLIENT_SECRET", "TSG_ID", "ENDPOINT", "TOKEN_ENDPOINT"):
        monkeypatch.delenv(f"PANW_MGMT_{suffix}", raising=False)


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    """Intercept HTTP with the OAuth2 client-credentials exchange already stubbed."""
    with respx.mock(assert_all_called=False) as router:
        router.post(DEFAULT_TOKEN_ENDPOINT, name="token").mock(
            return_value=httpx.Response(200, json={"access_token": ACCESS_TOKEN, "expires_in": 899})
        )
        yield router


@pytest.fixture
def mgmt(api: respx.MockRouter) -> Iterator[ManagementClient]:
    """A client with explicit credentials and retries disabled."""
    with ManagementClient(
        client_id="cid",
        client_secret="secret",
        tsg_id=TSG_ID,
        num_retries=0,
    ) as client:
        yield client


def sent(route: respx.Route) -> httpx.Request:
    """The last request a route received."""
    return route.calls.last.request


def body_of(route: respx.Route) -> object:
    """The last request body a route received, decoded from JSON."""
    return json.loads(sent(route).content)


class TestEndpointResolution:
    def test_defaults_to_the_scm_endpoint(self) -> None:
        assert resolve_management_endpoint() == "https://api.sase.paloaltonetworks.com/aisec"

    def test_reads_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANW_MGMT_ENDPOINT", "https://from-env.test")

        assert resolve_management_endpoint() == "https://from-env.test"

    def test_an_explicit_endpoint_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANW_MGMT_ENDPOINT", "https://from-env.test")

        assert resolve_management_endpoint("https://proxy.internal") == "https://proxy.internal"


class TestConstruction:
    def test_requires_credentials(self) -> None:
        with pytest.raises(AISecMissingVariableError, match="PANW_MGMT_CLIENT_ID"):
            ManagementClient()

    def test_does_not_name_the_same_prefix_twice(self) -> None:
        """PANW_MGMT is the prefix other planes fall back *to*, so it has no fallback.

        Resolving it against itself would advertise
        "PANW_MGMT_CLIENT_ID (or PANW_MGMT_CLIENT_ID)".
        """
        with pytest.raises(AISecMissingVariableError) as err:
            ManagementClient()

        assert "(or" not in str(err.value)
        assert str(err.value).endswith(
            "PANW_MGMT_CLIENT_ID, PANW_MGMT_CLIENT_SECRET, PANW_MGMT_TSG_ID"
        )

    def test_reads_credentials_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "env-id")
        monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "env-secret")
        monkeypatch.setenv("PANW_MGMT_TSG_ID", "9876543210")

        with ManagementClient() as client:
            assert client.tsg_id == "9876543210"
            assert client.endpoint == BASE

    def test_names_every_missing_credential(self) -> None:
        with pytest.raises(AISecMissingVariableError, match="PANW_MGMT_TSG_ID"):
            ManagementClient(client_id="cid", client_secret="secret")

    def test_an_explicit_endpoint_reaches_the_sub_clients(self, api: respx.MockRouter) -> None:
        """The constructor argument has to steer real traffic, not just the property."""
        route = api.get("https://mgmt.internal/v1/mgmt/dlpprofiles").mock(
            return_value=httpx.Response(200, json={})
        )

        with ManagementClient(
            client_id="cid",
            client_secret="secret",
            tsg_id=TSG_ID,
            endpoint="https://mgmt.internal",
            num_retries=0,
        ) as client:
            assert client.endpoint == "https://mgmt.internal"
            client.dlp_profiles.list()

        assert str(sent(route).url) == "https://mgmt.internal/v1/mgmt/dlpprofiles"

    def test_an_endpoint_from_the_environment_reaches_the_sub_clients(
        self, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PANW_MGMT_ENDPOINT", "https://from-env.test")
        route = api.get("https://from-env.test/v1/mgmt/dlpprofiles").mock(
            return_value=httpx.Response(200, json={})
        )

        with ManagementClient(client_id="cid", client_secret="secret", tsg_id=TSG_ID) as client:
            client.dlp_profiles.list()

        assert route.call_count == 1

    @pytest.mark.parametrize("value", [-1, 6, 1.5, True])
    def test_rejects_an_unusable_retry_count(self, value: object) -> None:
        with pytest.raises(AISecPayloadError, match="num_retries"):
            ManagementClient(
                client_id="cid",
                client_secret="secret",
                tsg_id=TSG_ID,
                num_retries=value,  # type: ignore[arg-type]
            )

    def test_the_retry_budget_reaches_every_sub_client(self, api: respx.MockRouter) -> None:
        with ManagementClient(
            client_id="cid", client_secret="secret", tsg_id=TSG_ID, num_retries=3
        ) as client:
            budgets = {
                client.profiles._num_retries,
                client.topics._num_retries,
                client.api_keys._num_retries,
                client.customer_apps._num_retries,
                client.dlp_profiles._num_retries,
                client.deployment_profiles._num_retries,
                client.scan_logs._num_retries,
                client.oauth._num_retries,
                client.dashboard._num_retries,
            }

        assert budgets == {3}

    def test_a_zero_budget_makes_exactly_one_attempt(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """A 500 is retryable, so only the budget stops it from being retried."""
        route = api.get(DLP_PROFILES_URL).mock(return_value=httpx.Response(500, json={}))

        with pytest.raises(AISecServerError):
            mgmt.dlp_profiles.list()

        assert route.call_count == 1


class TestAuthentication:
    def test_sends_the_bearer_token_from_the_exchange(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(DLP_PROFILES_URL).mock(return_value=httpx.Response(200, json={}))

        mgmt.dlp_profiles.list()

        assert sent(route).headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"

    def test_does_not_send_the_gateway_tenant_header(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """x-tsg-id belongs to the AI Gateway; the management plane scopes by token."""
        route = api.get(DLP_PROFILES_URL).mock(return_value=httpx.Response(200, json={}))

        mgmt.dlp_profiles.list()

        assert "x-tsg-id" not in sent(route).headers

    def test_one_token_exchange_serves_every_sub_client(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """All nine sub-clients share one OAuthClient, so the token is fetched once."""
        api.get(DLP_PROFILES_URL).mock(return_value=httpx.Response(200, json={}))
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [PROFILE]})
        )

        mgmt.dlp_profiles.list()
        mgmt.profiles.list()

        assert api["token"].call_count == 1


class TestProfiles:
    def test_creates_a_profile(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=PROFILE))

        profile = mgmt.profiles.create(
            CreateSecurityProfileRequest(
                profile_name="sdk-example",
                active=True,
                policy=Policy(ai_security_profiles=[], dlp_data_profiles=[]),
            )
        )

        assert str(sent(route).url) == PROFILE_URL
        assert body_of(route) == {
            "profile_name": "sdk-example",
            "active": True,
            # The policy keys are kebab-case on the wire, not snake_case.
            "policy": {"ai-security-profiles": [], "dlp-data-profiles": []},
        }
        assert profile.profile_id == UUID

    def test_lists_with_default_pagination(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [PROFILE], "next_offset": 20})
        )

        page = mgmt.profiles.list()

        assert str(sent(route).url) == f"{PROFILES_TSG_URL}?offset=0&limit=100"
        assert page.next_offset == 20

    def test_lists_with_explicit_pagination(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": []})
        )

        mgmt.profiles.list(offset=20, limit=5)

        assert str(sent(route).url) == f"{PROFILES_TSG_URL}?offset=20&limit=5"

    def test_gets_by_id_through_the_list_endpoint(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """There is no single-profile endpoint, so a get is a list plus a filter."""
        other = {**PROFILE, "profile_id": OTHER_UUID, "profile_name": "staging"}
        route = api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [other, PROFILE]})
        )

        profile = mgmt.profiles.get(UUID)

        assert route.call_count == 1
        assert profile.profile_name == "prod"

    def test_raises_when_no_profile_has_that_id(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [PROFILE]})
        )

        with pytest.raises(AISecPayloadError, match=f"Profile not found: {OTHER_UUID}"):
            mgmt.profiles.get(OTHER_UUID)

    def test_gets_by_name_returns_the_highest_revision(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """Revisions accumulate under one name; the newest is the live policy."""
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "ai_profiles": [
                        {**PROFILE, "revision": 1},
                        {**PROFILE, "revision": 3},
                        {**PROFILE, "revision": 2},
                        {**PROFILE, "profile_name": "staging", "revision": 9},
                    ]
                },
            )
        )

        assert mgmt.profiles.get_by_name("prod").revision == 3

    def test_gets_by_name_tolerates_a_missing_revision(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "ai_profiles": [
                        {"profile_name": "prod"},
                        {"profile_name": "prod", "revision": 2},
                    ]
                },
            )
        )

        assert mgmt.profiles.get_by_name("prod").revision == 2

    def test_raises_when_no_profile_has_that_name(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [PROFILE]})
        )

        with pytest.raises(AISecPayloadError, match="Profile not found: nope"):
            mgmt.profiles.get_by_name("nope")

    def test_updates_through_the_uuid_segment(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """Update is /profile/uuid/{id} while delete is /profile/{id}; not symmetric."""
        route = api.put(f"{PROFILE_URL}/uuid/{UUID}").mock(
            return_value=httpx.Response(200, json={**PROFILE, "revision": 2})
        )

        updated = mgmt.profiles.update(
            UUID, CreateSecurityProfileRequest(profile_name="prod", active=False)
        )

        assert str(sent(route).url) == f"{PROFILE_URL}/uuid/{UUID}"
        assert body_of(route) == {"profile_name": "prod", "active": False}
        assert updated.revision == 2

    def test_deletes(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.delete(f"{PROFILE_URL}/{UUID}").mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = mgmt.profiles.delete(UUID)

        assert str(sent(route).url) == f"{PROFILE_URL}/{UUID}"
        assert result.message == "deleted"

    def test_accepts_a_bare_string_delete_body(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """The service answers a delete with a JSON string, not an object."""
        api.delete(f"{PROFILE_URL}/{UUID}").mock(
            return_value=httpx.Response(200, json=f"successfully deleted profileId: {UUID}")
        )

        assert mgmt.profiles.delete(UUID).message.startswith("successfully deleted")

    def test_force_deletes_with_the_operator_email(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.delete(f"{PROFILE_URL}/{UUID}/force").mock(
            return_value=httpx.Response(200, json={"message": "force deleted"})
        )

        result = mgmt.profiles.force_delete(UUID, "admin@example.com")

        assert str(sent(route).url) == f"{PROFILE_URL}/{UUID}/force?updated_by=admin%40example.com"
        assert result.message == "force deleted"

    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c.profiles.update(
                "not-a-uuid", CreateSecurityProfileRequest(profile_name="p")
            ),
            lambda c: c.profiles.delete("not-a-uuid"),
            lambda c: c.profiles.force_delete("not-a-uuid", "admin@example.com"),
        ],
        ids=["update", "delete", "force_delete"],
    )
    def test_rejects_a_malformed_profile_id(
        self,
        mgmt: ManagementClient,
        api: respx.MockRouter,
        call: Callable[[ManagementClient], object],
    ) -> None:
        """A malformed ID would otherwise reshape the path and 404."""
        with pytest.raises(AISecPayloadError, match="Invalid profile_id: not-a-uuid"):
            call(mgmt)

        assert api.calls.call_count == 0


class TestTopics:
    def test_creates_a_topic(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.post(TOPIC_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        topic = mgmt.topics.create(
            CreateCustomTopicRequest(
                topic_name="credit-cards",
                active=True,
                description="Detects credit card numbers",
                examples=["4111-1111-1111-1111"],
            )
        )

        assert str(sent(route).url) == TOPIC_URL
        assert body_of(route) == {
            "topic_name": "credit-cards",
            "active": True,
            "description": "Detects credit card numbers",
            "examples": ["4111-1111-1111-1111"],
        }
        assert topic.topic_id == UUID

    def test_lists_with_default_pagination(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        page = mgmt.topics.list()

        assert str(sent(route).url) == f"{TOPICS_TSG_URL}?offset=0&limit=100"
        assert page.custom_topics[0].topic_name == "credit-cards"

    def test_lists_with_explicit_pagination(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": []})
        )

        mgmt.topics.list(offset=10, limit=25)

        assert str(sent(route).url) == f"{TOPICS_TSG_URL}?offset=10&limit=25"

    def test_updates_through_the_uuid_segment(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{TOPIC_URL}/uuid/{UUID}").mock(
            return_value=httpx.Response(200, json={**TOPIC, "revision": 2})
        )

        updated = mgmt.topics.update(UUID, CreateCustomTopicRequest(topic_name="credit-cards"))

        assert str(sent(route).url) == f"{TOPIC_URL}/uuid/{UUID}"
        assert body_of(route) == {"topic_name": "credit-cards"}
        assert updated.revision == 2

    def test_deletes(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.delete(f"{TOPIC_URL}/{UUID}").mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = mgmt.topics.delete(UUID)

        assert str(sent(route).url) == f"{TOPIC_URL}/{UUID}"
        assert result.message == "deleted"

    def test_force_deletes_through_a_separate_endpoint(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """The force path is /topic/force/{id}, not a flag on the plain delete."""
        route = api.delete(f"{TOPIC_FORCE_URL}/{UUID}").mock(
            return_value=httpx.Response(200, json={"message": "force deleted"})
        )

        result = mgmt.topics.force_delete(UUID)

        assert str(sent(route).url) == f"{TOPIC_FORCE_URL}/{UUID}"
        assert result.message == "force deleted"

    def test_force_deletes_with_the_operator_email(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.delete(f"{TOPIC_FORCE_URL}/{UUID}").mock(
            return_value=httpx.Response(200, json={"message": "force deleted"})
        )

        mgmt.topics.force_delete(UUID, updated_by="admin@example.com")

        assert str(sent(route).url) == f"{TOPIC_FORCE_URL}/{UUID}?updated_by=admin%40example.com"

    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c.topics.update("not-a-uuid", CreateCustomTopicRequest(topic_name="t")),
            lambda c: c.topics.delete("not-a-uuid"),
            lambda c: c.topics.force_delete("not-a-uuid"),
        ],
        ids=["update", "delete", "force_delete"],
    )
    def test_rejects_a_malformed_topic_id(
        self,
        mgmt: ManagementClient,
        api: respx.MockRouter,
        call: Callable[[ManagementClient], object],
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid topic_id: not-a-uuid"):
            call(mgmt)

        assert api.calls.call_count == 0


class TestApiKeys:
    def test_creates_a_key(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=API_KEY))

        key = mgmt.api_keys.create(
            ApiKeyCreateRequest(
                auth_code="ac",
                cust_app="app1",
                revoked=False,
                created_by="user@example.com",
                api_key_name="key1",
                rotation_time_interval=90,
                rotation_time_unit="days",
            )
        )

        assert str(sent(route).url) == API_KEY_URL
        assert body_of(route) == {
            "auth_code": "ac",
            "cust_app": "app1",
            "revoked": False,
            "created_by": "user@example.com",
            "api_key_name": "key1",
            "rotation_time_interval": 90.0,
            "rotation_time_unit": "days",
        }
        assert key.api_key_id == "k1"

    def test_lists_with_default_pagination(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": [API_KEY]})
        )

        page = mgmt.api_keys.list()

        assert str(sent(route).url) == f"{API_KEYS_TSG_URL}?offset=0&limit=100"
        assert page.api_keys is not None
        assert page.api_keys[0].api_key_last8 == "12345678"

    def test_lists_with_explicit_pagination(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(API_KEYS_TSG_URL).mock(return_value=httpx.Response(200, json={}))

        mgmt.api_keys.list(offset=5, limit=1)

        assert str(sent(route).url) == f"{API_KEYS_TSG_URL}?offset=5&limit=1"

    def test_deletes_by_name(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.delete(f"{API_KEY_URL}/delete/key1").mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = mgmt.api_keys.delete("key1", "user@example.com")

        assert str(sent(route).url) == f"{API_KEY_URL}/delete/key1?updated_by=user%40example.com"
        assert result.message == "deleted"

    def test_percent_encodes_the_key_name(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """The name is a path segment, so a slash in it must not become one."""
        route = api.delete(url__startswith=f"{API_KEY_URL}/delete/").mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        mgmt.api_keys.delete("prod key/1", "user@example.com")

        assert str(sent(route).url).startswith(f"{API_KEY_URL}/delete/prod%20key%2F1?")

    def test_rejects_an_empty_key_name(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        with pytest.raises(AISecPayloadError, match="api_key_name is required"):
            mgmt.api_keys.delete("", "user@example.com")

        assert api.calls.call_count == 0

    def test_regenerates_by_id(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.post(f"{API_KEY_URL}/regenerate/k1").mock(
            return_value=httpx.Response(200, json=API_KEY)
        )

        key = mgmt.api_keys.regenerate(
            "k1", ApiKeyRegenerateRequest(rotation_time_interval=30, rotation_time_unit="days")
        )

        assert str(sent(route).url) == f"{API_KEY_URL}/regenerate/k1"
        assert body_of(route) == {"rotation_time_interval": 30.0, "rotation_time_unit": "days"}
        assert key.api_key_last8 == "12345678"

    def test_percent_encodes_the_key_id(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """The ID is a path segment too, and it is not constrained to a UUID."""
        route = api.post(url__startswith=f"{API_KEY_URL}/regenerate/").mock(
            return_value=httpx.Response(200, json=API_KEY)
        )

        mgmt.api_keys.regenerate(
            "k 1/2", ApiKeyRegenerateRequest(rotation_time_interval=30, rotation_time_unit="days")
        )

        assert str(sent(route).url) == f"{API_KEY_URL}/regenerate/k%201%2F2"

    def test_rejects_an_empty_key_id(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        with pytest.raises(AISecPayloadError, match="api_key_id is required"):
            mgmt.api_keys.regenerate(
                "", ApiKeyRegenerateRequest(rotation_time_interval=30, rotation_time_unit="days")
            )

        assert api.calls.call_count == 0


class TestCustomerApps:
    def test_gets_by_name_through_a_query_parameter(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json=CUSTOMER_APP))

        app = mgmt.customer_apps.get("myapp")

        assert str(sent(route).url) == f"{CUSTOMER_APP_URL}?app_name=myapp"
        assert app.app_name == "myapp"

    def test_lists_with_default_pagination(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(CUSTOMER_APPS_TSG_URL).mock(
            return_value=httpx.Response(
                200, json={"customer_apps": [{**CUSTOMER_APP, "customer_appId": UUID}]}
            )
        )

        page = mgmt.customer_apps.list()

        assert str(sent(route).url) == f"{CUSTOMER_APPS_TSG_URL}?offset=0&limit=100"
        assert page.customer_apps is not None
        assert page.customer_apps[0].customer_app_id == UUID

    def test_lists_with_explicit_pagination(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(CUSTOMER_APPS_TSG_URL).mock(return_value=httpx.Response(200, json={}))

        mgmt.customer_apps.list(offset=2, limit=3)

        assert str(sent(route).url) == f"{CUSTOMER_APPS_TSG_URL}?offset=2&limit=3"

    def test_updates_by_query_parameter(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """The app ID travels as a query parameter, not a path segment."""
        route = api.put(CUSTOMER_APP_URL).mock(
            return_value=httpx.Response(200, json={**CUSTOMER_APP, "environment": "staging"})
        )

        app = mgmt.customer_apps.update(
            UUID,
            CustomerApp(
                tsg_id=TSG_ID, app_name="myapp", cloud_provider="aws", environment="staging"
            ),
        )

        assert str(sent(route).url) == f"{CUSTOMER_APP_URL}?customer_app_id={UUID}"
        assert body_of(route) == {
            "tsg_id": TSG_ID,
            "app_name": "myapp",
            "cloud_provider": "aws",
            "environment": "staging",
        }
        assert app.environment == "staging"

    def test_deletes_with_both_parameters(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.delete(CUSTOMER_APP_URL).mock(
            return_value=httpx.Response(200, json="customer app and associated keys deleted")
        )

        result = mgmt.customer_apps.delete("myapp", "user@example.com")

        assert (
            str(sent(route).url)
            == f"{CUSTOMER_APP_URL}?app_name=myapp&updated_by=user%40example.com"
        )
        assert result.message == "customer app and associated keys deleted"


class TestDlpProfiles:
    def test_lists_without_pagination(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.get(DLP_PROFILES_URL).mock(
            return_value=httpx.Response(200, json={"dlp_profiles": [{"name": "pci", "uuid": "u1"}]})
        )

        result = mgmt.dlp_profiles.list()

        assert str(sent(route).url) == DLP_PROFILES_URL
        assert result.dlp_profiles is not None
        assert result.dlp_profiles[0].uuid == "u1"


class TestDeploymentProfiles:
    def test_omits_the_filter_when_unset(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """Absent and false are distinct to this endpoint."""
        route = api.get(DEPLOYMENT_PROFILES_URL).mock(
            return_value=httpx.Response(200, json=DEPLOYMENT_PROFILES)
        )

        result = mgmt.deployment_profiles.list()

        assert str(sent(route).url) == DEPLOYMENT_PROFILES_URL
        # The auth_code here is what ApiKeysClient.create needs.
        assert result.deployment_profiles[0].auth_code == "ac"
        assert result.status == "ok"

    @pytest.mark.parametrize(("value", "expected"), [(True, "true"), (False, "false")])
    def test_sends_the_json_spelling_of_the_boolean(
        self, mgmt: ManagementClient, api: respx.MockRouter, value: bool, expected: str
    ) -> None:
        """Python's str(True) is "True", which this endpoint does not accept."""
        route = api.get(DEPLOYMENT_PROFILES_URL).mock(
            return_value=httpx.Response(200, json=DEPLOYMENT_PROFILES)
        )

        mgmt.deployment_profiles.list(unactivated=value)

        assert str(sent(route).url) == f"{DEPLOYMENT_PROFILES_URL}?unactivated={expected}"


class TestScanLogs:
    def test_sends_every_filter_in_the_query_string(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """pageNumber and pageSize are camelCase; the parameters beside them are not."""
        route = api.post(SCAN_LOGS_URL).mock(
            return_value=httpx.Response(200, json={"total_pages": 1, "page_number": 1})
        )

        page = mgmt.scan_logs.query(
            time_interval=24,
            time_unit="hour",
            page_number=1,
            page_size=10,
            verdict_filter="threat",
        )

        assert str(sent(route).url) == (
            f"{SCAN_LOGS_URL}"
            "?time_interval=24&time_unit=hour&pageNumber=1&pageSize=10&filter=threat"
        )
        assert sent(route).content == b""
        assert page.total_pages == 1

    def test_carries_the_continuation_token_in_the_body(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.post(SCAN_LOGS_URL).mock(return_value=httpx.Response(200, json={}))

        mgmt.scan_logs.query(
            time_interval=1,
            time_unit="day",
            page_number=2,
            page_size=10,
            verdict_filter="all",
            page_token="encrypted-cursor",
        )

        assert body_of(route) == {"page_token": "encrypted-cursor"}
        assert sent(route).headers["Content-Type"] == "application/json"

    def test_tolerates_an_empty_body_from_a_quiet_window(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """A window with no traffic returns no body at all, which is not an error."""
        api.post(SCAN_LOGS_URL).mock(return_value=httpx.Response(200, text=""))

        result = mgmt.scan_logs.query(
            time_interval=24,
            time_unit="hour",
            page_number=1,
            page_size=10,
            verdict_filter="all",
        )

        assert result.scan_result_for_dashboard is None


class TestOAuthManagement:
    def test_invalidates_a_token(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.post(OAUTH_INVALIDATE_URL).mock(
            return_value=httpx.Response(200, json="token invalidated")
        )

        result = mgmt.oauth.invalidate_token(
            "issued-token", ClientIdAndCustomerApp(client_id="cid", customer_app="app1")
        )

        assert str(sent(route).url) == f"{OAUTH_INVALIDATE_URL}?token=issued-token"
        assert body_of(route) == {"client_id": "cid", "customer_app": "app1"}
        assert result == "token invalidated"

    def test_issues_a_token_without_a_ttl(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.post(OAUTH_TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "issued", "expires_in": "86400"})
        )

        token = mgmt.oauth.get_access_token(
            ClientIdAndCustomerApp(client_id="cid", customer_app="app1")
        )

        assert str(sent(route).url) == OAUTH_TOKEN_URL
        assert token.expires_in == "86400"

    def test_issues_a_token_with_a_ttl(self, mgmt: ManagementClient, api: respx.MockRouter) -> None:
        route = api.post(OAUTH_TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "issued"})
        )

        mgmt.oauth.get_access_token(
            ClientIdAndCustomerApp(client_id="cid", customer_app="app1"),
            token_ttl_interval=3,
            token_ttl_unit="hours",
        )

        assert str(sent(route).url) == f"{OAUTH_TOKEN_URL}?tokenTtlInterval=3&tokenTtlUnit=hours"

    def test_sends_only_the_ttl_parameter_supplied(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.post(OAUTH_TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "issued"})
        )

        mgmt.oauth.get_access_token(
            ClientIdAndCustomerApp(client_id="cid", customer_app="app1"), token_ttl_unit="hours"
        )

        assert str(sent(route).url) == f"{OAUTH_TOKEN_URL}?tokenTtlUnit=hours"


class TestDashboard:
    def test_queries_one_application_with_the_default_window(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """appid and appname are lowercase and unseparated; the window keys are not."""
        route = api.get(DASHBOARD_APP_URL).mock(
            return_value=httpx.Response(
                200, json={"name": "chatbot", "token_stats": {"monthly_total_tokens": 17.71}}
            )
        )

        overview = mgmt.dashboard.application(app_id=UUID, app_name="chatbot")

        assert str(sent(route).url) == (
            f"{DASHBOARD_APP_URL}?appid={UUID}&appname=chatbot&time_interval=30&time_unit=days"
        )
        assert overview.token_stats is not None
        assert overview.token_stats.monthly_total_tokens == 17.71

    def test_queries_one_application_with_an_explicit_window(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(DASHBOARD_APP_URL).mock(return_value=httpx.Response(200, json={}))

        mgmt.dashboard.application(app_id=UUID, app_name="chatbot", time_interval=7)

        assert str(sent(route).url) == (
            f"{DASHBOARD_APP_URL}?appid={UUID}&appname=chatbot&time_interval=7&time_unit=days"
        )

    def test_queries_the_violation_breakdown(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(DASHBOARD_BREAKDOWN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "detection_type_violation_breakdown": [
                        {"detection_type": "topic_guardrails", "violation_breakdown": {"total": 3}}
                    ],
                    "total_violating": 3,
                },
            )
        )

        breakdown = mgmt.dashboard.application_violation_breakdown(app_id=UUID, app_name="chatbot")

        assert str(sent(route).url) == (
            f"{DASHBOARD_BREAKDOWN_URL}?appid={UUID}&appname=chatbot"
            "&time_interval=30&time_unit=days"
        )
        assert breakdown.total_violating == 3

    def test_enumerates_the_buckets_with_default_pagination(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(
                200, json={"items": [{"id": UUID, "name": "chatbot"}], "pagination": {"limit": 25}}
            )
        )

        result = mgmt.dashboard.applications_overview()

        assert str(sent(route).url) == (
            f"{DASHBOARD_OVERVIEW_URL}?time_interval=30&time_unit=days&limit=25&offset=0"
        )
        assert result.items is not None
        assert result.items[0].name == "chatbot"

    def test_enumerates_the_buckets_over_an_hourly_window(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        """This endpoint accepts the singular units the per-app endpoint rejects."""
        route = api.get(DASHBOARD_OVERVIEW_URL).mock(return_value=httpx.Response(200, json={}))

        mgmt.dashboard.applications_overview(time_interval=1, time_unit="hour", limit=5, offset=10)

        assert str(sent(route).url) == (
            f"{DASHBOARD_OVERVIEW_URL}?time_interval=1&time_unit=hour&limit=5&offset=10"
        )

    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c.dashboard.application(app_id="", app_name="chatbot"),
            lambda c: c.dashboard.application_violation_breakdown(app_id="", app_name="chatbot"),
        ],
        ids=["application", "violation_breakdown"],
    )
    def test_rejects_an_empty_app_id(
        self,
        mgmt: ManagementClient,
        api: respx.MockRouter,
        call: Callable[[ManagementClient], object],
    ) -> None:
        with pytest.raises(AISecPayloadError, match="app_id is required"):
            call(mgmt)

        assert api.calls.call_count == 0

    @pytest.mark.parametrize(
        "call",
        [
            lambda c: c.dashboard.application(app_id=UUID, app_name=""),
            lambda c: c.dashboard.application_violation_breakdown(app_id=UUID, app_name=""),
        ],
        ids=["application", "violation_breakdown"],
    )
    def test_rejects_an_empty_app_name(
        self,
        mgmt: ManagementClient,
        api: respx.MockRouter,
        call: Callable[[ManagementClient], object],
    ) -> None:
        """An empty appname returns 400 and an absent one an all-null body."""
        with pytest.raises(AISecPayloadError, match="app_name is required"):
            call(mgmt)

        assert api.calls.call_count == 0


class TestTsgPathEncoding:
    """The TSG ID is interpolated into four list paths, and only one of them encodes it.

    Immaterial for the numeric IDs the service issues, but the asymmetry is in the
    reference implementation and a "tidy-up" that encoded all four -- or none -- would
    change which URL is addressed.
    """

    AWKWARD_TSG = "tsg/1 2"

    @pytest.fixture
    def awkward(self, api: respx.MockRouter) -> Iterator[ManagementClient]:
        with ManagementClient(
            client_id="cid", client_secret="secret", tsg_id=self.AWKWARD_TSG, num_retries=0
        ) as client:
            yield client

    def test_customer_apps_percent_encodes_the_tsg_id(
        self, awkward: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(url__startswith=f"{BASE}/v1/mgmt/customerapp/tsg/").mock(
            return_value=httpx.Response(200, json={})
        )

        awkward.customer_apps.list()

        assert str(sent(route).url).startswith(f"{BASE}/v1/mgmt/customerapp/tsg/tsg%2F1%202?")

    @pytest.mark.parametrize(
        ("resource", "segment"),
        [
            ("profiles", "profiles"),
            ("topics", "topics"),
            ("api_keys", "apikeys"),
        ],
    )
    def test_the_other_tsg_paths_do_not_encode_it(
        self, awkward: ManagementClient, api: respx.MockRouter, resource: str, segment: str
    ) -> None:
        route = api.get(url__startswith=f"{BASE}/v1/mgmt/{segment}/tsg/").mock(
            return_value=httpx.Response(200, json={"ai_profiles": [], "custom_topics": []})
        )

        getattr(awkward, resource).list()

        # The slash stays a path separator, exactly as the template literal leaves it.
        assert str(sent(route).url).startswith(f"{BASE}/v1/mgmt/{segment}/tsg/tsg/1%202?")


class TestDlpNamespace:
    """DLP administration reached through ``mgmt.dlp``.

    A separate host sharing this client's token, pool, and retry budget.
    """

    def test_sends_to_the_dlp_host_not_the_management_host(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        route = api.get(DLP_DATA_PATTERNS_URL).mock(
            return_value=httpx.Response(200, json={"content": [{"name": "pci"}]})
        )

        page = mgmt.dlp.data_patterns.list()

        assert str(sent(route).url) == DLP_DATA_PATTERNS_URL
        assert page.content is not None
        assert page.content[0].name == "pci"

    def test_shares_one_token_with_the_management_plane(
        self, mgmt: ManagementClient, api: respx.MockRouter
    ) -> None:
        api.get(DLP_PROFILES_URL).mock(return_value=httpx.Response(200, json={}))
        route = api.get(DLP_DATA_PATTERNS_URL).mock(
            return_value=httpx.Response(200, json={"content": []})
        )

        mgmt.dlp_profiles.list()
        mgmt.dlp.data_patterns.list()

        assert sent(route).headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"
        assert api["token"].call_count == 1

    def test_an_explicit_dlp_endpoint_wins(self, api: respx.MockRouter) -> None:
        route = api.get("https://dlp.internal/v2/api/data-patterns").mock(
            return_value=httpx.Response(200, json={"content": []})
        )

        with ManagementClient(
            client_id="cid",
            client_secret="secret",
            tsg_id=TSG_ID,
            dlp_endpoint="https://dlp.internal",
            num_retries=0,
        ) as client:
            client.dlp.data_patterns.list()

        assert route.call_count == 1

    def test_the_management_endpoint_override_does_not_move_it(
        self, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DLP has no environment prefix, so PANW_MGMT_ENDPOINT must not redirect it."""
        monkeypatch.setenv("PANW_MGMT_ENDPOINT", "https://from-env.test")
        route = api.get(DLP_DATA_PATTERNS_URL).mock(
            return_value=httpx.Response(200, json={"content": []})
        )

        with ManagementClient(client_id="cid", client_secret="secret", tsg_id=TSG_ID) as client:
            assert client.endpoint == "https://from-env.test"
            client.dlp.data_patterns.list()

        assert route.call_count == 1

    def test_carries_the_management_retry_budget(self, api: respx.MockRouter) -> None:
        with ManagementClient(
            client_id="cid", client_secret="secret", tsg_id=TSG_ID, num_retries=2
        ) as client:
            assert client.dlp._num_retries == 2


class TestTransportLifecycle:
    def test_every_sub_client_sends_through_the_supplied_pool(self, api: respx.MockRouter) -> None:
        """One pool for the whole client, so a caller's proxy or instrumentation covers it."""
        probe = httpx.Client(headers={"x-probe": "shared-pool"})
        mgmt_route = api.get(DLP_PROFILES_URL).mock(return_value=httpx.Response(200, json={}))
        dlp_route = api.get(DLP_DATA_PATTERNS_URL).mock(
            return_value=httpx.Response(200, json={"content": []})
        )

        with ManagementClient(
            client_id="cid", client_secret="secret", tsg_id=TSG_ID, http_client=probe
        ) as client:
            client.dlp_profiles.list()
            client.dlp.data_patterns.list()

        assert sent(mgmt_route).headers["x-probe"] == "shared-pool"
        assert sent(dlp_route).headers["x-probe"] == "shared-pool"
        assert sent(api["token"]).headers["x-probe"] == "shared-pool"
        probe.close()

    def test_closes_a_client_it_created(self) -> None:
        client = ManagementClient(client_id="cid", client_secret="secret", tsg_id=TSG_ID)

        client.close()

        assert client._http.is_closed

    def test_leaves_a_supplied_client_open(self) -> None:
        """A caller-supplied pool belongs to the rest of their application."""
        supplied = httpx.Client()

        with ManagementClient(
            client_id="cid", client_secret="secret", tsg_id=TSG_ID, http_client=supplied
        ):
            pass

        assert not supplied.is_closed
        supplied.close()

    def test_the_context_manager_closes_on_exit(self) -> None:
        with ManagementClient(client_id="cid", client_secret="secret", tsg_id=TSG_ID) as client:
            pass

        assert client._http.is_closed
