"""Contract tests for the AI Gateway core clients.

These assert the exact request that goes on the wire -- method, URL, query, headers, and
body -- which is what keeps the port honest against the reference implementation. Which
plane a call lands on is load-bearing here: the same path answers differently on
``/ai_gw/v2`` and ``/ai_gw/admin/v2``, and a write sent to the data plane is a 403.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx

from prisma_airs.ai_gateway.ai_gateway_core import (
    AIGatewayClient,
    AIGatewayConfigsClient,
    resolve_gateway_endpoint,
)
from prisma_airs.constants import (
    DEFAULT_AI_GW_ADMIN_ENDPOINT,
    DEFAULT_AI_GW_DATA_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
    ENV_AI_GW_ADMIN_ENDPOINT,
    ENV_AI_GW_DATA_ENDPOINT,
    ENV_PREFIX_AI_GW,
    ENV_PREFIX_MGMT,
    HEADER_TSG_ID,
)
from prisma_airs.errors import (
    AISecMissingVariableError,
    AISecPayloadError,
    AISecServerError,
)
from prisma_airs.models.ai_gateway import GatewayRateLimit, GuardrailActions, GuardrailCheck

DATA = DEFAULT_AI_GW_DATA_ENDPOINT
ADMIN = DEFAULT_AI_GW_ADMIN_ENDPOINT

TSG_ID = "1852583913"
TOKEN = "gw-access-token"

WORKSPACE_ID = "16f7e90d-382a-4e78-b577-1b01eb5f8297"
WORKSPACE_SLUG = "ws-produc-985697"
CONFIG_ID = "764cf9cd-4ebf-449e-b669-08149b0fbbbc"
GUARDRAIL_ID = "9f6c2a8e-2b3d-4e5f-8a9b-0c1d2e3f4a5b"
PROVIDER_ID = "f6692544-3265-49be-9711-bbdcebc079e4"
INTEGRATION_ID = "f6692544-3265-49be-9711-bbdcebc079e4"
AI_PROVIDER_ID = "de7d7d50-31cd-11ee-b93b-0e06f1aa7f7c"
KEY_ID = "11111111-1111-4111-8111-111111111111"
USER_ID = "fad91538-65a9-41f7-8b9c-6e4c0e8b9c5f"

WORKSPACE_ROW = {
    "id": WORKSPACE_ID,
    "slug": "ws-main-a-349e0e",
    "name": "Main",
    "icon": None,
    "description": None,
    "created_at": "2026-07-01T00:00:00Z",
    "last_updated_at": "2026-07-02T00:00:00Z",
    "is_default": 1,
    "status": "active",
    "scope_name": "main_airs_workspace_1852583913",
    "object": "workspace",
}
WORKSPACES_PAGE = {"object": "list", "total": 1, "data": [WORKSPACE_ROW]}

WORKSPACE_DETAIL = {
    "id": WORKSPACE_ID,
    "name": "Main",
    "description": None,
    "created_at": "2026-07-01T00:00:00Z",
    "last_updated_at": "2026-07-02T00:00:00Z",
    "is_default": 1,
    "slug": "ws-main-a-349e0e",
    "icon": None,
    "defaults": None,
    "usage_limits": None,
    "rate_limits": None,
    "security_settings": {"membersViewLogs": True},
}

WORKSPACE_CREATED = {
    "id": WORKSPACE_ID,
    "name": "Production",
    "slug": "ws-produc-985697",
    "description": "All production applications",
    "created_at": "2026-08-01T00:00:00Z",
    "last_updated_at": "2026-08-01T00:00:00Z",
    "scope_name": "ws_production_bx7qw0",
    "object": "workspace",
}

CONFIG_ROW = {
    "id": CONFIG_ID,
    "name": "claude-code",
    "slug": "pc-claude-e46fe6",
    "organisation_id": "8b5f7e3d-1c2a-4d5e-9f80-2b3c4d5e6f70",
    "is_default": 0,
    "status": "active",
    "owner_id": "owner-1",
    "updated_by": "owner-1",
    "created_at": "2026-07-28T00:00:00Z",
    "last_updated_at": "2026-07-28T00:00:00Z",
    "workspace_id": WORKSPACE_ID,
    "object": "config",
}
CONFIGS_PAGE = {"object": "list", "total": 1, "data": [CONFIG_ROW]}
CONFIG_DETAIL = {
    **CONFIG_ROW,
    "config": '{"provider":"@anthropic-prod"}',
    "format": "template",
    "type": "config",
    "version_id": "v1",
}
CONFIG_RECEIPT = {
    "id": CONFIG_ID,
    "version_id": "v1",
    "slug": "pc-sdk-ve-14620d",
    "object": "config",
}

GUARDRAIL_ROW = {
    "id": GUARDRAIL_ID,
    "name": "PrismaAIRS",
    "slug": "pg-prisma-099a16",
    "organisation_id": "8b5f7e3d-1c2a-4d5e-9f80-2b3c4d5e6f70",
    "status": "active",
    "owner_id": "owner-1",
    "updated_by": None,
    "created_at": "2026-07-28T00:00:00Z",
    "last_updated_at": "2026-07-28T00:00:00Z",
    "workspace_id": WORKSPACE_ID,
    "object": "guardrail",
}
GUARDRAILS_PAGE = {"object": "list", "total": 1, "data": [GUARDRAIL_ROW]}
GUARDRAIL_DETAIL = {
    **GUARDRAIL_ROW,
    "checks": [
        {
            "id": "panw-prisma-airs.intercept",
            "parameters": {"profile_name": "AI Gateway - Strict"},
            "is_enabled": True,
        }
    ],
    "actions": {"deny": False, "async": False, "sequential": False},
    "version_id": "v1",
}
GUARDRAIL_RECEIPT = {
    "id": GUARDRAIL_ID,
    "version_id": "v1",
    "slug": "pg-sdk-ve-874b62",
    "object": "guardrail",
}

PROVIDERS_PAGE = {
    "object": "list",
    "total": 1,
    "data": [{"id": PROVIDER_ID, "name": "openai-calvin", "slug": "openai-calvin"}],
}
PROVIDER_RECEIPT = {"id": PROVIDER_ID, "slug": "openai-calvin", "object": "provider"}

API_KEYS_PAGE = {
    "object": "list",
    "total": 1,
    "data": [{"id": KEY_ID, "name": "ci-runner", "object": "api-key"}],
}

SERVICE_KEY_ARGS = {
    "name": "ci-runner",
    "scopes": ["completions.write", "logs.write"],
    "organisation_id": TSG_ID,
    "workspace_id": WORKSPACE_ID,
    "key_type": "workspace",
}


@pytest.fixture(autouse=True)
def _hermetic_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep ambient PANW_* variables out of the client under test."""
    monkeypatch.delenv(ENV_AI_GW_DATA_ENDPOINT, raising=False)
    monkeypatch.delenv(ENV_AI_GW_ADMIN_ENDPOINT, raising=False)
    for prefix in (ENV_PREFIX_AI_GW, ENV_PREFIX_MGMT):
        for suffix in ("CLIENT_ID", "CLIENT_SECRET", "TSG_ID", "TOKEN_ENDPOINT"):
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)


@pytest.fixture
def gateway() -> Iterator[AIGatewayClient]:
    client = AIGatewayClient(
        client_id="client-id", client_secret="client-secret", tsg_id=TSG_ID, num_retries=0
    )
    yield client
    client.close()


@pytest.fixture
def api(respx_mock: respx.MockRouter) -> respx.MockRouter:
    """A router with the OAuth exchange stubbed; every gateway call fetches a token first."""
    respx_mock.post(DEFAULT_TOKEN_ENDPOINT, name="token").mock(
        return_value=httpx.Response(200, json={"access_token": TOKEN, "expires_in": 900})
    )
    return respx_mock


def sent_body(route: respx.Route) -> dict[str, Any]:
    """Decode the JSON body of the most recent request on ``route``."""
    body: dict[str, Any] = json.loads(route.calls.last.request.content)
    return body


class TestEndpointResolution:
    def test_defaults_to_the_documented_data_plane(self) -> None:
        assert resolve_gateway_endpoint("data") == "https://api.apps.paloaltonetworks.com/ai_gw/v2"

    def test_defaults_to_the_documented_admin_plane(self) -> None:
        """The admin plane is a different path prefix, not a different host."""
        assert (
            resolve_gateway_endpoint("admin")
            == "https://api.apps.paloaltonetworks.com/ai_gw/admin/v2"
        )

    def test_each_plane_reads_its_own_environment_variable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_AI_GW_DATA_ENDPOINT, "https://data.internal/ai_gw/v2")
        monkeypatch.setenv(ENV_AI_GW_ADMIN_ENDPOINT, "https://admin.internal/ai_gw/admin/v2")

        assert resolve_gateway_endpoint("data") == "https://data.internal/ai_gw/v2"
        assert resolve_gateway_endpoint("admin") == "https://admin.internal/ai_gw/admin/v2"

    def test_an_explicit_endpoint_wins_over_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_AI_GW_DATA_ENDPOINT, "https://from-env.test")

        assert resolve_gateway_endpoint("data", "https://explicit.test") == "https://explicit.test"


class TestConstruction:
    def test_requires_credentials(self) -> None:
        with pytest.raises(AISecMissingVariableError, match="PANW_AI_GW_CLIENT_ID"):
            AIGatewayClient()

    def test_falls_back_to_the_management_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One service account drives every plane, so PANW_MGMT_* alone is enough."""
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_ID", "mgmt-id")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_SECRET", "mgmt-secret")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_TSG_ID", "999")

        with AIGatewayClient() as client:
            assert client.tsg_id == "999"

    def test_prefers_the_gateway_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_ID", "mgmt-id")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_SECRET", "mgmt-secret")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_TSG_ID", "999")
        monkeypatch.setenv(f"{ENV_PREFIX_AI_GW}_TSG_ID", TSG_ID)

        with AIGatewayClient() as client:
            assert client.tsg_id == TSG_ID

    def test_exposes_both_plane_endpoints(self, gateway: AIGatewayClient) -> None:
        assert (gateway.data_endpoint, gateway.admin_endpoint) == (DATA, ADMIN)

    def test_keeps_a_usable_retry_budget(self) -> None:
        with AIGatewayClient(
            client_id="a", client_secret="b", tsg_id=TSG_ID, num_retries=3
        ) as client:
            assert client.num_retries == 3

    @pytest.mark.parametrize("value", [-1, 6, 1.5, True])
    def test_rejects_an_unusable_retry_count(self, value: object) -> None:
        """Rejected rather than clamped, matching every other client in this SDK."""
        with pytest.raises(AISecPayloadError, match="num_retries"):
            AIGatewayClient(client_id="a", client_secret="b", tsg_id=TSG_ID, num_retries=value)  # type: ignore[arg-type]

    @pytest.mark.parametrize(("budget", "attempts"), [(0, 1), (2, 3)])
    def test_hands_the_retry_budget_to_every_sub_client(
        self,
        api: respx.MockRouter,
        monkeypatch: pytest.MonkeyPatch,
        budget: int,
        attempts: int,
    ) -> None:
        """Validating the budget is only half the job -- it has to reach the wire.

        A caller asking for ``num_retries=0`` on a fail-fast path must not silently get
        the default five.
        """
        monkeypatch.setattr("prisma_airs._http.retry.time.sleep", lambda _seconds: None)
        route = api.get(f"{DATA}/configs").mock(return_value=httpx.Response(503))

        with (
            AIGatewayClient(
                client_id="a", client_secret="b", tsg_id=TSG_ID, num_retries=budget
            ) as client,
            pytest.raises(AISecServerError),
        ):
            client.configs.list(workspace_id=WORKSPACE_ID)

        assert route.call_count == attempts


class TestLifecycle:
    """Shutdown, and the plumbing this client hands out for other clients to share."""

    def test_closes_the_http_client_it_created(self) -> None:
        client = AIGatewayClient(client_id="a", client_secret="b", tsg_id=TSG_ID)
        http = client.http

        client.close()

        assert http.is_closed

    def test_does_not_close_a_caller_supplied_http_client(self) -> None:
        """A caller pooling connections across SDKs keeps ownership of the client."""
        http = httpx.Client()
        AIGatewayClient(client_id="a", client_secret="b", tsg_id=TSG_ID, http_client=http).close()

        assert not http.is_closed
        http.close()

    def test_close_also_ends_the_oauth_session(self, api: respx.MockRouter) -> None:
        """The token session is a second socket pool, and closing only one leaks the other.

        Supplying the API client keeps it open across ``close()``, so the failure below
        can only come from the OAuth session having been shut.
        """
        http = httpx.Client()
        client = AIGatewayClient(
            client_id="a", client_secret="b", tsg_id=TSG_ID, http_client=http, num_retries=0
        )
        api.get(f"{DATA}/workspaces").mock(return_value=httpx.Response(200, json=WORKSPACES_PAGE))

        client.close()

        with pytest.raises(RuntimeError, match="closed"):
            client.workspaces.list()
        assert not http.is_closed
        http.close()

    def test_every_sub_client_sends_through_the_supplied_http_client(
        self, api: respx.MockRouter
    ) -> None:
        """Proxy, mTLS, and pool settings live on the caller's client, so calls must use it."""
        http = httpx.Client(headers={"x-caller-marker": "shared"})
        route = api.get(f"{DATA}/configs").mock(return_value=httpx.Response(200, json=CONFIGS_PAGE))

        with AIGatewayClient(
            client_id="a", client_secret="b", tsg_id=TSG_ID, http_client=http, num_retries=0
        ) as client:
            client.configs.list(workspace_id=WORKSPACE_ID)

        assert route.calls.last.request.headers["x-caller-marker"] == "shared"
        http.close()

    def test_exposes_an_auth_adapter_that_carries_the_tenant_header(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Admin-plane clients are built outside this module and attach to this adapter.

        They have to inherit the tenant header as well as the bearer token, and must not
        open a second OAuth session against the same tenant to get it.
        """
        api.get(f"{DATA}/workspaces").mock(return_value=httpx.Response(200, json=WORKSPACES_PAGE))
        route = api.get(f"{ADMIN}/configs").mock(
            return_value=httpx.Response(200, json=CONFIGS_PAGE)
        )
        gateway.workspaces.list()
        attached = AIGatewayConfigsClient(
            base_url=ADMIN, auth=gateway.auth, http=gateway.http, num_retries=0
        )

        attached.list(workspace_id=WORKSPACE_ID)

        assert route.calls.last.request.headers["Authorization"] == f"Bearer {TOKEN}"
        assert route.calls.last.request.headers[HEADER_TSG_ID] == TSG_ID
        assert api["token"].call_count == 1


class TestAuthentication:
    def test_sends_the_bearer_token(self, gateway: AIGatewayClient, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACES_PAGE)
        )

        gateway.workspaces.list()

        assert route.calls.last.request.headers["Authorization"] == f"Bearer {TOKEN}"

    def test_sends_the_tenant_header(self, gateway: AIGatewayClient, api: respx.MockRouter) -> None:
        """Without x-tsg-id the gateway answers a 403 that reads exactly like a stale token."""
        route = api.get(f"{DATA}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACES_PAGE)
        )

        gateway.workspaces.list()

        assert route.calls.last.request.headers[HEADER_TSG_ID] == TSG_ID

    def test_shares_one_token_across_sub_clients(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        api.get(f"{DATA}/workspaces").mock(return_value=httpx.Response(200, json=WORKSPACES_PAGE))
        api.get(f"{DATA}/configs").mock(return_value=httpx.Response(200, json=CONFIGS_PAGE))

        gateway.workspaces.list()
        gateway.configs.list(workspace_id=WORKSPACE_ID)

        assert api["token"].call_count == 1


class TestWorkspacesList:
    def test_reads_the_data_plane_by_default(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACES_PAGE)
        )

        gateway.workspaces.list()

        assert str(route.calls.last.request.url) == f"{DATA}/workspaces"

    def test_omits_the_status_filter_when_unset(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """An empty status parameter is not the same as no status parameter."""
        route = api.get(f"{DATA}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACES_PAGE)
        )

        gateway.workspaces.list()

        assert "status" not in route.calls.last.request.url.params

    def test_sends_the_status_filter(self, gateway: AIGatewayClient, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACES_PAGE)
        )

        gateway.workspaces.list(status="archived")

        assert str(route.calls.last.request.url) == f"{DATA}/workspaces?status=archived"

    def test_routes_to_the_admin_plane(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Archived workspaces tenant-wide is the one query that needs both options."""
        route = api.get(f"{ADMIN}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACES_PAGE)
        )

        gateway.workspaces.list(plane="admin", status="archived")

        assert str(route.calls.last.request.url) == f"{ADMIN}/workspaces?status=archived"

    def test_returns_the_scope_that_grants_data_plane_access(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        api.get(f"{DATA}/workspaces").mock(return_value=httpx.Response(200, json=WORKSPACES_PAGE))

        result = gateway.workspaces.list()

        assert result.data[0].scope_name == "main_airs_workspace_1852583913"


class TestWorkspacesGet:
    def test_addresses_the_workspace_by_uuid(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/workspaces/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        gateway.workspaces.get(WORKSPACE_ID)

        assert str(route.calls.last.request.url) == f"{DATA}/workspaces/{WORKSPACE_ID}"

    def test_accepts_a_slug(self, gateway: AIGatewayClient, api: respx.MockRouter) -> None:
        """Upstream documents the slug as accepted; a UUID-only check would reject it."""
        route = api.get(f"{DATA}/workspaces/{WORKSPACE_SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        gateway.workspaces.get(WORKSPACE_SLUG)

        assert str(route.calls.last.request.url) == f"{DATA}/workspaces/{WORKSPACE_SLUG}"

    def test_routes_to_the_admin_plane(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """A workspace outside the caller's scope answers 403 AB03 on the data plane."""
        route = api.get(f"{ADMIN}/workspaces/{WORKSPACE_SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        gateway.workspaces.get(WORKSPACE_SLUG, plane="admin")

        assert str(route.calls.last.request.url) == f"{ADMIN}/workspaces/{WORKSPACE_SLUG}"

    def test_parses_the_settings_block(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        api.get(f"{DATA}/workspaces/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        detail = gateway.workspaces.get(WORKSPACE_ID)

        assert detail.security_settings == {"membersViewLogs": True}

    @pytest.mark.parametrize("ref", ["../../admin/v2/workspaces", "ws/produc", "", "_leading"])
    def test_rejects_a_ref_that_could_reshape_the_path(
        self, gateway: AIGatewayClient, ref: str
    ) -> None:
        with pytest.raises(AISecPayloadError, match="workspace_ref"):
            gateway.workspaces.get(ref)


class TestWorkspacesCreate:
    def test_posts_to_the_admin_plane(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Creating a workspace needs a tenant-root role; the data plane refuses it."""
        route = api.post(f"{ADMIN}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )

        gateway.workspaces.create(name="Production", scope_name="ws_production_bx7qw0")

        assert route.calls.last.request.method == "POST"
        assert str(route.calls.last.request.url) == f"{ADMIN}/workspaces"

    def test_sends_only_the_supplied_fields(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{ADMIN}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )

        gateway.workspaces.create(name="Production", scope_name="ws_production_bx7qw0")

        assert sent_body(route) == {"name": "Production", "scope_name": "ws_production_bx7qw0"}

    def test_sends_limit_policies_as_arrays(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Both limit fields are arrays of policies, not single objects."""
        route = api.post(f"{ADMIN}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )

        gateway.workspaces.create(
            name="Production",
            scope_name="ws_production_bx7qw0",
            description="All production applications",
            defaults={"metadata": {"env": "production"}},
            users=["user-1"],
            rate_limits=[GatewayRateLimit(type="requests", unit="rpm", value=100)],
        )

        assert sent_body(route) == {
            "name": "Production",
            "scope_name": "ws_production_bx7qw0",
            "description": "All production applications",
            "defaults": {"metadata": {"env": "production"}},
            "rate_limits": [{"type": "requests", "unit": "rpm", "value": 100}],
            "users": ["user-1"],
        }

    def test_a_limit_model_widens_its_numbers_but_a_mapping_does_not(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """The limit models declare float fields, so an int given to one leaves as a float.

        Asserted against the raw bytes because ``100 == 100.0`` in Python, which would let
        a decoded-body assertion pass while the wire carried something else. The reference
        implementation types these as open records and sends whatever it is handed, so a
        caller who needs the integer form passes a mapping.
        """
        route = api.post(f"{ADMIN}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )
        limit = {"type": "requests", "unit": "rpm", "value": 100}

        gateway.workspaces.create(
            name="Production",
            scope_name="ws_production_bx7qw0",
            rate_limits=[GatewayRateLimit(**limit)],
        )
        via_model = route.calls.last.request.content.decode()

        gateway.workspaces.create(
            name="Production", scope_name="ws_production_bx7qw0", rate_limits=[limit]
        )
        via_mapping = route.calls.last.request.content.decode()

        assert '"value":100.0' in via_model
        assert '"value":100' in via_mapping
        assert '"value":100.0' not in via_mapping

    def test_returns_the_created_record(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Workspaces are the one create that returns a record rather than a receipt."""
        api.post(f"{ADMIN}/workspaces").mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )

        created = gateway.workspaces.create(name="Production", scope_name="ws_production_bx7qw0")

        assert created.scope_name == "ws_production_bx7qw0"

    def test_rejects_a_missing_name(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Missing name"):
            gateway.workspaces.create(name="", scope_name="ws_production_bx7qw0")

    def test_rejects_a_missing_scope_name(self, gateway: AIGatewayClient) -> None:
        """scope_name is Prisma AIRS-specific and is not derived from name."""
        with pytest.raises(AISecPayloadError, match="Missing scope_name"):
            gateway.workspaces.create(name="Production", scope_name="")


class TestWorkspacesUpdate:
    def test_puts_to_the_admin_plane(self, gateway: AIGatewayClient, api: respx.MockRouter) -> None:
        route = api.put(f"{ADMIN}/workspaces/{WORKSPACE_SLUG}").mock(
            return_value=httpx.Response(200, json={})
        )

        gateway.workspaces.update(WORKSPACE_SLUG, description="Production workloads, us-east")

        assert route.calls.last.request.method == "PUT"
        assert str(route.calls.last.request.url) == f"{ADMIN}/workspaces/{WORKSPACE_SLUG}"

    def test_sends_only_the_changed_fields(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{ADMIN}/workspaces/{WORKSPACE_SLUG}").mock(
            return_value=httpx.Response(200, json={})
        )

        gateway.workspaces.update(WORKSPACE_SLUG, description="Production workloads, us-east")

        assert sent_body(route) == {"description": "Production workloads, us-east"}

    def test_accepts_an_empty_acknowledgement(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """The API acknowledges the write with an empty body rather than the record.

        An empty 200 is the success case here, not a validation failure, and the caller
        gets an empty acknowledgement rather than the updated workspace.
        """
        api.put(f"{ADMIN}/workspaces/{WORKSPACE_SLUG}").mock(
            return_value=httpx.Response(200, text="")
        )

        ack = gateway.workspaces.update(WORKSPACE_SLUG, name="Prod")

        assert ack.model_dump() == {}

    def test_rejects_an_empty_patch(self, gateway: AIGatewayClient) -> None:
        """Mirrors the API's own "No update fields provided" without a round trip."""
        with pytest.raises(AISecPayloadError, match="Empty update"):
            gateway.workspaces.update(WORKSPACE_SLUG)

    def test_rejects_a_malformed_ref(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="workspace_ref"):
            gateway.workspaces.update("bad/ref", name="Prod")


class TestWorkspacesDelete:
    def test_deletes_on_the_admin_plane(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """A soft delete: the row survives, visible only via list(status="archived")."""
        route = api.delete(f"{ADMIN}/workspaces/{WORKSPACE_SLUG}").mock(
            return_value=httpx.Response(200, text="")
        )

        gateway.workspaces.delete(WORKSPACE_SLUG)

        assert route.calls.last.request.method == "DELETE"
        assert str(route.calls.last.request.url) == f"{ADMIN}/workspaces/{WORKSPACE_SLUG}"

    def test_sends_no_body_and_no_query(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Unlike integrations and deployments, this delete takes no organisation_id."""
        route = api.delete(f"{ADMIN}/workspaces/{WORKSPACE_SLUG}").mock(
            return_value=httpx.Response(200, text="")
        )

        gateway.workspaces.delete(WORKSPACE_SLUG)

        assert route.calls.last.request.content == b""
        assert dict(route.calls.last.request.url.params) == {}

    def test_rejects_a_malformed_ref(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="workspace_ref"):
            gateway.workspaces.delete("../workspaces")


class TestConfigs:
    def test_list_filters_by_workspace(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/configs").mock(return_value=httpx.Response(200, json=CONFIGS_PAGE))

        result = gateway.configs.list(workspace_id=WORKSPACE_ID)

        assert str(route.calls.last.request.url) == f"{DATA}/configs?workspace_id={WORKSPACE_ID}"
        assert (result.total, result.data[0].slug) == (1, "pc-claude-e46fe6")

    def test_list_rows_are_the_documented_twelve_fields(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """A strict subset of the detail read, and every field of it is declared.

        Nothing falls through to ``model_extra``, which is what distinguishes the config
        row from the near-identical guardrail row; and ``config`` is detail-only, so a
        caller must not reach for it here.
        """
        api.get(f"{DATA}/configs").mock(return_value=httpx.Response(200, json=CONFIGS_PAGE))

        row = gateway.configs.list(workspace_id=WORKSPACE_ID).data[0]

        assert row.model_extra == {}
        assert row.is_default == 0
        assert not hasattr(row, "config")

    def test_list_rejects_a_malformed_workspace_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid workspace_id"):
            gateway.configs.list(workspace_id="not-a-uuid")

    def test_get_addresses_the_config_by_id(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/configs/{CONFIG_ID}").mock(
            return_value=httpx.Response(200, json=CONFIG_DETAIL)
        )

        gateway.configs.get(CONFIG_ID)

        assert str(route.calls.last.request.url) == f"{DATA}/configs/{CONFIG_ID}"

    def test_get_leaves_the_routing_config_encoded(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Reads return `config` as a JSON string; parsing it silently would hide that."""
        api.get(f"{DATA}/configs/{CONFIG_ID}").mock(
            return_value=httpx.Response(200, json=CONFIG_DETAIL)
        )

        detail = gateway.configs.get(CONFIG_ID)

        assert json.loads(detail.config) == {"provider": "@anthropic-prod"}

    def test_get_rejects_a_malformed_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid config_id"):
            gateway.configs.get("764cf9cd")

    def test_create_sends_the_config_as_an_object(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Writes take an object even though reads hand it back as a string."""
        route = api.post(f"{DATA}/configs").mock(
            return_value=httpx.Response(200, json=CONFIG_RECEIPT)
        )

        gateway.configs.create(
            name="vertex-airs", workspace_id=WORKSPACE_ID, config={"retry": {"attempts": 3}}
        )

        assert sent_body(route) == {
            "name": "vertex-airs",
            "workspace_id": WORKSPACE_ID,
            "config": {"retry": {"attempts": 3}},
        }

    def test_create_returns_a_receipt(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Create answers {id, version_id, slug, object}, never the full record."""
        api.post(f"{DATA}/configs").mock(return_value=httpx.Response(200, json=CONFIG_RECEIPT))

        receipt = gateway.configs.create(name="vertex-airs", workspace_id=WORKSPACE_ID, config={})

        assert (receipt.id, receipt.slug) == (CONFIG_ID, "pc-sdk-ve-14620d")

    def test_create_rejects_a_malformed_workspace_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid workspace_id"):
            gateway.configs.create(name="vertex-airs", workspace_id="ws-main-a-349e0e", config={})

    def test_update_puts_to_the_config_path(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{DATA}/configs/{CONFIG_ID}").mock(
            return_value=httpx.Response(200, json={})
        )

        gateway.configs.update(
            CONFIG_ID,
            name="claude-code",
            workspace_id=WORKSPACE_ID,
            config={"retry": {"attempts": 5}},
        )

        assert route.calls.last.request.method == "PUT"
        assert str(route.calls.last.request.url) == f"{DATA}/configs/{CONFIG_ID}"
        assert sent_body(route) == {
            "name": "claude-code",
            "workspace_id": WORKSPACE_ID,
            "config": {"retry": {"attempts": 5}},
        }

    def test_update_rejects_a_malformed_config_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid config_id"):
            gateway.configs.update(
                "pc-claude-e46fe6", name="x", workspace_id=WORKSPACE_ID, config={}
            )

    def test_update_rejects_a_malformed_workspace_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid workspace_id"):
            gateway.configs.update(CONFIG_ID, name="x", workspace_id="main", config={})

    def test_delete_hits_the_config_path(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """A hard delete: no organisation_id query parameter, unlike deployments."""
        route = api.delete(f"{DATA}/configs/{CONFIG_ID}").mock(
            return_value=httpx.Response(200, text="")
        )

        gateway.configs.delete(CONFIG_ID)

        assert route.calls.last.request.method == "DELETE"
        assert str(route.calls.last.request.url) == f"{DATA}/configs/{CONFIG_ID}"

    def test_delete_rejects_a_malformed_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid config_id"):
            gateway.configs.delete("not-a-uuid")


class TestGuardrails:
    def test_list_filters_by_workspace(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/guardrails").mock(
            return_value=httpx.Response(200, json=GUARDRAILS_PAGE)
        )

        result = gateway.guardrails.list(workspace_id=WORKSPACE_ID)

        assert str(route.calls.last.request.url) == f"{DATA}/guardrails?workspace_id={WORKSPACE_ID}"
        assert (result.total, result.data[0].slug) == (1, "pg-prisma-099a16")

    def test_list_rejects_a_malformed_workspace_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid workspace_id"):
            gateway.guardrails.list(workspace_id="")

    def test_get_addresses_the_guardrail_by_id(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/guardrails/{GUARDRAIL_ID}").mock(
            return_value=httpx.Response(200, json=GUARDRAIL_DETAIL)
        )

        detail = gateway.guardrails.get(GUARDRAIL_ID)

        assert str(route.calls.last.request.url) == f"{DATA}/guardrails/{GUARDRAIL_ID}"
        assert detail.checks[0].id == "panw-prisma-airs.intercept"

    def test_get_rejects_a_malformed_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid guardrail_id"):
            gateway.guardrails.get("pg-prisma-099a16")

    def test_create_renders_actions_under_their_wire_names(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """`async` is a Python keyword, so the model attribute is async_ -- the wire is not."""
        route = api.post(f"{DATA}/guardrails").mock(
            return_value=httpx.Response(200, json=GUARDRAIL_RECEIPT)
        )

        gateway.guardrails.create(
            workspace_id=WORKSPACE_ID,
            name="PrismaAIRS",
            checks=[
                GuardrailCheck(
                    id="panw-prisma-airs.intercept",
                    parameters={"profile_name": "AI Gateway - Strict"},
                    is_enabled=True,
                )
            ],
            actions=GuardrailActions(deny=False, async_=False, sequential=False),
        )

        assert sent_body(route) == {
            "workspace_id": WORKSPACE_ID,
            "name": "PrismaAIRS",
            "checks": [
                {
                    "id": "panw-prisma-airs.intercept",
                    "parameters": {"profile_name": "AI Gateway - Strict"},
                    "is_enabled": True,
                }
            ],
            "actions": {"deny": False, "async": False, "sequential": False},
        }

    def test_create_passes_plain_mappings_through(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Checks and actions are open-ended upstream, so raw mappings must survive intact."""
        route = api.post(f"{DATA}/guardrails").mock(
            return_value=httpx.Response(200, json=GUARDRAIL_RECEIPT)
        )

        gateway.guardrails.create(
            workspace_id=WORKSPACE_ID,
            name="PrismaAIRS",
            checks=[{"id": "future.check", "parameters": {}, "is_enabled": True}],
            actions={"deny": True, "on_fail": {"feedback": {"value": -5}}},
        )

        assert sent_body(route)["actions"] == {
            "deny": True,
            "on_fail": {"feedback": {"value": -5}},
        }

    def test_create_keeps_an_explicit_null_supplied_as_a_mapping(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """A mapping is the escape hatch for sending an explicit null.

        Models are dumped with ``exclude_none``, so a field set to ``None`` on a model is
        omitted rather than sent as ``null``. A caller who needs the API to see ``null``
        passes the fragment as a mapping, which is forwarded verbatim.
        """
        route = api.post(f"{DATA}/guardrails").mock(
            return_value=httpx.Response(200, json=GUARDRAIL_RECEIPT)
        )

        gateway.guardrails.create(
            workspace_id=WORKSPACE_ID,
            name="PrismaAIRS",
            checks=[
                {"id": "future.check", "parameters": {"profile_name": None}, "is_enabled": True}
            ],
            actions={"deny": True, "on_fail": None},
        )

        body = sent_body(route)
        assert body["actions"] == {"deny": True, "on_fail": None}
        assert body["checks"][0]["parameters"] == {"profile_name": None}

    def test_create_returns_a_receipt(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Create answers {id, version_id, slug, object}, never the full guardrail."""
        api.post(f"{DATA}/guardrails").mock(
            return_value=httpx.Response(200, json=GUARDRAIL_RECEIPT)
        )

        receipt = gateway.guardrails.create(
            workspace_id=WORKSPACE_ID, name="PrismaAIRS", checks=[], actions={}
        )

        assert (receipt.id, receipt.version_id, receipt.slug) == (
            GUARDRAIL_ID,
            "v1",
            "pg-sdk-ve-874b62",
        )
        assert not hasattr(receipt, "checks")

    def test_create_rejects_a_malformed_workspace_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid workspace_id"):
            gateway.guardrails.create(workspace_id="main", name="PrismaAIRS", checks=[], actions={})

    def test_delete_hits_the_guardrail_path(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.delete(f"{DATA}/guardrails/{GUARDRAIL_ID}").mock(
            return_value=httpx.Response(200, text="")
        )

        gateway.guardrails.delete(GUARDRAIL_ID)

        assert route.calls.last.request.method == "DELETE"
        assert str(route.calls.last.request.url) == f"{DATA}/guardrails/{GUARDRAIL_ID}"

    def test_delete_rejects_a_malformed_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid guardrail_id"):
            gateway.guardrails.delete("not-a-uuid")


class TestProviders:
    def test_list_filters_by_workspace(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/providers").mock(
            return_value=httpx.Response(200, json=PROVIDERS_PAGE)
        )

        result = gateway.providers.list(workspace_id=WORKSPACE_ID)

        assert str(route.calls.last.request.url) == f"{DATA}/providers?workspace_id={WORKSPACE_ID}"
        assert result.data[0].slug == "openai-calvin"

    def test_list_rejects_a_malformed_workspace_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid workspace_id"):
            gateway.providers.list(workspace_id="openai-calvin")

    def test_create_binds_an_integration_into_the_workspace(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{DATA}/providers").mock(
            return_value=httpx.Response(200, json=PROVIDER_RECEIPT)
        )

        gateway.providers.create(
            workspace_id=WORKSPACE_ID,
            ai_provider_id=AI_PROVIDER_ID,
            integration_id=INTEGRATION_ID,
            name="openai-calvin",
            slug="openai-calvin",
        )

        assert str(route.calls.last.request.url) == f"{DATA}/providers"
        assert sent_body(route) == {
            "workspace_id": WORKSPACE_ID,
            "ai_provider_id": AI_PROVIDER_ID,
            "name": "openai-calvin",
            "integration_id": INTEGRATION_ID,
            "slug": "openai-calvin",
        }

    def test_create_includes_the_optional_fields_when_given(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{DATA}/providers").mock(
            return_value=httpx.Response(200, json=PROVIDER_RECEIPT)
        )

        gateway.providers.create(
            workspace_id=WORKSPACE_ID,
            ai_provider_id=AI_PROVIDER_ID,
            integration_id=INTEGRATION_ID,
            name="openai-calvin",
            slug="openai-calvin",
            note="owned by platform",
            expires_at="2027-01-01T00:00:00Z",
        )

        body = sent_body(route)
        assert (body["note"], body["expires_at"]) == ("owned by platform", "2027-01-01T00:00:00Z")

    def test_create_returns_a_receipt_without_a_version_id(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """The provider receipt has no version_id, unlike configs and guardrails."""
        api.post(f"{DATA}/providers").mock(return_value=httpx.Response(200, json=PROVIDER_RECEIPT))

        receipt = gateway.providers.create(
            workspace_id=WORKSPACE_ID,
            ai_provider_id=AI_PROVIDER_ID,
            integration_id=INTEGRATION_ID,
            name="openai-calvin",
            slug="openai-calvin",
        )

        assert (receipt.id, receipt.slug, receipt.object) == (
            PROVIDER_ID,
            "openai-calvin",
            "provider",
        )
        assert not hasattr(receipt, "version_id")

    def test_create_reports_the_first_malformed_id(self, gateway: AIGatewayClient) -> None:
        """Three ids are checked in the reference's order; the caller hears about one."""
        with pytest.raises(AISecPayloadError, match="Invalid workspace_id"):
            gateway.providers.create(
                workspace_id="main",
                ai_provider_id="openai",
                integration_id="integration-1",
                name="openai-calvin",
                slug="openai-calvin",
            )

    @pytest.mark.parametrize(
        ("field", "overrides"),
        [
            ("workspace_id", {"workspace_id": "ws-main-a-349e0e"}),
            ("ai_provider_id", {"ai_provider_id": "openai"}),
            ("integration_id", {"integration_id": "integration-1"}),
        ],
    )
    def test_create_rejects_each_malformed_id(
        self, gateway: AIGatewayClient, field: str, overrides: dict[str, str]
    ) -> None:
        args: dict[str, str] = {
            "workspace_id": WORKSPACE_ID,
            "ai_provider_id": AI_PROVIDER_ID,
            "integration_id": INTEGRATION_ID,
            "name": "openai-calvin",
            "slug": "openai-calvin",
            **overrides,
        }

        with pytest.raises(AISecPayloadError, match=f"Invalid {field}"):
            gateway.providers.create(**args)

    def test_delete_hits_the_provider_path(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.delete(f"{DATA}/providers/{PROVIDER_ID}").mock(
            return_value=httpx.Response(200, text="")
        )

        gateway.providers.delete(PROVIDER_ID)

        assert route.calls.last.request.method == "DELETE"
        assert str(route.calls.last.request.url) == f"{DATA}/providers/{PROVIDER_ID}"

    def test_delete_rejects_a_malformed_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid provider_id"):
            gateway.providers.delete("openai-calvin")


class TestApiKeys:
    def test_list_service_uses_the_service_sub_collection(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """There is no combined api-keys endpoint; the collections are separate."""
        route = api.get(f"{DATA}/api-keys/service").mock(
            return_value=httpx.Response(200, json=API_KEYS_PAGE)
        )

        result = gateway.api_keys.list_service(workspace_id=WORKSPACE_ID)

        assert (
            str(route.calls.last.request.url)
            == f"{DATA}/api-keys/service?workspace_id={WORKSPACE_ID}"
        )
        assert (result.total, result.data[0].name) == (1, "ci-runner")

    def test_list_user_uses_the_user_sub_collection(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/api-keys/user").mock(
            return_value=httpx.Response(200, json=API_KEYS_PAGE)
        )

        gateway.api_keys.list_user(workspace_id=WORKSPACE_ID)

        assert (
            str(route.calls.last.request.url) == f"{DATA}/api-keys/user?workspace_id={WORKSPACE_ID}"
        )

    def test_list_rejects_a_malformed_workspace_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid workspace_id"):
            gateway.api_keys.list_service(workspace_id="workspace")

    def test_create_service_sends_the_key_type_as_type(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """organisation_id is the numeric TSG here, not the organisation UUID reads return."""
        route = api.post(f"{DATA}/api-keys/service").mock(
            return_value=httpx.Response(200, json={"id": KEY_ID})
        )

        gateway.api_keys.create_service(**SERVICE_KEY_ARGS)  # type: ignore[arg-type]

        assert sent_body(route) == {
            "name": "ci-runner",
            "scopes": ["completions.write", "logs.write"],
            "organisation_id": TSG_ID,
            "workspace_id": WORKSPACE_ID,
            "type": "workspace",
        }

    def test_create_surfaces_the_generated_secret(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """Creation is the only time the key material is returned, so nothing may drop it.

        The response shape is unverified against a live tenant, so it parses as an open
        acknowledgement and the fields survive on ``model_extra``.
        """
        api.post(f"{DATA}/api-keys/service").mock(
            return_value=httpx.Response(200, json={"id": KEY_ID, "key": "sk-live-secret"})
        )

        created = gateway.api_keys.create_service(**SERVICE_KEY_ARGS)  # type: ignore[arg-type]

        assert created.model_extra == {"id": KEY_ID, "key": "sk-live-secret"}

    def test_create_user_adds_the_user_id(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{DATA}/api-keys/user").mock(
            return_value=httpx.Response(200, json={"id": KEY_ID})
        )

        gateway.api_keys.create_user(**SERVICE_KEY_ARGS, user_id=USER_ID)  # type: ignore[arg-type]

        body = sent_body(route)
        assert str(route.calls.last.request.url) == f"{DATA}/api-keys/user"
        assert body["user_id"] == USER_ID

    def test_create_omits_the_unset_optional_fields(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        """The API distinguishes an absent key from an explicit null."""
        route = api.post(f"{DATA}/api-keys/service").mock(
            return_value=httpx.Response(200, json={"id": KEY_ID})
        )

        gateway.api_keys.create_service(**SERVICE_KEY_ARGS)  # type: ignore[arg-type]

        body = sent_body(route)
        assert "expires_at" not in body
        assert "rotation_policy" not in body

    def test_create_includes_the_optional_fields_when_given(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{DATA}/api-keys/service").mock(
            return_value=httpx.Response(200, json={"id": KEY_ID})
        )

        gateway.api_keys.create_service(
            **SERVICE_KEY_ARGS,  # type: ignore[arg-type]
            description="CI runner key",
            expires_at="2027-01-01T00:00:00Z",
            defaults={"metadata": {"env": "ci"}},
            rotation_policy={"days": 90},
        )

        body = sent_body(route)
        assert body["description"] == "CI runner key"
        assert body["defaults"] == {"metadata": {"env": "ci"}}
        assert body["rotation_policy"] == {"days": 90}

    def test_create_rejects_a_malformed_workspace_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid workspace_id"):
            gateway.api_keys.create_service(
                name="ci-runner",
                scopes=["completions.write"],
                organisation_id=TSG_ID,
                workspace_id="main",
                key_type="workspace",
            )

    def test_update_service_addresses_the_key_by_id(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{DATA}/api-keys/service/{KEY_ID}").mock(
            return_value=httpx.Response(200, json={})
        )

        gateway.api_keys.update_service(KEY_ID, **SERVICE_KEY_ARGS)  # type: ignore[arg-type]

        assert route.calls.last.request.method == "PUT"
        assert str(route.calls.last.request.url) == f"{DATA}/api-keys/service/{KEY_ID}"

    def test_update_user_addresses_the_key_by_id(
        self, gateway: AIGatewayClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{DATA}/api-keys/user/{KEY_ID}").mock(
            return_value=httpx.Response(200, json={})
        )

        gateway.api_keys.update_user(KEY_ID, **SERVICE_KEY_ARGS, user_id=USER_ID)  # type: ignore[arg-type]

        assert str(route.calls.last.request.url) == f"{DATA}/api-keys/user/{KEY_ID}"
        assert sent_body(route)["user_id"] == USER_ID

    def test_update_service_rejects_a_malformed_key_id(self, gateway: AIGatewayClient) -> None:
        """Key ids are UUIDs; the slug-shaped name a caller reaches for is not one."""
        with pytest.raises(AISecPayloadError, match="Invalid key_id"):
            gateway.api_keys.update_service("ci-runner", **SERVICE_KEY_ARGS)  # type: ignore[arg-type]

    def test_update_user_rejects_a_malformed_key_id(self, gateway: AIGatewayClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid key_id"):
            gateway.api_keys.update_user("ci-runner", **SERVICE_KEY_ARGS, user_id=USER_ID)  # type: ignore[arg-type]

    def test_update_checks_the_key_id_before_the_workspace_id(
        self, gateway: AIGatewayClient
    ) -> None:
        """Matching the reference's order, so a caller sees the same first complaint."""
        with pytest.raises(AISecPayloadError, match="Invalid key_id"):
            gateway.api_keys.update_service(
                "ci-runner",
                name="ci-runner",
                scopes=["completions.write"],
                organisation_id=TSG_ID,
                workspace_id="also-not-a-uuid",
                key_type="workspace",
            )
