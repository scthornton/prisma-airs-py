"""Contract tests for the AI Gateway admin and telemetry clients.

These assert the exact request that goes on the wire -- method, URL, query parameters,
headers, and body -- which is what keeps the port honest against the reference
implementation. Response shapes are checked only where the parse itself is load-bearing.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple

import httpx
import pytest
import respx

from prisma_airs.ai_gateway.ai_gateway_admin import (
    DEFAULT_WINDOW_DAYS,
    AIGatewayAdminClient,
    to_offset_iso,
    to_utc_iso_z,
)
from prisma_airs.constants import (
    AI_GW_CHART_METRICS,
    AI_GW_GROUP_COLUMNS,
    AI_GW_GROUP_DIMENSIONS,
    DEFAULT_AI_GW_ADMIN_ENDPOINT,
    DEFAULT_AI_GW_DATA_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
    ENV_PREFIX_AI_GW,
    ENV_PREFIX_MGMT,
    HEADER_TSG_ID,
)
from prisma_airs.errors import AISecMissingVariableError, AISecPayloadError
from prisma_airs.models.ai_gateway import (
    CacheHitTrendResponse,
    CacheSummaryResponse,
    CostChartResponse,
    CountChartResponse,
    ErrorTrendsResponse,
    FeedbackModelsResponse,
    FeedbackScoreDistributionResponse,
    GatewayIntegrationModel,
    LatencyChartResponse,
    OrganisationSelfResponse,
    RescuedRetriesResponse,
    TokensChartResponse,
    UserTrendsResponse,
)

CLIENT_ID = "svc-client"
CLIENT_SECRET = "svc-secret"
TSG = "1852583913"
TOKEN = "test-access-token"

DATA = DEFAULT_AI_GW_DATA_ENDPOINT
ADMIN = DEFAULT_AI_GW_ADMIN_ENDPOINT

WORKSPACE = "ws-main-a-349e0e"
INTEGRATION_ID = "f6692544-3265-49be-9711-bbdcebc079e4"
PROVIDER_ID = "de7d7d50-31cd-11ee-b93b-0e06f1aa7f7c"
DEPLOYMENT_ID = "32e8314e-7e68-4384-aacb-a476f6c3f91d"
NOT_A_UUID = "openai-calvin"

START = datetime(2026, 7, 20, tzinfo=timezone.utc)
END = datetime(2026, 7, 27, tzinfo=timezone.utc)
START_PARAM = "2026-07-20T00:00:00+00:00"
END_PARAM = "2026-07-27T00:00:00+00:00"

WINDOW_PARAMS = {
    "organisationId": TSG,
    "workspaceSlug": WORKSPACE,
    "timeOfGenerationMin": START_PARAM,
    "timeOfGenerationMax": END_PARAM,
}

# --- response payloads, trimmed to what each model requires -------------------------

QUOTA = {"isQuotaExceeded": False}

COST = {
    "success": True,
    "data": {
        **QUOTA,
        "records": [{"x": "2026-07-20", "y": 411083.0}],
        "total": 411083.0,
        "avg": 1.0,
    },
}
COUNT = {
    "success": True,
    "data": {**QUOTA, "records": [{"x": "2026-07-20", "y": 25746.0}], "total": 25746.0},
}
LATENCY = {
    "success": True,
    "data": {
        **QUOTA,
        "records": [{"x": "2026-07-20", "y": 1.0, "p50": 1.0, "p90": 2.0, "p99": 8329.14}],
        "total": 1.0,
        "p50": 1.0,
        "p90": 2.0,
        "p99": 8329.14,
    },
}
TOKENS = {
    "success": True,
    "data": {
        **QUOTA,
        "records": [
            {
                "x": "2026-07-20",
                "y": 1.0,
                "total_request_units": 4919015459.0,
                "total_response_units": 2.0,
                "avg": 1.0,
            }
        ],
        "total": 1.0,
        "avg": 1.0,
        "total_request_units": 4919015459.0,
        "total_response_units": 2.0,
    },
}
CACHE_SUMMARY = {
    "success": True,
    "data": {
        **QUOTA,
        "summary": {
            "cacheHits": 0,
            "avgCacheLatency": None,
            "totalRequests": 25621,
            "cacheSpeedup": 0,
        },
    },
}
CACHE_HIT_TREND = {
    "success": True,
    "data": {
        **QUOTA,
        "trend": [
            {
                "x": "2026-07-20",
                "simpleHits": 0,
                "semanticHits": 0,
                "hitRate": 0,
                "cumulativeSimpleHitSavings": 0,
                "cumulativeSemanticHitSavings": 0,
            }
        ],
        "total": 0,
        "summary": {"totalCacheHits": 0, "hitRate": 0},
    },
}
USER_TRENDS = {
    "success": True,
    "data": {
        **QUOTA,
        "summary": {"total": 25748, "unique": 1, "avg": 25748},
        "trend": [{"x": "2026-07-20", "y": 25748}],
    },
}
ERROR_TRENDS = {
    "success": True,
    "data": {
        **QUOTA,
        "summary": {"errorPercent": 0.485},
        "trend": [{"x": "2026-07-20", "y": 0.485}],
    },
}
RESCUED_RETRIES = {
    "success": True,
    "data": {
        **QUOTA,
        "trend": [{"x": "2026-07-20", "y": []}],
        "total": 0,
        "trends": [{"x": "2026-07-20", "retry": [], "fallback": []}],
        "retryTotal": 0,
        "fallbackTotal": 0,
    },
}
FEEDBACK_DISTRIBUTION = {
    "success": True,
    "data": {**QUOTA, "records": [{"x": 5, "y": 30}, {"x": -5, "y": 33}], "total": 63},
}
FEEDBACK_MODELS = {
    "success": True,
    "data": {
        **QUOTA,
        "records": [
            {"x": "claude-sonnet-5", "y": {"avgWeightedFeedback": 4.2, "feedbackCount": 12}}
        ],
    },
}


class ChartCase(NamedTuple):
    """One ``logs/charts/*`` endpoint under test."""

    method: str
    slug: str
    payload: dict[str, Any]
    model: type[Any]


#: Every ``logs/charts/*`` endpoint. The model column matters as much as the slug:
#: unknown keys are preserved rather than rejected, so several of these envelopes parse
#: each other's payloads without complaint and only the declared type tells them apart.
CHART_CALLS = [
    ChartCase("cost", "cost", COST, CostChartResponse),
    ChartCase("requests", "requests", COUNT, CountChartResponse),
    ChartCase("latency", "latency", LATENCY, LatencyChartResponse),
    ChartCase("tokens", "tokens", TOKENS, TokensChartResponse),
    ChartCase("errors", "errors", COUNT, CountChartResponse),
    ChartCase("users", "users", COUNT, CountChartResponse),
    ChartCase("cache_summary", "cache-summary", CACHE_SUMMARY, CacheSummaryResponse),
    ChartCase("cache_hit_trend", "cache-hit-trend", CACHE_HIT_TREND, CacheHitTrendResponse),
    ChartCase("user_trends", "user-trends", USER_TRENDS, UserTrendsResponse),
    ChartCase("error_trends", "error-trends", ERROR_TRENDS, ErrorTrendsResponse),
    ChartCase("rescued_retries", "rescued-retries", RESCUED_RETRIES, RescuedRetriesResponse),
    ChartCase("feedback_trend", "feedback-trend", COUNT, CountChartResponse),
    ChartCase("feedback_weighted", "feedback-weighted", COUNT, CountChartResponse),
    ChartCase(
        "feedback_score_distribution",
        "feedback-score-distribution",
        FEEDBACK_DISTRIBUTION,
        FeedbackScoreDistributionResponse,
    ),
    ChartCase("feedback_models", "feedback-models", FEEDBACK_MODELS, FeedbackModelsResponse),
]

GROUP_ROWS = {
    "object": "list",
    "is_quota_exceeded": False,
    "total": 1,
    "data": [{"requests": 10506.0, "cost": 29704.16, "object": "group"}],
}
USER_GROUP = {
    "success": True,
    "data": {**QUOTA, "records": [{"_user": "", "count": 25748, "cost": 411060.85}], "total": 1},
}
LOG_RECORD = {
    "id": "log-1",
    "workspace_slug": WORKSPACE,
    "ai_model": "claude-sonnet-5",
    "_user": "",
    "total_units": 12.0,
    "cost": 0.0,
    "trace_id": "trace-1",
    "is_proxy_call": 1,
    "created_at": "2026-07-20T00:00:00Z",
    "is_success": 0,
    "cache_status": "MISS",
    "retry_success_count": 0,
    "mode": "proxy",
    "last_used_option_index": 0,
    "response_status_code": 446,
    "request_url": "https://gw.test/v1/chat",
    "request_method": "POST",
    "ai_org": "org",
    "api_key_id": "key-1",
    "license_id": "lic-1",
    "log_store_file_path_format": "fmt",
    "metadataKey": [],
    "metadataValue": [],
    "prompt_slug": "",
    "feedback": [],
}
LOGS = {
    "success": True,
    "data": {**QUOTA, "records": [LOG_RECORD], "total": 125, "capturedTotal": 0},
}

INTEGRATION = {
    "id": INTEGRATION_ID,
    "name": "openai-calvin",
    "owner_id": "user-1",
    "status": "active",
    "created_at": "2026-07-01T00:00:00Z",
    "last_updated_at": "2026-07-02T00:00:00Z",
    "slug": "openai-calvin",
    "description": None,
    "workspace_id": None,
    "ai_provider_id": PROVIDER_ID,
    "object": "integration",
}
INTEGRATION_LIST = {"object": "list", "total": 1, "data": [INTEGRATION]}
INTEGRATION_MODELS = {
    "models": [{"slug": "gpt-4", "enabled": True}],
    "allow_all_models": False,
    "object": "integration_models",
}
INTEGRATION_WORKSPACES = {
    "workspaces": [
        {
            "id": "ws-1",
            "usage_limits": None,
            "rate_limits": None,
            "enabled": True,
            "status": "active",
            "created_at": "2026-07-01T00:00:00Z",
            "last_updated_at": "2026-07-02T00:00:00Z",
            "last_reset_at": None,
        }
    ],
    "global_workspace_access": {"enabled": False, "rate_limits": None, "usage_limits": None},
    "object": "integration_workspaces",
}
MCP_LIST = {
    "object": "list",
    "total": 1,
    "data": [
        {
            "id": INTEGRATION_ID,
            "organisation_id": TSG,
            "name": "Context 7",
            "owner_id": "user-1",
            "status": "active",
            "type": "mcp",
            "url": "https://mcp.context7.com/mcp",
            "auth_type": "none",
            "transport": "http",
            "configurations": '{"headers":{}}',
            "created_at": "2026-07-01T00:00:00Z",
            "last_updated_at": "2026-07-02T00:00:00Z",
        }
    ],
}
DEPLOYMENT = {
    "id": DEPLOYMENT_ID,
    "name": "talos",
    "slug": "dp-talos-f3b74e",
    "type": "production",
    "status": "active",
    "created_at": "2026-07-01T00:00:00Z",
    "last_updated_at": "2026-07-02T00:00:00Z",
    "last_synced_at": None,
    "last_resynced_at": None,
    "is_default": 0,
    "created_by": "user-1",
    "object": "deployment",
}
DEPLOYMENT_LIST = {
    "object": "list",
    "total": 2,
    "data": [DEPLOYMENT, {**DEPLOYMENT, "id": INTEGRATION_ID, "status": "archived"}],
}
DEPLOYMENT_DETAIL = {**DEPLOYMENT, "deployment_config": None}
DEPLOYMENT_RECEIPT = {
    "id": DEPLOYMENT_ID,
    "client_auth": "client-auth-abc",
    "credentials": {"username": "dp-user", "password": "dp-pass"},
    "organisation_id": "0f8f8f8f-0000-0000-0000-000000000000",
    "object": "deployment",
}
PLUGIN_LIST = {
    "object": "list",
    "total": 1,
    "data": [
        {
            "id": "plugin-1",
            "integration_id": INTEGRATION_ID,
            "credentials": {"AIRS_API_KEY": "sn*****Gul"},
            "owner_id": "user-1",
            "created_at": "2026-07-01T00:00:00Z",
            "last_updated_at": "2026-07-02T00:00:00Z",
            "status": "active",
            "integration_slug": "panw-prisma-airs",
            "plugin_provider_id": "pp-1",
            "plugin_provider_slug": "panw",
            "object": "plugin",
        }
    ],
}
AUDIT_LOGS = {
    "records": [
        {
            "timestamp": "2026-07-20T00:00:00Z",
            "method": "POST",
            "uri": "/ai_gw/admin/v2/integrations",
            "request_id": "req-1",
            "request_body": '{"key":"sk-live-secret"}',
            "query_params": "",
            "request_headers": '{"authorization":"***"}',
            "user_id": "user-1",
            "user_type": "service",
            "organisation_id": TSG,
            "workspace_id": "ws-1",
            "response_status_code": 200,
            "resource_type": "integration",
            "action": "create",
            "client_ip": "203.0.113.7",
            "country": "US",
        }
    ]
}
WRITE_OK = {"id": INTEGRATION_ID}


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer's real gateway environment out of these tests."""
    for prefix in (ENV_PREFIX_AI_GW, ENV_PREFIX_MGMT):
        for suffix in ("CLIENT_ID", "CLIENT_SECRET", "TSG_ID", "TOKEN_ENDPOINT"):
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)
    monkeypatch.delenv(f"{ENV_PREFIX_AI_GW}_DATA_ENDPOINT", raising=False)
    monkeypatch.delenv(f"{ENV_PREFIX_AI_GW}_ADMIN_ENDPOINT", raising=False)


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    """A mock router with the OAuth2 token endpoint already answered."""
    with respx.mock(assert_all_called=False) as router:
        router.post(DEFAULT_TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"access_token": TOKEN, "expires_in": 900})
        )
        yield router


@pytest.fixture
def client(api: respx.MockRouter) -> Iterator[AIGatewayAdminClient]:
    with AIGatewayAdminClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        tsg_id=TSG,
        num_retries=0,
    ) as gateway:
        yield gateway


def sent_body(route: respx.Route) -> Any:
    """Decode the JSON body of the last request on ``route``."""
    return json.loads(route.calls.last.request.content)


def sent_params(route: respx.Route) -> dict[str, str]:
    """Flatten the query string of the last request on ``route``."""
    return dict(route.calls.last.request.url.params)


class TestConstruction:
    def test_requires_credentials(self) -> None:
        with pytest.raises(AISecMissingVariableError, match="CLIENT_ID"):
            AIGatewayAdminClient()

    def test_falls_back_to_the_management_prefix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """One service account drives every plane, so PANW_MGMT_* alone must suffice."""
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_ID", CLIENT_ID)
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_SECRET", CLIENT_SECRET)
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_TSG_ID", "999")

        with AIGatewayAdminClient() as gateway:
            assert gateway.tsg_id == "999"

    def test_prefers_the_gateway_prefix_over_the_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_ID", CLIENT_ID)
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_SECRET", CLIENT_SECRET)
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_TSG_ID", "999")
        monkeypatch.setenv(f"{ENV_PREFIX_AI_GW}_TSG_ID", TSG)

        with AIGatewayAdminClient() as gateway:
            assert gateway.tsg_id == TSG

    def test_defaults_to_the_published_endpoints(self, client: AIGatewayAdminClient) -> None:
        assert (client.data_endpoint, client.admin_endpoint) == (DATA, ADMIN)

    def test_reads_endpoint_overrides_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """api.sase and api.apps are the same host; an operator may already allowlist one."""
        monkeypatch.setenv(f"{ENV_PREFIX_AI_GW}_DATA_ENDPOINT", "https://sase.test/ai_gw/v2")
        monkeypatch.setenv(f"{ENV_PREFIX_AI_GW}_ADMIN_ENDPOINT", "https://sase.test/ai_gw/admin/v2")

        with AIGatewayAdminClient(
            client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG
        ) as gateway:
            assert gateway.data_endpoint == "https://sase.test/ai_gw/v2"
            assert gateway.admin_endpoint == "https://sase.test/ai_gw/admin/v2"

    def test_an_explicit_endpoint_wins_over_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(f"{ENV_PREFIX_AI_GW}_ADMIN_ENDPOINT", "https://from-env.test")

        with AIGatewayAdminClient(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            tsg_id=TSG,
            admin_endpoint="https://explicit.test",
        ) as gateway:
            assert gateway.admin_endpoint == "https://explicit.test"

    def test_close_leaves_an_injected_http_client_open(self) -> None:
        """A caller-supplied client is the caller's to close; a shared pool would die."""
        external = httpx.Client()

        with AIGatewayAdminClient(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            tsg_id=TSG,
            http_client=external,
        ):
            pass

        assert not external.is_closed
        external.close()

    @pytest.mark.parametrize("value", [-1, 6, 1.5, True])
    def test_rejects_an_unusable_retry_count(self, value: object) -> None:
        with pytest.raises(AISecPayloadError, match="num_retries"):
            AIGatewayAdminClient(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                tsg_id=TSG,
                num_retries=value,  # type: ignore[arg-type]
            )


class TestAuthentication:
    def test_sends_the_bearer_token_and_the_tenant_header(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """Omitting x-tsg-id yields a 403 OPA denial indistinguishable from a stale token."""
        route = api.get(f"{ADMIN}/plugins").mock(return_value=httpx.Response(200, json=PLUGIN_LIST))

        client.plugins.list()

        headers = route.calls.last.request.headers
        assert headers["authorization"] == f"Bearer {TOKEN}"
        assert headers[HEADER_TSG_ID] == TSG

    def test_telemetry_carries_the_tenant_header_too(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """Telemetry rides the other plane but the same auth adapter."""
        route = api.get(f"{DATA}/logs/charts/cost").mock(
            return_value=httpx.Response(200, json=COST)
        )

        client.telemetry.cost(workspace_slug=WORKSPACE)

        assert route.calls.last.request.headers[HEADER_TSG_ID] == TSG


class TestTimestampRendering:
    def test_renders_a_numeric_offset_rather_than_a_z_suffix(self) -> None:
        """The telemetry validator rejects a Z suffix with AB01."""
        assert to_offset_iso(START) == "2026-07-20T00:00:00+00:00"

    def test_renders_a_positive_offset(self) -> None:
        stamp = datetime(2026, 7, 20, tzinfo=timezone(timedelta(hours=2)))

        assert to_offset_iso(stamp) == "2026-07-20T00:00:00+02:00"

    def test_renders_a_fractional_negative_offset(self) -> None:
        stamp = datetime(2026, 7, 20, tzinfo=timezone(timedelta(hours=-4, minutes=-30)))

        assert to_offset_iso(stamp) == "2026-07-20T00:00:00-04:30"

    def test_reads_a_naive_datetime_as_local_time(self) -> None:
        """A naive value means local time, exactly as a JavaScript ``Date`` would read it.

        Two ways to get this wrong, so both are pinned. Converting to UTC
        (``astimezone(timezone.utc)``) moves the wall clock; stamping UTC onto it
        (``replace(tzinfo=utc)``) keeps the wall clock but moves the instant, which is the
        one that silently shifts the queried window. Only the second assertion catches
        that, and only when the host is not itself on UTC.
        """
        naive = datetime(2026, 7, 20, 12, 30, 15)  # noqa: DTZ001

        rendered = to_offset_iso(naive)

        assert rendered.startswith("2026-07-20T12:30:15")
        assert datetime.fromisoformat(rendered) == naive.astimezone()

    def test_drops_sub_second_precision(self) -> None:
        stamp = datetime(2026, 7, 20, microsecond=123456, tzinfo=timezone.utc)

        assert to_offset_iso(stamp) == "2026-07-20T00:00:00+00:00"

    def test_audit_stamps_keep_the_z_suffix(self) -> None:
        """audit-logs wants exactly what Date.toISOString() emits -- the opposite rule."""
        assert to_utc_iso_z(START) == "2026-07-20T00:00:00.000Z"

    def test_audit_stamps_are_converted_to_utc(self) -> None:
        stamp = datetime(2026, 7, 20, 2, tzinfo=timezone(timedelta(hours=2)))

        assert to_utc_iso_z(stamp) == "2026-07-20T00:00:00.000Z"

    def test_audit_stamps_carry_exactly_three_fractional_digits(self) -> None:
        stamp = datetime(2026, 7, 20, microsecond=123456, tzinfo=timezone.utc)

        assert to_utc_iso_z(stamp) == "2026-07-20T00:00:00.123Z"


class TestCharts:
    @pytest.mark.parametrize("case", CHART_CALLS, ids=lambda case: case.slug)
    def test_each_chart_hits_its_own_slug_with_its_own_model(
        self, client: AIGatewayAdminClient, api: respx.MockRouter, case: ChartCase
    ) -> None:
        """Plural versus singular is load-bearing: cache-hits-trend 404s."""
        route = api.get(f"{DATA}/logs/charts/{case.slug}").mock(
            return_value=httpx.Response(200, json=case.payload)
        )

        result = getattr(client.telemetry, case.method)(
            workspace_slug=WORKSPACE, start=START, end=END
        )

        assert route.calls.last.request.url.path.endswith(f"/logs/charts/{case.slug}")
        assert type(result) is case.model

    def test_covers_every_documented_chart_metric(self) -> None:
        """A metric added to the constants without a method here is a coverage gap."""
        assert {case.slug for case in CHART_CALLS} == set(AI_GW_CHART_METRICS)

    def test_rejects_a_slug_the_constants_do_not_know(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """cache-hits-trend is the plausible typo that 404s; the constants are the authority."""
        with pytest.raises(AISecPayloadError, match="Unknown chart metric"):
            client.telemetry._chart("cache-hits-trend", CostChartResponse, {})

        assert not api.calls

    def test_sends_exactly_the_four_window_parameters(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/logs/charts/cost").mock(
            return_value=httpx.Response(200, json=COST)
        )

        client.telemetry.cost(workspace_slug=WORKSPACE, start=START, end=END)

        assert sent_params(route) == WINDOW_PARAMS

    def test_defaults_to_a_seven_day_window(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """Seven is a literal in the reference implementation, so pin the literal.

        Comparing against ``DEFAULT_WINDOW_DAYS`` here would move both sides of the
        assertion together and could never fail.
        """
        route = api.get(f"{DATA}/logs/charts/cost").mock(
            return_value=httpx.Response(200, json=COST)
        )

        client.telemetry.cost(workspace_slug=WORKSPACE)

        params = sent_params(route)
        span = datetime.fromisoformat(params["timeOfGenerationMax"]) - datetime.fromisoformat(
            params["timeOfGenerationMin"]
        )
        assert span == timedelta(days=7)

    def test_publishes_the_default_window_it_actually_sends(self) -> None:
        """The constant is public, so it must not drift away from the wire behaviour."""
        assert DEFAULT_WINDOW_DAYS == 7

    def test_days_sizes_the_window(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/logs/charts/cost").mock(
            return_value=httpx.Response(200, json=COST)
        )

        client.telemetry.cost(workspace_slug=WORKSPACE, days=1, end=END)

        assert sent_params(route)["timeOfGenerationMin"] == "2026-07-26T00:00:00+00:00"

    def test_an_explicit_start_overrides_days(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/logs/charts/cost").mock(
            return_value=httpx.Response(200, json=COST)
        )

        client.telemetry.cost(workspace_slug=WORKSPACE, days=30, start=START, end=END)

        assert sent_params(route)["timeOfGenerationMin"] == START_PARAM

    def test_end_defaults_to_now(self, client: AIGatewayAdminClient, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/logs/charts/cost").mock(
            return_value=httpx.Response(200, json=COST)
        )

        client.telemetry.cost(workspace_slug=WORKSPACE, start=START)

        rendered = datetime.fromisoformat(sent_params(route)["timeOfGenerationMax"])
        assert abs(datetime.now(timezone.utc) - rendered) < timedelta(minutes=1)

    def test_parses_cost_in_cents_without_rescaling(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """Nothing in the SDK divides by 100; callers own the conversion."""
        api.get(f"{DATA}/logs/charts/cost").mock(return_value=httpx.Response(200, json=COST))

        assert client.telemetry.cost(workspace_slug=WORKSPACE).data.total == 411083.0

    def test_parses_a_null_cache_latency_as_none(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """Null means "no hits to average", which is not a zero."""
        api.get(f"{DATA}/logs/charts/cache-summary").mock(
            return_value=httpx.Response(200, json=CACHE_SUMMARY)
        )

        summary = client.telemetry.cache_summary(workspace_slug=WORKSPACE).data.summary
        assert summary.avg_cache_latency is None


class TestGroupBy:
    def test_hits_the_dimension_path(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/logs/groups/model").mock(
            return_value=httpx.Response(200, json=GROUP_ROWS)
        )

        client.telemetry.group_by("model", workspace_slug=WORKSPACE, start=START, end=END)

        assert sent_params(route) == WINDOW_PARAMS

    @pytest.mark.parametrize("dimension", list(AI_GW_GROUP_DIMENSIONS))
    def test_accepts_every_documented_dimension(
        self, client: AIGatewayAdminClient, api: respx.MockRouter, dimension: str
    ) -> None:
        route = api.get(f"{DATA}/logs/groups/{dimension}").mock(
            return_value=httpx.Response(200, json=GROUP_ROWS)
        )

        client.telemetry.group_by(dimension, workspace_slug=WORKSPACE)

        assert route.called

    def test_joins_columns_with_commas_in_one_parameter(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """Comma-joined in a single key, not repeated keys."""
        route = api.get(f"{DATA}/logs/groups/model").mock(
            return_value=httpx.Response(200, json=GROUP_ROWS)
        )

        client.telemetry.group_by(
            "model", workspace_slug=WORKSPACE, columns=["cost", "total_tokens"]
        )

        query = route.calls.last.request.url.params
        assert query.get_list("columns") == ["cost,total_tokens"]

    def test_omits_columns_when_unset(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/logs/groups/model").mock(
            return_value=httpx.Response(200, json=GROUP_ROWS)
        )

        client.telemetry.group_by("model", workspace_slug=WORKSPACE)

        assert "columns" not in sent_params(route)

    def test_omits_columns_for_an_empty_list(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """An empty list asks for no extra columns, so no empty `columns=` may go out."""
        route = api.get(f"{DATA}/logs/groups/model").mock(
            return_value=httpx.Response(200, json=GROUP_ROWS)
        )

        client.telemetry.group_by("model", workspace_slug=WORKSPACE, columns=[])

        assert "columns" not in sent_params(route)

    def test_keeps_the_dimension_column_from_model_extra(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """The dimension key varies per endpoint, so it is not a declared field."""
        rows = {**GROUP_ROWS, "data": [{**GROUP_ROWS["data"][0], "model": "claude-sonnet-5"}]}  # type: ignore[index]
        api.get(f"{DATA}/logs/groups/model").mock(return_value=httpx.Response(200, json=rows))

        row = client.telemetry.group_by("model", workspace_slug=WORKSPACE).data[0]
        assert row.model_extra == {"model": "claude-sonnet-5"}

    def test_rejects_an_unknown_dimension(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """A hyphenated or camelCase spelling is a 400 upstream, so it fails here first."""
        with pytest.raises(AISecPayloadError, match="Unknown group dimension"):
            client.telemetry.group_by("apiKey", workspace_slug=WORKSPACE)

        assert not api.calls

    def test_rejects_an_unknown_column(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """The API silently drops bad columns, so a typo would look like missing data."""
        with pytest.raises(AISecPayloadError, match="Unknown group columns: totl_tokens"):
            client.telemetry.group_by(
                "model", workspace_slug=WORKSPACE, columns=["cost", "totl_tokens"]
            )

        assert not api.calls

    @pytest.mark.parametrize("column", list(AI_GW_GROUP_COLUMNS))
    def test_accepts_every_documented_column(
        self, client: AIGatewayAdminClient, api: respx.MockRouter, column: str
    ) -> None:
        """Validation must not reject a name the constants bless -- that would be worse
        than the typo it exists to catch."""
        route = api.get(f"{DATA}/logs/groups/model").mock(
            return_value=httpx.Response(200, json=GROUP_ROWS)
        )

        client.telemetry.group_by("model", workspace_slug=WORKSPACE, columns=[column])

        assert sent_params(route)["columns"] == column


class TestGroupUsersAndStatusCodes:
    def test_by_user_hits_the_users_sub_resource(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/logs/groups/users").mock(
            return_value=httpx.Response(200, json=USER_GROUP)
        )

        client.telemetry.by_user(workspace_slug=WORKSPACE, start=START, end=END)

        assert sent_params(route) == WINDOW_PARAMS

    def test_by_user_parses_the_success_data_envelope(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """users is envelope A while every sibling group endpoint is envelope C."""
        api.get(f"{DATA}/logs/groups/users").mock(return_value=httpx.Response(200, json=USER_GROUP))

        result = client.telemetry.by_user(workspace_slug=WORKSPACE)

        assert result.success is True
        assert result.data.records[0].user == ""

    def test_by_status_code_hits_the_status_code_sub_resource(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/logs/groups/status_code").mock(
            return_value=httpx.Response(200, json=GROUP_ROWS)
        )

        client.telemetry.by_status_code(workspace_slug=WORKSPACE, columns=["cost", "avg_latency"])

        assert route.calls.last.request.url.params.get_list("columns") == ["cost,avg_latency"]

    def test_by_status_code_rejects_an_unknown_column(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Unknown group columns"):
            client.telemetry.by_status_code(workspace_slug=WORKSPACE, columns=["latency"])

        assert not api.calls


class TestLogs:
    def test_sends_only_the_window_when_unfiltered(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """There is no offset parameter: upstream paging is broken and ignores it."""
        route = api.get(f"{DATA}/logs").mock(return_value=httpx.Response(200, json=LOGS))

        client.telemetry.logs(workspace_slug=WORKSPACE, start=START, end=END)

        assert sent_params(route) == WINDOW_PARAMS

    def test_sends_the_page_size(self, client: AIGatewayAdminClient, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/logs").mock(return_value=httpx.Response(200, json=LOGS))

        client.telemetry.logs(workspace_slug=WORKSPACE, start=START, end=END, page_size=25)

        assert sent_params(route) == {**WINDOW_PARAMS, "pageSize": "25"}

    def test_sends_the_trace_id(self, client: AIGatewayAdminClient, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/logs").mock(return_value=httpx.Response(200, json=LOGS))

        client.telemetry.logs(workspace_slug=WORKSPACE, start=START, end=END, trace_id="trace-1")

        assert sent_params(route) == {**WINDOW_PARAMS, "traceId": "trace-1"}

    def test_sends_the_status_code_filter(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """446 is the AIRS block code, and filtering on it bypasses the ~50-row cap."""
        route = api.get(f"{DATA}/logs").mock(return_value=httpx.Response(200, json=LOGS))

        client.telemetry.logs(workspace_slug=WORKSPACE, start=START, end=END, status_code=446)

        assert sent_params(route) == {**WINDOW_PARAMS, "statusCode": "446"}

    def test_parses_zero_one_flags_through_the_helper_properties(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        api.get(f"{DATA}/logs").mock(return_value=httpx.Response(200, json=LOGS))

        record = client.telemetry.logs(workspace_slug=WORKSPACE).data.records[0]

        assert record.succeeded is False
        assert record.proxied is True


class TestIntegrations:
    def test_list_reads_the_admin_plane(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{ADMIN}/integrations").mock(
            return_value=httpx.Response(200, json=INTEGRATION_LIST)
        )

        result = client.integrations.list()

        assert sent_params(route) == {}
        assert result.data[0].slug == "openai-calvin"

    def test_get_addresses_the_integration_by_id(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{ADMIN}/integrations/{INTEGRATION_ID}").mock(
            return_value=httpx.Response(200, json=INTEGRATION)
        )

        client.integrations.get(INTEGRATION_ID)

        assert route.called

    def test_get_rejects_a_non_uuid(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid integration_id"):
            client.integrations.get(NOT_A_UUID)

        assert not api.calls

    def test_create_posts_the_documented_body(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{ADMIN}/integrations").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.integrations.create(
            organisation_id=TSG,
            ai_provider_id=PROVIDER_ID,
            name="openai-prod",
            slug="openai-prod",
            key="sk-live",
        )

        assert sent_body(route) == {
            "organisation_id": TSG,
            "ai_provider_id": PROVIDER_ID,
            "name": "openai-prod",
            "slug": "openai-prod",
            "key": "sk-live",
        }

    def test_create_omits_unset_optional_fields(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """An explicit null is not the same as an absent key on this API."""
        route = api.post(f"{ADMIN}/integrations").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.integrations.create(
            organisation_id=TSG, ai_provider_id=PROVIDER_ID, name="n", slug="s"
        )

        assert "description" not in sent_body(route)

    def test_create_rejects_a_non_uuid_provider(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid ai_provider_id"):
            client.integrations.create(
                organisation_id=TSG, ai_provider_id="openai", name="n", slug="s"
            )

        assert not api.calls

    def test_update_puts_only_the_supplied_fields(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{ADMIN}/integrations/{INTEGRATION_ID}").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.integrations.update(
            INTEGRATION_ID, name="openai-prod", description="Production OpenAI"
        )

        assert sent_body(route) == {"name": "openai-prod", "description": "Production OpenAI"}

    def test_update_rejects_a_non_uuid_provider_when_supplied(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid ai_provider_id"):
            client.integrations.update(INTEGRATION_ID, ai_provider_id="openai")

        assert not api.calls

    def test_update_rejects_a_non_uuid_integration(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid integration_id"):
            client.integrations.update(NOT_A_UUID, name="n")

        assert not api.calls

    def test_delete_sends_the_tenant_as_a_snake_case_query_parameter(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """organisation_id here, organisationId on the telemetry endpoints."""
        route = api.delete(f"{ADMIN}/integrations/{INTEGRATION_ID}").mock(
            return_value=httpx.Response(200)
        )

        client.integrations.delete(INTEGRATION_ID, TSG)

        assert sent_params(route) == {"organisation_id": TSG}
        assert route.calls.last.request.content == b""

    def test_delete_rejects_a_non_uuid_integration(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """The id is interpolated into the path, so it is checked before the tenant is."""
        with pytest.raises(AISecPayloadError, match="Invalid integration_id"):
            client.integrations.delete(NOT_A_UUID, TSG)

        assert not api.calls

    def test_delete_rejects_a_non_numeric_tenant(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """The organisation UUID from a read is not the TSG this endpoint wants."""
        with pytest.raises(AISecPayloadError, match="Invalid organisation_id"):
            client.integrations.delete(INTEGRATION_ID, PROVIDER_ID)

        assert not api.calls

    def test_delete_rejects_a_non_ascii_digit_tenant(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """Arabic-Indic digits satisfy a naive \\d check but not the service."""
        with pytest.raises(AISecPayloadError, match="Invalid organisation_id"):
            client.integrations.delete(INTEGRATION_ID, "١٨٥٢")

        assert not api.calls

    def test_get_models_reads_the_models_sub_resource(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{ADMIN}/integrations/{INTEGRATION_ID}/models").mock(
            return_value=httpx.Response(200, json=INTEGRATION_MODELS)
        )

        result = client.integrations.get_models(INTEGRATION_ID)

        assert route.called
        assert result.allow_all_models is False

    def test_get_models_rejects_a_non_uuid(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid integration_id"):
            client.integrations.get_models(NOT_A_UUID)

        assert not api.calls

    def test_set_models_replaces_the_whole_list(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{ADMIN}/integrations/{INTEGRATION_ID}/models").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.integrations.set_models(
            INTEGRATION_ID,
            [
                GatewayIntegrationModel(slug="gpt-4", enabled=True),
                GatewayIntegrationModel(slug="gpt-4-32k", enabled=False),
            ],
        )

        assert sent_body(route) == {
            "models": [
                {"slug": "gpt-4", "enabled": True},
                {"slug": "gpt-4-32k", "enabled": False},
            ]
        }

    def test_set_models_rejects_a_non_uuid(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid integration_id"):
            client.integrations.set_models(NOT_A_UUID, [])

        assert not api.calls

    def test_get_workspaces_parses_the_object_shaped_global_access(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """global_workspace_access reads as an object and writes as a boolean."""
        route = api.get(f"{ADMIN}/integrations/{INTEGRATION_ID}/workspaces").mock(
            return_value=httpx.Response(200, json=INTEGRATION_WORKSPACES)
        )

        result = client.integrations.get_workspaces(INTEGRATION_ID)

        assert route.called
        assert result.global_workspace_access.enabled is False

    def test_get_workspaces_rejects_a_non_uuid(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid integration_id"):
            client.integrations.get_workspaces(NOT_A_UUID)

        assert not api.calls

    def test_set_workspaces_writes_a_plain_boolean(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{ADMIN}/integrations/{INTEGRATION_ID}/workspaces").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.integrations.set_workspaces(INTEGRATION_ID, global_workspace_access=True)

        assert sent_body(route) == {"global_workspace_access": True}

    def test_set_workspaces_keeps_an_explicit_false(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """False is a value, not an omission -- revoking access must reach the wire."""
        route = api.put(f"{ADMIN}/integrations/{INTEGRATION_ID}/workspaces").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.integrations.set_workspaces(INTEGRATION_ID, global_workspace_access=False)

        assert sent_body(route) == {"global_workspace_access": False}

    def test_set_workspaces_rejects_a_non_uuid(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid integration_id"):
            client.integrations.set_workspaces(NOT_A_UUID, global_workspace_access=True)

        assert not api.calls


class TestMcpIntegrations:
    def test_list_uses_the_hyphenated_path(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{ADMIN}/mcp-integrations").mock(
            return_value=httpx.Response(200, json=MCP_LIST)
        )

        result = client.mcp_integrations.list()

        assert route.called
        assert result.data[0].configurations == '{"headers":{}}'

    def test_create_posts_the_documented_body(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{ADMIN}/mcp-integrations").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.mcp_integrations.create(
            name="Context 7",
            organisation_id=TSG,
            slug="context-7",
            url="https://mcp.context7.com/mcp",
            auth_type="none",
            transport="http",
        )

        assert sent_body(route) == {
            "name": "Context 7",
            "organisation_id": TSG,
            "slug": "context-7",
            "url": "https://mcp.context7.com/mcp",
            "auth_type": "none",
            "transport": "http",
        }

    def test_create_sends_configurations_as_an_object(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """Reads return this field as a JSON string; the write side does not."""
        route = api.post(f"{ADMIN}/mcp-integrations").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.mcp_integrations.create(
            name="Context 7",
            organisation_id=TSG,
            slug="context-7",
            url="https://mcp.context7.com/mcp",
            auth_type="none",
            transport="http",
            configurations={"headers": {"x-api-key": "k"}},
        )

        assert sent_body(route)["configurations"] == {"headers": {"x-api-key": "k"}}

    def test_set_workspaces_targets_the_mcp_sub_resource(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{ADMIN}/mcp-integrations/{INTEGRATION_ID}/workspaces").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.mcp_integrations.set_workspaces(INTEGRATION_ID, global_workspace_access=True)

        assert sent_body(route) == {"global_workspace_access": True}

    def test_set_workspaces_rejects_a_non_uuid(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid mcp_integration_id"):
            client.mcp_integrations.set_workspaces(NOT_A_UUID, global_workspace_access=True)

        assert not api.calls


class TestDeployments:
    def test_list_returns_archived_rows_too(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """delete() is a soft delete, so callers must filter on status themselves."""
        api.get(f"{ADMIN}/deployments").mock(return_value=httpx.Response(200, json=DEPLOYMENT_LIST))

        statuses = [row.status for row in client.deployments.list().data]

        assert statuses == ["active", "archived"]

    def test_get_addresses_the_deployment_by_id(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{ADMIN}/deployments/{DEPLOYMENT_ID}").mock(
            return_value=httpx.Response(200, json=DEPLOYMENT_DETAIL)
        )

        client.deployments.get(DEPLOYMENT_ID)

        assert route.called

    def test_get_rejects_a_non_uuid(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid deployment_id"):
            client.deployments.get("dp-talos-f3b74e")

        assert not api.calls

    def test_create_sends_the_type_field_under_its_wire_name(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """The argument is deployment_type only because `type` shadows a builtin."""
        route = api.post(f"{ADMIN}/deployments").mock(
            return_value=httpx.Response(200, json=DEPLOYMENT_RECEIPT)
        )

        client.deployments.create(
            name="prod-us",
            deployment_type="production",
            organisation_id=TSG,
            auth_settings={"allow_all_workspaces": True},
        )

        assert sent_body(route) == {
            "name": "prod-us",
            "type": "production",
            "organisation_id": TSG,
            "auth_settings": {"allow_all_workspaces": True},
        }

    def test_create_returns_the_one_time_credentials(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """The detail read masks these; the receipt is the only chance to capture them."""
        api.post(f"{ADMIN}/deployments").mock(
            return_value=httpx.Response(200, json=DEPLOYMENT_RECEIPT)
        )

        receipt = client.deployments.create(
            name="prod-us", deployment_type="production", organisation_id=TSG
        )

        assert receipt.credentials.password == "dp-pass"
        assert receipt.client_auth == "client-auth-abc"

    def test_delete_sends_the_tenant_as_a_query_parameter(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.delete(f"{ADMIN}/deployments/{DEPLOYMENT_ID}").mock(
            return_value=httpx.Response(200)
        )

        client.deployments.delete(DEPLOYMENT_ID, TSG)

        assert sent_params(route) == {"organisation_id": TSG}

    def test_delete_rejects_a_non_numeric_tenant(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid organisation_id"):
            client.deployments.delete(DEPLOYMENT_ID, "tsg-1852583913")

        assert not api.calls

    def test_delete_rejects_a_non_uuid_deployment(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid deployment_id"):
            client.deployments.delete("dp-talos-f3b74e", TSG)

        assert not api.calls


class TestPlugins:
    def test_list_returns_masked_credentials(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{ADMIN}/plugins").mock(return_value=httpx.Response(200, json=PLUGIN_LIST))

        result = client.plugins.list()

        assert route.called
        assert result.data[0].credentials == {"AIRS_API_KEY": "sn*****Gul"}

    def test_create_posts_the_documented_body(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{ADMIN}/plugins").mock(return_value=httpx.Response(200, json=WRITE_OK))

        client.plugins.create(
            organisation_id=TSG,
            integration_id=INTEGRATION_ID,
            credentials={"AIRS_API_KEY": "live-key"},
        )

        assert sent_body(route) == {
            "organisation_id": TSG,
            "integration_id": INTEGRATION_ID,
            "credentials": {"AIRS_API_KEY": "live-key"},
        }

    def test_create_rejects_a_non_uuid_integration(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid integration_id"):
            client.plugins.create(
                organisation_id=TSG,
                integration_id="panw-prisma-airs",
                credentials={"AIRS_API_KEY": "live-key"},
            )

        assert not api.calls


class TestOrganisations:
    def test_get_self_reads_the_self_path(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{ADMIN}/organisations/self").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {"name": "Acme"}})
        )

        result = client.organisations.get_self()

        assert route.called
        # AuthSettingsResponse is the same envelope over the same payload type, so only
        # the declared model tells the two endpoints' results apart.
        assert type(result) is OrganisationSelfResponse
        assert result.data["name"] == "Acme"

    def test_update_self_puts_the_body(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{ADMIN}/organisations/self").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.organisations.update_self({"name": "Acme Corp"})

        assert sent_body(route) == {"name": "Acme Corp"}

    def test_get_auth_settings_interpolates_the_tenant_into_the_path(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{ADMIN}/organisations/{TSG}/auth-settings").mock(
            return_value=httpx.Response(200, json={"success": True, "data": {"scim_token": "s"}})
        )

        client.organisations.get_auth_settings(TSG)

        assert route.called

    def test_get_auth_settings_rejects_a_uuid(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """This path wants the numeric TSG, not the organisation UUID reads return."""
        with pytest.raises(AISecPayloadError, match="Invalid tsg_id"):
            client.organisations.get_auth_settings(INTEGRATION_ID)

        assert not api.calls

    def test_get_auth_settings_rejects_a_traversal_attempt(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """The value is interpolated into a path, so `..` must never reach the URL."""
        with pytest.raises(AISecPayloadError, match="Invalid tsg_id"):
            client.organisations.get_auth_settings("../../deployments")

        assert not api.calls

    def test_update_auth_settings_puts_the_body(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{ADMIN}/organisations/{TSG}/auth-settings").mock(
            return_value=httpx.Response(200, json=WRITE_OK)
        )

        client.organisations.update_auth_settings(TSG, {"domains": ["acme.com"]})

        assert sent_body(route) == {"domains": ["acme.com"]}

    def test_update_auth_settings_rejects_a_non_numeric_tenant(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid tsg_id"):
            client.organisations.update_auth_settings("acme", {"domains": []})

        assert not api.calls


class TestAuditLogs:
    def test_sends_z_suffixed_utc_bounds(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """Unlike telemetry, this endpoint wants the Z form, not a numeric offset."""
        route = api.get(f"{ADMIN}/audit-logs").mock(
            return_value=httpx.Response(200, json=AUDIT_LOGS)
        )

        client.audit_logs.list(start=START, end=END)

        assert sent_params(route) == {
            "start_time": "2026-07-20T00:00:00.000Z",
            "end_time": "2026-07-27T00:00:00.000Z",
        }

    def test_returns_the_unredacted_request_body_faithfully(
        self, client: AIGatewayAdminClient, api: respx.MockRouter
    ) -> None:
        """The SDK does not sanitise; callers must never log these records wholesale."""
        api.get(f"{ADMIN}/audit-logs").mock(return_value=httpx.Response(200, json=AUDIT_LOGS))

        record = client.audit_logs.list(start=START, end=END).records[0]

        assert record.request_body == '{"key":"sk-live-secret"}'
        assert "sk-live-secret" not in repr(record)
