"""AI Gateway telemetry, config, and admin models."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from prisma_airs.models.ai_gateway import (
    AuthSettingsResponse,
    CacheHitTrendData,
    CacheHitTrendPoint,
    CacheHitTrendResponse,
    CacheHitTrendSummary,
    CacheSummary,
    CacheSummaryData,
    CacheSummaryResponse,
    CostChartData,
    CostChartResponse,
    CountChartData,
    CountChartResponse,
    ErrorTrendsData,
    ErrorTrendsResponse,
    ErrorTrendsSummary,
    FeedbackModelRecord,
    FeedbackModelScore,
    FeedbackModelsData,
    FeedbackModelsResponse,
    FeedbackScoreDistributionData,
    FeedbackScoreDistributionResponse,
    FeedbackScoreRecord,
    GatewayApiKey,
    GatewayAuditLogRecord,
    GatewayAuditLogsResponse,
    GatewayChartRecord,
    GatewayConfig,
    GatewayConfigCreateResponse,
    GatewayConfigDetail,
    GatewayDeployment,
    GatewayDeploymentAuthSettings,
    GatewayDeploymentCreateResponse,
    GatewayDeploymentCredentials,
    GatewayDeploymentDetail,
    GatewayDeploymentWorkspaceRef,
    GatewayGlobalWorkspaceAccess,
    GatewayGuardrail,
    GatewayGuardrailCreateResponse,
    GatewayGuardrailDetail,
    GatewayIntegration,
    GatewayIntegrationModel,
    GatewayIntegrationModelsResponse,
    GatewayIntegrationWorkspace,
    GatewayIntegrationWorkspacesResponse,
    GatewayLogRecord,
    GatewayLogsData,
    GatewayLogsResponse,
    GatewayPlugin,
    GatewayProvider,
    GatewayProviderCreateResponse,
    GatewayRateLimit,
    GatewayUsageLimit,
    GatewayWorkspace,
    GatewayWorkspaceCreateResponse,
    GatewayWorkspaceDetail,
    GatewayWriteResponse,
    GroupListResponse,
    GuardrailActions,
    GuardrailCheck,
    GuardrailFeedback,
    GuardrailFeedbackAction,
    LatencyChartData,
    LatencyChartRecord,
    LatencyChartResponse,
    ListApiKeysResponse,
    ListConfigsResponse,
    ListDeploymentsResponse,
    ListGuardrailsResponse,
    ListIntegrationsResponse,
    ListMcpIntegrationsResponse,
    ListPluginsResponse,
    ListProvidersResponse,
    ListWorkspacesResponse,
    McpIntegration,
    OrganisationSelfResponse,
    RescuedRetriesData,
    RescuedRetriesPoint,
    RescuedRetriesResponse,
    RescuedRetriesTrendPoint,
    TokensChartData,
    TokensChartRecord,
    TokensChartResponse,
    UserGroupData,
    UserGroupRecord,
    UserGroupResponse,
    UserTrendsData,
    UserTrendsResponse,
    UserTrendsSummary,
)

# Every collection endpoint is wrapped in envelope B. Listed once so a new resource
# cannot quietly ship without the envelope contract being checked.
LIST_RESPONSES = [
    ListApiKeysResponse,
    ListConfigsResponse,
    ListDeploymentsResponse,
    ListGuardrailsResponse,
    ListIntegrationsResponse,
    ListMcpIntegrationsResponse,
    ListPluginsResponse,
    ListProvidersResponse,
    ListWorkspacesResponse,
]

# ---------------------------------------------------------------------------
# Payload fixtures -- shaped after live responses, trimmed to what is asserted
# ---------------------------------------------------------------------------


def cost_chart_payload(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "records": [
            {"x": "2026-07-26T00:00:00Z", "y": 431.2, "avg": 4.4},
            {"x": "2026-07-27T00:00:00Z", "y": 118.0, "avg": 2.1},
        ],
        "total": 549.2,
        "avg": 3.25,
        "isQuotaExceeded": False,
        **overrides,
    }
    return {"success": True, "data": data}


def log_record_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "log_01J8",
        "workspace_slug": "spark-ee4aa3",
        "ai_model": "gpt-4o-mini",
        "_user": "",
        "total_units": 1482,
        "cost": 0.37,
        "trace_id": "trace_7f1c",
        "is_proxy_call": 1,
        "created_at": "2026-07-27T18:04:11.000Z",
        "is_success": 1,
        "cache_status": "MISS",
        "retry_success_count": 0,
        "mode": "single",
        "last_used_option_index": 0,
        "response_status_code": 200,
        "request_url": "https://api.openai.com/v1/chat/completions",
        "request_method": "POST",
        "ai_org": "openai",
        "api_key_id": "key_9910",
        "license_id": "lic_0021",
        "log_store_file_path_format": "org/ws/2026/07/27",
        "metadataKey": ["env", "team"],
        "metadataValue": ["prod", "secops"],
        "prompt_slug": "",
        "feedback": [],
    }
    payload.update(overrides)
    return payload


def workspace_row_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "ws_01",
        "slug": "secops",
        "name": "SecOps",
        "icon": None,
        "description": None,
        "created_at": "2026-06-01T00:00:00Z",
        "last_updated_at": "2026-08-01T00:00:00Z",
        "is_default": 0,
        "status": "active",
        "scope_name": "prisma-airs-ws-secops",
        "object": "workspace",
    }
    payload.update(overrides)
    return payload


def workspace_create_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "ws_02",
        "name": "Research",
        "slug": "research",
        "description": None,
        "created_at": "2026-08-01T00:00:00Z",
        "last_updated_at": "2026-08-01T00:00:00Z",
        "scope_name": "prisma-airs-ws-research",
        "object": "workspace",
    }
    payload.update(overrides)
    return payload


def integration_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "int_1",
        "organisation_id": "org-uuid",
        "name": "OpenAI",
        "owner_id": "user_1",
        "status": "active",
        "created_at": "2026-07-27T00:00:00Z",
        "last_updated_at": "2026-07-27T00:00:00Z",
        "slug": "openai-a1",
        "tags": None,
        "description": None,
        "workspaces_count": 2,
        "type": "provider",
        "workspace_id": None,
        "ai_provider_id": "openai",
        "object": "integration",
    }
    payload.update(overrides)
    return payload


def integration_workspace_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "ws_01",
        "usage_limits": None,
        "rate_limits": None,
        "enabled": True,
        "status": "active",
        "created_at": "2026-07-27T00:00:00Z",
        "last_updated_at": "2026-07-27T00:00:00Z",
        "last_reset_at": None,
    }
    payload.update(overrides)
    return payload


def global_workspace_access_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"enabled": True, "rate_limits": None, "usage_limits": None}
    payload.update(overrides)
    return payload


def workspace_detail_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "ws_01",
        "name": "SecOps",
        "description": None,
        "created_at": "2026-06-01T00:00:00Z",
        "last_updated_at": "2026-08-01T00:00:00Z",
        "is_default": 0,
        "slug": "secops",
        "icon": None,
        "defaults": None,
        "usage_limits": None,
        "rate_limits": None,
    }
    payload.update(overrides)
    return payload


def config_row_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "cfg_1",
        "name": "default",
        "slug": "default-a1",
        "organisation_id": "org-uuid",
        "is_default": 1,
        "status": "active",
        "owner_id": "user_1",
        "updated_by": "user_1",
        "created_at": "2026-07-28T00:00:00Z",
        "last_updated_at": "2026-07-28T00:00:00Z",
        "workspace_id": "ws_01",
        "object": "config",
    }
    payload.update(overrides)
    return payload


def config_detail_payload(**overrides: Any) -> dict[str, Any]:
    payload = config_row_payload()
    payload.update(
        {
            "config": json.dumps({"retry": {"attempts": 3}}),
            "format": "json",
            "type": "config",
            "version_id": "cfgv_1",
        }
    )
    payload.update(overrides)
    return payload


def mcp_integration_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "mcp_1",
        "organisation_id": "org-uuid",
        "name": "securebank-ops",
        "owner_id": "user_1",
        "status": "active",
        "type": "mcp",
        "url": "https://mcp.example.com/sse",
        "auth_type": "api_key",
        "transport": "sse",
        "configurations": json.dumps({"headers": {"x-portkey-api-key": "***"}}),
        "created_at": "2026-07-27T00:00:00Z",
        "last_updated_at": "2026-07-27T00:00:00Z",
    }
    payload.update(overrides)
    return payload


def guardrail_detail_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "gr_01",
        "name": "airs-intercept",
        "slug": "airs-intercept-a1",
        "organisation_id": "org-uuid",
        "status": "active",
        "owner_id": "user_1",
        "updated_by": None,
        "created_at": "2026-07-28T00:00:00Z",
        "last_updated_at": "2026-07-28T00:00:00Z",
        "workspace_id": "ws_01",
        "object": "guardrail",
        "checks": [
            {
                "id": "panw-prisma-airs.intercept",
                "parameters": {"profile_name": "spark-ee4aa3"},
                "is_enabled": True,
            }
        ],
        "actions": {"deny": True, "async": False, "sequential": True},
        "version_id": "grv_01",
    }
    payload.update(overrides)
    return payload


def deployment_detail_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "dep_01",
        "name": "airs-gw",
        "slug": "airs-gw",
        "type": "self-hosted",
        "status": "active",
        "created_at": "2026-07-27T00:00:00Z",
        "last_updated_at": "2026-07-27T00:00:00Z",
        "last_synced_at": None,
        "last_resynced_at": None,
        "is_default": 0,
        "created_by": "user_1",
        "object": "deployment",
        "credentials": {"username": "dep_01", "password": "********"},
        "deployment_config": None,
        "auth_settings": {
            "disable_portkey_gateway": 0,
            "workspaces_allowed": ["ws_01"],
            "allow_all_workspaces": 1,
        },
        "client_auth": "********",
        "workspaces": [{"id": "ws_01", "slug": "secops"}],
    }
    payload.update(overrides)
    return payload


#: The five keys a deployment detail read adds on top of the list row.
DEPLOYMENT_DETAIL_ONLY = (
    "credentials",
    "deployment_config",
    "auth_settings",
    "client_auth",
    "workspaces",
)


def deployment_row_payload(**overrides: Any) -> dict[str, Any]:
    payload = {
        k: v for k, v in deployment_detail_payload().items() if k not in DEPLOYMENT_DETAIL_ONLY
    }
    payload.update(overrides)
    return payload


def plugin_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "plg_1",
        "integration_id": "int_1",
        "credentials": {"api_key": "****"},
        "owner_id": "user_1",
        "created_at": "2026-07-27T00:00:00Z",
        "last_updated_at": "2026-07-27T00:00:00Z",
        "status": "active",
        "integration_slug": "panw-prisma-airs",
        "plugin_provider_id": "pp_1",
        "plugin_provider_slug": "panw-prisma-airs",
        "object": "plugin",
    }
    payload.update(overrides)
    return payload


def audit_record_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "timestamp": "2026-07-27T18:04:11Z",
        "method": "POST",
        "uri": "/ai_gw/admin/v2/plugins",
        "request_id": "req_44",
        "request_body": '{"credentials":{"api_key":"leaked-key"}}',
        "query_params": "",
        "request_headers": '{"authorization":"****"}',
        "user_id": "user_1",
        "user_type": "sso",
        "organisation_id": "org-uuid",
        "workspace_id": "ws_01",
        "response_status_code": 201,
        "resource_type": "plugin",
        "action": "create",
        "client_ip": "198.51.100.7",
        "country": "US",
    }
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# Envelope A + the quota flag
# ---------------------------------------------------------------------------


class TestChartEnvelope:
    def test_parses_a_full_cost_chart(self) -> None:
        result = CostChartResponse.model_validate(cost_chart_payload())

        assert result.success is True
        assert [r.x for r in result.data.records] == [
            "2026-07-26T00:00:00Z",
            "2026-07-27T00:00:00Z",
        ]
        assert result.data.model_extra == {}

    def test_leaves_cost_in_cents(self) -> None:
        """Cents, never dollars. A helpful /100 anywhere here is the bug this guards."""
        result = CostChartResponse.model_validate(cost_chart_payload())

        assert result.data.total == 549.2
        assert result.data.records[0].y == 431.2
        assert result.data.avg == 3.25

    def test_maps_the_camel_case_quota_flag(self) -> None:
        result = CostChartResponse.model_validate(cost_chart_payload(isQuotaExceeded=True))

        assert result.data.is_quota_exceeded is True
        assert result.data.model_extra == {}

    def test_also_accepts_the_quota_flag_by_field_name(self) -> None:
        payload = cost_chart_payload()
        payload["data"].pop("isQuotaExceeded")
        payload["data"]["is_quota_exceeded"] = True

        assert CostChartResponse.model_validate(payload).data.is_quota_exceeded is True

    def test_dumps_the_quota_flag_back_to_camel_case(self) -> None:
        result = CostChartResponse.model_validate(cost_chart_payload())

        dumped = result.model_dump(by_alias=True)
        assert "isQuotaExceeded" in dumped["data"]
        assert "is_quota_exceeded" not in dumped["data"]

    def test_requires_the_quota_flag(self) -> None:
        payload = cost_chart_payload()
        payload["data"].pop("isQuotaExceeded")

        with pytest.raises(ValidationError, match="isQuotaExceeded"):
            CostChartResponse.model_validate(payload)

    def test_requires_the_envelope_success_field(self) -> None:
        payload = cost_chart_payload()
        payload.pop("success")

        with pytest.raises(ValidationError, match="success"):
            CostChartResponse.model_validate(payload)

    def test_preserves_unknown_fields_at_both_levels(self) -> None:
        payload = cost_chart_payload(newBucketStat=7)
        payload["requestId"] = "req_1"

        result = CostChartResponse.model_validate(payload)

        assert result.model_extra == {"requestId": "req_1"}
        assert result.data.model_extra == {"newBucketStat": 7}

    def test_bucket_average_is_optional(self) -> None:
        payload = cost_chart_payload(records=[{"x": "2026-07-27T00:00:00Z", "y": 1.0}])

        assert CostChartResponse.model_validate(payload).data.records[0].avg is None


class TestCountChart:
    def _payload(self, total: float | None) -> dict[str, Any]:
        return {
            "success": True,
            "data": {
                "records": [{"x": "2026-07-27T00:00:00Z", "y": 9}],
                "total": total,
                "isQuotaExceeded": False,
            },
        }

    def test_accepts_a_null_total(self) -> None:
        assert CountChartResponse.model_validate(self._payload(None)).data.total is None

    def test_still_requires_the_total_key(self) -> None:
        """Nullable is not optional: a missing key is a shape change and must fail loudly."""
        payload = self._payload(None)
        payload["data"].pop("total")

        with pytest.raises(ValidationError, match="total"):
            CountChartResponse.model_validate(payload)


class TestLatencyChart:
    def test_parses_percentiles_at_both_levels(self) -> None:
        result = LatencyChartResponse.model_validate(
            {
                "success": True,
                "data": {
                    "records": [
                        {
                            "x": "2026-07-27T00:00:00Z",
                            "y": 812,
                            "p50": 640,
                            "p90": 1400,
                            "p99": 3100,
                        }
                    ],
                    "total": 2411,
                    "p50": 655,
                    "p90": 1420,
                    "p99": 3180,
                    "isQuotaExceeded": False,
                },
            }
        )

        assert result.data.p99 == 3180
        assert result.data.records[0].p50 == 640

    def test_rejects_a_bucket_missing_a_percentile(self) -> None:
        with pytest.raises(ValidationError, match="p99"):
            LatencyChartResponse.model_validate(
                {
                    "success": True,
                    "data": {
                        "records": [{"x": "b", "y": 1, "p50": 1, "p90": 1}],
                        "total": 1,
                        "p50": 1,
                        "p90": 1,
                        "p99": 1,
                        "isQuotaExceeded": False,
                    },
                }
            )


class TestCacheCharts:
    def test_cache_summary_tolerates_a_null_average_latency(self) -> None:
        """Null means "no hits to average", which is not the same as a zero-latency cache."""
        result = CacheSummaryResponse.model_validate(
            {
                "success": True,
                "data": {
                    "summary": {
                        "cacheHits": 0,
                        "avgCacheLatency": None,
                        "totalRequests": 240,
                        "cacheSpeedup": 0,
                    },
                    "isQuotaExceeded": False,
                },
            }
        )

        assert result.data.summary.avg_cache_latency is None
        assert result.data.summary.total_requests == 240

    def test_cache_hit_trend_maps_every_camel_case_key(self) -> None:
        result = CacheHitTrendResponse.model_validate(
            {
                "success": True,
                "data": {
                    "trend": [
                        {
                            "x": "2026-07-26T00:00:00Z",
                            "simpleHits": 4,
                            "semanticHits": 1,
                            "hitRate": 0.2,
                            "cumulativeSimpleHitSavings": 12.5,
                            "cumulativeSemanticHitSavings": 3.0,
                        },
                        {
                            "x": "2026-07-27T00:00:00Z",
                            "simpleHits": 2,
                            "semanticHits": 0,
                            "hitRate": 0.1,
                            "cumulativeSimpleHitSavings": 19.0,
                            "cumulativeSemanticHitSavings": 3.0,
                        },
                    ],
                    "total": 7,
                    "summary": {"totalCacheHits": 7, "hitRate": 0.15},
                    "isQuotaExceeded": False,
                },
            }
        )

        latest = result.data.trend[-1]
        assert latest.simple_hits == 2
        assert latest.semantic_hits == 0
        assert latest.hit_rate == 0.1
        # Cumulative, not per-bucket: the last figure already covers the whole window.
        assert latest.cumulative_simple_hit_savings == 19.0
        assert result.data.summary.total_cache_hits == 7
        assert result.data.trend[0].model_extra == {}


class TestRescuedRetries:
    def _payload(self, y: Any) -> dict[str, Any]:
        return {
            "success": True,
            "data": {
                "trend": [{"x": "2026-07-27T00:00:00Z", "y": y}],
                "total": 0,
                "trends": [{"x": "2026-07-27T00:00:00Z", "retry": [], "fallback": []}],
                "retryTotal": 0,
                "fallbackTotal": 0,
                "isQuotaExceeded": False,
            },
        }

    def test_parses_the_sparse_empty_shape(self) -> None:
        result = RescuedRetriesResponse.model_validate(self._payload([]))

        assert result.data.trend[0].y == []
        assert result.data.retry_total == 0

    def test_keeps_unmodelled_retry_elements(self) -> None:
        """Element shape is unobserved upstream, so anything inside the array must survive."""
        result = RescuedRetriesResponse.model_validate(self._payload([{"attempt": 1}]))

        assert result.data.trend[0].y == [{"attempt": 1}]

    def test_rejects_a_scalar_y(self) -> None:
        """``y`` is an array here and a number on every other chart -- the split is the point."""
        with pytest.raises(ValidationError, match="y"):
            RescuedRetriesResponse.model_validate(self._payload(3))


class TestFeedbackModels:
    def test_y_is_an_object_not_a_number(self) -> None:
        result = FeedbackModelsResponse.model_validate(
            {
                "success": True,
                "data": {
                    "records": [
                        {"x": "gpt-4o", "y": {"avgWeightedFeedback": 4.2, "feedbackCount": 18}}
                    ],
                    "isQuotaExceeded": False,
                },
            }
        )

        assert result.data.records[0].y.avg_weighted_feedback == 4.2
        assert result.data.records[0].y.feedback_count == 18

    def test_rejects_a_scalar_y(self) -> None:
        with pytest.raises(ValidationError, match="y"):
            FeedbackModelsResponse.model_validate(
                {
                    "success": True,
                    "data": {"records": [{"x": "gpt-4o", "y": 4.2}], "isQuotaExceeded": False},
                }
            )


class TestTokensChart:
    def test_unit_splits_are_snake_case_at_both_levels(self) -> None:
        """They sit beside camelCase isQuotaExceeded in one object; the mix is upstream's."""
        result = TokensChartResponse.model_validate(
            {
                "success": True,
                "data": {
                    "records": [
                        {
                            "x": "2026-07-27T00:00:00Z",
                            "y": 1482,
                            "total_request_units": 900,
                            "total_response_units": 582,
                            "avg": 741,
                        }
                    ],
                    "total": 1482,
                    "avg": 741,
                    "total_request_units": 900,
                    "total_response_units": 582,
                    "isQuotaExceeded": False,
                },
            }
        )

        assert result.data.total_request_units == 900
        assert result.data.records[0].total_response_units == 582
        # Nothing fell through to extras, so both spellings are modelled as declared.
        assert result.data.model_extra == {}
        assert result.data.records[0].model_extra == {}


class TestTrendCharts:
    def test_user_trends_summary_counts_users_not_buckets(self) -> None:
        result = UserTrendsResponse.model_validate(
            {
                "success": True,
                "data": {
                    "summary": {"total": 180, "unique": 12, "avg": 15},
                    "trend": [{"x": "2026-07-27T00:00:00Z", "y": 180}],
                    "isQuotaExceeded": False,
                },
            }
        )

        assert result.data.summary.unique == 12
        # avg is requests-per-user, so it must not be derivable from the bucket count.
        assert result.data.summary.avg == 15
        assert result.data.trend[0].avg is None

    def test_error_trends_maps_the_camel_case_percentage(self) -> None:
        result = ErrorTrendsResponse.model_validate(
            {
                "success": True,
                "data": {
                    "summary": {"errorPercent": 2.5},
                    "trend": [{"x": "2026-07-27T00:00:00Z", "y": 2.5}],
                    "isQuotaExceeded": False,
                },
            }
        )

        assert result.data.summary.error_percent == 2.5
        assert result.data.summary.model_extra == {}
        assert result.data.summary.model_dump(by_alias=True) == {"errorPercent": 2.5}


class TestFeedbackScoreDistribution:
    def _payload(self, x: Any, total: float | None = 2) -> dict[str, Any]:
        return {
            "success": True,
            "data": {"records": [{"x": x, "y": 2}], "total": total, "isQuotaExceeded": False},
        }

    def test_x_is_the_score_not_a_timestamp(self) -> None:
        """Every other chart keys buckets by an ISO string; here x is the +/-5 score itself."""
        result = FeedbackScoreDistributionResponse.model_validate(self._payload(-5))

        assert result.data.records[0].x == -5

    def test_rejects_a_timestamp_shaped_x(self) -> None:
        with pytest.raises(ValidationError, match="x"):
            FeedbackScoreDistributionResponse.model_validate(self._payload("2026-07-27T00:00:00Z"))

    def test_total_is_nullable_but_still_required(self) -> None:
        parsed = FeedbackScoreDistributionResponse.model_validate(self._payload(5, None))
        assert parsed.data.total is None

        payload = self._payload(5)
        payload["data"].pop("total")
        with pytest.raises(ValidationError, match="total"):
            FeedbackScoreDistributionResponse.model_validate(payload)


# ---------------------------------------------------------------------------
# Envelope C and the group endpoints
# ---------------------------------------------------------------------------


class TestGroupList:
    def _payload(self, **overrides: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "object": "list",
            "is_quota_exceeded": False,
            "total": 2,
            "data": [
                {
                    "requests": 140,
                    "cost": 431.2,
                    "avg_latency": 812,
                    "avg_tokens": 1482,
                    "total_tokens": 207480,
                    "success_rate": 0.98,
                    "last_seen": "2026-07-27T18:04:11Z",
                    "object": "group",
                    "model": "gpt-4o-mini",
                },
                {"requests": 3, "object": "group", "model": "claude-sonnet-4"},
            ],
        }
        payload.update(overrides)
        return payload

    def test_parses_a_full_group_listing(self) -> None:
        result = GroupListResponse.model_validate(self._payload())

        assert result.total == 2
        assert result.data[0].success_rate == 0.98
        assert result.data[1].cost is None

    def test_carries_the_varying_dimension_key_through_extra(self) -> None:
        """The dimension column is named per endpoint, so it can only arrive as an extra."""
        result = GroupListResponse.model_validate(self._payload())

        assert result.data[0].model_extra == {"model": "gpt-4o-mini"}

    def test_quota_flag_is_snake_case_on_this_envelope_only(self) -> None:
        """Envelope C spells the flag snake_case; the camelCase spelling is envelope A's."""
        camel = self._payload()
        camel["isQuotaExceeded"] = camel.pop("is_quota_exceeded")

        with pytest.raises(ValidationError, match="is_quota_exceeded"):
            GroupListResponse.model_validate(camel)

    def test_envelope_c_has_no_has_more(self) -> None:
        """Envelope B paginates with has_more; envelope C does not declare it."""
        result = GroupListResponse.model_validate(self._payload(has_more=True))

        assert result.model_extra == {"has_more": True}


class TestUserGroup:
    def _payload(self, **record_overrides: Any) -> dict[str, Any]:
        record: dict[str, Any] = {"_user": "", "count": 41, "cost": 118.0}
        record.update(record_overrides)
        return {
            "success": True,
            "data": {"records": [record], "total": 1, "isQuotaExceeded": False},
        }

    def test_uses_envelope_a_unlike_its_siblings(self) -> None:
        """Verified live: the users dimension is wrapped in {success, data}, not envelope C."""
        result = UserGroupResponse.model_validate(self._payload())

        assert result.success is True
        assert result.data.total == 1

    def test_rejects_the_envelope_c_shape(self) -> None:
        with pytest.raises(ValidationError, match="success"):
            UserGroupResponse.model_validate(
                {"object": "list", "is_quota_exceeded": False, "total": 1, "data": []}
            )

    def test_maps_the_underscore_prefixed_user_key(self) -> None:
        """``_user`` cannot be a pydantic field name, so it is aliased onto ``user``."""
        result = UserGroupResponse.model_validate(self._payload(_user="alice@example.com"))

        assert result.data.records[0].user == "alice@example.com"
        # The alias consumed the wire key rather than letting it fall through to extras.
        assert result.data.records[0].model_extra == {}

    def test_keeps_the_empty_user_and_still_requires_the_key(self) -> None:
        """``''`` means "calls with no end-user id"; an absent key is a shape change."""
        assert UserGroupResponse.model_validate(self._payload()).data.records[0].user == ""

        payload = self._payload()
        payload["data"]["records"][0].pop("_user")
        with pytest.raises(ValidationError, match="_user"):
            UserGroupResponse.model_validate(payload)

    def test_dumps_the_user_key_back_with_its_underscore(self) -> None:
        result = UserGroupResponse.model_validate(self._payload(_user="bob"))

        assert result.data.records[0].model_dump(by_alias=True)["_user"] == "bob"


# ---------------------------------------------------------------------------
# Raw logs
# ---------------------------------------------------------------------------


class TestGatewayLogRecord:
    def test_parses_a_full_live_row(self) -> None:
        record = GatewayLogRecord.model_validate(log_record_payload())

        assert record.ai_model == "gpt-4o-mini"
        assert record.metadata_key == ["env", "team"]
        assert record.metadata_value == ["prod", "secops"]
        assert record.cache_status == "MISS"

    def test_round_trips_every_key_under_its_wire_name(self) -> None:
        payload = log_record_payload(newColumn="surprise")

        dumped = GatewayLogRecord.model_validate(payload).model_dump(by_alias=True)

        assert set(dumped) == set(payload)
        assert dumped["newColumn"] == "surprise"

    def test_reads_the_zero_one_success_flag_as_a_boolean(self) -> None:
        assert GatewayLogRecord.model_validate(log_record_payload()).succeeded is True
        assert GatewayLogRecord.model_validate(log_record_payload(is_success=0)).succeeded is False

    def test_reads_the_zero_one_proxy_flag_as_a_boolean(self) -> None:
        assert GatewayLogRecord.model_validate(log_record_payload()).proxied is True
        record = GatewayLogRecord.model_validate(log_record_payload(is_proxy_call=0))
        assert record.proxied is False

    def test_parses_an_airs_security_block(self) -> None:
        """446 is the AIRS block verdict; the request is billed at zero."""
        record = GatewayLogRecord.model_validate(
            log_record_payload(response_status_code=446, is_success=0, cost=0)
        )

        assert record.response_status_code == 446
        assert record.cost == 0
        assert record.succeeded is False

    def test_numbers_stay_floats_even_where_the_wire_sends_integers(self) -> None:
        """Nothing upstream says ``.int()``, so every z.number() lands as a float here."""
        record = GatewayLogRecord.model_validate(log_record_payload())

        assert isinstance(record.response_status_code, float)
        assert isinstance(record.is_success, float)
        assert isinstance(record.total_units, float)

    def test_does_not_close_the_cache_status_value_set(self) -> None:
        """Documented as HIT|MISS|DISABLED, deliberately not an enum: upstream adds modes."""
        record = GatewayLogRecord.model_validate(log_record_payload(cache_status="SEMANTIC_HIT"))

        assert record.cache_status == "SEMANTIC_HIT"

    def test_requires_the_columns_a_log_row_always_has(self) -> None:
        payload = log_record_payload()
        payload.pop("trace_id")

        with pytest.raises(ValidationError, match="trace_id"):
            GatewayLogRecord.model_validate(payload)


class TestGatewayLogsResponse:
    def _payload(self, **data_overrides: Any) -> dict[str, Any]:
        data: dict[str, Any] = {
            "records": [log_record_payload()],
            "total": 5120,
            "capturedTotal": 0,
            "isQuotaExceeded": False,
        }
        data.update(data_overrides)
        return {"success": True, "data": data}

    def test_parses_the_bare_logs_collection(self) -> None:
        result = GatewayLogsResponse.model_validate(self._payload())

        # capturedTotal is always 0 upstream; paging must follow `total`, never this.
        assert result.data.total == 5120
        assert result.data.records[0].user == ""
        # The alias consumed capturedTotal rather than leaving it to fall through.
        assert result.data.model_extra == {}

    def test_captured_total_reads_the_wire_value_not_a_constant(self) -> None:
        """It is 0 on every live tenant, so only a non-zero payload can prove it is read."""
        result = GatewayLogsResponse.model_validate(self._payload(capturedTotal=17))

        assert result.data.captured_total == 17


# ---------------------------------------------------------------------------
# Write responses and receipts
# ---------------------------------------------------------------------------


class TestGatewayWriteResponse:
    def test_keeps_an_unverified_body_intact(self) -> None:
        result = GatewayWriteResponse.model_validate({"id": "x_1", "object": "thing"})

        assert result.model_extra == {"id": "x_1", "object": "thing"}

    def test_accepts_an_empty_body(self) -> None:
        assert GatewayWriteResponse.model_validate({}).model_extra == {}


class TestCreateReceipts:
    def test_config_receipt_declares_all_four_fields(self) -> None:
        receipt = GatewayConfigCreateResponse.model_validate(
            {"id": "cfg_1", "version_id": "cfgv_1", "slug": "cfg-1", "object": "config"}
        )

        assert receipt.version_id == "cfgv_1"
        # Nothing fell through to extras, so all four are modelled rather than tolerated.
        assert receipt.model_extra == {}

    def test_guardrail_receipt_declares_all_four_fields(self) -> None:
        receipt = GatewayGuardrailCreateResponse.model_validate(
            {"id": "gr_1", "version_id": "grv_1", "slug": "gr-1", "object": "guardrail"}
        )

        assert receipt.version_id == "grv_1"
        assert receipt.model_extra == {}

    def test_receipts_still_require_their_own_fields(self) -> None:
        """A receipt is minimal, not lenient: dropping version_id is still a failure."""
        with pytest.raises(ValidationError, match="version_id"):
            GatewayConfigCreateResponse.model_validate(
                {"id": "cfg_1", "slug": "cfg-1", "object": "config"}
            )

    def test_provider_receipt_declares_no_version_id(self) -> None:
        """Providers return three fields; a version_id would have to arrive as an extra."""
        receipt = GatewayProviderCreateResponse.model_validate(
            {"id": "prov_1", "slug": "prov-1", "object": "provider", "version_id": "v_1"}
        )

        assert receipt.model_extra == {"version_id": "v_1"}

    def test_a_receipt_is_not_the_record(self) -> None:
        receipt = {"id": "cfg_1", "version_id": "cfgv_1", "slug": "cfg-1", "object": "config"}

        with pytest.raises(ValidationError, match="organisation_id"):
            GatewayConfig.model_validate(receipt)


# ---------------------------------------------------------------------------
# Workspaces
# ---------------------------------------------------------------------------


class TestWorkspaces:
    def test_parses_a_list_page(self) -> None:
        result = ListWorkspacesResponse.model_validate(
            {"object": "list", "total": 1, "data": [workspace_row_payload()]}
        )

        assert result.has_more is None
        assert result.data[0].scope_name == "prisma-airs-ws-secops"
        assert result.data[0].description is None
        assert result.data[0].model_extra == {}

    def test_reports_further_pages_when_upstream_says_so(self) -> None:
        result = ListWorkspacesResponse.model_validate(
            {"object": "list", "total": 40, "has_more": True, "data": []}
        )

        assert result.has_more is True
        # Declared on envelope B, so it must not land in extras alongside the flag.
        assert result.model_extra == {}
        assert result.data == []

    def test_detail_accepts_limits_as_an_array_of_policies(self) -> None:
        """The array form is what a tenant with limits configured returns (issue #211)."""
        result = GatewayWorkspaceDetail.model_validate(
            workspace_detail_payload(
                usage_limits=[
                    {"credit_limit": 5000, "type": "cost", "alert_threshold": 0.8, "id": "ul_1"}
                ],
                rate_limits=[{"type": "requests", "unit": "rpm", "value": 600}],
            )
        )

        assert isinstance(result.usage_limits, list)
        assert result.usage_limits[0].credit_limit == 5000
        # Server-side bookkeeping the contract omits still has to survive.
        assert result.usage_limits[0].model_extra == {"id": "ul_1"}
        assert isinstance(result.rate_limits, list)
        assert result.rate_limits[0].unit == "rpm"

    def test_detail_still_accepts_the_legacy_object_form(self) -> None:
        result = GatewayWorkspaceDetail.model_validate(
            workspace_detail_payload(usage_limits={"credit_limit": 5000})
        )

        assert result.usage_limits == {"credit_limit": 5000}

    def test_detail_accepts_null_limits(self) -> None:
        assert GatewayWorkspaceDetail.model_validate(workspace_detail_payload()).rate_limits is None

    def test_detail_requires_the_limits_keys(self) -> None:
        payload = workspace_detail_payload()
        payload.pop("usage_limits")

        with pytest.raises(ValidationError, match="usage_limits"):
            GatewayWorkspaceDetail.model_validate(payload)

    def test_detail_tolerates_a_null_status(self) -> None:
        """get() reports null where list() reports 'active'; null means unknown, not inactive."""
        detail = GatewayWorkspaceDetail.model_validate(workspace_detail_payload(status=None))

        assert detail.status is None

    def test_detail_keeps_the_settings_blocks_typed(self) -> None:
        result = GatewayWorkspaceDetail.model_validate(
            workspace_detail_payload(
                security_settings={"block_inline_config": True},
                data_plane_security_settings={"trusted_custom_hosts": ["spark.local"]},
            )
        )

        assert result.security_settings == {"block_inline_config": True}
        assert result.data_plane_security_settings is not None
        assert result.data_plane_security_settings["trusted_custom_hosts"] == ["spark.local"]

    def test_security_settings_values_must_be_flags(self) -> None:
        """``security_settings`` is a map of booleans; its sibling block is a map of anything."""
        nested = {"trusted_custom_hosts": ["spark.local"]}

        with pytest.raises(ValidationError, match="security_settings"):
            GatewayWorkspaceDetail.model_validate(
                workspace_detail_payload(security_settings=nested)
            )

        parsed = GatewayWorkspaceDetail.model_validate(
            workspace_detail_payload(data_plane_security_settings=nested)
        )
        assert parsed.data_plane_security_settings == nested

    def test_create_response_carries_seeded_users(self) -> None:
        """``users`` appears on the create receipt and on no other workspace read."""
        result = GatewayWorkspaceCreateResponse.model_validate(
            workspace_create_payload(users=[{"id": "user_1", "role": "admin"}])
        )

        assert result.users == [{"id": "user_1", "role": "admin"}]
        assert "users" not in GatewayWorkspaceDetail.model_fields

    def test_create_response_is_not_the_detail_shape(self) -> None:
        """Create omits icon, defaults, and both limit blocks, so it cannot parse as detail."""
        create_body = workspace_create_payload()

        assert GatewayWorkspaceCreateResponse.model_validate(create_body).users is None
        with pytest.raises(ValidationError, match="usage_limits"):
            GatewayWorkspaceDetail.model_validate(create_body)


# ---------------------------------------------------------------------------
# Configs and guardrails
# ---------------------------------------------------------------------------


class TestConfigs:
    def test_list_row_parses_without_the_detail_fields(self) -> None:
        """The 12 list columns are all modelled -- none of them survives only as an extra."""
        row = GatewayConfig.model_validate(config_row_payload())

        assert row.is_default == 1
        assert row.model_extra == {}
        assert set(GatewayConfig.model_fields) == set(config_row_payload())

    def test_the_collection_wraps_list_rows(self) -> None:
        result = ListConfigsResponse.model_validate(
            {"object": "list", "total": 1, "data": [config_row_payload()]}
        )

        assert result.data[0].workspace_id == "ws_01"
        assert result.data[0].model_extra == {}

    def test_detail_requires_the_four_extra_fields(self) -> None:
        with pytest.raises(ValidationError, match="version_id"):
            GatewayConfigDetail.model_validate(config_row_payload())

    def test_detail_leaves_the_config_as_an_unparsed_string(self) -> None:
        """The wire type is a JSON string; parsing it here would lose the round trip."""
        raw = json.dumps({"retry": {"attempts": 3}, "strategy": {"mode": "fallback"}})
        detail = GatewayConfigDetail.model_validate(config_detail_payload(config=raw))

        assert isinstance(detail.config, str)
        assert json.loads(detail.config)["retry"]["attempts"] == 3

    def test_detail_rejects_a_config_object(self) -> None:
        with pytest.raises(ValidationError, match="config"):
            GatewayConfigDetail.model_validate(
                config_detail_payload(config={"retry": {"attempts": 3}})
            )


class TestGuardrails:
    def test_parses_a_full_detail_record(self) -> None:
        detail = GatewayGuardrailDetail.model_validate(guardrail_detail_payload())

        assert detail.checks[0].id == "panw-prisma-airs.intercept"
        assert detail.checks[0].parameters == {"profile_name": "spark-ee4aa3"}
        assert detail.checks[0].is_enabled is True
        assert detail.actions.deny is True
        assert detail.updated_by is None

    def test_maps_the_async_action_off_the_python_keyword(self) -> None:
        detail = GatewayGuardrailDetail.model_validate(
            guardrail_detail_payload(actions={"deny": False, "async": True, "sequential": False})
        )

        assert detail.actions.async_ is True
        assert detail.actions.model_dump(by_alias=True)["async"] is True

    def test_feedback_actions_are_absent_when_never_configured(self) -> None:
        detail = GatewayGuardrailDetail.model_validate(guardrail_detail_payload())

        assert detail.actions.on_success is None
        assert detail.actions.on_fail is None

    def test_parses_configured_feedback_actions(self) -> None:
        detail = GatewayGuardrailDetail.model_validate(
            guardrail_detail_payload(
                actions={
                    "deny": True,
                    "async": False,
                    "sequential": True,
                    "on_fail": {"feedback": {"value": -5, "weight": 1, "metadata": "airs-block"}},
                }
            )
        )

        assert detail.actions.on_fail is not None
        assert detail.actions.on_fail.feedback.value == -5
        assert detail.actions.on_fail.feedback.metadata == "airs-block"

    def test_list_row_cannot_stand_in_for_detail(self) -> None:
        payload = guardrail_detail_payload()
        for detail_only in ("checks", "actions", "version_id"):
            payload.pop(detail_only)

        with pytest.raises(ValidationError, match="checks"):
            GatewayGuardrailDetail.model_validate(payload)

    def test_the_list_row_declares_none_of_the_detail_fields(self) -> None:
        """Feeding the list row a detail body proves exactly which keys it does not model."""
        row = GatewayGuardrail.model_validate(guardrail_detail_payload())

        assert row.model_extra == {
            "checks": [
                {
                    "id": "panw-prisma-airs.intercept",
                    "parameters": {"profile_name": "spark-ee4aa3"},
                    "is_enabled": True,
                }
            ],
            "actions": {"deny": True, "async": False, "sequential": True},
            "version_id": "grv_01",
        }

    def test_the_collection_wraps_list_rows(self) -> None:
        payload = guardrail_detail_payload()
        for detail_only in ("checks", "actions", "version_id"):
            payload.pop(detail_only)

        result = ListGuardrailsResponse.model_validate(
            {"object": "list", "total": 1, "data": [payload]}
        )

        assert result.data[0].updated_by is None
        assert result.data[0].model_extra == {}


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------


class TestIntegrations:
    def test_parses_per_model_enablement(self) -> None:
        result = GatewayIntegrationModelsResponse.model_validate(
            {
                "models": [
                    {"slug": "gpt-4o", "enabled": True},
                    {"slug": "gpt-3.5-turbo", "enabled": False},
                ],
                "allow_all_models": False,
                "object": "list",
            }
        )

        assert [m.slug for m in result.models if m.enabled] == ["gpt-4o"]
        assert result.allow_all_models is False

    def test_global_workspace_access_is_an_object(self) -> None:
        result = GatewayIntegrationWorkspacesResponse.model_validate(
            {
                "workspaces": [
                    integration_workspace_payload(
                        rate_limits=[{"type": "tokens", "unit": "rpd", "value": 100000}]
                    )
                ],
                "global_workspace_access": global_workspace_access_payload(),
                "object": "list",
            }
        )

        assert result.global_workspace_access.enabled is True
        binding = result.workspaces[0]
        assert isinstance(binding.rate_limits, list)
        assert binding.rate_limits[0].value == 100000
        assert binding.last_reset_at is None

    def test_rejects_the_request_side_boolean_for_global_access(self) -> None:
        """The request sends a boolean here; the response never does."""
        with pytest.raises(ValidationError, match="global_workspace_access"):
            GatewayIntegrationWorkspacesResponse.model_validate(
                {"workspaces": [], "global_workspace_access": True, "object": "list"}
            )


class TestGatewayIntegration:
    def test_parses_an_org_level_integration(self) -> None:
        result = ListIntegrationsResponse.model_validate(
            {"object": "list", "total": 1, "data": [integration_payload()]}
        )

        integration = result.data[0]
        # An org-level integration is bound to no single workspace.
        assert integration.workspace_id is None
        assert integration.workspaces_count == 2
        assert integration.model_extra == {}

    def test_tags_shape_is_left_unconstrained(self) -> None:
        """Null on every tenant sampled, so whatever upstream starts sending must survive."""
        assert GatewayIntegration.model_validate(integration_payload(tags=["prod"])).tags == [
            "prod"
        ]

        row = integration_payload()
        row.pop("tags")
        assert GatewayIntegration.model_validate(row).tags is None


class TestMcpIntegration:
    def test_configurations_arrive_json_encoded(self) -> None:
        integration = McpIntegration.model_validate(mcp_integration_payload())

        assert isinstance(integration.configurations, str)
        assert json.loads(integration.configurations)["headers"] == {"x-portkey-api-key": "***"}

    def test_rejects_the_create_request_object_form(self) -> None:
        with pytest.raises(ValidationError, match="configurations"):
            McpIntegration.model_validate(mcp_integration_payload(configurations={"headers": {}}))

    def test_the_collection_wraps_rows_in_envelope_b(self) -> None:
        result = ListMcpIntegrationsResponse.model_validate(
            {"object": "list", "total": 1, "data": [mcp_integration_payload()]}
        )

        assert result.data[0].transport == "sse"


# ---------------------------------------------------------------------------
# Providers, API keys, and plugins
# ---------------------------------------------------------------------------


class TestMinimalRecords:
    def test_provider_declares_only_id_as_required(self) -> None:
        result = ListProvidersResponse.model_validate(
            {"object": "list", "total": 1, "data": [{"id": "prov_1"}]}
        )

        provider = result.data[0]
        assert (provider.name, provider.slug, provider.object) == (None, None, None)

    def test_provider_still_requires_the_id(self) -> None:
        with pytest.raises(ValidationError, match="id"):
            GatewayProvider.model_validate({"name": "openai"})

    def test_api_key_declares_only_id_as_required(self) -> None:
        result = ListApiKeysResponse.model_validate(
            {"object": "list", "total": 1, "data": [{"id": "key_1", "name": "ci"}]}
        )

        assert result.data[0].name == "ci"
        assert result.data[0].object is None

    def test_api_key_promises_no_secret_field(self) -> None:
        """The secret is returned at creation only, so a read model must not declare one."""
        assert "key" not in GatewayApiKey.model_fields

        parsed = GatewayApiKey.model_validate({"id": "key_1", "key": "sk-live-xxx"})
        assert parsed.model_extra == {"key": "sk-live-xxx"}


class TestPlugins:
    def test_parses_a_binding_with_masked_credentials(self) -> None:
        result = ListPluginsResponse.model_validate(
            {"object": "list", "total": 1, "data": [plugin_payload()]}
        )

        plugin = result.data[0]
        assert plugin.credentials == {"api_key": "****"}
        assert plugin.plugin_provider_slug == "panw-prisma-airs"
        assert plugin.model_extra == {}

    def test_credentials_are_a_flat_map_of_strings(self) -> None:
        """Not the username/password pair deployments use -- this one is a record<string>."""
        with pytest.raises(ValidationError, match="credentials"):
            GatewayPlugin.model_validate(plugin_payload(credentials={"api_key": {"value": "x"}}))


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------


class TestDeployments:
    def test_parses_a_full_detail_record(self) -> None:
        detail = GatewayDeploymentDetail.model_validate(deployment_detail_payload())

        assert detail.status == "active"
        assert detail.credentials is not None
        assert detail.credentials.password == "********"
        assert detail.auth_settings is not None
        assert detail.auth_settings.workspaces_allowed == ["ws_01"]
        assert detail.auth_settings.disable_portkey_gateway == 0
        assert detail.workspaces is not None
        assert detail.workspaces[0].slug == "secops"

    def test_detail_tolerates_an_archived_deployment(self) -> None:
        """DELETE archives rather than removes, so archived rows keep coming back."""
        detail = GatewayDeploymentDetail.model_validate(
            deployment_detail_payload(status="archived", last_synced_at=None)
        )

        assert detail.status == "archived"
        assert detail.last_synced_at is None

    def test_does_not_close_the_deployment_status_value_set(self) -> None:
        """Documented as active|archived, deliberately not an enum: a third state must parse."""
        detail = GatewayDeploymentDetail.model_validate(
            deployment_detail_payload(status="provisioning")
        )

        assert detail.status == "provisioning"

    def test_detail_requires_the_nullable_deployment_config_key(self) -> None:
        payload = deployment_detail_payload()
        payload.pop("deployment_config")

        with pytest.raises(ValidationError, match="deployment_config"):
            GatewayDeploymentDetail.model_validate(payload)

    def test_create_receipt_exposes_the_only_readable_password(self) -> None:
        receipt = GatewayDeploymentCreateResponse.model_validate(
            {
                "id": "dep_02",
                "client_auth": "ca-once",
                "credentials": {"username": "dep_02", "password": "once-only"},
                "organisation_id": "org-uuid",
                "object": "deployment",
            }
        )

        assert receipt.credentials.password == "once-only"
        # Printing the receipt is how callers capture it, so it must stay in repr.
        assert "once-only" in repr(receipt)

    def test_the_list_row_declares_none_of_the_detail_fields(self) -> None:
        """The 12 list columns are all a list() page carries; the rest is get()-only."""
        row = GatewayDeployment.model_validate(deployment_detail_payload())

        assert set(row.model_extra or {}) == set(DEPLOYMENT_DETAIL_ONLY)

    def test_the_collection_wraps_list_rows(self) -> None:
        result = ListDeploymentsResponse.model_validate(
            {"object": "list", "total": 1, "data": [deployment_row_payload()]}
        )

        assert result.data[0].last_resynced_at is None
        assert result.data[0].model_extra == {}

    def test_create_receipt_is_not_a_deployment_row(self) -> None:
        with pytest.raises(ValidationError, match="slug"):
            GatewayDeploymentDetail.model_validate(
                {
                    "id": "dep_02",
                    "client_auth": "ca-once",
                    "credentials": {"username": "dep_02", "password": "x"},
                    "organisation_id": "org-uuid",
                    "object": "deployment",
                }
            )


# ---------------------------------------------------------------------------
# Organisations and audit logs
# ---------------------------------------------------------------------------


class TestOrganisationSelf:
    def test_wraps_an_opaque_data_block(self) -> None:
        result = OrganisationSelfResponse.model_validate(
            {"success": True, "data": {"id": "org-uuid", "name": "perfecXion", "tsg": "1852583913"}}
        )

        assert result.data["tsg"] == "1852583913"

    def test_requires_the_data_block(self) -> None:
        with pytest.raises(ValidationError, match="data"):
            OrganisationSelfResponse.model_validate({"success": True})


class TestAuthSettings:
    def test_wraps_an_opaque_data_block(self) -> None:
        result = AuthSettingsResponse.model_validate(
            {"success": True, "data": {"sso_enabled": True, "allowed_domains": ["perfecxion.ai"]}}
        )

        assert result.data["allowed_domains"] == ["perfecxion.ai"]

    def test_rejects_a_scalar_data_block(self) -> None:
        with pytest.raises(ValidationError, match="data"):
            AuthSettingsResponse.model_validate({"success": True, "data": "enabled"})


class TestAuditLogs:
    def test_parses_a_records_object_with_neither_list_envelope(self) -> None:
        result = GatewayAuditLogsResponse.model_validate({"records": [audit_record_payload()]})

        assert len(result.records) == 1
        assert result.records[0].resource_type == "plugin"
        assert result.records[0].response_status_code == 201

    def test_keeps_the_unredacted_body_out_of_repr(self) -> None:
        """The API returns request_body unredacted; an incidental print must not spill it."""
        record = GatewayAuditLogRecord.model_validate(audit_record_payload())

        assert "leaked-key" not in repr(record)
        assert "request_body" not in repr(record)

    def test_still_exposes_the_body_to_deliberate_access(self) -> None:
        record = GatewayAuditLogRecord.model_validate(audit_record_payload())

        assert "leaked-key" in record.request_body
        assert "leaked-key" in record.model_dump()["request_body"]

    def test_leaves_the_masked_headers_visible(self) -> None:
        record = GatewayAuditLogRecord.model_validate(audit_record_payload())

        assert "request_headers" in repr(record)


# ---------------------------------------------------------------------------
# Cross-cutting conventions
# ---------------------------------------------------------------------------


QUOTA_FLAG = {"isQuotaExceeded": False}
CHART_BUCKET = {"x": "2026-07-27T00:00:00Z", "y": 9.0, "avg": 4.5}
FEEDBACK = {"value": -5, "weight": 1, "metadata": "airs-block"}
CACHE_SUMMARY = {
    "cacheHits": 3,
    "avgCacheLatency": 12.0,
    "totalRequests": 240,
    "cacheSpeedup": 1.4,
}

#: One payload per model carrying EVERY field the port declares, optionals included.
#:
#: ``extra="allow"`` means a dropped or misspelled field does not raise -- its value quietly
#: lands in ``model_extra`` instead, and a test that only reads a handful of attributes will
#: never notice. Asserting the extras bag is empty against a complete payload is what turns
#: that silent degradation into a failure.
FULL_SHAPES: list[tuple[Any, dict[str, Any]]] = [
    # Chart buckets and summaries.
    (GatewayChartRecord, dict(CHART_BUCKET)),
    (LatencyChartRecord, {"x": "b", "y": 812, "p50": 640, "p90": 1400, "p99": 3100}),
    (
        TokensChartRecord,
        {
            "x": "b",
            "y": 1482,
            "total_request_units": 900,
            "total_response_units": 582,
            "avg": 741,
        },
    ),
    (
        CacheHitTrendPoint,
        {
            "x": "b",
            "simpleHits": 4,
            "semanticHits": 1,
            "hitRate": 0.2,
            "cumulativeSimpleHitSavings": 12.5,
            "cumulativeSemanticHitSavings": 3.0,
        },
    ),
    (RescuedRetriesPoint, {"x": "b", "y": []}),
    (RescuedRetriesTrendPoint, {"x": "b", "retry": [], "fallback": []}),
    (FeedbackScoreRecord, {"x": -5, "y": 2}),
    (FeedbackModelScore, {"avgWeightedFeedback": 4.2, "feedbackCount": 18}),
    (
        FeedbackModelRecord,
        {"x": "gpt-4o", "y": {"avgWeightedFeedback": 4.2, "feedbackCount": 18}},
    ),
    (CacheSummary, dict(CACHE_SUMMARY)),
    (CacheHitTrendSummary, {"totalCacheHits": 7, "hitRate": 0.15}),
    (UserTrendsSummary, {"total": 180, "unique": 12, "avg": 15}),
    (ErrorTrendsSummary, {"errorPercent": 2.5}),
    # Envelope-A payload bodies.
    (CostChartData, {"records": [], "total": 549.2, "avg": 3.25, **QUOTA_FLAG}),
    (CountChartData, {"records": [], "total": 9, **QUOTA_FLAG}),
    (
        LatencyChartData,
        {"records": [], "total": 2411, "p50": 655, "p90": 1420, "p99": 3180, **QUOTA_FLAG},
    ),
    (
        TokensChartData,
        {
            "records": [],
            "total": 1482,
            "avg": 741,
            "total_request_units": 900,
            "total_response_units": 582,
            **QUOTA_FLAG,
        },
    ),
    (CacheSummaryData, {"summary": dict(CACHE_SUMMARY), **QUOTA_FLAG}),
    (
        CacheHitTrendData,
        {
            "trend": [],
            "total": 7,
            "summary": {"totalCacheHits": 7, "hitRate": 0.15},
            **QUOTA_FLAG,
        },
    ),
    (
        UserTrendsData,
        {"summary": {"total": 180, "unique": 12, "avg": 15}, "trend": [], **QUOTA_FLAG},
    ),
    (ErrorTrendsData, {"summary": {"errorPercent": 2.5}, "trend": [], **QUOTA_FLAG}),
    (
        RescuedRetriesData,
        {
            "trend": [],
            "total": 0,
            "trends": [],
            "retryTotal": 0,
            "fallbackTotal": 0,
            **QUOTA_FLAG,
        },
    ),
    (FeedbackScoreDistributionData, {"records": [], "total": 2, **QUOTA_FLAG}),
    (FeedbackModelsData, {"records": [], **QUOTA_FLAG}),
    (UserGroupData, {"records": [], "total": 1, **QUOTA_FLAG}),
    (GatewayLogsData, {"records": [], "total": 5120, "capturedTotal": 0, **QUOTA_FLAG}),
    # Group and log rows.
    (UserGroupRecord, {"_user": "", "count": 41, "cost": 118.0}),
    (GatewayLogRecord, log_record_payload()),
    # Limit policies.
    (
        GatewayUsageLimit,
        {
            "credit_limit": 5000,
            "type": "cost",
            "alert_threshold": 0.8,
            "periodic_reset": "monthly",
            "periodic_reset_days": 30,
            "next_usage_reset_at": "2026-09-01T00:00:00Z",
        },
    ),
    (GatewayRateLimit, {"type": "requests", "unit": "rpm", "value": 600}),
    # Workspaces, configs, guardrails.
    (GatewayWorkspace, workspace_row_payload()),
    (
        GatewayWorkspaceDetail,
        workspace_detail_payload(
            security_settings={"block_inline_config": True},
            data_plane_security_settings={"trusted_custom_hosts": []},
            settings={},
            status="active",
        ),
    ),
    (GatewayWorkspaceCreateResponse, workspace_create_payload(defaults=None, users=[])),
    (GatewayConfigDetail, config_detail_payload()),
    (GuardrailFeedback, dict(FEEDBACK)),
    (GuardrailFeedbackAction, {"feedback": dict(FEEDBACK)}),
    (GuardrailCheck, {"id": "panw-prisma-airs.intercept", "parameters": {}, "is_enabled": True}),
    (
        GuardrailActions,
        {
            "deny": True,
            "async": False,
            "sequential": True,
            "on_success": {"feedback": dict(FEEDBACK)},
            "on_fail": {"feedback": dict(FEEDBACK)},
        },
    ),
    (GatewayGuardrailDetail, guardrail_detail_payload()),
    # Providers, keys, integrations.
    (GatewayProvider, {"id": "prov_1", "name": "OpenAI", "slug": "openai", "object": "provider"}),
    (GatewayApiKey, {"id": "key_1", "name": "ci", "object": "api-key"}),
    (GatewayIntegration, integration_payload()),
    (GatewayIntegrationModel, {"slug": "gpt-4o", "enabled": True}),
    (
        GatewayIntegrationModelsResponse,
        {"models": [], "allow_all_models": False, "object": "list"},
    ),
    (GatewayIntegrationWorkspace, integration_workspace_payload()),
    (GatewayGlobalWorkspaceAccess, global_workspace_access_payload()),
    (
        GatewayIntegrationWorkspacesResponse,
        {
            "workspaces": [],
            "global_workspace_access": global_workspace_access_payload(),
            "object": "list",
        },
    ),
    (McpIntegration, mcp_integration_payload()),
    # Deployments, plugins, audit logs.
    (GatewayDeploymentCredentials, {"username": "dep_01", "password": "***"}),
    (
        GatewayDeploymentAuthSettings,
        {"disable_portkey_gateway": 0, "workspaces_allowed": [], "allow_all_workspaces": 1},
    ),
    (GatewayDeploymentWorkspaceRef, {"id": "ws_01", "slug": "secops"}),
    (GatewayDeployment, deployment_row_payload()),
    (GatewayDeploymentDetail, deployment_detail_payload()),
    (
        GatewayDeploymentCreateResponse,
        {
            "id": "dep_02",
            "client_auth": "ca-once",
            "credentials": {"username": "dep_02", "password": "once-only"},
            "organisation_id": "org-uuid",
            "object": "deployment",
        },
    ),
    (GatewayPlugin, plugin_payload()),
    (GatewayAuditLogRecord, audit_record_payload()),
]

FULL_SHAPE_IDS = [model.__name__ for model, _payload in FULL_SHAPES]


class TestNoFieldSilentlyDropped:
    """Every key of a complete payload has to be claimed by a declared field."""

    @pytest.mark.parametrize(("model", "payload"), FULL_SHAPES, ids=FULL_SHAPE_IDS)
    def test_a_complete_payload_leaves_the_extras_bag_empty(
        self, model: Any, payload: dict[str, Any]
    ) -> None:
        parsed = model.model_validate(payload)

        assert parsed.model_extra == {}

    @pytest.mark.parametrize(("model", "payload"), FULL_SHAPES, ids=FULL_SHAPE_IDS)
    def test_the_payload_really_covers_every_declared_field(
        self, model: Any, payload: dict[str, Any]
    ) -> None:
        """Guards the guard: an incomplete fixture would make the test above vacuous."""
        wire_names = {f.alias or name for name, f in model.model_fields.items()}

        assert wire_names == set(payload)


#: Every field the upstream schemas declare ``.nullable()`` WITHOUT ``.optional()``: the key
#: is required and its value may be null. Losing that distinction is silent -- the field keeps
#: type-checking, and a genuinely absent key starts arriving as ``None`` instead of raising.
NULLABLE_BUT_REQUIRED: list[tuple[Any, Any, str]] = [
    (GatewayWorkspace, workspace_row_payload, "icon"),
    (GatewayWorkspace, workspace_row_payload, "description"),
    (GatewayWorkspaceDetail, workspace_detail_payload, "description"),
    (GatewayWorkspaceDetail, workspace_detail_payload, "icon"),
    (GatewayWorkspaceDetail, workspace_detail_payload, "defaults"),
    (GatewayWorkspaceDetail, workspace_detail_payload, "usage_limits"),
    (GatewayWorkspaceDetail, workspace_detail_payload, "rate_limits"),
    (GatewayWorkspaceCreateResponse, workspace_create_payload, "description"),
    (GatewayGuardrail, guardrail_detail_payload, "updated_by"),
    (GatewayIntegration, integration_payload, "description"),
    (GatewayIntegration, integration_payload, "workspace_id"),
    (GatewayIntegrationWorkspace, integration_workspace_payload, "usage_limits"),
    (GatewayIntegrationWorkspace, integration_workspace_payload, "rate_limits"),
    (GatewayIntegrationWorkspace, integration_workspace_payload, "last_reset_at"),
    (GatewayGlobalWorkspaceAccess, global_workspace_access_payload, "rate_limits"),
    (GatewayGlobalWorkspaceAccess, global_workspace_access_payload, "usage_limits"),
    (GatewayDeployment, deployment_detail_payload, "last_synced_at"),
    (GatewayDeployment, deployment_detail_payload, "last_resynced_at"),
    (GatewayDeploymentDetail, deployment_detail_payload, "deployment_config"),
]

NULLABLE_IDS = [f"{model.__name__}.{key}" for model, _factory, key in NULLABLE_BUT_REQUIRED]


class TestNullableIsNotOptional:
    """The upstream schemas distinguish "may be null" from "may be absent"; so does this port."""

    @pytest.mark.parametrize(("model", "factory", "key"), NULLABLE_BUT_REQUIRED, ids=NULLABLE_IDS)
    def test_a_null_value_parses(self, model: Any, factory: Any, key: str) -> None:
        parsed = model.model_validate(factory(**{key: None}))

        assert getattr(parsed, key) is None

    @pytest.mark.parametrize(("model", "factory", "key"), NULLABLE_BUT_REQUIRED, ids=NULLABLE_IDS)
    def test_an_absent_key_is_rejected(self, model: Any, factory: Any, key: str) -> None:
        payload = factory()
        payload.pop(key)

        with pytest.raises(ValidationError, match=key):
            model.model_validate(payload)


class TestListEnvelope:
    @pytest.mark.parametrize("model", LIST_RESPONSES)
    def test_every_collection_shares_envelope_b(self, model: Any) -> None:
        result = model.model_validate({"object": "list", "total": 0, "data": []})

        assert result.total == 0
        assert result.has_more is None
        assert result.model_extra == {}

    @pytest.mark.parametrize("model", LIST_RESPONSES)
    def test_every_collection_requires_a_total(self, model: Any) -> None:
        """Envelope B always reports the full count; a page without one is a shape change."""
        with pytest.raises(ValidationError, match="total"):
            model.model_validate({"object": "list", "data": []})


class TestApiConventions:
    def test_rate_limit_units_stay_open(self) -> None:
        """Documented as rpd|rph|rpm, left as a string so a new unit cannot break parsing."""
        assert GatewayRateLimit.model_validate({"unit": "rps", "value": 10}).unit == "rps"

    def test_partial_limit_policies_parse(self) -> None:
        assert GatewayRateLimit.model_validate({}).value is None

    def test_usage_limit_policies_keep_server_side_bookkeeping(self) -> None:
        """The contract omits these five keys; a live tenant returns them anyway."""
        policy = GatewayUsageLimit.model_validate(
            {"credit_limit": 5000, "current_usage": 12, "is_exhausted_alerts_sent": False}
        )

        assert policy.credit_limit == 5000
        assert policy.type is None
        assert policy.model_extra == {"current_usage": 12, "is_exhausted_alerts_sent": False}

    @pytest.mark.parametrize(
        "model,payload",
        [
            (GatewayLogRecord, log_record_payload(vendorAddedColumn=1)),
            (GatewayWorkspaceDetail, workspace_detail_payload(vendorAddedColumn=1)),
            (GatewayGuardrailDetail, guardrail_detail_payload(vendorAddedColumn=1)),
            (GatewayDeploymentDetail, deployment_detail_payload(vendorAddedColumn=1)),
            (GatewayAuditLogRecord, audit_record_payload(vendorAddedColumn=1)),
        ],
    )
    def test_unknown_fields_survive_everywhere(self, model: Any, payload: dict[str, Any]) -> None:
        """Upstream adds response fields without a version bump; rejecting them is an outage."""
        parsed = model.model_validate(payload)

        assert parsed.model_extra == {"vendorAddedColumn": 1}
