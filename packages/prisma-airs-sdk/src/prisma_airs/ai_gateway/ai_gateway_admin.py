"""Clients for the AI Gateway admin plane, plus the runtime telemetry it reports on.

Two planes over one credential set. :class:`AIGatewayTelemetryClient` reads the DATA plane
(``/ai_gw/v2``); every other client in this module reads the ADMIN plane
(``/ai_gw/admin/v2``). They authorize against different SCM role scopes, so a service
account needs both grants or half of this module answers 403: an admin role at tenant-root
scope for the admin plane, and ``view_only_admin`` or higher on
``main_airs_workspace_<TSG>`` for the data plane. A 403 whose body carries
``errorCode: "AB03"`` means the workspace-scope grant is missing; a 403 carrying
``x-opa-decision: false`` means the tenant-root grant is.

Two wire conventions here look like typos and are not:

* Timestamps differ per plane and must not be unified. Telemetry requires a **numeric** UTC
  offset and rejects a ``Z`` suffix with ``AB01``; ``audit-logs`` requires exactly the
  ``Z``-suffixed form.
* The tenant is spelled ``organisationId`` in telemetry query strings and
  ``organisation_id`` in admin DELETE query strings.

Endpoint slugs are bespoke rather than derivable -- ``user-trends`` is plural,
``cache-hit-trend`` is singular, and ``cache-hits-trend`` 404s -- so every slug comes from
:data:`~prisma_airs.constants.AI_GW_CHART_METRICS` and is checked against it before it
reaches a URL.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, Final, TypeVar

import httpx

from prisma_airs._http.auth import OAuthAuth, TsgHeaderAuth
from prisma_airs._http.transport import RequestSpec, request
from prisma_airs._http.types import AuthAdapter, HttpMethod
from prisma_airs._utils import is_valid_uuid
from prisma_airs.auth.oauth import OAuthClient, resolve_credentials
from prisma_airs.constants import (
    AI_GW_AUDIT_LOGS_PATH,
    AI_GW_CHART_METRICS,
    AI_GW_CHARTS_PATH,
    AI_GW_DEPLOYMENTS_PATH,
    AI_GW_GROUP_COLUMNS,
    AI_GW_GROUP_DIMENSIONS,
    AI_GW_GROUPS_PATH,
    AI_GW_INTEGRATIONS_PATH,
    AI_GW_LOGS_PATH,
    AI_GW_MCP_INTEGRATIONS_PATH,
    AI_GW_ORGANISATIONS_SELF_PATH,
    AI_GW_PLUGINS_PATH,
    DEFAULT_AI_GW_ADMIN_ENDPOINT,
    DEFAULT_AI_GW_DATA_ENDPOINT,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_AI_GW_ADMIN_ENDPOINT,
    ENV_AI_GW_DATA_ENDPOINT,
    ENV_PREFIX_AI_GW,
    ENV_PREFIX_MGMT,
    MAX_NUMBER_OF_RETRIES,
    ai_gw_organisations_auth_settings_path,
)
from prisma_airs.errors import AISecPayloadError
from prisma_airs.models.ai_gateway import (
    AuthSettingsResponse,
    CacheHitTrendResponse,
    CacheSummaryResponse,
    CostChartResponse,
    CountChartResponse,
    ErrorTrendsResponse,
    FeedbackModelsResponse,
    FeedbackScoreDistributionResponse,
    GatewayAuditLogsResponse,
    GatewayDeploymentCreateResponse,
    GatewayDeploymentDetail,
    GatewayIntegration,
    GatewayIntegrationModel,
    GatewayIntegrationModelsResponse,
    GatewayIntegrationWorkspacesResponse,
    GatewayLogsResponse,
    GatewayWriteResponse,
    GroupListResponse,
    LatencyChartResponse,
    ListDeploymentsResponse,
    ListIntegrationsResponse,
    ListMcpIntegrationsResponse,
    ListPluginsResponse,
    OrganisationSelfResponse,
    RescuedRetriesResponse,
    TokensChartResponse,
    UserGroupResponse,
    UserTrendsResponse,
)

T = TypeVar("T")

#: Any sub-client constructible from the four plane-independent arguments -- that is,
#: every one in this module except :class:`AIGatewayTelemetryClient`, which also needs the
#: TSG for its query strings.
SubClientT = TypeVar("SubClientT", bound="_AiGatewaySubClient")

#: Rolling window applied when a caller gives neither ``days`` nor ``start``.
DEFAULT_WINDOW_DAYS: Final = 7

#: ASCII digits only. Python's ``\d`` also matches Devanagari and Arabic-Indic digits,
#: which the service rejects, so the character class is spelled out.
_NUMERIC_ID_RE: Final = re.compile(r"^[0-9]+$")

# The endpoint-override variable names have no constant in ``prisma_airs.constants`` (only
# the prefix does), so they are derived from the prefix rather than spelled out here.

# Sub-resource segments with no constant of their own. ``users`` and ``status_code`` are
# deliberately absent from AI_GW_GROUP_DIMENSIONS: both live under ``logs/groups`` but
# neither is a valid ``group_by`` dimension, and ``users`` returns a different envelope
# from every sibling. Kept as named constants so there is one place to fix if they move.
_GROUPS_USERS_SEGMENT: Final = "users"
_GROUPS_STATUS_CODE_SEGMENT: Final = "status_code"
_INTEGRATION_MODELS_SEGMENT: Final = "models"
_INTEGRATION_WORKSPACES_SEGMENT: Final = "workspaces"


def to_offset_iso(value: datetime) -> str:
    """Render a datetime the way the telemetry endpoints demand it.

    ISO-8601 with a **numeric** UTC offset (``2026-07-20T00:00:00+02:00``). A ``Z`` suffix
    is rejected with error code ``AB01``, so :meth:`datetime.isoformat` output for a UTC
    datetime is fine but ``strftime('%Z')`` output is not. Sub-second precision is dropped;
    the service ignores it.

    An aware value keeps its own offset rather than being converted to the host's zone.
    The reference implementation always renders in host-local time only because a
    JavaScript ``Date`` carries no zone of its own; both spellings name the same instant
    and the service resolves them identically, so the window queried is the same.

    Args:
        value: The instant to render. A naive value is read as local time, matching the
            reference implementation's ``Date`` handling.

    Returns:
        The formatted timestamp.
    """
    aware = value.astimezone() if value.tzinfo is None else value
    offset = aware.utcoffset() or timedelta(0)
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    hours, minutes = divmod(abs(total_minutes), 60)
    return f"{aware:%Y-%m-%dT%H:%M:%S}{sign}{hours:02d}:{minutes:02d}"


def to_utc_iso_z(value: datetime) -> str:
    """Render a datetime the way ``audit-logs`` demands it.

    UTC with a ``Z`` suffix and exactly three fractional digits -- byte-for-byte what
    JavaScript's ``Date.toISOString()`` produces. This is the opposite of what the
    telemetry endpoints accept (see :func:`to_offset_iso`); the two are not interchangeable
    and unifying them breaks one caller or the other.

    Args:
        value: The instant to render. A naive value is read as local time.

    Returns:
        The formatted timestamp.
    """
    utc = value.astimezone(timezone.utc)
    return f"{utc:%Y-%m-%dT%H:%M:%S}.{utc.microsecond // 1000:03d}Z"


def _validate_retries(value: int) -> int:
    """Reject a retry count the transport cannot honour."""
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= MAX_NUMBER_OF_RETRIES
    ):
        raise AISecPayloadError(
            f"num_retries must be an integer between 0 and {MAX_NUMBER_OF_RETRIES}"
        )
    return value


def _assert_uuid(value: str, field: str) -> None:
    """Reject a malformed UUID before it is interpolated into a path."""
    if not is_valid_uuid(value):
        raise AISecPayloadError(f"Invalid {field}: {value}")


def _assert_numeric_id(value: str, field: str) -> None:
    """Reject anything that is not a plain numeric-string id.

    The TSG is numeric but not a UUID, so :func:`_assert_uuid` is the wrong check. Beyond
    catching a swapped-in organisation UUID, this rejects ``/`` and ``..``, so a
    caller-supplied value cannot reshape a path built by interpolation.
    """
    if not _NUMERIC_ID_RE.match(value):
        raise AISecPayloadError(f"Invalid {field}: {value}")


def _drop_unset(**fields: Any) -> dict[str, Any]:
    """Build a request body, omitting every key whose value is ``None``.

    Mirrors ``JSON.stringify``, which drops ``undefined`` members. The gateway treats an
    absent key and an explicit ``null`` differently on update, so an unset optional must
    not go out as ``"field": null``.
    """
    return {name: value for name, value in fields.items() if value is not None}


class _AiGatewaySubClient:
    """Shared plumbing for every client in this module.

    Holds the base URL, auth adapter, retry budget, and HTTP client, and funnels all four
    verbs through :func:`prisma_airs._http.transport.request` so retries, error mapping,
    and the ``x-tsg-id`` header stay in exactly one place.
    """

    def __init__(
        self,
        *,
        base_url: str,
        auth: AuthAdapter,
        http_client: httpx.Client,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
    ) -> None:
        self._base_url = base_url
        self._auth = auth
        self._http = http_client
        self._num_retries = _validate_retries(num_retries)

    def _get(self, path: str, model: type[T], *, params: Mapping[str, str] | None = None) -> T:
        """Send a GET and validate the response against ``model``."""
        return request(
            RequestSpec[T](
                method="GET",
                base_url=self._base_url,
                path=path,
                params=params,
                auth=self._auth,
                response_model=model,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def _write(self, method: HttpMethod, path: str, body: dict[str, Any], model: type[T]) -> T:
        """Send a POST or PUT and validate the response against ``model``."""
        return request(
            RequestSpec[T](
                method=method,
                base_url=self._base_url,
                path=path,
                body=body,
                auth=self._auth,
                response_model=model,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def _delete(self, path: str, *, params: Mapping[str, str]) -> None:
        """Send a DELETE and discard the body.

        These endpoints answer 200 with an empty body. ``request()`` resolves to ``None``
        whenever no response model is declared, regardless of ``allow_empty_body``, so that
        flag is intentionally omitted rather than implying it does something here.
        """
        request(
            RequestSpec[None](
                method="DELETE",
                base_url=self._base_url,
                path=path,
                params=params,
                auth=self._auth,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class AIGatewayTelemetryClient(_AiGatewaySubClient):
    """Runtime telemetry -- the data behind the SCM Observability tabs.

    Rides the DATA plane, unlike everything else in this module.

    Every query takes the same window arguments, documented once here rather than on each
    of the eighteen methods:

    * ``workspace_slug`` -- required by every endpoint, e.g. ``ws-main-a-349e0e``.
    * ``days`` -- rolling window size counted back from ``end``; defaults to
      :data:`DEFAULT_WINDOW_DAYS`. Ignored when ``start`` is given.
    * ``start`` -- explicit window start, overriding ``days``.
    * ``end`` -- explicit window end; defaults to now.

    Example:
        >>> cost = client.cost(workspace_slug="ws-main-a-349e0e", days=7)
        >>> f"${cost.data.total / 100:.2f}"
        '$4110.83'
    """

    def __init__(
        self,
        *,
        base_url: str,
        auth: AuthAdapter,
        http_client: httpx.Client,
        tsg_id: str,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
    ) -> None:
        super().__init__(
            base_url=base_url, auth=auth, http_client=http_client, num_retries=num_retries
        )
        self._tsg_id = tsg_id

    def cost(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CostChartResponse:
        """Total and per-day spend.

        **Values are in cents**, here and everywhere else the gateway reports cost. Nothing
        in the SDK divides them.

        Returns:
            The cost series plus the period total, in cents.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("cost", CostChartResponse, window)

    def requests(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CountChartResponse:
        """Per-day request counts.

        Returns:
            The request-count series plus the period total.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("requests", CountChartResponse, window)

    def latency(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> LatencyChartResponse:
        """Latency in milliseconds, with percentiles per bucket and for the period.

        Returns:
            The latency series. ``data.total`` is the period **mean**, not a sum.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("latency", LatencyChartResponse, window)

    def tokens(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> TokensChartResponse:
        """Token usage, split into request and response units.

        Returns:
            The token series plus request/response unit totals.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("tokens", TokensChartResponse, window)

    def errors(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CountChartResponse:
        """Per-day error counts.

        Returns:
            The error-count series plus the period total.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("errors", CountChartResponse, window)

    def users(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CountChartResponse:
        """Per-day distinct end-user counts.

        Returns:
            The unique-user series plus the period total.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("users", CountChartResponse, window)

    def cache_summary(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CacheSummaryResponse:
        """Cache hit count, speedup, and average cached-response latency.

        Returns:
            The cache summary. ``avg_cache_latency`` is ``None`` when there were no hits,
            which is not the same as a genuine zero.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("cache-summary", CacheSummaryResponse, window)

    def cache_hit_trend(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CacheHitTrendResponse:
        """Cache hit-rate trend and cumulative savings.

        Returns:
            Per-bucket hits plus **cumulative** savings in cents -- read the last non-zero
            bucket for the period total rather than summing the series.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("cache-hit-trend", CacheHitTrendResponse, window)

    def user_trends(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> UserTrendsResponse:
        """Requests-per-user trend.

        Returns:
            Daily request counts plus ``summary.avg``, which is requests per user rather
            than requests per bucket.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("user-trends", UserTrendsResponse, window)

    def error_trends(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> ErrorTrendsResponse:
        """Error-rate trend as a percentage.

        Returns:
            Daily error percentages plus ``summary.error_percent`` for the period.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("error-trends", ErrorTrendsResponse, window)

    def rescued_retries(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> RescuedRetriesResponse:
        """Gateway auto-retry and fallback resilience.

        Sparse: only populated when an upstream provider actually failed.

        Returns:
            Retry and fallback trends. ``trend[].y`` is an **array**, not a scalar.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("rescued-retries", RescuedRetriesResponse, window)

    def feedback_trend(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CountChartResponse:
        """Daily count of feedback submissions.

        Returns:
            The feedback-count series plus the period total.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("feedback-trend", CountChartResponse, window)

    def feedback_weighted(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> CountChartResponse:
        """Weighted average feedback score, averaged over days.

        Returns:
            The weighted-score series. ``data.total`` is ``None`` when there is no feedback.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("feedback-weighted", CountChartResponse, window)

    def feedback_score_distribution(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> FeedbackScoreDistributionResponse:
        """Distribution of feedback scores.

        Feedback is binary: +5 (thumbs up) or -5 (thumbs down), so the histogram has at
        most two buckets.

        Returns:
            The score histogram as ``{x: score, y: count}`` records.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("feedback-score-distribution", FeedbackScoreDistributionResponse, window)

    def feedback_models(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> FeedbackModelsResponse:
        """Feedback broken down by AI model.

        Returns:
            Records where ``x`` is the model and ``y`` is an object, not a number as on
            every other chart.
        """
        window = self._window_params(workspace_slug, days, start, end)
        return self._chart("feedback-models", FeedbackModelsResponse, window)

    def group_by(
        self,
        dimension: str,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        columns: Sequence[str] | None = None,
    ) -> GroupListResponse:
        """Aggregate requests by one dimension.

        Args:
            dimension: One of :data:`~prisma_airs.constants.AI_GW_GROUP_DIMENSIONS`.
                Underscored names only -- hyphen and camelCase spellings return 400.
            workspace_slug: Workspace to query.
            days: Rolling window size in days.
            start: Explicit window start.
            end: Explicit window end.
            columns: Extra columns to aggregate, from
                :data:`~prisma_airs.constants.AI_GW_GROUP_COLUMNS`, sent comma-joined in a
                single parameter. Validated here because the API silently **drops** names
                it does not recognise, so a typo would otherwise surface as missing data
                rather than as an error.

        Returns:
            One row per distinct dimension value.

        Raises:
            AISecPayloadError: If the dimension or any column is unrecognised.
        """
        if dimension not in AI_GW_GROUP_DIMENSIONS:
            known = ", ".join(AI_GW_GROUP_DIMENSIONS)
            raise AISecPayloadError(
                f"Unknown group dimension {dimension!r}; expected one of {known}"
            )
        return self._get(
            f"{AI_GW_GROUPS_PATH}/{dimension}",
            GroupListResponse,
            params=self._group_params(workspace_slug, days, start, end, columns),
        )

    def by_user(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> UserGroupResponse:
        """Requests and cost per end user.

        Not reachable through :meth:`group_by`: ``users`` returns the ``{success, data}``
        envelope while every other group endpoint returns ``{object, total, data[]}``.

        Returns:
            One record per user. ``user`` is ``''`` for calls made with no end-user id,
            which is not the same as an unknown user. Costs are in cents.
        """
        return self._get(
            f"{AI_GW_GROUPS_PATH}/{_GROUPS_USERS_SEGMENT}",
            UserGroupResponse,
            params=self._window_params(workspace_slug, days, start, end),
        )

    def by_status_code(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        columns: Sequence[str] | None = None,
    ) -> GroupListResponse:
        """Requests grouped by HTTP status code.

        Args:
            workspace_slug: Workspace to query.
            days: Rolling window size in days.
            start: Explicit window start.
            end: Explicit window end.
            columns: Extra columns, as on :meth:`group_by`.

        Returns:
            One row per status. **446 is an AIRS security block** -- cost 0, because the
            request never reached the LLM.

        Raises:
            AISecPayloadError: If any column is unrecognised.
        """
        return self._get(
            f"{AI_GW_GROUPS_PATH}/{_GROUPS_STATUS_CODE_SEGMENT}",
            GroupListResponse,
            params=self._group_params(workspace_slug, days, start, end, columns),
        )

    def logs(
        self,
        *,
        workspace_slug: str,
        days: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page_size: int | None = None,
        trace_id: str | None = None,
        status_code: int | None = None,
    ) -> GatewayLogsResponse:
        """Raw per-request log rows -- the deepest granularity this API offers.

        Upstream pagination is broken, which is why this method takes no offset: ``skip``,
        ``offset``, and ``page`` are all ignored, and an unfiltered call keeps returning
        the same most-recent batch of roughly fifty rows however you ask. Filtering by
        ``status_code`` bypasses that cap and returns every match in the window, so it is
        the only way to read past the first batch.

        Args:
            workspace_slug: Workspace to query.
            days: Rolling window size in days.
            start: Explicit window start.
            end: Explicit window end.
            page_size: Rows per response. The only pagination control that works.
            trace_id: Return the single row for one trace id.
            status_code: Filter by HTTP status; use 446 to pull every AIRS block.

        Returns:
            Log records plus the full-period ``total`` -- which you cannot page to.
        """
        params = self._window_params(workspace_slug, days, start, end)
        if page_size is not None:
            params["pageSize"] = str(page_size)
        if trace_id is not None:
            params["traceId"] = trace_id
        if status_code is not None:
            params["statusCode"] = str(status_code)
        return self._get(AI_GW_LOGS_PATH, GatewayLogsResponse, params=params)

    def _chart(self, metric: str, model: type[T], window: Mapping[str, str]) -> T:
        """Send one ``logs/charts/{metric}`` GET.

        Raises:
            AISecPayloadError: If ``metric`` is not a known slug. The slugs are bespoke
                and unguessable, so this catches a mistyped one here instead of as a 404.
        """
        if metric not in AI_GW_CHART_METRICS:
            raise AISecPayloadError(f"Unknown chart metric: {metric}")
        return self._get(f"{AI_GW_CHARTS_PATH}/{metric}", model, params=window)

    def _window_params(
        self,
        workspace_slug: str,
        days: int | None,
        start: datetime | None,
        end: datetime | None,
    ) -> dict[str, str]:
        """Build the four query parameters every telemetry endpoint requires.

        The tenant key is ``organisationId``, camelCase -- the admin-plane DELETEs in this
        module spell the same value ``organisation_id``.
        """
        resolved_end = end if end is not None else datetime.now().astimezone()
        window = DEFAULT_WINDOW_DAYS if days is None else days
        resolved_start = start if start is not None else resolved_end - timedelta(days=window)
        return {
            "organisationId": self._tsg_id,
            "workspaceSlug": workspace_slug,
            "timeOfGenerationMin": to_offset_iso(resolved_start),
            "timeOfGenerationMax": to_offset_iso(resolved_end),
        }

    def _group_params(
        self,
        workspace_slug: str,
        days: int | None,
        start: datetime | None,
        end: datetime | None,
        columns: Sequence[str] | None,
    ) -> dict[str, str]:
        """Build window parameters plus the comma-joined ``columns`` filter."""
        params = self._window_params(workspace_slug, days, start, end)
        if columns:
            unknown = [column for column in columns if column not in AI_GW_GROUP_COLUMNS]
            if unknown:
                known = ", ".join(AI_GW_GROUP_COLUMNS)
                raise AISecPayloadError(
                    f"Unknown group columns: {', '.join(unknown)}; expected any of {known}"
                )
            params["columns"] = ",".join(columns)
        return params


class AIGatewayIntegrationsClient(_AiGatewaySubClient):
    """Organisation-level provider integrations (admin plane)."""

    def list(self) -> ListIntegrationsResponse:
        """List organisation integrations.

        Returns:
            Every provider integration defined on the organisation.
        """
        return self._get(AI_GW_INTEGRATIONS_PATH, ListIntegrationsResponse)

    def get(self, integration_id: str) -> GatewayIntegration:
        """Fetch one integration.

        Args:
            integration_id: Integration UUID.

        Returns:
            The integration record.

        Raises:
            AISecPayloadError: If the id is not a UUID.
        """
        _assert_uuid(integration_id, "integration_id")
        return self._get(f"{AI_GW_INTEGRATIONS_PATH}/{integration_id}", GatewayIntegration)

    def create(
        self,
        *,
        organisation_id: str,
        ai_provider_id: str,
        name: str,
        slug: str,
        description: str | None = None,
        configurations: Mapping[str, Any] | None = None,
        key: str | None = None,
        secret_mappings: Sequence[Any] | None = None,
    ) -> GatewayWriteResponse:
        """Create an integration.

        ``key`` is a live provider secret. Setting ``PANW_AI_SEC_DEBUG`` prints the whole
        request body, unredacted, to the SDK's own debug log.

        Args:
            organisation_id: The TSG as a numeric string.
            ai_provider_id: Upstream AI provider UUID.
            name: Display name.
            slug: URL-safe identifier.
            description: Free-text description.
            configurations: Provider-specific settings, e.g. ``vertex_auth_type``.
            key: Provider API key, when the provider authenticates by key.
            secret_mappings: Provider-specific secret bindings; shape not modelled upstream.

        Returns:
            The raw create response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If ``ai_provider_id`` is not a UUID.
        """
        _assert_uuid(ai_provider_id, "ai_provider_id")
        body = _drop_unset(
            organisation_id=organisation_id,
            ai_provider_id=ai_provider_id,
            name=name,
            slug=slug,
            description=description,
            configurations=dict(configurations) if configurations is not None else None,
            key=key,
            secret_mappings=list(secret_mappings) if secret_mappings is not None else None,
        )
        return self._write("POST", AI_GW_INTEGRATIONS_PATH, body, GatewayWriteResponse)

    def update(
        self,
        integration_id: str,
        *,
        organisation_id: str | None = None,
        ai_provider_id: str | None = None,
        name: str | None = None,
        slug: str | None = None,
        description: str | None = None,
        configurations: Mapping[str, Any] | None = None,
        key: str | None = None,
        secret_mappings: Sequence[Any] | None = None,
    ) -> GatewayWriteResponse:
        """Update an integration.

        Every field is optional; only what you pass is sent, so an omitted field is left
        alone rather than nulled.

        Args:
            integration_id: Integration UUID.
            organisation_id: The TSG as a numeric string.
            ai_provider_id: Upstream AI provider UUID.
            name: Display name.
            slug: URL-safe identifier.
            description: Free-text description.
            configurations: Provider-specific settings.
            key: Provider API key. Debug logging prints it unredacted, as on :meth:`create`.
            secret_mappings: Provider-specific secret bindings.

        Returns:
            The raw update response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If ``integration_id`` or a supplied ``ai_provider_id`` is
                not a UUID.
        """
        _assert_uuid(integration_id, "integration_id")
        if ai_provider_id is not None:
            _assert_uuid(ai_provider_id, "ai_provider_id")
        body = _drop_unset(
            organisation_id=organisation_id,
            ai_provider_id=ai_provider_id,
            name=name,
            slug=slug,
            description=description,
            configurations=dict(configurations) if configurations is not None else None,
            key=key,
            secret_mappings=list(secret_mappings) if secret_mappings is not None else None,
        )
        return self._write(
            "PUT", f"{AI_GW_INTEGRATIONS_PATH}/{integration_id}", body, GatewayWriteResponse
        )

    def delete(self, integration_id: str, organisation_id: str) -> None:
        """Delete an integration.

        Args:
            integration_id: Integration UUID.
            organisation_id: The TSG as a numeric string, sent as the ``organisation_id``
                query parameter -- snake_case here, unlike the telemetry endpoints'
                ``organisationId``.

        Raises:
            AISecPayloadError: If either identifier is malformed.
        """
        _assert_uuid(integration_id, "integration_id")
        _assert_numeric_id(organisation_id, "organisation_id")
        self._delete(
            f"{AI_GW_INTEGRATIONS_PATH}/{integration_id}",
            params={"organisation_id": organisation_id},
        )

    def get_models(self, integration_id: str) -> GatewayIntegrationModelsResponse:
        """Read which models this integration exposes.

        Args:
            integration_id: Integration UUID.

        Returns:
            Per-model enablement plus the ``allow_all_models`` switch. Read the two
            together: ``models`` alone does not tell you what is reachable.

        Raises:
            AISecPayloadError: If the id is not a UUID.
        """
        _assert_uuid(integration_id, "integration_id")
        return self._get(
            f"{AI_GW_INTEGRATIONS_PATH}/{integration_id}/{_INTEGRATION_MODELS_SEGMENT}",
            GatewayIntegrationModelsResponse,
        )

    def set_models(
        self, integration_id: str, models: Sequence[GatewayIntegrationModel]
    ) -> GatewayWriteResponse:
        """Replace which models this integration exposes.

        Args:
            integration_id: Integration UUID.
            models: The full model list. This is a replace, not a merge -- anything omitted
                is dropped.

        Returns:
            The raw response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If the id is not a UUID.
        """
        _assert_uuid(integration_id, "integration_id")
        body = {
            "models": [model.model_dump(mode="json", by_alias=True) for model in models],
        }
        return self._write(
            "PUT",
            f"{AI_GW_INTEGRATIONS_PATH}/{integration_id}/{_INTEGRATION_MODELS_SEGMENT}",
            body,
            GatewayWriteResponse,
        )

    def get_workspaces(self, integration_id: str) -> GatewayIntegrationWorkspacesResponse:
        """Read which workspaces may use this integration.

        Args:
            integration_id: Integration UUID.

        Returns:
            Bound workspaces plus ``global_workspace_access``, which is an **object** here
            (``{enabled, rate_limits, usage_limits}``) despite the field name. The matching
            write, :meth:`set_workspaces`, sends a plain boolean; the two are not
            symmetric.

        Raises:
            AISecPayloadError: If the id is not a UUID.
        """
        _assert_uuid(integration_id, "integration_id")
        return self._get(
            f"{AI_GW_INTEGRATIONS_PATH}/{integration_id}/{_INTEGRATION_WORKSPACES_SEGMENT}",
            GatewayIntegrationWorkspacesResponse,
        )

    def set_workspaces(
        self,
        integration_id: str,
        *,
        workspaces: Sequence[Any] | None = None,
        global_workspace_access: bool | None = None,
    ) -> GatewayWriteResponse:
        """Replace which workspaces may use this integration.

        Args:
            integration_id: Integration UUID.
            workspaces: Workspace bindings; shape not modelled upstream.
            global_workspace_access: Grant every workspace access. A plain boolean on the
                way in, an object on the way back out -- see :meth:`get_workspaces`.

        Returns:
            The raw response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If the id is not a UUID.
        """
        _assert_uuid(integration_id, "integration_id")
        body = _drop_unset(
            workspaces=list(workspaces) if workspaces is not None else None,
            global_workspace_access=global_workspace_access,
        )
        return self._write(
            "PUT",
            f"{AI_GW_INTEGRATIONS_PATH}/{integration_id}/{_INTEGRATION_WORKSPACES_SEGMENT}",
            body,
            GatewayWriteResponse,
        )


class AIGatewayMcpIntegrationsClient(_AiGatewaySubClient):
    """MCP server integrations (admin plane)."""

    def list(self) -> ListMcpIntegrationsResponse:
        """List organisation MCP integrations.

        Returns:
            Every MCP server integration on the organisation. Note that each record's
            ``configurations`` is a JSON-encoded **string** on reads, not an object.
        """
        return self._get(AI_GW_MCP_INTEGRATIONS_PATH, ListMcpIntegrationsResponse)

    def create(
        self,
        *,
        name: str,
        organisation_id: str,
        slug: str,
        url: str,
        auth_type: str,
        transport: str,
        description: str | None = None,
        configurations: Mapping[str, Any] | None = None,
        secret_mappings: Sequence[Any] | None = None,
    ) -> GatewayWriteResponse:
        """Register an MCP server.

        Args:
            name: Display name.
            organisation_id: The TSG as a numeric string.
            slug: URL-safe identifier.
            url: MCP server URL.
            auth_type: e.g. ``none`` or ``bearer``.
            transport: e.g. ``http`` or ``sse``.
            description: Free-text description.
            configurations: Provider-specific settings. Sent as an object even though reads
                return it as a JSON string.
            secret_mappings: Provider-specific secret bindings; shape not modelled upstream.

        Returns:
            The raw create response. Shape unverified against a live tenant.
        """
        body = _drop_unset(
            name=name,
            organisation_id=organisation_id,
            slug=slug,
            url=url,
            auth_type=auth_type,
            transport=transport,
            description=description,
            configurations=dict(configurations) if configurations is not None else None,
            secret_mappings=list(secret_mappings) if secret_mappings is not None else None,
        )
        return self._write("POST", AI_GW_MCP_INTEGRATIONS_PATH, body, GatewayWriteResponse)

    def set_workspaces(
        self,
        mcp_integration_id: str,
        *,
        workspaces: Sequence[Any] | None = None,
        global_workspace_access: bool | None = None,
    ) -> GatewayWriteResponse:
        """Replace which workspaces may use this MCP integration.

        The payload shape is inferred from the sibling provider-integration endpoint and
        has not been confirmed against a live MCP-integrations tenant.

        Args:
            mcp_integration_id: MCP integration UUID.
            workspaces: Workspace bindings. This is a replace, not a merge.
            global_workspace_access: Grant every workspace access.

        Returns:
            The raw response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If the id is not a UUID.
        """
        _assert_uuid(mcp_integration_id, "mcp_integration_id")
        body = _drop_unset(
            workspaces=list(workspaces) if workspaces is not None else None,
            global_workspace_access=global_workspace_access,
        )
        return self._write(
            "PUT",
            f"{AI_GW_MCP_INTEGRATIONS_PATH}/{mcp_integration_id}/{_INTEGRATION_WORKSPACES_SEGMENT}",
            body,
            GatewayWriteResponse,
        )


class AIGatewayDeploymentsClient(_AiGatewaySubClient):
    """Gateway deployments (admin plane)."""

    def list(self) -> ListDeploymentsResponse:
        """List deployments.

        Returns:
            Every deployment, **active and archived** -- :meth:`delete` is a soft delete,
            so filter on ``status == 'active'`` if you only want live ones.
        """
        return self._get(AI_GW_DEPLOYMENTS_PATH, ListDeploymentsResponse)

    def get(self, deployment_id: str) -> GatewayDeploymentDetail:
        """Fetch one deployment.

        Args:
            deployment_id: Deployment UUID.

        Returns:
            Deployment detail, including bound workspaces and masked credentials. Note
            ``auth_settings.allow_all_workspaces`` comes back as 0/1, not a boolean, even
            though :meth:`create` accepts a real boolean for the same setting.

        Raises:
            AISecPayloadError: If the id is not a UUID.
        """
        _assert_uuid(deployment_id, "deployment_id")
        return self._get(f"{AI_GW_DEPLOYMENTS_PATH}/{deployment_id}", GatewayDeploymentDetail)

    def create(
        self,
        *,
        name: str,
        deployment_type: str,
        organisation_id: str,
        auth_settings: Mapping[str, Any] | None = None,
    ) -> GatewayDeploymentCreateResponse:
        """Create a deployment.

        The response is a **creation receipt**, not a deployment record: five fields, with
        no ``name``, ``slug``, or ``status``. Call :meth:`get` for the full record.

        This is the only time ``credentials.password`` and ``client_auth`` are readable --
        the detail read masks both. Capture them here or they are unrecoverable. Never log
        them; setting ``PANW_AI_SEC_DEBUG`` prints the raw response, password included, to
        the SDK's own debug log regardless of this warning.

        Args:
            name: Deployment name.
            deployment_type: ``production`` or ``non_production``. Sent as ``type``; the
                argument is renamed only because ``type`` shadows a builtin.
            organisation_id: The TSG as a numeric string -- **not** the organisation UUID
                that reads return.
            auth_settings: Auth settings, e.g. ``{"allow_all_workspaces": True}``. A real
                boolean here; reads return 0/1.

        Returns:
            The creation receipt, including the deployment's gateway credentials.
        """
        body = _drop_unset(
            name=name,
            type=deployment_type,
            organisation_id=organisation_id,
            auth_settings=dict(auth_settings) if auth_settings is not None else None,
        )
        return self._write("POST", AI_GW_DEPLOYMENTS_PATH, body, GatewayDeploymentCreateResponse)

    def delete(self, deployment_id: str, organisation_id: str) -> None:
        """Archive a deployment.

        This is a **soft delete** and the one exception to the gateway's usual delete
        semantics: the API answers 200 with an empty body and the record persists with
        ``status: 'archived'``, still visible in :meth:`list`. There is no observed hard
        delete for deployments. Configs, guardrails, and providers all hard-delete, so do
        not assume archive-on-delete is a gateway-wide convention.

        Args:
            deployment_id: Deployment UUID.
            organisation_id: The TSG as a numeric string, sent as the ``organisation_id``
                query parameter.

        Raises:
            AISecPayloadError: If either identifier is malformed.
        """
        _assert_uuid(deployment_id, "deployment_id")
        _assert_numeric_id(organisation_id, "organisation_id")
        self._delete(
            f"{AI_GW_DEPLOYMENTS_PATH}/{deployment_id}",
            params={"organisation_id": organisation_id},
        )


class AIGatewayPluginsClient(_AiGatewaySubClient):
    """Plugin bindings such as the Prisma AIRS scanner (admin plane)."""

    def list(self) -> ListPluginsResponse:
        """List organisation plugin bindings.

        Returns:
            Every plugin bound to the organisation, with credentials masked.
        """
        return self._get(AI_GW_PLUGINS_PATH, ListPluginsResponse)

    def create(
        self,
        *,
        organisation_id: str,
        integration_id: str,
        credentials: Mapping[str, str],
    ) -> GatewayWriteResponse:
        """Bind a plugin to the organisation.

        ``credentials`` holds live secrets (e.g. ``AIRS_API_KEY``). Setting
        ``PANW_AI_SEC_DEBUG`` prints them, unredacted, to the SDK's own debug log.

        Args:
            organisation_id: The TSG as a numeric string.
            integration_id: Plugin provider integration UUID, e.g. the ``panw-prisma-airs``
                provider.
            credentials: Provider-specific secrets. Never log this mapping.

        Returns:
            The raw create response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If ``integration_id`` is not a UUID.
        """
        _assert_uuid(integration_id, "integration_id")
        body = _drop_unset(
            organisation_id=organisation_id,
            integration_id=integration_id,
            credentials=dict(credentials),
        )
        return self._write("POST", AI_GW_PLUGINS_PATH, body, GatewayWriteResponse)


class AIGatewayOrganisationsClient(_AiGatewaySubClient):
    """Organisation and auth settings (admin plane)."""

    def get_self(self) -> OrganisationSelfResponse:
        """Fetch the calling organisation's settings.

        Returns:
            The organisation record, wrapped in ``{success, data}`` unlike the other admin
            resources.
        """
        return self._get(AI_GW_ORGANISATIONS_SELF_PATH, OrganisationSelfResponse)

    def update_self(self, body: Mapping[str, Any]) -> GatewayWriteResponse:
        """Update the calling organisation's settings.

        Args:
            body: Replacement fields. Left free-form because the upstream contract is not
                published for this endpoint.

        Returns:
            The raw update response. Shape unverified against a live tenant.
        """
        return self._write("PUT", AI_GW_ORGANISATIONS_SELF_PATH, dict(body), GatewayWriteResponse)

    def get_auth_settings(self, tsg_id: str) -> AuthSettingsResponse:
        """Fetch an organisation's auth settings.

        The response includes a ``scim_token`` -- a live secret. Never log the returned
        object; setting ``PANW_AI_SEC_DEBUG`` prints it unredacted to the SDK's own debug
        log regardless, since debug logging only sanitises header values.

        Args:
            tsg_id: The TSG as a numeric string, not a UUID.

        Returns:
            Auth settings, including domains and the SCIM token.

        Raises:
            AISecPayloadError: If the TSG is not numeric.
        """
        _assert_numeric_id(tsg_id, "tsg_id")
        return self._get(ai_gw_organisations_auth_settings_path(tsg_id), AuthSettingsResponse)

    def update_auth_settings(self, tsg_id: str, body: Mapping[str, Any]) -> GatewayWriteResponse:
        """Update an organisation's auth settings.

        Args:
            tsg_id: The TSG as a numeric string, not a UUID.
            body: Replacement fields, e.g. ``{"domains": ["acme.com"]}``.

        Returns:
            The raw update response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If the TSG is not numeric.
        """
        _assert_numeric_id(tsg_id, "tsg_id")
        return self._write(
            "PUT",
            ai_gw_organisations_auth_settings_path(tsg_id),
            dict(body),
            GatewayWriteResponse,
        )


class AIGatewayAuditLogsClient(_AiGatewaySubClient):
    """Organisation audit logs (admin plane)."""

    def list(self, *, start: datetime, end: datetime) -> GatewayAuditLogsResponse:
        """Read organisation audit logs.

        **Handle the result as sensitive.** Each entry's ``request_body`` comes back
        **unredacted**, so records for credential-bearing calls (integrations, plugins) can
        contain live secrets -- private keys, provider API keys -- in plaintext. The
        sibling ``request_headers`` field is masked; ``request_body`` is not. The SDK
        returns the response faithfully rather than altering it, so never log these records
        wholesale and never forward them to a third-party sink. Setting
        ``PANW_AI_SEC_DEBUG`` prints the raw response, secrets included, regardless of this
        warning.

        Args:
            start: Inclusive window start. Required -- this endpoint has no default window.
            end: Inclusive window end.

        Returns:
            Audit records, newest first.
        """
        return self._get(
            AI_GW_AUDIT_LOGS_PATH,
            GatewayAuditLogsResponse,
            # Z-suffixed UTC, unlike every telemetry endpoint in this module, which
            # rejects that spelling with AB01.
            params={"start_time": to_utc_iso_z(start), "end_time": to_utc_iso_z(end)},
        )


class AIGatewayAdminClient:
    """AI Gateway organisation administration, plus the runtime telemetry beside it.

    Resolves one OAuth2 service account from ``PANW_AI_GW_*``, falling back to
    ``PANW_MGMT_*``, and shares it across both planes. Every request carries the tenant
    header as well as the bearer token; omitting ``x-tsg-id`` produces a 403 OPA denial
    that looks exactly like an expired token.

    Example:
        >>> client = AIGatewayAdminClient()
        >>> client.integrations.list().total
        3.0
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        tsg_id: str | None = None,
        data_endpoint: str | None = None,
        admin_endpoint: str | None = None,
        token_endpoint: str | None = None,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        credentials = resolve_credentials(
            primary_env_prefix=ENV_PREFIX_AI_GW,
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            token_endpoint=token_endpoint,
            fallback_env_prefix=ENV_PREFIX_MGMT,
        )
        self._data_endpoint = (
            data_endpoint or os.environ.get(ENV_AI_GW_DATA_ENDPOINT) or DEFAULT_AI_GW_DATA_ENDPOINT
        )
        self._admin_endpoint = (
            admin_endpoint
            or os.environ.get(ENV_AI_GW_ADMIN_ENDPOINT)
            or DEFAULT_AI_GW_ADMIN_ENDPOINT
        )
        self._num_retries = _validate_retries(num_retries)
        self._owns_client = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)

        self._oauth = OAuthClient(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            tsg_id=credentials.tsg_id,
            token_endpoint=credentials.token_endpoint,
            http_client=self._http,
            timeout=timeout,
        )
        # The tenant header wraps the bearer adapter rather than replacing it, so token
        # refresh still works. Every AI Gateway endpoint requires both.
        auth: AuthAdapter = TsgHeaderAuth(OAuthAuth(self._oauth), credentials.tsg_id)

        def on_admin_plane(client: type[SubClientT]) -> SubClientT:
            return client(
                base_url=self._admin_endpoint,
                auth=auth,
                http_client=self._http,
                num_retries=self._num_retries,
            )

        # Telemetry is the one client here that reads the data plane.
        self.telemetry = AIGatewayTelemetryClient(
            base_url=self._data_endpoint,
            auth=auth,
            http_client=self._http,
            tsg_id=credentials.tsg_id,
            num_retries=self._num_retries,
        )
        self.integrations = on_admin_plane(AIGatewayIntegrationsClient)
        self.mcp_integrations = on_admin_plane(AIGatewayMcpIntegrationsClient)
        self.deployments = on_admin_plane(AIGatewayDeploymentsClient)
        self.plugins = on_admin_plane(AIGatewayPluginsClient)
        self.organisations = on_admin_plane(AIGatewayOrganisationsClient)
        self.audit_logs = on_admin_plane(AIGatewayAuditLogsClient)

    @property
    def data_endpoint(self) -> str:
        """Base URL for the data plane, which telemetry reads."""
        return self._data_endpoint

    @property
    def admin_endpoint(self) -> str:
        """Base URL for the admin plane, which every other client here reads."""
        return self._admin_endpoint

    @property
    def tsg_id(self) -> str:
        """The tenant every request in this client is scoped to."""
        return self._oauth.tsg_id

    def close(self) -> None:
        """Close the underlying HTTP client, if this instance created it."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> AIGatewayAdminClient:
        """Enter a context that closes the HTTP client on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the HTTP client if this instance owns it."""
        self.close()
