"""Models for the Prisma AIRS AI Gateway API.

Derived from live responses against TSG 1852583913 on 2026-07-27, not from an OpenAPI spec
(none exists for this API). Schema rationale, landmines, and the full endpoint inventory
live in ``PRD-ai-gateway-client.md`` in the Obsidian vault.

Conventions specific to this API:
    * ``cost`` values are in CENTS. Nothing in this module divides them.
    * Booleans arrive as 0/1 integers on many records, so those fields are numbers rather
      than ``bool``.
    * Fields observed null on a live tenant are modelled nullable, not optional: the key is
      required and its value may be ``None``. A missing key is a real shape change and
      should fail loudly.

Nothing here is shared with :mod:`prisma_airs.models.scan` -- the gateway subsystem has no
overlap with the runtime scan API's detection reports, metadata, or tool events.
"""

from __future__ import annotations

from typing import Annotated, Any, Generic, TypeVar

from pydantic import Field

from prisma_airs.models.base import AirsModel

DataT = TypeVar("DataT")
ItemT = TypeVar("ItemT")


# ---------------------------------------------------------------------------
# Envelopes -- three distinct families
# ---------------------------------------------------------------------------


class _AiGatewayEnvelope(AirsModel, Generic[DataT]):
    """Envelope A: ``{success, data}`` -- telemetry charts and the bare ``logs`` collection.

    Module-private like its two siblings: it is only ever applied within this module, and
    exporting it would put an internal factory on the package's public API surface. The
    concrete responses below subclass it instead.
    """

    success: bool
    data: DataT


class _AiGatewayList(AirsModel, Generic[ItemT]):
    """Envelope B: ``{object, total, data[]}`` -- config and admin collections."""

    object: str
    total: float
    has_more: bool | None = None
    data: list[ItemT]


class _AiGatewayGroupList(AirsModel, Generic[ItemT]):
    """Envelope C: ``logs/groups/*``.

    ``is_quota_exceeded`` is snake_case on the wire here and camelCase on every envelope-A
    payload, so this one carries no alias. Feeding it a camelCase payload fails, which is
    the intent: the two envelopes are not interchangeable.
    """

    object: str
    is_quota_exceeded: bool
    total: float
    data: list[ItemT]


class _QuotaFlagged(AirsModel):
    """Mixin for envelope-A telemetry payloads, which all carry the quota flag.

    Split out because it is the one field every chart, the users group, and the raw log
    payload share.
    """

    #: camelCase on the wire here; envelope C spells the same flag snake_case.
    is_quota_exceeded: Annotated[bool, Field(alias="isQuotaExceeded")]


# ---------------------------------------------------------------------------
# Shared limit policies
# ---------------------------------------------------------------------------


class GatewayUsageLimit(AirsModel):
    """One usage-limit policy, attached to workspaces and to integration bindings.

    Every field is optional. The upstream contract defines ``credit_limit``, ``type``,
    ``alert_threshold``, ``periodic_reset``, ``periodic_reset_days`` and
    ``next_usage_reset_at``, but a live tenant also returns server-side bookkeeping the
    spec omits (``id``, ``status``, ``current_usage``, ``is_exhausted_alerts_sent``,
    ``is_threshold_alerts_sent``). Those survive in ``model_extra``, and full optionality
    means a partial policy from either side still parses.
    """

    credit_limit: float | None = None
    type: str | None = None
    alert_threshold: float | None = None
    periodic_reset: str | None = None
    periodic_reset_days: float | None = None
    next_usage_reset_at: str | None = None


class GatewayRateLimit(AirsModel):
    """One rate-limit policy: ``type`` requests|tokens, ``unit`` rpd|rph|rpm, ``value``.

    The value sets are left as free strings rather than enums; upstream adds units without
    a version bump and a closed enum would turn that into a client-side outage.
    """

    type: str | None = None
    unit: str | None = None
    value: float | None = None


#: ``usage_limits`` as it actually appears on the wire: an **array** of policy objects,
#: or ``null``.
#:
#: Originally modelled as ``record | null``, because the tenant the schemas were derived
#: from had ``null`` for every occurrence and the array form was never observed -- which
#: made ``workspaces.get()`` throw AISEC_RESPONSE_VALIDATION against any workspace that
#: actually had limits configured (issue #211). The object form is retained because
#: dropping it would be a gratuitous breaking change for any tenant or endpoint that does
#: return one, and it costs nothing.
UsageLimits = list[GatewayUsageLimit] | dict[str, Any] | None

#: ``rate_limits`` on the wire. Same array-or-object-or-null history as :data:`UsageLimits`.
RateLimits = list[GatewayRateLimit] | dict[str, Any] | None


# ---------------------------------------------------------------------------
# Telemetry -- charts
# ---------------------------------------------------------------------------


class GatewayChartRecord(AirsModel):
    """A ``{x, y}`` time bucket, optionally carrying a bucket average."""

    x: str
    y: float
    avg: float | None = None


class CostChartData(_QuotaFlagged):
    """``logs/charts/cost`` payload. Both ``records[].y`` and ``total`` are in CENTS."""

    records: list[GatewayChartRecord]
    total: float
    avg: float


class CostChartResponse(_AiGatewayEnvelope[CostChartData]):
    """``logs/charts/cost``."""


class CountChartData(_QuotaFlagged):
    """Plain per-bucket counts. ``total`` is nullable but never absent."""

    records: list[GatewayChartRecord]
    total: float | None


class CountChartResponse(_AiGatewayEnvelope[CountChartData]):
    """``logs/charts/{requests,errors,users,feedback-trend,feedback-weighted}``."""


class LatencyChartRecord(AirsModel):
    """One latency bucket. Percentiles are milliseconds."""

    x: str
    y: float
    p50: float
    p90: float
    p99: float


class LatencyChartData(_QuotaFlagged):
    """Latency payload. Percentiles appear per-bucket AND at top level; milliseconds."""

    records: list[LatencyChartRecord]
    total: float
    p50: float
    p90: float
    p99: float


class LatencyChartResponse(_AiGatewayEnvelope[LatencyChartData]):
    """``logs/charts/latency``."""


class TokensChartRecord(AirsModel):
    """One token bucket, split into request and response units."""

    x: str
    y: float
    total_request_units: float
    total_response_units: float
    avg: float


class TokensChartData(_QuotaFlagged):
    """Token payload. The request/response unit splits appear at both levels."""

    records: list[TokensChartRecord]
    total: float
    avg: float
    total_request_units: float
    total_response_units: float


class TokensChartResponse(_AiGatewayEnvelope[TokensChartData]):
    """``logs/charts/tokens``."""


class CacheSummary(AirsModel):
    """Cache effectiveness over the queried window."""

    cache_hits: Annotated[float, Field(alias="cacheHits")]
    #: ``None`` when there were no hits to average over -- distinct from a genuine zero.
    avg_cache_latency: Annotated[float | None, Field(alias="avgCacheLatency")]
    total_requests: Annotated[float, Field(alias="totalRequests")]
    cache_speedup: Annotated[float, Field(alias="cacheSpeedup")]


class CacheSummaryData(_QuotaFlagged):
    """``logs/charts/cache-summary`` payload."""

    summary: CacheSummary


class CacheSummaryResponse(_AiGatewayEnvelope[CacheSummaryData]):
    """``logs/charts/cache-summary``."""


class CacheHitTrendPoint(AirsModel):
    """One cache-hit bucket.

    The two ``cumulative_*_savings`` figures are CUMULATIVE cents across the window, not
    per-bucket deltas: read the last non-zero bucket for the window total rather than
    summing the series.
    """

    x: str
    simple_hits: Annotated[float, Field(alias="simpleHits")]
    semantic_hits: Annotated[float, Field(alias="semanticHits")]
    hit_rate: Annotated[float, Field(alias="hitRate")]
    cumulative_simple_hit_savings: Annotated[float, Field(alias="cumulativeSimpleHitSavings")]
    cumulative_semantic_hit_savings: Annotated[float, Field(alias="cumulativeSemanticHitSavings")]


class CacheHitTrendSummary(AirsModel):
    """Window totals accompanying a cache-hit trend."""

    total_cache_hits: Annotated[float, Field(alias="totalCacheHits")]
    hit_rate: Annotated[float, Field(alias="hitRate")]


class CacheHitTrendData(_QuotaFlagged):
    """``logs/charts/cache-hit-trend`` payload."""

    trend: list[CacheHitTrendPoint]
    total: float
    summary: CacheHitTrendSummary


class CacheHitTrendResponse(_AiGatewayEnvelope[CacheHitTrendData]):
    """``logs/charts/cache-hit-trend``."""


class UserTrendsSummary(AirsModel):
    """User activity totals. ``avg`` is requests-per-user, not requests-per-bucket."""

    total: float
    unique: float
    avg: float


class UserTrendsData(_QuotaFlagged):
    """``logs/charts/user-trends`` payload."""

    summary: UserTrendsSummary
    trend: list[GatewayChartRecord]


class UserTrendsResponse(_AiGatewayEnvelope[UserTrendsData]):
    """``logs/charts/user-trends``."""


class ErrorTrendsSummary(AirsModel):
    """Error rate for the window, as a percentage."""

    error_percent: Annotated[float, Field(alias="errorPercent")]


class ErrorTrendsData(_QuotaFlagged):
    """``logs/charts/error-trends`` payload. ``trend[].y`` is a percentage, not a count."""

    summary: ErrorTrendsSummary
    trend: list[GatewayChartRecord]


class ErrorTrendsResponse(_AiGatewayEnvelope[ErrorTrendsData]):
    """``logs/charts/error-trends``."""


class RescuedRetriesPoint(AirsModel):
    """One rescued-retry bucket.

    ``y`` is an ARRAY, not a scalar, so this cannot share :class:`GatewayChartRecord`. The
    element shape is unobserved -- sample tenants only ever produced an empty array -- so
    elements stay untyped until a tenant with real gateway retries confirms it. See the
    open questions in ``PRD-ai-gateway-client.md``.
    """

    x: str
    y: list[Any]


class RescuedRetriesTrendPoint(AirsModel):
    """One bucket of the parallel ``trends`` series. Element shapes unobserved, as above."""

    x: str
    retry: list[Any]
    fallback: list[Any]


class RescuedRetriesData(_QuotaFlagged):
    """``logs/charts/rescued-retries`` payload. Sparse: only populated on upstream failures."""

    trend: list[RescuedRetriesPoint]
    total: float
    trends: list[RescuedRetriesTrendPoint]
    retry_total: Annotated[float, Field(alias="retryTotal")]
    fallback_total: Annotated[float, Field(alias="fallbackTotal")]


class RescuedRetriesResponse(_AiGatewayEnvelope[RescuedRetriesData]):
    """``logs/charts/rescued-retries``."""


class FeedbackScoreRecord(AirsModel):
    """One feedback bucket: ``x`` is the score, ``y`` the count. Feedback is binary +/-5."""

    x: float
    y: float


class FeedbackScoreDistributionData(_QuotaFlagged):
    """``logs/charts/feedback-score-distribution`` payload."""

    records: list[FeedbackScoreRecord]
    total: float | None


class FeedbackScoreDistributionResponse(_AiGatewayEnvelope[FeedbackScoreDistributionData]):
    """``logs/charts/feedback-score-distribution``."""


class FeedbackModelScore(AirsModel):
    """Aggregate feedback for one model."""

    avg_weighted_feedback: Annotated[float, Field(alias="avgWeightedFeedback")]
    feedback_count: Annotated[float, Field(alias="feedbackCount")]


class FeedbackModelRecord(AirsModel):
    """``x`` is the model; ``y`` is an object here, not a number as on every other chart."""

    x: str
    y: FeedbackModelScore


class FeedbackModelsData(_QuotaFlagged):
    """``logs/charts/feedback-models`` payload. Carries no ``total``."""

    records: list[FeedbackModelRecord]


class FeedbackModelsResponse(_AiGatewayEnvelope[FeedbackModelsData]):
    """``logs/charts/feedback-models``."""


# ---------------------------------------------------------------------------
# Telemetry -- groups
# ---------------------------------------------------------------------------


class GatewayGroupRow(AirsModel):
    """One ``logs/groups/{dimension}`` row.

    The dimension key itself varies by endpoint (``model``, ``ai_service``, ``api_key``,
    ``provider``, ``status_code``), so only the shared columns are declared; the dimension
    key arrives through ``model_extra``.
    """

    requests: float
    #: Cents.
    cost: float | None = None
    avg_latency: float | None = None
    avg_tokens: float | None = None
    total_tokens: float | None = None
    success_rate: float | None = None
    last_seen: str | None = None
    object: str


class GroupListResponse(_AiGatewayGroupList[GatewayGroupRow]):
    """``logs/groups/{ai_service,model,api_key,provider,status_code}``."""


class UserGroupRecord(AirsModel):
    """One ``logs/groups/users`` row.

    Wire name for :attr:`user` is ``_user``, which cannot be a Python attribute name --
    pydantic reserves leading underscores for private attributes -- hence the alias. An
    empty string means calls made with no end-user id, not an unknown user.
    """

    user: Annotated[str, Field(alias="_user")]
    count: float
    #: Cents.
    cost: float


class UserGroupData(_QuotaFlagged):
    """``logs/groups/users`` payload."""

    records: list[UserGroupRecord]
    total: float


class UserGroupResponse(_AiGatewayEnvelope[UserGroupData]):
    """``logs/groups/users`` -- envelope A while every sibling group endpoint uses envelope C.

    Not a typo; verified live.
    """


# ---------------------------------------------------------------------------
# Telemetry -- raw logs
# ---------------------------------------------------------------------------


class GatewayLogRecord(AirsModel):
    """One per-request row from the bare ``logs`` collection.

    The deepest granularity the gateway exposes; everything else is an aggregate over these.
    """

    id: str
    workspace_slug: str
    ai_model: str
    #: Wire name ``_user``; see :class:`UserGroupRecord` for why it is aliased.
    user: Annotated[str, Field(alias="_user")]
    total_units: float
    #: Cents.
    cost: float
    trace_id: str
    #: 0/1, not a boolean. :attr:`proxied` does the comparison.
    is_proxy_call: float
    created_at: str
    #: 0/1, not a boolean. :attr:`succeeded` does the comparison.
    is_success: float
    #: ``HIT`` | ``MISS`` | ``DISABLED``, left as a free string so a new mode cannot
    #: break parsing.
    cache_status: str
    retry_success_count: float
    mode: str
    last_used_option_index: float
    #: 200 success, 446 AIRS security block (cost 0), 400 validation.
    response_status_code: float
    request_url: str
    request_method: str
    ai_org: str
    api_key_id: str
    license_id: str
    log_store_file_path_format: str
    metadata_key: Annotated[list[str], Field(alias="metadataKey")]
    metadata_value: Annotated[list[str], Field(alias="metadataValue")]
    prompt_slug: str
    feedback: list[Any]

    @property
    def succeeded(self) -> bool:
        """Whether the request succeeded, reading the 0/1 integer as a boolean."""
        return self.is_success == 1

    @property
    def proxied(self) -> bool:
        """Whether the request went through the proxy, reading the 0/1 integer as a boolean."""
        return self.is_proxy_call == 1


class GatewayLogsData(_QuotaFlagged):
    """Bare ``logs`` payload.

    ``captured_total`` is always 0 upstream; ``total`` is the full-period count, so page
    against ``total``.
    """

    records: list[GatewayLogRecord]
    total: float
    captured_total: Annotated[float, Field(alias="capturedTotal")]


class GatewayLogsResponse(_AiGatewayEnvelope[GatewayLogsData]):
    """The bare ``logs`` collection."""


# ---------------------------------------------------------------------------
# Write responses
# ---------------------------------------------------------------------------


class GatewayWriteResponse(AirsModel):
    """Placeholder for write responses whose shape has NOT been verified against a live tenant.

    Verifying ``deployments``, ``configs``, ``guardrails``, and ``providers`` create
    responses proved every create returns a minimal receipt rather than the record it
    creates -- never inferable from the corresponding read. See
    :class:`GatewayDeploymentCreateResponse`, :class:`GatewayConfigCreateResponse`,
    :class:`GatewayGuardrailCreateResponse`, and :class:`GatewayProviderCreateResponse` for
    the four now-verified receipts. This placeholder still covers every remaining unverified
    write (all ``update()`` PUT responses, plus ``api-keys``/``integrations``/
    ``mcp-integrations``/``workspaces``/``plugins`` create responses). Tighten each into a
    named model as it is verified; the body is reachable through ``model_extra`` until then.
    See ``PRD-ai-gateway-client.md`` "Testing".
    """


# ---------------------------------------------------------------------------
# Workspaces (data plane)
# ---------------------------------------------------------------------------


class GatewayWorkspace(AirsModel):
    """A workspace list row.

    ``scope_name`` is the SCM role scope that grants data-plane access.
    """

    id: str
    slug: str
    name: str
    icon: str | None
    #: Null for a workspace created without one, and upstream declares it nullable.
    #: Observed on an archived workspace (#213).
    description: str | None
    created_at: str
    last_updated_at: str
    #: 0/1, not a boolean.
    is_default: float
    status: str
    scope_name: str
    object: str


class GatewayWorkspaceDetail(AirsModel):
    """Workspace detail. Carries settings blocks absent from list rows."""

    id: str
    name: str
    #: Nullable -- see :class:`GatewayWorkspace`.
    description: str | None
    created_at: str
    last_updated_at: str
    #: 0/1, not a boolean.
    is_default: float
    slug: str
    icon: str | None
    defaults: dict[str, Any] | None
    usage_limits: UsageLimits
    rate_limits: RateLimits
    security_settings: dict[str, bool] | None = None
    data_plane_security_settings: dict[str, Any] | None = None
    settings: dict[str, Any] | None = None
    #: Lifecycle state, and it DIVERGES from the list row: ``list()`` reports ``'active'``
    #: for a workspace whose ``get()`` reports ``None`` (observed live 2026-08-01). Prefer
    #: the list value, or treat ``None`` here as "unknown", never as "inactive".
    status: str | None = None


class GatewayWorkspaceCreateResponse(AirsModel):
    """``POST /ai_gw/admin/v2/workspaces`` response -- verified live 2026-08-01.

    The exception to this subsystem's "receipt, not record" write pattern.
    ``configs.create()``, ``guardrails.create()``, ``providers.create()``, and
    ``deployments.create()`` each return a 4-5 field receipt; workspace create returns most
    of the record instead.

    It is still not the full detail shape -- ``status``, ``is_default``, ``icon``,
    ``usage_limits``, ``rate_limits``, and the settings blocks are all absent -- so call
    ``get()`` when those matter. Conversely ``users`` appears here and nowhere else.
    """

    id: str
    name: str
    slug: str
    description: str | None
    created_at: str
    last_updated_at: str
    scope_name: str
    object: str
    defaults: dict[str, Any] | None = None
    #: Seeded workspace members. Present on create only.
    users: list[Any] | None = None


class ListWorkspacesResponse(_AiGatewayList[GatewayWorkspace]):
    """``GET /workspaces``."""


# ---------------------------------------------------------------------------
# Configs (data plane)
# ---------------------------------------------------------------------------


class GatewayConfig(AirsModel):
    """A gateway config LIST row -- 12 fields.

    The list read (``GET /configs?workspace_id=``) returns a strict subset of the detail
    read: it does NOT carry ``config``, ``format``, ``type``, or ``version_id``. See
    :class:`GatewayConfigDetail`, and :class:`GatewayDeployment` /
    :class:`GatewayDeploymentDetail` for the same split already established for deployments.
    """

    id: str
    name: str
    slug: str
    #: Internal organisation UUID -- NOT the TSG that write requests take.
    organisation_id: str
    #: 0/1, not a boolean.
    is_default: float
    status: str
    owner_id: str
    updated_by: str
    created_at: str
    last_updated_at: str
    workspace_id: str
    object: str


class ListConfigsResponse(_AiGatewayList[GatewayConfig]):
    """``GET /configs?workspace_id=``."""


class GatewayConfigDetail(GatewayConfig):
    """Config detail (``GET /configs/{id}``) -- the list row plus four fields.

    ``config`` is a JSON-encoded STRING, not an object. The wire type is preserved rather
    than silently parsed, so call ``json.loads(detail.config)`` at the call site. Same
    request/response asymmetry as ``mcp-integrations.configurations``; see
    :class:`McpIntegration`.
    """

    config: str
    format: str
    type: str
    version_id: str


class GatewayConfigCreateResponse(AirsModel):
    """``POST /configs`` response -- a 4-field creation receipt.

    Not a :class:`GatewayConfig` or :class:`GatewayConfigDetail`. Verified live 2026-07-28
    (create -> read -> delete cycle), confirming that the "create returns a receipt, not the
    record" pattern first established for :class:`GatewayDeploymentCreateResponse` also
    holds for configs. Call ``get()`` for the full record.
    """

    id: str
    version_id: str
    slug: str
    object: str


# ---------------------------------------------------------------------------
# Guardrails (data plane) -- list row, detail, and create receipt, verified live
# ---------------------------------------------------------------------------


class GatewayGuardrail(AirsModel):
    """A guardrail LIST row (``GET /guardrails?workspace_id=``).

    It does NOT carry ``checks``, ``actions``, or ``version_id``; see
    :class:`GatewayGuardrailDetail` for those. Verified live 2026-07-28.
    """

    id: str
    name: str
    slug: str
    organisation_id: str
    status: str
    owner_id: str
    updated_by: str | None
    created_at: str
    last_updated_at: str
    workspace_id: str
    object: str


class ListGuardrailsResponse(_AiGatewayList[GatewayGuardrail]):
    """``GET /guardrails?workspace_id=``."""


class GuardrailFeedback(AirsModel):
    """The feedback datum recorded by an ``on_success``/``on_fail`` action."""

    value: float
    weight: float
    metadata: str


class GuardrailFeedbackAction(AirsModel):
    """One ``on_success``/``on_fail`` feedback action."""

    feedback: GuardrailFeedback


class GuardrailCheck(AirsModel):
    """One check within a guardrail."""

    #: e.g. ``panw-prisma-airs.intercept``, the Prisma AIRS intercept check.
    id: str
    parameters: dict[str, Any]
    is_enabled: bool


class GuardrailActions(AirsModel):
    """What the gateway does when a guardrail's checks resolve."""

    deny: bool
    #: Wire name ``async``, which is a Python keyword; the trailing underscore is the only
    #: reason this one is renamed.
    async_: Annotated[bool, Field(alias="async")]
    sequential: bool
    #: Absent entirely when the guardrail was created without a pass/fail feedback action.
    on_success: GuardrailFeedbackAction | None = None
    on_fail: GuardrailFeedbackAction | None = None


class GatewayGuardrailDetail(GatewayGuardrail):
    """Guardrail detail (``GET /guardrails/{id}``).

    Adds ``checks``, ``actions``, and ``version_id`` on top of the list row. Verified live
    2026-07-28.
    """

    checks: list[GuardrailCheck]
    actions: GuardrailActions
    version_id: str


class GatewayGuardrailCreateResponse(AirsModel):
    """``POST /guardrails`` response -- a 4-field creation receipt.

    Not a :class:`GatewayGuardrail` or :class:`GatewayGuardrailDetail`. Verified live
    2026-07-28. Same receipt pattern as :class:`GatewayConfigCreateResponse`.
    """

    id: str
    version_id: str
    slug: str
    object: str


# ---------------------------------------------------------------------------
# Providers (data plane)
# ---------------------------------------------------------------------------


class GatewayProvider(AirsModel):
    """A workspace-scoped AI provider binding."""

    id: str
    name: str | None = None
    slug: str | None = None
    object: str | None = None


class ListProvidersResponse(_AiGatewayList[GatewayProvider]):
    """``GET /providers?workspace_id=``."""


class GatewayProviderCreateResponse(AirsModel):
    """``POST /providers`` response -- a 3-field creation receipt, not a :class:`GatewayProvider`.

    Verified live 2026-07-28. There is NO ``version_id``, unlike its
    :class:`GatewayConfigCreateResponse` and :class:`GatewayGuardrailCreateResponse`
    siblings. Do not add one speculatively -- if a tenant ever returns it, it lands in
    ``model_extra`` and the field can be declared then.
    """

    id: str
    slug: str
    object: str


# ---------------------------------------------------------------------------
# API keys (data plane)
# ---------------------------------------------------------------------------


class GatewayApiKey(AirsModel):
    """A service or user API key. The secret itself is only ever returned at creation."""

    id: str
    name: str | None = None
    object: str | None = None


class ListApiKeysResponse(_AiGatewayList[GatewayApiKey]):
    """``GET /api-keys?workspace_id=``."""


# ---------------------------------------------------------------------------
# Integrations (admin plane)
# ---------------------------------------------------------------------------


class GatewayIntegration(AirsModel):
    """An organisation-level provider integration."""

    id: str
    organisation_id: str | None = None
    name: str
    owner_id: str
    status: str
    created_at: str
    last_updated_at: str
    slug: str
    #: Shape unobserved: null on every tenant sampled.
    tags: Any = None
    description: str | None
    workspaces_count: float | None = None
    type: str | None = None
    workspace_id: str | None
    ai_provider_id: str
    object: str


class ListIntegrationsResponse(_AiGatewayList[GatewayIntegration]):
    """``GET /integrations``."""


class GatewayIntegrationModel(AirsModel):
    """Per-model enablement for one integration."""

    slug: str
    enabled: bool


class GatewayIntegrationModelsResponse(AirsModel):
    """``integrations/{id}/models`` -- per-model enablement for one integration.

    Both the per-model flags and the ``allow_all_models`` switch are returned; read them
    together rather than concluding anything from ``models`` alone.
    """

    models: list[GatewayIntegrationModel]
    allow_all_models: bool
    object: str


class GatewayIntegrationWorkspace(AirsModel):
    """One workspace bound to an integration.

    ``usage_limits``, ``rate_limits``, and ``last_reset_at`` are observed null on a healthy
    tenant, which is why all three are nullable rather than optional.
    """

    id: str
    usage_limits: UsageLimits
    rate_limits: RateLimits
    enabled: bool
    status: str
    created_at: str
    last_updated_at: str
    last_reset_at: str | None


class GatewayGlobalWorkspaceAccess(AirsModel):
    """``integrations/{id}/workspaces.global_workspace_access``.

    An OBJECT, not a boolean, despite the field name. The request side of the same endpoint
    does send a plain boolean here; only the response is an object.
    """

    enabled: bool
    rate_limits: RateLimits
    usage_limits: UsageLimits


class GatewayIntegrationWorkspacesResponse(AirsModel):
    """``integrations/{id}/workspaces`` -- which workspaces may use this integration."""

    workspaces: list[GatewayIntegrationWorkspace]
    global_workspace_access: GatewayGlobalWorkspaceAccess
    object: str


class McpIntegration(AirsModel):
    """An MCP server integration."""

    id: str
    organisation_id: str
    name: str
    owner_id: str
    status: str
    type: str
    url: str
    auth_type: str
    transport: str
    #: JSON-encoded STRING on reads -- the same request/response asymmetry as
    #: ``configs.config`` (see :class:`GatewayConfigDetail`). The create request sends an
    #: object; this is the read shape, so ``json.loads`` it at the call site.
    configurations: str
    created_at: str
    last_updated_at: str


class ListMcpIntegrationsResponse(_AiGatewayList[McpIntegration]):
    """``GET /mcp-integrations``."""


# ---------------------------------------------------------------------------
# Deployments (admin plane) -- three distinct shapes, verified live
# ---------------------------------------------------------------------------


class GatewayDeploymentCredentials(AirsModel):
    """Basic-auth credentials for a deployment.

    Deliberately NOT hidden from ``repr``: on :class:`GatewayDeploymentCreateResponse` this
    is the one and only chance to read the password, and printing the receipt is the
    intended way to capture it. On the detail read the password arrives masked anyway.
    """

    username: str
    password: str


class GatewayDeploymentAuthSettings(AirsModel):
    """Which workspaces may authenticate against a deployment."""

    #: 0/1, not a boolean -- the create REQUEST sends a real boolean for the same setting.
    disable_portkey_gateway: float
    workspaces_allowed: list[str]
    #: 0/1, not a boolean.
    allow_all_workspaces: float


class GatewayDeploymentWorkspaceRef(AirsModel):
    """A workspace bound to a deployment, by id and slug."""

    id: str
    slug: str


class GatewayDeployment(AirsModel):
    """A deployment list row."""

    id: str
    name: str
    slug: str
    type: str
    #: ``active`` | ``archived``. DELETE archives rather than removes.
    status: str
    created_at: str
    last_updated_at: str
    last_synced_at: str | None
    last_resynced_at: str | None
    #: 0/1, not a boolean.
    is_default: float
    created_by: str
    object: str


class GatewayDeploymentDetail(GatewayDeployment):
    """Deployment detail -- adds credentials (masked), auth settings, and bound workspaces."""

    credentials: GatewayDeploymentCredentials | None = None
    deployment_config: dict[str, Any] | None
    auth_settings: GatewayDeploymentAuthSettings | None = None
    client_auth: str | None = None
    workspaces: list[GatewayDeploymentWorkspaceRef] | None = None


class GatewayDeploymentCreateResponse(AirsModel):
    """``POST /deployments`` response -- a 5-field creation receipt.

    Not a :class:`GatewayDeployment`. Verified live 2026-07-27.

    This is the ONLY time ``credentials.password`` and ``client_auth`` are readable; the
    detail read masks them. Capture them at creation or they are unrecoverable.
    """

    id: str
    client_auth: str
    credentials: GatewayDeploymentCredentials
    #: Internal organisation UUID -- NOT the TSG sent in the request.
    organisation_id: str
    object: str


class ListDeploymentsResponse(_AiGatewayList[GatewayDeployment]):
    """``GET /deployments``."""


# ---------------------------------------------------------------------------
# Plugins / organisations / audit logs (admin plane)
# ---------------------------------------------------------------------------


class GatewayPlugin(AirsModel):
    """A gateway plugin binding (e.g. the Prisma AIRS scanner). Credentials arrive masked."""

    id: str
    integration_id: str
    credentials: dict[str, str]
    owner_id: str
    created_at: str
    last_updated_at: str
    status: str
    integration_slug: str
    plugin_provider_id: str
    plugin_provider_slug: str
    object: str


class ListPluginsResponse(_AiGatewayList[GatewayPlugin]):
    """``GET /plugins``."""


class OrganisationSelfResponse(_AiGatewayEnvelope[dict[str, Any]]):
    """``organisations/self``. Wrapped in ``{success, data}`` unlike the other admin resources."""


class AuthSettingsResponse(_AiGatewayEnvelope[dict[str, Any]]):
    """``organisations/{tsg}/auth-settings``."""


class GatewayAuditLogRecord(AirsModel):
    """One audit-log record.

    SECURITY: ``request_body`` is returned UNREDACTED by the API and can contain live
    credentials (private keys, API keys) submitted through the SCM UI. The sibling
    ``request_headers`` field IS masked. Never log this record wholesale.

    ``request_body`` is therefore excluded from ``repr``, so an incidental ``print(record)``
    or an exception traceback cannot spill it. The value is untouched and still reachable
    through the attribute and through ``model_dump()`` -- this guards the accidental path
    only, not a deliberate dump.
    """

    timestamp: str
    method: str
    uri: str
    request_id: str
    request_body: Annotated[str, Field(repr=False)]
    query_params: str
    #: Masked upstream, unlike :attr:`request_body`.
    request_headers: str
    user_id: str
    user_type: str
    organisation_id: str
    workspace_id: str
    response_status_code: float
    resource_type: str
    action: str
    client_ip: str
    country: str


class GatewayAuditLogsResponse(AirsModel):
    """``audit-logs`` -- a bare ``{records}`` object, neither list envelope."""

    records: list[GatewayAuditLogRecord]
