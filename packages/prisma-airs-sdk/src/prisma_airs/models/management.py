"""Request and response models for the Prisma AIRS management API.

Covers security profiles, custom topics, API keys, customer apps, DLP data profiles,
deployment profiles, the SCM dashboard, scan logs, and the OAuth token exchange.

Much of the security-profile policy arrives with kebab-case keys on the wire
(``model-configuration``, ``data-protection``, ``log-severity``). Those fields carry a
``Field(alias=...)`` so the Python attribute stays snake_case; ``populate_by_name`` on
:class:`~prisma_airs.models.base.AirsModel` means either spelling is accepted on input.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import ConfigDict, Field, model_validator

from prisma_airs.models.base import AirsModel

# ---------------------------------------------------------------------------
# Shared bases
# ---------------------------------------------------------------------------


class _AllowsModelPrefix(AirsModel):
    """Base for models whose wire contract uses ``model_``-prefixed field names.

    Pydantic below 2.10 -- still inside this package's supported range -- defaults
    ``protected_namespaces`` to ``("model_",)`` and warns on import for every such field.
    The names here are dictated by the API (``model-type``, ``model-configuration``,
    ``model-protection``, ``model_name``), so the guard is switched off rather than the
    fields renamed. Pydantic merges config down the MRO, so ``extra="allow"`` and
    ``populate_by_name`` from :class:`~prisma_airs.models.base.AirsModel` still apply.
    """

    model_config = ConfigDict(protected_namespaces=())


class _MessageResponse(AirsModel):
    """Base for management DELETE responses that may arrive as a bare JSON string.

    AIRS management answers a successful DELETE with a JSON-encoded plain string --
    ``"successfully deleted profileId: <id>"`` -- despite sending
    ``Content-Type: application/json``. Modelling those responses with the resource
    schema (as the TypeScript SDK originally did for customer apps) made every delete
    fail response validation even though the resource was gone.

    Both shapes are accepted and the string form is normalised to ``{"message": ...}``
    so callers always see an object.
    """

    @model_validator(mode="before")
    @classmethod
    def _accept_a_bare_string(cls, value: Any) -> Any:
        if isinstance(value, str):
            return {"message": value}
        return value


# ---------------------------------------------------------------------------
# Security profile policy -- leaf schemas
# ---------------------------------------------------------------------------


class PolicyLatency(AirsModel):
    """Inline latency budget and what to do when the budget is exceeded."""

    inline_timeout_action: Annotated[str | None, Field(alias="inline-timeout-action")] = None
    max_inline_latency: Annotated[float | None, Field(alias="max-inline-latency")] = None


class DataLeakDetectionMember(AirsModel):
    """One DLP data profile referenced by a data-leak-detection rule."""

    text: str
    id: str | None = None
    version: str | None = None


class DatabaseSecurityItem(AirsModel):
    """One database-security rule and the action it takes."""

    name: str
    action: str


class DataLeakDetection(AirsModel):
    """Data-leak-detection rule: which DLP profiles apply and what happens on a match.

    ``member`` is marked required and non-nullable by the upstream OpenAPI, but the API
    returns ``null`` for it on some profiles, so a missing or null value is accepted
    here rather than failing an otherwise valid profile.
    """

    member: list[DataLeakDetectionMember] | None = None
    action: str
    mask_data_inline: Annotated[bool | None, Field(alias="mask-data-inline")] = None


class DataProtection(AirsModel):
    """Data-protection section of a model configuration: DLP plus database security.

    ``database-security`` is absent from the upstream OpenAPI but the API does return
    it. It is modelled here until the spec catches up -- dropping it would silently
    discard live policy content.
    """

    data_leak_detection: Annotated[DataLeakDetection | None, Field(alias="data-leak-detection")] = (
        None
    )
    database_security: Annotated[
        list[DatabaseSecurityItem] | None, Field(alias="database-security")
    ] = None


class UrlCategory(AirsModel):
    """A URL-category bucket, holding the category names it covers."""

    member: list[str] | None = None


class MaliciousCodeProtection(AirsModel):
    """Malicious-code detection rule and the action it takes."""

    name: str
    action: str


class PolicyAppProtection(AirsModel):
    """App-protection section of a model configuration: URL filtering and code detection."""

    alert_url_category: Annotated[UrlCategory | None, Field(alias="alert-url-category")] = None
    block_url_category: Annotated[UrlCategory | None, Field(alias="block-url-category")] = None
    allow_url_category: Annotated[UrlCategory | None, Field(alias="allow-url-category")] = None
    default_url_category: Annotated[UrlCategory | None, Field(alias="default-url-category")] = None
    url_detected_action: Annotated[str | None, Field(alias="url-detected-action")] = None
    malicious_code_protection: Annotated[
        MaliciousCodeProtection | None, Field(alias="malicious-code-protection")
    ] = None


class TopicObject(AirsModel):
    """A reference to a custom topic, pinned to a specific revision."""

    topic_name: str
    topic_id: str
    revision: float


class TopicArray(AirsModel):
    """One allow or block bucket of a topic guardrail.

    ``topic`` is required but nullable: when a bucket holds no topics the API serialises
    ``"topic": null`` rather than ``[]``. The upstream OpenAPI marks it required and
    non-nullable -- a known divergence, verified against a live
    ``/v1/mgmt/profiles/tsg`` response.
    """

    action: str
    topic: list[TopicObject] | None


class ModelProtectionItem(AirsModel):
    """One model-protection guardrail, optionally scoped to a set of topic buckets."""

    name: str
    action: str
    topic_list: Annotated[list[TopicArray] | None, Field(alias="topic-list")] = None
    options: list[Any] | None = None


class AgentProtectionItem(AirsModel):
    """One agent-protection rule and the action it takes."""

    name: str
    action: str


class DlpRule(AirsModel):
    """A DLP rule slot (``rule1``/``rule2``) carrying the action to take on a match."""

    action: str | None = None


class DlpDataProfilePolicy(AirsModel):
    """A DLP data profile as embedded in a security profile policy.

    Differs from the standalone :class:`DlpDataProfile` returned by the DLP profile list
    endpoint only by carrying a ``description``.
    """

    name: str
    uuid: str
    id: str | None = None
    version: str | None = None
    description: str | None = None
    rule1: DlpRule | None = None
    rule2: DlpRule | None = None
    log_severity: Annotated[str | None, Field(alias="log-severity")] = None
    non_file_based: Annotated[str | None, Field(alias="non-file-based")] = None
    file_based: Annotated[str | None, Field(alias="file-based")] = None


# ---------------------------------------------------------------------------
# Security profile policy -- composite schemas
# ---------------------------------------------------------------------------


class ModelConfiguration(_AllowsModelPrefix):
    """All protection and latency settings for one AI security profile entry."""

    mask_data_in_storage: Annotated[bool | None, Field(alias="mask-data-in-storage")] = None
    latency: PolicyLatency | None = None
    data_protection: Annotated[DataProtection | None, Field(alias="data-protection")] = None
    app_protection: Annotated[PolicyAppProtection | None, Field(alias="app-protection")] = None
    model_protection: Annotated[
        list[ModelProtectionItem] | None, Field(alias="model-protection")
    ] = None
    agent_protection: Annotated[
        list[AgentProtectionItem] | None, Field(alias="agent-protection")
    ] = None


class AiSecurityProfile(_AllowsModelPrefix):
    """One AI security profile entry within a policy, scoped by model and content type."""

    model_type: Annotated[str | None, Field(alias="model-type")] = None
    content_type: Annotated[str | None, Field(alias="content-type")] = None
    model_configuration: Annotated[
        ModelConfiguration | None, Field(alias="model-configuration")
    ] = None


class Policy(AirsModel):
    """The policy body of a security profile."""

    ai_security_profiles: Annotated[
        list[AiSecurityProfile] | None, Field(alias="ai-security-profiles")
    ] = None
    dlp_data_profiles: Annotated[
        list[DlpDataProfilePolicy] | None, Field(alias="dlp-data-profiles")
    ] = None


# ---------------------------------------------------------------------------
# Security profiles
# ---------------------------------------------------------------------------


class SecurityProfile(AirsModel):
    """An AIRS security profile with its policy and audit metadata.

    ``profile_name`` is the only guaranteed field: the scan API accepts a profile by
    name as well as by ID, so a profile that has not been assigned an ID yet is still
    usable.
    """

    profile_id: str | None = None
    profile_name: str
    csp_id: str | None = None
    tsg_id: str | None = None
    revision: float | None = None
    active: bool | None = None
    policy: Policy | None = None
    created_by: str | None = None
    updated_by: str | None = None
    last_modified_ts: str | None = None


class CreateSecurityProfileRequest(AirsModel):
    """Request body for creating or updating a security profile.

    Structurally identical to :class:`SecurityProfile`: the API takes the whole resource
    back on update, including server-assigned fields such as ``revision``.
    """

    profile_id: str | None = None
    profile_name: str
    csp_id: str | None = None
    tsg_id: str | None = None
    revision: float | None = None
    active: bool | None = None
    policy: Policy | None = None
    created_by: str | None = None
    updated_by: str | None = None
    last_modified_ts: str | None = None


class SecurityProfileListResponse(AirsModel):
    """A page of security profiles.

    ``next_offset`` is absent on the last page; its presence is the only signal that
    more pages exist.
    """

    ai_profiles: list[SecurityProfile]
    next_offset: float | None = None


class DeleteProfileResponse(_MessageResponse):
    """Acknowledgement that a security profile was deleted."""

    message: str


class DeleteProfileConflictItem(AirsModel):
    """One policy still referencing the profile that could not be deleted."""

    policy_id: str
    policy_name: str
    priority: float


class DeleteProfileConflict(AirsModel):
    """409 body listing the policies that still reference the profile.

    The payload names the blockers so the caller can detach them rather than guess.
    """

    message: str
    payload: list[DeleteProfileConflictItem]


# ---------------------------------------------------------------------------
# Custom topics
# ---------------------------------------------------------------------------


class CustomTopic(AirsModel):
    """A custom topic used by topic-guardrail policy.

    ``description`` and ``examples`` are required on the response because they are what
    the classifier matches against -- a topic without them cannot guard anything.
    """

    topic_id: str | None = None
    topic_name: str
    revision: float
    active: bool | None = None
    description: str
    examples: list[str]
    created_by: str | None = None
    updated_by: str | None = None
    last_modified_ts: str | None = None
    created_ts: str | None = None


class CreateCustomTopicRequest(AirsModel):
    """Request body for creating or updating a custom topic.

    Looser than :class:`CustomTopic`: only ``topic_name`` is required, since the server
    fills in ``revision`` and the audit fields, and an update may send a partial body.
    """

    topic_id: str | None = None
    topic_name: str
    revision: float | None = None
    active: bool | None = None
    description: str | None = None
    examples: list[str] | None = None
    created_by: str | None = None
    updated_by: str | None = None
    last_modified_ts: str | None = None
    created_ts: str | None = None


class CustomTopicListResponse(AirsModel):
    """A page of custom topics."""

    custom_topics: list[CustomTopic]
    next_offset: float | None = None


class DeleteTopicResponse(_MessageResponse):
    """Acknowledgement that a custom topic was deleted."""

    message: str


class DeleteTopicConflictItem(AirsModel):
    """One security profile still referencing the topic that could not be deleted."""

    profile_id: str
    profile_name: str
    revision: float


class DeleteTopicConflict(AirsModel):
    """409 body listing the security profiles that still reference the topic."""

    message: str
    payload: list[DeleteTopicConflictItem]


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


class ApiKey(AirsModel):
    """An AIRS API key record.

    The secret itself (``api_key``) is only ever populated on create and regenerate --
    list and get responses carry ``api_key_last8`` instead, which is what the console
    displays.
    """

    api_key_id: str
    api_key_last8: str
    api_key_name: str | None = None
    auth_code: str
    csp_id: str | None = None
    tsg_id: str | None = None
    expiration: str
    revoked: bool
    revoke_reason: str | None = None
    cust_app: str | None = None
    cust_env: str | None = None
    cust_ai_agent_framework: str | None = None
    cust_cloud_provider: str | None = None
    created_by: str | None = None
    updated_by: str | None = None
    last_modified_ts: str | None = None
    rotation_time_interval: float | None = None
    rotation_time_unit: str | None = None
    dp_name: str | None = None
    status: str | None = None
    api_key: str | None = None
    lic_expiration: str | None = None
    avg_text_records: float | None = None
    creation_ts: str | None = None
    customer_app_id: Annotated[str | None, Field(alias="customer_appId")] = None


class ApiKeyCreateRequest(AirsModel):
    """Request body for minting a new API key.

    ``revoked`` is required and ordinarily ``False``; the field exists because the API
    reuses the key record shape for creation.
    """

    dp_name: str | None = None
    auth_code: str
    cust_app: str
    cust_env: str | None = None
    cust_cloud_provider: str | None = None
    cust_ai_agent_framework: str | None = None
    revoked: bool
    created_by: str
    api_key_name: str
    rotation_time_interval: float
    rotation_time_unit: str


class ApiKeyRegenerateRequest(AirsModel):
    """Request body for rotating an existing API key."""

    rotation_time_interval: float
    rotation_time_unit: str
    updated_by: str | None = None


class ApiKeyListResponse(AirsModel):
    """A page of API keys."""

    api_keys: list[ApiKey] | None = None
    next_offset: float | None = None


class ApiKeyDeleteResponse(_MessageResponse):
    """Acknowledgement that an API key was deleted.

    ``message`` is optional here, unlike the profile and topic deletes, because the
    object form of this response has been observed without it.
    """

    message: str | None = None


# ---------------------------------------------------------------------------
# Customer applications
# ---------------------------------------------------------------------------


class ApiKeyDPInfo(AirsModel):
    """An API key paired with the deployment profile it was minted against."""

    api_key_name: str
    dp_name: str
    auth_code: str


class CustomerApp(_AllowsModelPrefix):
    """A registered customer application."""

    customer_app_id: Annotated[str | None, Field(alias="customer_appId")] = None
    tsg_id: str
    app_name: str
    model_name: str | None = None
    cloud_provider: str
    environment: str
    status: str | None = None
    created_by: str | None = None
    updated_by: str | None = None
    ai_agent_framework: str | None = None


class CustomerAppWithKeys(_AllowsModelPrefix):
    """A customer application as returned by the list endpoint, with its API keys.

    ``customer_appId`` is required here (unlike on :class:`CustomerApp`) because the
    list endpoint only ever returns persisted apps, which always carry an ID.
    """

    customer_app_id: Annotated[str, Field(alias="customer_appId")]
    tsg_id: str
    app_name: str
    model_name: str | None = None
    cloud_provider: str
    environment: str
    ai_agent_framework: str | None = None
    api_keys_dp_info: list[ApiKeyDPInfo] | None = None


class CustomerAppListResponse(AirsModel):
    """A page of customer applications."""

    customer_apps: list[CustomerAppWithKeys] | None = None
    next_offset: float | None = None


class CustomerAppDeleteResponse(_MessageResponse):
    """Acknowledgement that a customer app and its associated keys were deleted."""

    message: str


# ---------------------------------------------------------------------------
# DLP data profiles
# ---------------------------------------------------------------------------


class DlpDataProfile(AirsModel):
    """A DLP data profile as returned by the DLP profile list endpoint.

    ``uuid`` is the identifier a security profile references; ``id`` is a separate
    numeric-ish handle and is not interchangeable with it.
    """

    name: str
    uuid: str
    id: str | None = None
    version: str | None = None
    rule1: DlpRule | None = None
    rule2: DlpRule | None = None
    log_severity: Annotated[str | None, Field(alias="log-severity")] = None
    non_file_based: Annotated[str | None, Field(alias="non-file-based")] = None
    file_based: Annotated[str | None, Field(alias="file-based")] = None


class DlpProfileListResponse(AirsModel):
    """The DLP data profiles available to the tenant."""

    dlp_profiles: list[DlpDataProfile] | None = None


# ---------------------------------------------------------------------------
# Deployment profiles
# ---------------------------------------------------------------------------


class DeploymentProfileEntry(AirsModel):
    """One deployment profile that API keys can be minted against."""

    dp_name: str
    auth_code: str
    tsg_id: str | None = None
    status: str | None = None
    expiration_date: str | None = None
    #: Wire name is ``ave_text_records``, not ``avg_`` -- the upstream typo is load-bearing.
    ave_text_records: float | None = None


class DeploymentProfilesResponse(AirsModel):
    """The deployment profiles visible to the tenant, plus the lookup status."""

    deployment_profiles: list[DeploymentProfileEntry]
    status: str


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class TokenStats(AirsModel):
    """Token consumption for an application over the requested window.

    The API returns a numeric value paired with a scale qualifier (``K`` for thousands,
    ``M`` for millions); both are needed to reconstruct the value the SCM panel shows.
    """

    average_daily_tokens: float | None = None
    average_daily_tokens_scale: str | None = None
    monthly_total_tokens: float | None = None
    monthly_total_tokens_scale: str | None = None


class ViolationSeverityCounts(AirsModel):
    """Severity-bucketed counts, shared by session stats and per-detector breakdowns."""

    critical: float | None = None
    high: float | None = None
    medium: float | None = None
    low: float | None = None
    total: float | None = None


class DashboardSessionStats(AirsModel):
    """Session activity for an application over the requested window."""

    total: float | None = None
    violating: float | None = None
    violation_breakdown: ViolationSeverityCounts | None = None
    last_session_id: str | None = None
    most_recent_session_time: str | None = None


class DashboardApplication(AirsModel):
    """Per-application overview powering SCM's "API Applications" detail panel.

    The history window is 30 days, the API's maximum. ``appname`` is required on the
    request: omitting it returns a body whose fields are all null rather than an error,
    so an all-null instance usually means a malformed query, not an idle application.
    """

    id: str | None = None
    name: str | None = None
    cloud: str | None = None
    source: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    profiles: list[str] | None = None
    token_stats: TokenStats | None = None
    session_stats: DashboardSessionStats | None = None


class DetectorViolationBreakdownEntry(AirsModel):
    """Severity counts for a single detector.

    ``detection_type`` values observed live (2026-05-28): ``agent_security``,
    ``contextual_grounding``, ``dbs`` (database security), ``dlp``, ``malicious_code``,
    ``pi`` (prompt injection), ``source_code``, ``tc`` (toxic content),
    ``topic_guardrails``, ``uf`` (URL filtering). The detector set evolves, so this stays
    a plain string rather than an enum -- additions must parse without an SDK release.
    """

    detection_type: str | None = None
    violation_breakdown: ViolationSeverityCounts | None = None


class DashboardApplicationViolationBreakdown(AirsModel):
    """Per-application violation counts, detector by detector."""

    detection_type_violation_breakdown: list[DetectorViolationBreakdownEntry] | None = None
    total_violating: float | None = None


class DashboardApplicationSessionsBucket(AirsModel):
    """One time bucket of session activity inside an applications-overview item.

    The exact bucket shape varies with the requested ``time_unit``/``time_interval``
    combination, so every field is optional.
    """

    bucket_number: float | None = None
    date: str | None = None
    total: float | None = None
    violated: float | None = None


class DashboardApplicationsOverviewItem(AirsModel):
    """One application entry in the applications-overview response.

    The dashboard buckets traffic by the literal ``metadata.app_name`` value that scan
    payloads actually sent, so a single registered customer-app can appear here as
    several items -- one per distinct scan-payload name.

    ``id`` is the registered ``customer_appId`` UUID (it matches
    ``CustomerApp.customer_app_id``); ``name`` is the scan-payload value, which may
    differ from ``CustomerApp.app_name`` when the integration overrides it. Correlating
    on ``name`` alone will therefore mis-attribute traffic.
    """

    id: str | None = None
    name: str | None = None
    cloud: str | None = None
    source: str | None = None
    created_at: str | None = None
    sessions: list[DashboardApplicationSessionsBucket] | None = None
    sessions_total: float | None = None
    sessions_violated: float | None = None


class DashboardPagination(AirsModel):
    """Pagination metadata on the applications-overview response."""

    limit: float | None = None
    skip: float | None = None
    total_items: float | None = None


class DashboardApplicationsOverview(AirsModel):
    """Response from the dashboard applications-overview endpoint.

    Each item is one dashboard bucket. Enumerate the buckets here, then fetch each
    ``(item.id, item.name)`` pair as a :class:`DashboardApplication` to get its
    ``token_stats`` -- the overview does not carry token data itself.
    """

    items: list[DashboardApplicationsOverviewItem] | None = None
    pagination: DashboardPagination | None = None


# ---------------------------------------------------------------------------
# Scan logs
# ---------------------------------------------------------------------------


class ScanResultEntry(_AllowsModelPrefix):
    """One scanned transaction as it appears in the scan-logs view.

    The verdict fields are flattened three ways: ``*_final_verdict`` is the combined
    result for a detector, while ``prompt_*`` and ``response_*`` carry the per-direction
    result. A detector can be benign on the prompt and malicious on the response, so the
    final verdict is not derivable from either direction alone.
    """

    csp_id: str
    tsg_id: str
    scan_id: str
    scan_sub_req_id: float
    api_key_name: str
    app_name: str
    tokens: float
    text_records: float
    transaction_id: str | None = None
    profile_id: str | None = None
    profile_name: str | None = None
    model_name: str | None = None
    user: str | None = None
    environment: str | None = None
    cloud_provider: str | None = None
    agent_framework: str | None = None
    report_id: str | None = None
    received_ts: str | None = None
    completed_ts: str | None = None
    status: str | None = None
    verdict: str | None = None
    action: str | None = None
    is_prompt: bool | None = None
    is_response: bool | None = None

    # Combined per-detector verdicts.
    pi_final_verdict: str | None = None
    uf_final_verdict: str | None = None
    dlp_final_verdict: str | None = None
    dbs_final_verdict: str | None = None
    tc_final_verdict: str | None = None
    mc_final_verdict: str | None = None
    agent_final_verdict: str | None = None
    cg_final_verdict: str | None = None
    tg_final_verdict: str | None = None

    # Prompt-side verdicts and actions.
    prompt_pi_verdict: str | None = None
    prompt_uf_verdict: str | None = None
    prompt_dlp_verdict: str | None = None
    prompt_tc_verdict: str | None = None
    prompt_mc_verdict: str | None = None
    prompt_agent_verdict: str | None = None
    prompt_tg_verdict: str | None = None
    prompt_verdict: str | None = None
    prompt_pi_action: str | None = None
    prompt_uf_action: str | None = None
    prompt_dlp_action: str | None = None
    prompt_tc_action: str | None = None
    prompt_mc_action: str | None = None
    prompt_agent_action: str | None = None
    prompt_tg_action: str | None = None

    # Response-side verdicts and actions.
    response_uf_verdict: str | None = None
    response_dlp_verdict: str | None = None
    response_dbs_verdict: str | None = None
    response_tc_verdict: str | None = None
    response_mc_verdict: str | None = None
    response_agent_verdict: str | None = None
    response_cg_verdict: str | None = None
    response_tg_verdict: str | None = None
    response_uf_action: str | None = None
    response_dlp_action: str | None = None
    response_dbs_action: str | None = None
    response_tc_action: str | None = None
    response_mc_action: str | None = None
    response_agent_action: str | None = None
    response_cg_action: str | None = None
    response_tg_action: str | None = None
    response_verdict: str | None = None

    #: Bitmask of the detection services that ran; the named verdict fields are authoritative.
    detection_service_flags: float | None = None
    content_masked: bool | None = None
    user_ip: str | None = None


class ScanResultForDashboard(AirsModel):
    """Scan-log rows plus the aggregate counters the dashboard renders above them."""

    text_records_count: float | None = None
    api_calls_count: float | None = None
    threats_count: float | None = None
    all_transactions_count: float | None = None
    benign_transaction_count: float | None = None
    scan_result_entries: list[ScanResultEntry] | None = None


class PaginatedScanResults(AirsModel):
    """A page of scan-log results.

    ``page_token`` drives the cursor; ``page_number`` and ``total_pages`` are display
    values and are not a reliable way to walk the result set.
    """

    scan_result_for_dashboard: ScanResultForDashboard | None = None
    total_pages: float | None = None
    page_number: float | None = None
    page_size: float | None = None
    page_token: str | None = None
    revision: float | None = None


# ---------------------------------------------------------------------------
# OAuth
# ---------------------------------------------------------------------------


class ClientIdAndCustomerApp(AirsModel):
    """Request body binding an OAuth client to a customer application."""

    client_id: str
    customer_app: str


class Oauth2Token(AirsModel):
    """An OAuth2 token record from the management API.

    ``expires_in`` is a string on the wire, not a number, so callers must convert it
    before doing arithmetic on the lifetime.

    Not to be confused with :class:`prisma_airs.models.shared.OAuthTokenResponse`, which
    is what the auth endpoint returns when the SDK acquires a token, and which types
    ``expires_in`` as a number. Both are correct for their own endpoint; picking the
    wrong one produces a validation error on that field alone, which is a confusing way
    to discover the mix-up.
    """

    token_type: str | None = None
    issued_at: str | None = None
    client_id: str | None = None
    access_token: str
    expires_in: str | None = None
    status: str | None = None
