"""Request and response models for the AI Red Teaming API.

Covers the data plane (jobs, attacks, reports, goals, streams), the management plane
(targets, custom target adapters, prompt sets, properties, EULA, licensing), and the
network broker channel API.

Two schemas are renamed from the TypeScript source so they do not shadow a name that
already means something else in Python: ``ValidationError`` becomes
:class:`RedTeamValidationError` and ``HTTPValidationError`` becomes
:class:`RedTeamHttpValidationError`. Both would otherwise collide with
``pydantic.ValidationError`` at any import site that also catches validation failures.
The wire shape is unchanged.

Adapter and target schemas track mp-openapi 0.7.67 (Adapters service).
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Final, TypeAlias

from pydantic import AfterValidator, ConfigDict, Field

from prisma_airs.models.base import AirsModel, WireEnum

# ---------------------------------------------------------------------------
# Shared constraints
# ---------------------------------------------------------------------------

#: Upstream ceiling on adapter names and adapter variable keys.
MAX_ADAPTER_NAME_LENGTH: Final = 255
MAX_ADAPTER_VAR_KEY_LENGTH: Final = 255

_UUID_RE: Final = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)


def _require_uuid(value: str) -> str:
    """Reject anything that is not a canonical 8-4-4-4-12 UUID.

    Applied to *request* fields only. The service answers a malformed identifier with a
    generic 400 that does not name the offending field, so catching it here is the
    difference between a useful error and a scavenger hunt.

    Response models deliberately keep these same identifiers as plain :class:`str`: a
    tenant that starts returning a differently shaped id must not make every response in
    the SDK unparseable. Strict outbound, tolerant inbound.

    Raises ``ValueError`` rather than an SDK error so Pydantic wraps it into a
    ``ValidationError`` that names the field. SDK errors belong to client calls.
    """
    if not _UUID_RE.match(value):
        raise ValueError("must be a UUID")
    return value


#: A UUID-validated string, for request payloads. See :func:`_require_uuid`.
UuidStr: TypeAlias = Annotated[str, AfterValidator(_require_uuid)]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ApiEndpointType(WireEnum):
    """How a target's endpoint is reachable, which decides whether a broker is needed."""

    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    NETWORK_BROKER = "NETWORK_BROKER"


class AttackStatus(WireEnum):
    """Attack lifecycle status."""

    INIT = "INIT"
    ATTACK = "ATTACK"
    DETECTION = "DETECTION"
    REPORT = "REPORT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class AttackType(WireEnum):
    """Attack type classification."""

    NORMAL = "NORMAL"
    CUSTOM = "CUSTOM"


class AuthType(WireEnum):
    """Databricks authentication mode. Distinct from :class:`TargetAuthType`."""

    OAUTH = "OAUTH"
    ACCESS_TOKEN = "ACCESS_TOKEN"  # noqa: S105 - the name of a mode, not a credential


class TargetAuthType(WireEnum):
    """Authentication scheme used when calling a target. Distinct from :class:`AuthType`."""

    HEADERS = "HEADERS"
    BASIC_AUTH = "BASIC_AUTH"
    OAUTH2 = "OAUTH2"


class BasicAuthLocation(WireEnum):
    """Where basic-auth credentials are placed on the outbound request."""

    HEADER = "HEADER"
    PAYLOAD = "PAYLOAD"


class BrandSubCategory(WireEnum):
    """Brand risk subcategories."""

    COMPETITOR_ENDORSEMENTS = "COMPETITOR_ENDORSEMENTS"
    BRAND_TARNISHING_SELF_CRITICISM = "BRAND_TARNISHING_SELF_CRITICISM"
    DISCRIMINATING_CLAIMS = "DISCRIMINATING_CLAIMS"
    POLITICAL_ENDORSEMENTS = "POLITICAL_ENDORSEMENTS"


class ChannelStatus(WireEnum):
    """Network broker channel lifecycle status.

    :attr:`Channel.status` is intentionally *not* typed as this enum -- see that class.
    """

    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    DRAFT = "DRAFT"


class ComplianceSubCategory(WireEnum):
    """Compliance frameworks a report can be mapped against."""

    OWASP = "OWASP"
    MITRE_ATLAS = "MITRE_ATLAS"
    NIST = "NIST"
    DASF_V2 = "DASF_V2"


class CountedQuotaEnum(WireEnum):
    """Whether a scan has been charged against the tenant's quota.

    ``HELD`` is a reservation, not a charge: an aborted job releases it.
    """

    HELD = "HELD"
    COUNTED = "COUNTED"
    NOT_COUNTED = "NOT_COUNTED"


class DateRangeFilter(WireEnum):
    """Date range filter for dashboard queries."""

    LAST_7_DAYS = "LAST_7_DAYS"
    LAST_15_DAYS = "LAST_15_DAYS"
    LAST_30_DAYS = "LAST_30_DAYS"
    ALL = "ALL"


class ErrorSource(WireEnum):
    """Which subsystem produced an error log entry."""

    TARGET = "TARGET"
    JOB = "JOB"
    SYSTEM = "SYSTEM"
    VALIDATION = "VALIDATION"
    TARGET_PROFILING = "TARGET_PROFILING"


class RedTeamErrorType(WireEnum):
    """Red Team error classification.

    Prefixed ``RedTeam`` to avoid colliding with the SDK's own error taxonomy.
    """

    CONTENT_FILTER = "CONTENT_FILTER"
    RATE_LIMIT = "RATE_LIMIT"
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK = "NETWORK"
    VALIDATION = "VALIDATION"
    NETWORK_CHANNEL = "NETWORK_CHANNEL"
    UNKNOWN = "UNKNOWN"


class FileFormat(WireEnum):
    """Report download file format."""

    CSV = "CSV"
    JSON = "JSON"
    ALL = "ALL"


class GoalType(WireEnum):
    """Dynamic scan goal type."""

    BASE = "BASE"
    TOOL_MISUSE = "TOOL_MISUSE"
    GOAL_MANIPULATION = "GOAL_MANIPULATION"


class GoalTypeQueryParam(WireEnum):
    """Goal filter accepted on list endpoints. Not the same set as :class:`GoalType`."""

    AGENT = "AGENT"
    HUMAN_AUGMENTED = "HUMAN_AUGMENTED"


class GuardrailAction(WireEnum):
    """Guardrail action for a recommended runtime security policy."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class JobStatus(WireEnum):
    """Red team scan job status."""

    INIT = "INIT"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETE = "PARTIALLY_COMPLETE"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class JobStatusFilter(WireEnum):
    """Job statuses accepted as a list filter.

    ``INIT`` is deliberately absent: the service rejects it as a filter value even though
    a job can hold that status.
    """

    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETE = "PARTIALLY_COMPLETE"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


class JobType(WireEnum):
    """Red team scan job type. Decides which job-metadata shape the service expects."""

    STATIC = "STATIC"
    DYNAMIC = "DYNAMIC"
    CUSTOM = "CUSTOM"


class PolicyType(WireEnum):
    """Runtime security policy recommended by a static report."""

    PROMPT_INJECTION = "PROMPT_INJECTION"
    TOXIC_CONTENT = "TOXIC_CONTENT"
    CUSTOM_TOPIC_GUARDRAILS = "CUSTOM_TOPIC_GUARDRAILS"
    MALICIOUS_CODE_DETECTION = "MALICIOUS_CODE_DETECTION"
    MALICIOUS_URL_DETECTION = "MALICIOUS_URL_DETECTION"
    SENSITIVE_DATA_PROTECTION = "SENSITIVE_DATA_PROTECTION"


class ProfilingStatus(WireEnum):
    """Progress of the AI-assisted target profiling pass."""

    INIT = "INIT"
    QUEUED = "QUEUED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RedTeamCategory(WireEnum):
    """Top-level risk category.

    Prefixed ``RedTeam`` to avoid colliding with the scan API's verdict category.
    """

    SECURITY = "SECURITY"
    SAFETY = "SAFETY"
    COMPLIANCE = "COMPLIANCE"
    BRAND = "BRAND"


class ResponseMode(WireEnum):
    """Whether the target answers in one shot or as a stream."""

    REST = "REST"
    STREAMING = "STREAMING"


class RiskRating(WireEnum):
    """Risk rating levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SafetySubCategory(WireEnum):
    """Safety risk subcategories."""

    BIAS = "BIAS"
    CBRN = "CBRN"
    CYBERCRIME = "CYBERCRIME"
    DRUGS = "DRUGS"
    HATE_TOXIC_ABUSE = "HATE_TOXIC_ABUSE"
    NON_VIOLENT_CRIMES = "NON_VIOLENT_CRIMES"
    POLITICAL = "POLITICAL"
    SELF_HARM = "SELF_HARM"
    SEXUAL = "SEXUAL"
    VIOLENT_CRIMES_WEAPONS = "VIOLENT_CRIMES_WEAPONS"


class SecuritySubCategory(WireEnum):
    """Security risk subcategories."""

    ADVERSARIAL_SUFFIX = "ADVERSARIAL_SUFFIX"
    EVASION = "EVASION"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    MULTI_TURN = "MULTI_TURN"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    REMOTE_CODE_EXECUTION = "REMOTE_CODE_EXECUTION"
    SYSTEM_PROMPT_LEAK = "SYSTEM_PROMPT_LEAK"
    TOOL_LEAK = "TOOL_LEAK"
    MALWARE_GENERATION = "MALWARE_GENERATION"


class SeverityFilter(WireEnum):
    """Severity filter levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class StatusQueryParam(WireEnum):
    """Attack outcome filter.

    ``SUCCESSFUL`` means the *attack* succeeded, i.e. the target was breached.
    """

    SUCCESSFUL = "SUCCESSFUL"
    FAILED = "FAILED"


class StreamType(WireEnum):
    """Dynamic scan stream type."""

    NORMAL = "NORMAL"
    ADVERSARIAL = "ADVERSARIAL"


class TargetConnectionType(WireEnum):
    """Target connection provider type."""

    DATABRICKS = "DATABRICKS"
    BEDROCK = "BEDROCK"
    OPENAI = "OPENAI"
    HUGGING_FACE = "HUGGING_FACE"
    CUSTOM = "CUSTOM"
    REST = "REST"
    STREAMING = "STREAMING"
    WEBSOCKET = "WEBSOCKET"


class TargetStatus(WireEnum):
    """Target lifecycle status."""

    DRAFT = "DRAFT"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    FAILED = "FAILED"
    PENDING_AUTH = "PENDING_AUTH"


class TargetType(WireEnum):
    """Target classification type."""

    APPLICATION = "APPLICATION"
    AGENT = "AGENT"
    MODEL = "MODEL"


class AdapterVarType(WireEnum):
    """Whether an adapter variable is a plain value or a stored secret.

    ``SECRET`` values are write-only: they are never returned by the API.
    """

    VAR = "VAR"
    SECRET = "SECRET"  # noqa: S105 - a variable kind, not a credential


# ---------------------------------------------------------------------------
# Shared / utility schemas
# ---------------------------------------------------------------------------


class RedTeamPagination(AirsModel):
    """Pagination envelope shared by every Red Team list response.

    Only a total is returned; paging itself is driven by request query parameters.
    """

    total_items: int | None = None


class CountByName(AirsModel):
    """A named bucket and its count, used throughout the dashboard aggregates."""

    name: str
    count: int


class RedTeamValidationError(AirsModel):
    """One FastAPI-style field error.

    Renamed from the upstream ``ValidationError`` so it cannot be mistaken for -- or
    shadow -- ``pydantic.ValidationError``.
    """

    #: Path to the offending value, e.g. ``["body", "target", 0]``.
    loc: list[str | float]
    msg: str
    type: str


class RedTeamHttpValidationError(AirsModel):
    """A 422 body. Renamed from the upstream ``HTTPValidationError``."""

    detail: list[RedTeamValidationError] | None = None


# ---------------------------------------------------------------------------
# Target context schemas (shared between data plane and management plane)
# ---------------------------------------------------------------------------


class TargetBackground(AirsModel):
    """Business context for a target.

    Feeds prompt generation: ``competitors`` in particular drives the brand-risk
    subcategories, so leaving it empty measurably weakens that part of a scan.
    """

    industry: str | None = None
    use_case: str | None = None
    competitors: list[str] | None = None


class TargetAdditionalContext(AirsModel):
    """Technical context for a target, used to tailor generated attacks."""

    base_model: str | None = None
    core_architecture: str | None = None
    system_prompt: str | None = None
    languages_supported: list[str] | None = None
    banned_keywords: list[str] | None = None
    tools_accessible: list[str] | None = None


class TargetMetadata(AirsModel):
    """Operational limits and error fingerprints for a target.

    The rate-limit and content-filter triples describe how the target *signals* those
    conditions, so the scanner can tell "you are going too fast" and "I refused" apart
    from a genuine failure. Matching is on status code, body JSON, or message.
    """

    multi_turn: bool | None = None
    multi_turn_error_message: str | None = None
    rate_limit: int | None = None
    rate_limit_enabled: bool | None = None
    rate_limit_error_code: int | None = None
    rate_limit_error_json: dict[str, Any] | None = None
    rate_limit_error_message: str | None = None
    content_filter_enabled: bool | None = None
    content_filter_error_code: int | None = None
    content_filter_error_json: dict[str, Any] | None = None
    content_filter_error_message: str | None = None
    probe_message: str | None = None
    request_timeout: float | None = None


# ---------------------------------------------------------------------------
# Multi-turn configuration
# ---------------------------------------------------------------------------


class MultiTurnStatefulConfig(AirsModel):
    """Multi-turn conversation carried by the target's own session identifiers.

    The SDK echoes the id from the previous response into the next request, so both
    field names are required -- there is no default that works across targets.
    """

    type: str = "stateful"
    response_id_field: str
    request_id_field: str


class MultiTurnStatelessConfig(AirsModel):
    """Multi-turn conversation replayed as a message history on every request."""

    type: str = "stateless"
    assistant_role: str | None = None


# ---------------------------------------------------------------------------
# Auth configuration
# ---------------------------------------------------------------------------


class HeadersAuthConfig(AirsModel):
    """Static headers merged into every request to the target."""

    auth_header: dict[str, Any]


class BasicAuthAuthConfig(AirsModel):
    """HTTP basic credentials, placed per :class:`BasicAuthLocation`."""

    basic_auth_location: str = "HEADER"
    basic_auth_header: dict[str, Any] | None = None


class OAuth2AuthConfig(AirsModel):
    """Client-credentials OAuth2 exchange performed before each scan window.

    ``oauth2_expiry_minutes`` is the SDK-side refresh interval, not a value read from
    the token: the service re-mints on that schedule regardless of the real expiry.
    """

    oauth2_token_url: str
    oauth2_expiry_minutes: int = 60
    oauth2_headers: dict[str, Any] | None = None
    oauth2_body_params: dict[str, Any] | None = None
    oauth2_token_response_key: str = "access_token"  # noqa: S105 - a JSON key name
    oauth2_inject_header: dict[str, Any]


#: Any of the three target authentication configurations.
AuthConfig: TypeAlias = HeadersAuthConfig | BasicAuthAuthConfig | OAuth2AuthConfig


# ---------------------------------------------------------------------------
# Provider-specific connection parameters
# ---------------------------------------------------------------------------


class OpenAIConnectionParams(AirsModel):
    """Direct OpenAI connection."""

    api_key: str
    model_name: str


class HuggingfaceConnectionParams(AirsModel):
    """Hugging Face inference endpoint connection."""

    api_key: str
    model_name: str


class DatabricksConnectionParams(AirsModel):
    """Databricks serving-endpoint connection.

    Which credential fields are required depends on ``auth_type``: ``ACCESS_TOKEN``
    needs ``access_token``, ``OAUTH`` needs ``client_id`` and ``secret``. All three are
    optional here because the service does that check, and it varies by workspace.
    """

    auth_type: str
    workspace_url: str
    model_name: str
    access_token: str | None = None
    client_id: str | None = None
    secret: str | None = None


class BedrockAccessConnectionParams(AirsModel):
    """AWS Bedrock connection using static access keys."""

    access_id: str
    access_secret: str
    region: str
    model_id: str
    session_token: str | None = None


# ---------------------------------------------------------------------------
# REST / streaming / websocket connection parameters
# ---------------------------------------------------------------------------


class RestConnectionParams(AirsModel):
    """Generic HTTP target definition.

    Either ``curl`` or the explicit ``api_endpoint`` plus templates may be supplied;
    the service derives the missing half. ``response_key`` is a path into the response
    body identifying the model's text.
    """

    api_endpoint: str | None = None
    request_headers: dict[str, Any] | None = None
    request_json: dict[str, Any] | None = None
    response_json: dict[str, Any] | None = None
    response_key: str | None = None
    target_connection_config: Any = None
    curl: str | None = None
    multi_turn_config: Any = None


class StreamingConnectionParams(RestConnectionParams):
    """A REST target that answers with a token stream.

    The stop key/value pair is how the scanner recognises end-of-stream; without it a
    streaming target hangs until the request timeout.
    """

    response_stop_key: str
    response_stop_value: str


class WebSocketConnectionParams(RestConnectionParams):
    """A WebSocket target."""

    ws_response_timeout: float = 110


#: Union of WebSocket, Streaming, and REST connection parameters.
#:
#: Ambiguous by construction: every field of the WebSocket variant has a default, so a
#: bare REST payload validates against it and resolves to
#: :class:`WebSocketConnectionParams`. The upstream Zod union has exactly the same
#: behaviour. Where the connection kind matters, read ``connection_type`` on the target
#: rather than the runtime class of this value.
ConnectionParams: TypeAlias = (
    WebSocketConnectionParams | StreamingConnectionParams | RestConnectionParams
)


# ---------------------------------------------------------------------------
# Data plane -- jobs and scans
# ---------------------------------------------------------------------------


class TargetJobRequest(AirsModel):
    """Reference to the target a job should run against.

    Pinning ``version`` reproduces an older scan against the target as it was configured
    then; omit it to use the current definition.
    """

    uuid: str
    version: int | None = None


class JobTimeRecord(AirsModel):
    """Queue, start, and completion timestamps for a job."""

    queued_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    time_taken: str | None = None


class StaticJobMetadata(AirsModel):
    """Configuration for a STATIC job -- a fixed prompt corpus.

    ``categories`` selects which category/subcategory prompts to run and is the field
    that distinguishes this shape from the other two job metadata variants.
    """

    categories: dict[str, Any]
    rate_limit_enabled: bool | None = None
    rate_limit: int | None = None
    rate_limit_error_code: int | None = None
    rate_limit_error_message: str | None = None
    rate_limit_error_json: Any = None
    content_filter_enabled: bool | None = None
    content_filter_error_code: int | None = None
    content_filter_error_message: str | None = None
    content_filter_error_json: Any = None


class DynamicJobMetadata(AirsModel):
    """Configuration for a DYNAMIC job -- adaptive, goal-driven attacks.

    ``stream_breadth`` times ``stream_depth`` bounds the search: breadth is how many
    parallel attack lines are explored per goal, depth how many turns each may take.

    Every field is optional, which makes this the fallback arm of the job-metadata
    union -- a payload that matches neither of the other two lands here.
    """

    rate_limit_enabled: bool | None = None
    rate_limit: int | None = None
    rate_limit_error_code: int | None = None
    rate_limit_error_message: str | None = None
    rate_limit_error_json: Any = None
    content_filter_enabled: bool | None = None
    content_filter_error_code: int | None = None
    content_filter_error_message: str | None = None
    content_filter_error_json: Any = None
    stream_breadth: int | None = None
    stream_depth: int | None = None
    max_tokens: int | None = None
    context_size: int | None = None
    attack_goals: list[Any] | None = None
    base_model: str | None = None
    use_case: str | None = None
    system_prompt: str | None = None


class CustomJobMetadata(AirsModel):
    """Configuration for a CUSTOM job -- tenant-authored prompt sets."""

    custom_prompt_sets: list[Any]
    rate_limit_enabled: bool | None = None
    rate_limit: int | None = None
    rate_limit_error_code: int | None = None
    rate_limit_error_message: str | None = None
    rate_limit_error_json: Any = None
    content_filter_enabled: bool | None = None
    content_filter_error_code: int | None = None
    content_filter_error_message: str | None = None
    content_filter_error_json: Any = None


#: The three job configuration shapes, discriminated by their required fields.
JobMetadata: TypeAlias = StaticJobMetadata | DynamicJobMetadata | CustomJobMetadata


class JobCreateRequest(AirsModel):
    """Request to start a red team scan.

    ``job_metadata`` must match ``job_type``: the service does not infer one from the
    other and rejects the mismatch.
    """

    name: str
    target: TargetJobRequest
    job_type: str
    job_metadata: JobMetadata
    version: int | None = None
    extra_info: dict[str, Any] | None = None


class StaticJobReportStats(AirsModel):
    """Progress counters for a STATIC job.

    A partial report can be unlocked before completion; ``partial_report_unlocked_at``
    records when that happened, and it is one-way.
    """

    output_completion_percentage: float
    partial_report_unlocked: bool | None = None
    partial_report_unlocked_at: str | None = None
    report_summary: str | None = None


class DynamicJobReportStats(AirsModel):
    """Progress counters for a DYNAMIC job."""

    total_goals: int | None = None
    total_streams: int | None = None
    total_threats: int | None = None
    goals_achieved: int | None = None
    report_summary: str | None = None


class TargetReference(AirsModel):
    """The target as embedded in a job response.

    A denormalised snapshot, not a live read: fields reflect the target at the time the
    job was created. Use the management-plane target endpoints for current state.
    """

    uuid: str
    tsg_id: str
    name: str
    description: str | None = None
    target_type: str | None = None
    connection_type: str | None = None
    api_endpoint_type: str | None = None
    response_mode: str | None = None
    session_supported: bool | None = None
    extra_info: dict[str, Any] | None = None
    status: str
    active: bool
    validated: bool
    version: int | None = None
    secret_version: str | None = None
    created_by_user_id: str | None = None
    updated_by_user_id: str | None = None
    created_at: str
    updated_at: str
    target_metadata: TargetMetadata | None = None
    target_background: TargetBackground | None = None
    profiling_status: str | None = None
    additional_context: TargetAdditionalContext | None = None
    auth_type: str | None = None


class JobResponse(AirsModel):
    """A red team scan job.

    ``job_metadata`` and ``report_stats`` are left untyped because their shape follows
    ``job_type``; narrow them with the matching ``*JobMetadata`` / ``*JobReportStats``
    model once that is known.

    ``asr`` is the attack success rate -- the fraction of attacks that breached the
    target, so higher is worse. ``score`` runs the other way.
    """

    uuid: str
    tsg_id: str
    name: str
    target: TargetReference
    job_type: str
    job_metadata: Any = None
    version: int | None = None
    extra_info: dict[str, Any] | None = None
    target_id: str
    target_type: str
    total: int | None = None
    completed: int | None = None
    status: str | None = None
    score: float | None = None
    asr: float | None = None
    time_record: JobTimeRecord | None = None
    created_at: str | None = None
    updated_at: str | None = None
    created_by_user_id: str | None = None
    report_stats: Any = None
    metering_quota_uuid: str | None = None
    counted_towards_quota: str | None = None
    invocation_id: str | None = None


class JobListResponse(AirsModel):
    """Paginated list of jobs."""

    pagination: RedTeamPagination
    data: list[JobResponse]


class JobAbortResponse(AirsModel):
    """Acknowledgement that an abort was accepted.

    Abort is asynchronous: the job reaches ``ABORTED`` some time after this returns.
    """

    job_id: str
    message: str


# ---------------------------------------------------------------------------
# Data plane -- categories
# ---------------------------------------------------------------------------


class PrerequisiteModel(AirsModel):
    """A subcategory that must also be selected for its dependant to run."""

    id: str
    display_name: str
    description: str


class SubCategoryModel(AirsModel):
    """One attack subcategory offered for a scan."""

    id: str
    display_name: str
    description: str
    preselect: bool | None = None
    prerequisites: list[PrerequisiteModel] | None = None
    active: bool | None = None


class CategoryModel(AirsModel):
    """A top-level attack category and the subcategories under it."""

    id: str
    display_name: str
    description: str
    preselect: bool | None = None
    sub_categories: list[SubCategoryModel]


# ---------------------------------------------------------------------------
# Data plane -- attacks
# ---------------------------------------------------------------------------


class AttackOutput(AirsModel):
    """One target response to a single-turn attack.

    ``threat`` is the automated judgement; ``marked_safe`` is a human override that wins
    when the two disagree.
    """

    uuid: str
    tsg_id: str
    attack_id: str
    job_id: str
    target_id: str
    output: str
    threat: bool | None = None
    marked_safe: bool | None = None


class AttackMultiTurnOutput(AirsModel):
    """One turn of a multi-turn attack, carrying the prompt that produced it."""

    uuid: str
    tsg_id: str
    attack_id: str
    job_id: str
    target_id: str
    output: str
    prompt: str
    turn: int
    threat: bool | None = None
    marked_safe: bool | None = None
    generation: int | None = None
    multi_turn: bool | None = None


class AttackListItem(AirsModel):
    """One attack in a list response, without its outputs."""

    uuid: str
    tsg_id: str
    job_id: str
    target_id: str
    prompt: str
    prompt_mapping_id: str
    prompt_id: str
    category: str
    sub_category: str
    category_display_name: str
    sub_category_display_name: str
    status: str | None = None
    marked_safe: bool | None = None
    extra_info: dict[str, Any] | None = None
    threat: bool | None = None
    attack_type: str | None = None
    multi_turn: bool | None = None
    asr: float | None = None
    version: int | None = None
    severity: str | None = None


class AttackListResponse(AirsModel):
    """Paginated list of attacks."""

    pagination: RedTeamPagination
    data: list[AttackListItem]


class AttackDetailResponse(AirsModel):
    """A single-turn attack with its target responses.

    ``goal`` is required but nullable: the key is always present, and ``None`` means the
    attack came from a fixed corpus prompt rather than a generated objective.
    """

    uuid: str
    tsg_id: str
    job_id: str
    target_id: str
    prompt: str
    prompt_mapping_id: str
    prompt_id: str
    category: str
    sub_category: str
    category_display_name: str
    sub_category_display_name: str
    compliance_frameworks: list[Any]
    goal: str | None
    status: str | None = None
    marked_safe: bool | None = None
    extra_info: dict[str, Any] | None = None
    threat: bool | None = None
    attack_type: str | None = None
    multi_turn: bool | None = None
    asr: float | None = None
    version: int | None = None
    severity: str | None = None
    outputs: list[AttackOutput] | None = None


class AttackMultiTurnDetailResponse(AirsModel):
    """A multi-turn attack. Identical to :class:`AttackDetailResponse` but for outputs."""

    uuid: str
    tsg_id: str
    job_id: str
    target_id: str
    prompt: str
    prompt_mapping_id: str
    prompt_id: str
    category: str
    sub_category: str
    category_display_name: str
    sub_category_display_name: str
    compliance_frameworks: list[Any]
    goal: str | None
    status: str | None = None
    marked_safe: bool | None = None
    extra_info: dict[str, Any] | None = None
    threat: bool | None = None
    attack_type: str | None = None
    multi_turn: bool | None = None
    asr: float | None = None
    version: int | None = None
    severity: str | None = None
    outputs: list[AttackMultiTurnOutput] | None = None


# ---------------------------------------------------------------------------
# Data plane -- reports
# ---------------------------------------------------------------------------


class SubCategoryStats(AirsModel):
    """A subcategory with its outcome counts.

    ``successful`` counts attacks that breached the target, so a high number is bad.
    """

    id: str
    display_name: str
    description: str
    preselect: bool | None = None
    prerequisites: list[PrerequisiteModel] | None = None
    active: bool | None = None
    successful: int
    failed: int
    total: int | None = None


class CategoryReport(AirsModel):
    """Per-category results for a static scan."""

    id: str
    display_name: str
    description: str
    preselect: bool | None = None
    sub_categories: list[SubCategoryStats]
    asr: float
    total_prompts: int
    total_attacks: int
    successful: int
    failed: int


class SeverityStats(AirsModel):
    """Outcome counts for one severity band."""

    severity: str
    successful: int | None = None
    failed: int | None = None


class SeverityReport(AirsModel):
    """Results grouped by severity."""

    stats: list[SeverityStats]
    successful: int | None = None
    failed: int | None = None
    total_attacks: int | None = None


class ComplianceTechnique(AirsModel):
    """One technique within a compliance framework, with its outcome counts."""

    id: str
    display_name: str
    compliance_id: str
    description: str
    link: str
    version: str
    active: bool
    successful: int | None = None
    failed: int | None = None
    total: int | None = None


class ComplianceReport(AirsModel):
    """Results mapped onto one compliance framework."""

    id: str
    display_name: str
    description: str
    active: bool
    version: str
    link: str
    techniques: list[ComplianceTechnique]
    score: int | None = None


class RuntimeSecurityPolicy(AirsModel):
    """A Prisma AIRS runtime policy recommended as remediation.

    ``config`` is the policy body to apply, so it is left as an open mapping rather than
    modelled here -- its shape belongs to the runtime security API, not to this one.
    """

    policy_id: str
    display_name: str
    config: dict[str, Any]


class StaticJobRemediation(AirsModel):
    """A non-policy remediation suggestion.

    ``effectiveness``, ``ease_of_implementation``, and ``priority`` are numeric ranks;
    :class:`RemediationDetail` carries the same information as labels instead.
    """

    remediation: str
    description: str
    mapping_remediation_id: str | None = None
    subcategories: list[str] | None = None
    effectiveness: int | None = None
    ease_of_implementation: int | None = None
    priority: int | None = None
    resource_links: list[str] | None = None
    categories: list[str] | None = None


class StaticJobRemediationRecommendation(AirsModel):
    """Remediations for a static scan, split into policy and non-policy measures."""

    runtime_security_policy_configuration: list[RuntimeSecurityPolicy] | None = None
    other_measures: list[StaticJobRemediation] | None = None


class StaticJobReport(AirsModel):
    """The full report for a STATIC job.

    The three category reports are nullable because a scan only produces the ones whose
    categories were selected.
    """

    severity_report: SeverityReport
    asr: float | None = None
    score: float | None = None
    security_report: CategoryReport | None = None
    safety_report: CategoryReport | None = None
    brand_report: CategoryReport | None = None
    compliance_report: list[ComplianceReport] | None = None
    report_summary: str | None = None
    recommendations: StaticJobRemediationRecommendation | None = None


class DynamicJobReport(AirsModel):
    """The full report for a DYNAMIC job."""

    total_goals: int | None = None
    total_streams: int | None = None
    total_threats: int | None = None
    goals_achieved: int | None = None
    report_summary: str | None = None
    score: float | None = None
    asr: float | None = None


class RemediationDetail(AirsModel):
    """A remediation with human-readable priority bands rather than numeric ranks."""

    remediation: str
    description: str
    resource_links: list[str] | None = None
    priority_level: str | None = None
    ease_of_implementation_level: str | None = None
    effectiveness_level: str | None = None


class RemediationResponse(AirsModel):
    """Standalone remediations endpoint payload."""

    remediations: list[RemediationDetail] | None = None


class RuntimeSecurityProfileResponse(AirsModel):
    """Recommended runtime security profile derived from a scan."""

    runtime_security_profile: list[RuntimeSecurityPolicy] | None = None


# ---------------------------------------------------------------------------
# Data plane -- goals and streams (dynamic reports)
# ---------------------------------------------------------------------------


class Goal(AirsModel):
    """An objective a dynamic scan tries to achieve against the target.

    ``safe_response`` and ``jailbroken_response`` are the reference answers the judge
    scores each turn against; ``goal_to_show`` is a sanitised label for display, since
    the raw goal text is often itself harmful.
    """

    goal: str
    safe_response: str
    jailbroken_response: str
    goal_metadata: dict[str, Any] | None = None
    custom_goal: bool | None = None
    goal_type: str | None = None
    uuid: str
    tsg_id: str
    job_id: str
    goal_to_show: str | None = None
    threat: bool | None = None
    version: int | None = None
    extra_info: dict[str, Any] | None = None


class GoalListResponse(AirsModel):
    """Paginated list of goals."""

    pagination: RedTeamPagination
    data: list[Goal]


class StreamIterationData(AirsModel):
    """One turn of a dynamic attack stream.

    ``techniques``, ``improvement``, and ``judge_reasoning`` are the attacker and judge
    models thinking out loud -- the audit trail for why the stream went where it did.
    """

    uuid: str
    tsg_id: str
    job_id: str
    stream_id: str
    goal_id: str
    iteration: int
    prompt: str
    techniques: str
    improvement: str
    prompts_objective: str
    summary: str
    output: str | None = None
    score: int | None = None
    judge_reasoning: str | None = None
    threat: bool | None = None
    created_at: str | None = None
    updated_at: str | None = None
    extra_info: dict[str, Any] | None = None
    version: int | None = None


class StreamDetailResponse(AirsModel):
    """One attack stream pursuing a goal.

    ``first_threat_iteration`` is the turn that first breached the target and is the
    useful entry point into a long stream -- it is repeated inside ``iterations``.
    """

    uuid: str
    tsg_id: str
    job_id: str
    target_id: str
    goal_id: str
    stream_idx: int | None = None
    iteration: int | None = None
    goal: Any = None
    marked_safe: bool | None = None
    stream_type: str | None = None
    threat: bool | None = None
    first_threat_iteration: StreamIterationData | None = None
    created_at: str | None = None
    updated_at: str | None = None
    extra_info: dict[str, Any] | None = None
    version: int | None = None
    iterations: list[StreamIterationData] | None = None


class StreamListResponse(AirsModel):
    """Paginated list of streams."""

    pagination: RedTeamPagination
    data: list[StreamDetailResponse]


# ---------------------------------------------------------------------------
# Data plane -- custom attack reports
# ---------------------------------------------------------------------------


class CustomAttackOutput(AirsModel):
    """One target response to a custom prompt."""

    uuid: str
    tsg_id: str
    custom_attack_id: str
    job_id: str
    target_id: str
    output: str
    threat: bool | None = None
    marked_safe: bool | None = None


class PropertyAssignment(AirsModel):
    """A property name/value pair attached to a custom prompt."""

    name: str
    value: str


class PropertyValueStatistic(AirsModel):
    """Success counts for one value of a property.

    Properties are the slicing dimension for custom scans: tag prompts with e.g.
    ``language=fr`` and this reports the breach rate for that slice.
    """

    value: str
    successful_attack_count: int
    total_attack_count: int
    success_rate: float


class PropertyStatistic(AirsModel):
    """All value-level statistics for one property name."""

    property_name: str
    values: list[PropertyValueStatistic]


class PromptSetSummary(AirsModel):
    """Aggregate results for one prompt set within a custom scan."""

    prompt_set_id: str
    prompt_set_name: str
    total_prompts: int
    total_attacks: int
    total_threats: int
    failed_attacks: int
    threat_rate: float
    property_names: list[str] | None = None
    property_statistics: list[PropertyStatistic] | None = None


class CustomAttackReportResponse(AirsModel):
    """The full report for a CUSTOM job."""

    total_prompts: int
    total_attacks: int
    total_threats: int
    failed_attacks: int
    score: float
    asr: float
    custom_attack_reports: list[PromptSetSummary] | None = None
    property_statistics: list[PropertyStatistic] | None = None


class PromptSetsReportResponse(AirsModel):
    """Prompt-set breakdown of a custom scan, with the filters that produced it."""

    prompt_sets: list[PromptSetSummary]
    total_prompt_sets: int
    applied_filters: dict[str, Any] | None = None


class PromptDetailResponse(AirsModel):
    """One custom prompt and everything the scan learned about it."""

    prompt_id: str
    prompt_text: str
    goal: str | None = None
    user_defined_goal: bool | None = None
    properties: list[PropertyAssignment] | None = None
    attack_id: str | None = None
    threat: bool | None = None
    attack_outputs: list[CustomAttackOutput] | None = None
    asr: float | None = None
    prompt_set_id: str | None = None
    prompt_set_name: str | None = None


class CustomAttacksListResponse(AirsModel):
    """Paginated list of custom attacks.

    ``data`` is untyped upstream -- its row shape depends on the query parameters used,
    so it is left as an open list rather than guessed at.
    """

    pagination: RedTeamPagination
    data: list[Any]
    total_attacks: int
    total_threats: int


# ---------------------------------------------------------------------------
# Data plane -- dashboard
# ---------------------------------------------------------------------------


class RiskLevel(AirsModel):
    """Count of targets sitting at one risk rating."""

    risk_rating: str
    total: int
    targets_by_type: list[CountByName] | None = None


class ScanStatisticsResponse(AirsModel):
    """Tenant-wide scan counters for the dashboard."""

    total_scans: int
    targets_scanned: int
    targets_scanned_by_type: list[CountByName] | None = None
    scan_status: list[CountByName] | None = None
    risk_profile: list[RiskLevel] | None = None


class ScoreTrendSeries(AirsModel):
    """One line on the score trend chart.

    ``data`` is positional against :attr:`ScoreTrendResponse.labels` and may contain
    ``None`` for buckets where the target was not scanned -- a gap, not a zero.
    """

    label: str
    data: list[float | None]


class ScoreTrendResponse(AirsModel):
    """Score trend chart: shared x-axis labels plus one series per target."""

    labels: list[str]
    series: list[ScoreTrendSeries]


# ---------------------------------------------------------------------------
# Data plane -- sentiment, quota, error log
# ---------------------------------------------------------------------------


class SentimentRequest(AirsModel):
    """Thumbs up or down on a job's report."""

    job_id: str
    up_vote: bool | None = None
    down_vote: bool | None = None


class SentimentResponse(AirsModel):
    """The recorded sentiment for a job."""

    job_id: str
    up_vote: bool | None = None
    down_vote: bool | None = None


class QuotaDetails(AirsModel):
    """Allocation and consumption for one scan type.

    When ``unlimited`` is true, ``allocated`` carries no meaning -- check the flag first.
    """

    allocated: int
    unlimited: bool
    consumed: int


class QuotaSummary(AirsModel):
    """Quota across all three scan types. Each is metered separately."""

    static: QuotaDetails
    dynamic: QuotaDetails
    custom: QuotaDetails


class ErrorLog(AirsModel):
    """One error recorded while running a job or profiling a target.

    ``target_object`` is a snapshot of the target configuration in use when the error
    fired, which is what makes these entries diagnosable after the target has changed.
    """

    created_at: str
    updated_at: str
    job_id: str | None = None
    target_id: str | None = None
    target_version: int | None = None
    attack_id: str | None = None
    error_type: str | None = None
    error_source: str | None = None
    error_message: str | None = None
    target_object: dict[str, Any] | None = None
    extra_info: dict[str, Any] | None = None
    version: int | None = None


class ErrorLogListResponse(AirsModel):
    """Paginated list of error log entries."""

    pagination: RedTeamPagination
    data: list[ErrorLog]


# ---------------------------------------------------------------------------
# Supported languages (data plane and management plane)
# ---------------------------------------------------------------------------


class LanguageOption(AirsModel):
    """A language option: code plus display name."""

    code: str
    name: str


class TenantLanguagesResponse(AirsModel):
    """The tenant's allowed languages for Red Team scans.

    ``supported_job_types`` scopes the entitlement: multilingual can be enabled for
    STATIC scans while DYNAMIC remains English-only.
    """

    multilingual_enabled: bool
    supported_job_types: list[str]
    languages: list[LanguageOption]


# ---------------------------------------------------------------------------
# Management -- custom target adapters
# ---------------------------------------------------------------------------


class AdapterVar(AirsModel):
    """An adapter configuration variable, as *sent* in a request.

    On update, ``value=None`` means "keep the existing value". That is the only way to
    leave a secret unchanged, because secret values are never returned and so cannot be
    read back and resubmitted.

    Also the shape of :attr:`TargetCreateRequest.adapter_variable_overrides`.
    """

    key: Annotated[str, Field(max_length=MAX_ADAPTER_VAR_KEY_LENGTH)]
    value: str | None = None
    type: AdapterVarType


class AdapterVarResponse(AdapterVar):
    """An adapter variable as *returned* by the API.

    Secrets are masked with ``is_redacted=True``. The spec says the masked ``value`` is
    null, but a live tenant returns the literal placeholder ``'**********'`` (verified
    2026-08-01) -- so treat ``is_redacted``, not the value, as the signal. Either form
    round-trips: pass the variable back on validate or update alongside ``adapter_uuid``
    and the real value is resolved from storage.
    """

    is_redacted: bool | None = None


class AdapterCreateRequest(AirsModel):
    """Create a custom target adapter.

    Rejects unknown fields. The upstream schema is strict here, and silently dropping a
    misspelled key on a create would produce an adapter that does not do what the caller
    wrote.
    """

    # Strict, unlike the response models: this is a request body, and a typo should fail
    # loudly rather than be posted and ignored.
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(max_length=MAX_ADAPTER_NAME_LENGTH)]
    description: str | None = None
    script_b64: str
    #: Optional while the adapter is a DRAFT; required to activate it (validate=True).
    network_broker_channel_uuid: UuidStr | None = None
    variables: list[AdapterVar] | None = None
    #: Sample prompt used to exercise the adapter end to end during validation. Not stored.
    prompt: str


class AdapterUpdateRequest(AirsModel):
    """Replace a custom target adapter.

    A full replacement (PUT), not a partial patch: ``name``, ``script_b64``, and
    ``prompt`` are required exactly as on create.

    ``variables`` defines the complete desired key set:

    - value provided -- set or add the value
    - value ``None`` -- keep the existing value (this is how secrets survive an update)
    - key omitted    -- **delete** the variable
    """

    # Strict for the same reason as AdapterCreateRequest, and more sharply: on a full
    # replacement, a dropped key deletes data.
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(max_length=MAX_ADAPTER_NAME_LENGTH)]
    description: str | None = None
    script_b64: str
    network_broker_channel_uuid: UuidStr | None = None
    variables: list[AdapterVar] | None = None
    prompt: str


class AdapterResponse(AirsModel):
    """A full adapter record, returned by get, create, and update.

    List rows use the smaller :class:`AdapterListItem`.

    ``status`` is ``DRAFT`` or ``ACTIVE``, kept as an open string per house convention so
    a new upstream status cannot break response parsing.
    """

    uuid: str
    tsg_id: str
    name: str
    script_b64: str
    status: str
    description: str | None = None
    network_broker_channel_uuid: str | None = None
    variables: list[AdapterVarResponse] | None = None
    #: Number of targets currently referencing this adapter.
    target_count: int | None = None
    created_at: str | None = None
    updated_at: str | None = None
    created_by_user_id: str | None = None
    updated_by_user_id: str | None = None


class AdapterListItem(AirsModel):
    """One adapter list row -- a seven-field subset of :class:`AdapterResponse`.

    List rows carry no ``script_b64``, ``tsg_id``, ``description``, or ``variables``;
    call the get endpoint for the full record. ``target_count`` is populated only when
    the list was requested with ``include_target_count``.
    """

    uuid: str
    name: str
    status: str
    created_at: str
    updated_at: str
    created_by_user_id: str | None = None
    target_count: int | None = None


class AdapterList(AirsModel):
    """Paginated list of adapters."""

    pagination: RedTeamPagination
    data: list[AdapterListItem] | None = None


class AdapterValidateRequest(AirsModel):
    """Run an adapter script against a broker channel and report the outcome.

    Deliberately *not* the create request: there is no ``name``,
    ``network_broker_channel_uuid`` is required, and ``adapter_uuid`` may reference an
    existing adapter so redacted or ``None`` variable values are resolved from its
    stored secrets before the script runs.
    """

    # Strict: see AdapterCreateRequest.
    model_config = ConfigDict(extra="forbid")

    script_b64: str
    network_broker_channel_uuid: UuidStr
    prompt: str
    variables: list[AdapterVar] | None = None
    #: Omit when validating a brand-new adapter.
    adapter_uuid: UuidStr | None = None


class AdapterValidateResponse(AirsModel):
    """The script's execution outcome -- not an adapter record.

    On failure, ``traceback`` is where the actual cause lives; ``stderr`` is often empty
    even when the script raised.
    """

    validated: bool
    stdout: str | None = None
    stderr: str | None = None
    traceback: str | None = None


# ---------------------------------------------------------------------------
# Management -- targets
# ---------------------------------------------------------------------------


class _TargetRequestBase(AirsModel):
    """Fields shared by target create, update, and probe requests.

    All three are strict upstream, so the setting lives here rather than being repeated.
    """

    # Strict: these are request bodies. A misspelled key would otherwise be posted and
    # silently ignored, leaving a target that does not match what the caller described.
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str | None = None
    target_type: str | None = None
    connection_type: str | None = None
    api_endpoint_type: str | None = None
    response_mode: str | None = None
    connection_params: RestConnectionParams | StreamingConnectionParams | None = None
    session_supported: bool | None = None
    target_metadata: TargetMetadata | None = None
    target_background: TargetBackground | None = None
    additional_context: TargetAdditionalContext | None = None
    extra_info: dict[str, Any] | None = None
    #: Not UUID-validated upstream, unlike ``adapter_uuid`` directly below it.
    network_broker_channel_uuid: str | None = None
    #: UUID of the custom target adapter to use. Required when the connection type is
    #: CUSTOM_TARGET_ADAPTER.
    adapter_uuid: UuidStr | None = None
    #: Per-target overrides for the adapter's own variables.
    adapter_variable_overrides: list[AdapterVar] | None = None


class TargetCreateRequest(_TargetRequestBase):
    """Create a red team target."""


class TargetUpdateRequest(_TargetRequestBase):
    """Replace a red team target. A full replacement, not a partial patch."""


class TargetContextUpdate(AirsModel):
    """Update only a target's context, leaving its connection settings alone."""

    target_background: TargetBackground | None = None
    additional_context: TargetAdditionalContext | None = None


class TargetResponse(AirsModel):
    """A red team target.

    Most optional fields are untyped because the service returns them in more than one
    shape depending on connection type and profiling state; the four flags that drive
    scan eligibility -- ``active``, ``validated``, ``status``, ``created_at`` -- are the
    ones worth relying on. Credentials are never returned.
    """

    uuid: str
    tsg_id: str
    name: str
    status: Any = None
    active: bool
    validated: bool
    created_at: str
    updated_at: str
    description: Any = None
    target_type: Any = None
    connection_type: Any = None
    api_endpoint_type: Any = None
    response_mode: Any = None
    session_supported: bool | None = None
    extra_info: Any = None
    version: Any = None
    secret_version: Any = None
    created_by_user_id: Any = None
    updated_by_user_id: Any = None
    target_metadata: Any = None
    target_background: Any = None
    profiling_status: Any = None
    additional_context: Any = None
    auth_type: str | None = None


class TargetListItem(AirsModel):
    """One target list row. Carries no context or profiling fields."""

    uuid: str
    tsg_id: str
    name: str
    status: Any = None
    active: bool
    validated: bool
    created_at: str
    updated_at: str
    description: Any = None
    target_type: Any = None
    connection_type: Any = None
    api_endpoint_type: Any = None
    response_mode: Any = None
    session_supported: bool | None = None
    extra_info: Any = None
    version: Any = None
    secret_version: Any = None
    created_by_user_id: Any = None
    updated_by_user_id: Any = None
    auth_type: str | None = None


class TargetList(AirsModel):
    """Paginated list of targets."""

    pagination: RedTeamPagination
    data: list[TargetListItem] | None = None


class TargetProbeRequest(_TargetRequestBase):
    """Send one probe request to a target without saving it.

    Carries the whole target definition so an unsaved draft can be exercised; pass
    ``uuid`` instead to probe a stored target. ``probe_fields`` narrows what the probe
    reports back.
    """

    uuid: str | None = None
    probe_fields: list[str] | None = None


class TargetAuthValidationRequest(AirsModel):
    """Check a target's auth configuration before saving it.

    ``auth_config`` is left open because its shape follows ``auth_type``; build it from
    the matching :data:`AuthConfig` member.
    """

    auth_type: str
    auth_config: Any = None
    target_id: str | None = None
    network_broker_channel_uuid: str | None = None


class TargetAuthValidationResponse(AirsModel):
    """Outcome of an auth check.

    ``token_preview`` is truncated by the service -- it exists to confirm the right
    credential was used, and is never the whole token.
    """

    validated: bool
    token_preview: str | None = None
    expires_in: int | None = None


class TargetProfileResponse(AirsModel):
    """AI-generated profile of a target.

    ``ai_generated_fields`` names which of the context fields the service inferred, as
    opposed to values the tenant supplied -- the difference matters when deciding what
    is safe to overwrite.
    """

    target_id: str
    target_version: int
    status: str
    profiling_status: Any = None
    target_background: Any = None
    additional_context: Any = None
    ai_generated_fields: Any = None
    other_details: Any = None


class TargetTemplateCollection(AirsModel):
    """Starter connection-parameter templates, keyed by provider.

    Wire keys are upper case; the attributes are snake_case aliases of them.
    """

    openai: Annotated[dict[str, Any], Field(alias="OPENAI")]
    hugging_face: Annotated[dict[str, Any], Field(alias="HUGGING_FACE")]
    databricks: Annotated[dict[str, Any], Field(alias="DATABRICKS")]
    bedrock: Annotated[dict[str, Any], Field(alias="BEDROCK")]
    rest: Annotated[dict[str, Any], Field(alias="REST")]
    streaming: Annotated[dict[str, Any], Field(alias="STREAMING")]
    websocket: Annotated[dict[str, Any], Field(alias="WEBSOCKET")]


class BaseResponse(AirsModel):
    """Generic message envelope.

    ``status`` repeats the HTTP status in the body; it is not an independent signal.
    """

    message: str
    status: int


# ---------------------------------------------------------------------------
# Management -- custom attacks and prompt sets
# ---------------------------------------------------------------------------


class PromptSetStats(AirsModel):
    """Prompt counts for a prompt set.

    ``validation_prompts`` are still being checked and are in neither the active nor the
    inactive bucket, so the three do not have to sum to ``total_prompts``.
    """

    total_prompts: int
    active_prompts: int
    inactive_prompts: int
    failed_prompts: int | None = None
    validation_prompts: int | None = None


class CustomPromptSetCreateRequest(AirsModel):
    """Create a custom prompt set.

    ``property_names`` declares the slicing dimensions up front; prompts may only be
    tagged with names declared here.
    """

    name: str
    description: Any = None
    property_names: list[str] | None = None


class CustomPromptSetUpdateRequest(AirsModel):
    """Update a custom prompt set.

    Every field is untyped upstream, making this a free-form patch body: send only the
    keys being changed.
    """

    name: Any = None
    description: Any = None
    archive: Any = None
    property_names: Any = None


class CustomPromptSetArchiveRequest(AirsModel):
    """Archive or unarchive a prompt set. Archiving hides it; it is not a delete."""

    archive: bool


class CustomPromptSetResponse(AirsModel):
    """A custom prompt set."""

    uuid: str
    name: str
    active: bool
    archive: bool
    status: str
    created_at: str
    updated_at: str
    description: Any = None
    property_names: list[str] | None = None
    properties: list[Any] | None = None
    stats: Any = None
    extra_info: Any = None
    version: Any = None
    created_by_user_id: Any = None
    updated_by_user_id: Any = None


class CustomPromptSetListItem(AirsModel):
    """One prompt set list row."""

    uuid: str
    name: str
    active: bool
    archive: bool
    status: str
    created_at: str
    updated_at: str
    description: Any = None
    property_names: list[str] | None = None
    stats: Any = None
    created_by_user_id: Any = None


class CustomPromptSetList(AirsModel):
    """Paginated list of prompt sets."""

    pagination: RedTeamPagination
    data: list[CustomPromptSetListItem] | None = None


class CustomPromptSetReference(AirsModel):
    """A prompt set as referenced from a job. Not paginated -- there is no envelope."""

    uuid: str
    name: str
    status: str
    active: bool
    tsg_id: str
    created_at: str
    updated_at: str
    version: Any = None


class CustomPromptSetListActive(AirsModel):
    """Prompt sets eligible for a CUSTOM job."""

    data: list[CustomPromptSetReference] | None = None


class CustomPromptSetVersionInfo(AirsModel):
    """One snapshot of a prompt set.

    Prompt sets are versioned by snapshot, so a completed job keeps reporting against
    the prompts as they were when it ran. ``is_latest`` marks the live version.
    """

    uuid: str
    status: str
    is_latest: bool
    version: str | None = None
    stats: PromptSetStats | None = None
    snapshot_created_at: str | None = None


class CustomPromptCreateRequest(AirsModel):
    """Add a prompt to a prompt set."""

    prompt: str
    prompt_set_id: str
    goal: Any = None
    properties: Any = None


class CustomPromptUpdateRequest(AirsModel):
    """Update a prompt. A free-form patch body: send only the keys being changed."""

    prompt: Any = None
    goal: Any = None
    properties: Any = None


class CustomPromptResponse(AirsModel):
    """A custom prompt.

    ``user_defined_goal`` distinguishes a goal the tenant wrote from one the service
    inferred, which is what the judge uses to decide how strictly to score.
    """

    uuid: str
    prompt: str
    user_defined_goal: bool
    status: str
    active: bool
    prompt_set_id: str
    created_at: str
    updated_at: str
    goal: Any = None
    properties: Any = None
    property_assignments: list[Any] | None = None
    detector_category: Any = None
    severity: Any = None
    extra_info: Any = None


class CustomPromptListItem(AirsModel):
    """One prompt list row. Carries no ``prompt_set_id`` -- the list is already scoped."""

    uuid: str
    prompt: str
    user_defined_goal: bool
    status: str
    active: bool
    created_at: str
    updated_at: str
    goal: Any = None
    properties: Any = None


class CustomPromptList(AirsModel):
    """Paginated list of prompts."""

    pagination: RedTeamPagination
    data: list[CustomPromptListItem] | None = None


# ---------------------------------------------------------------------------
# Management -- properties
# ---------------------------------------------------------------------------


class PropertyNameCreateRequest(AirsModel):
    """Declare a property name for the tenant."""

    name: str


class PropertyValueCreateRequest(AirsModel):
    """Declare an allowed value for an existing property name."""

    property_name: str
    property_value: str


class PropertyDefinition(AirsModel):
    """A declared property name."""

    property_name: str
    created_at: str


class PropertyNamesListResponse(AirsModel):
    """All declared property names."""

    data: list[str] | None = None


class PropertyValuesResponse(AirsModel):
    """Values declared for one property name."""

    name: str
    values: list[str] | None = None


class PropertyValuesMultipleResponse(AirsModel):
    """Values for several property names at once, keyed by name."""

    data: dict[str, list[str]] | None = None


# ---------------------------------------------------------------------------
# Management -- dashboard
# ---------------------------------------------------------------------------


class DashboardOverviewResponse(AirsModel):
    """Target counts for the management dashboard."""

    total_targets: int
    targets_by_type: list[CountByName] | None = None


# ---------------------------------------------------------------------------
# Management -- EULA
# ---------------------------------------------------------------------------


class EulaAcceptRequest(AirsModel):
    """Accept the Red Team EULA.

    ``eula_content`` is echoed back so the service can confirm which revision was
    accepted; omitting the timestamp lets the service stamp it.
    """

    eula_content: str
    accepted_at: str | None = None


class EulaContentResponse(AirsModel):
    """The current EULA text."""

    content: str


class EulaResponse(AirsModel):
    """EULA acceptance state for the tenant. Scans are refused until accepted."""

    uuid: str | None = None
    is_accepted: bool
    accepted_at: str | None = None
    accepted_by_user_id: str | None = None


# ---------------------------------------------------------------------------
# Management -- instances and licensing
# ---------------------------------------------------------------------------


class DeviceInstance(AirsModel):
    """The tenant instance a device registration belongs to."""

    app_id: str
    region: str
    tenant_id: str
    tsg_id: str


class DeviceLicense(AirsModel):
    """One license on a device.

    Wire names are camelCase here and snake_case almost everywhere else in this API --
    these fields come straight from the licensing backend.
    """

    authorization_code: Annotated[str | None, Field(alias="authorizationCode")] = None
    expiration_date: Annotated[str | None, Field(alias="expirationDate")] = None
    license_pan_db_identification: Annotated[
        str | None, Field(alias="licensePanDbIdentification")
    ] = None
    part_number: Annotated[str | None, Field(alias="partNumber")] = None
    serial_number: Annotated[str | None, Field(alias="serialNumber")] = None
    subtype_name: Annotated[str | None, Field(alias="subtypeName")] = None
    registration_date: Annotated[str | None, Field(alias="registrationDate")] = None


class Device(AirsModel):
    """A licensed device."""

    serial_number: str
    model: str | None = None
    sku: str | None = None
    device_type: str | None = None
    device_name: str | None = None
    tsg_id: str | None = None
    support_account_id: str | None = None
    asset_type: str | None = None
    licenses: list[DeviceLicense] | None = None


class DeviceStatus(AirsModel):
    """Per-device outcome of a registration call.

    Registration is partial-success: check each entry, not just the envelope status.
    """

    status: str
    error: str | None = None
    serial_number: str | None = None


class DeviceRequest(AirsModel):
    """Register devices against an instance."""

    instance: DeviceInstance
    created_by: str | None = None
    devices: list[Device] | None = None


class DeviceResponse(AirsModel):
    """Result of a device registration call."""

    devices: list[DeviceStatus] | None = None
    status: str | None = None


class DeploymentProfileAttribute(AirsModel):
    """One metered attribute of a deployment profile."""

    quantity: float | None = None
    unit_of_measure: str | None = None


class DeploymentProfileRequest(AirsModel):
    """A licensing deployment profile. Wire names are camelCase; attributes are aliases."""

    d_auth_code: Annotated[str | None, Field(alias="dAuthCode")] = None
    deployment_profile_id: Annotated[str | None, Field(alias="deploymentProfileId")] = None
    license_expiration: str | None = None
    profile_name: Annotated[str | None, Field(alias="profileName")] = None
    sub_type: Annotated[str | None, Field(alias="subType")] = None
    subscriptions: str | None = None
    type: str | None = None
    ave_text_record: Annotated[float, Field(alias="aveTextRecord")] = 0.0
    attributes: list[DeploymentProfileAttribute] | None = None


class InstanceExtraDetails(AirsModel):
    """Licensing extras carried alongside an instance."""

    deployment_profiles: list[DeploymentProfileRequest] | None = None
    airs_shared_by_tsg: str | None = None
    airs_unshared_dps: str | None = None


class InstanceRequest(AirsModel):
    """Provision a Red Team instance for a tenant."""

    tsg_id: str
    tenant_id: str
    app_id: str
    region: str
    support_account_id: str | None = None
    support_account_name: str | None = None
    created_by: str | None = None
    internal: bool | None = None
    tenant_instance_name: str | None = None
    extra: InstanceExtraDetails | None = None
    iam_controlled: bool | None = None
    platform_region: str | None = None
    csp_tenant_id: str | None = None
    tsg_instances: Any = None


class InstanceResponse(AirsModel):
    """Acknowledgement of an instance provisioning call."""

    tsg_id: str
    tenant_id: str | None = None
    app_id: str | None = None
    is_success: bool | None = None


class InstanceGetResponse(AirsModel):
    """A provisioned instance."""

    tsg_id: str
    tenant_id: str
    app_id: str
    region: str
    support_account_id: str | None = None
    support_account_name: str | None = None
    created_by: str | None = None
    internal: bool | None = None
    tenant_instance_name: str | None = None
    deployment_profiles: list[DeploymentProfileRequest] | None = None


class RegistryCredentials(AirsModel):
    """Short-lived credentials for the network broker container registry.

    Both fields are required and the token expires, so fetch these per pull rather than
    caching them.
    """

    token: str
    expiry: str


# ---------------------------------------------------------------------------
# Network broker channels
# ---------------------------------------------------------------------------


class CreateChannelRequest(AirsModel):
    """Create a network broker channel."""

    name: str
    description: str | None = None


class UpdateChannelRequest(AirsModel):
    """Update a network broker channel. Both fields are optional upstream."""

    name: str | None = None
    description: str | None = None


class Channel(AirsModel):
    """A network broker channel -- the tunnel used to reach a private target."""

    uuid: str | None = None
    name: str | None = None
    description: str | None = None
    #: Kept as a plain string rather than :class:`ChannelStatus` so an unknown upstream
    #: status can never fail parsing.
    status: str | None = None
    added_by: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    last_online_at: str | None = None
    #: Present on live responses, absent from the base OpenAPI Channel schema.
    connected_clients_count: int | None = None
    #: Present on live responses, absent from the base OpenAPI Channel schema.
    outdated_clients_count: int | None = None
    #: Present on live responses, absent from the base OpenAPI Channel schema.
    features: dict[str, bool] | None = None


class ChannelListPagination(AirsModel):
    """Pagination for a channel list.

    Structurally identical to :class:`RedTeamPagination` but declared separately: the
    network broker API is specified independently and has drifted before.
    """

    total_items: int | None = None


class ChannelListResponse(AirsModel):
    """Paginated list of network broker channels.

    ``data`` defaults to empty because a tenant with no channels omits the key entirely
    rather than sending an empty list.
    """

    pagination: ChannelListPagination | None = None
    data: list[Channel] = Field(default_factory=list)


class ChannelStats(AirsModel):
    """Network broker infrastructure details and channel counts.

    Carries the image and chart coordinates a tenant needs to deploy a broker client,
    which is why an otherwise statistics-shaped response includes them.
    """

    network_channels_server_domain: str | None = None
    docker_registry: str | None = None
    helm_chart: str | None = None
    docker_image: str | None = None
    online_channels: int | None = None
    total_channels: int | None = None
    #: Present on live responses, absent from the base OpenAPI ChannelStats schema.
    client_version: str | None = None
