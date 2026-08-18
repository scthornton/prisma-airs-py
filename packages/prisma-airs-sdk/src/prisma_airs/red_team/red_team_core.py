"""Clients for the AI Red Teaming API: scans, reports, targets, and custom adapters.

The service is split across three base URLs. Scans, attacks, goals, and streams live on
the data plane; targets, adapters, templates, and the management dashboard live on the
management plane; broker channels live on a third, network-broker URL.
:class:`RedTeamClient` resolves all three up front and hands each sub-client the one it
belongs to -- a management call sent to the data plane answers 404, not a redirect, so
the binding has to be right at construction time.

Two families of endpoint share a prefix but not a plane: ``/v1/dashboard/*`` on the data
plane returns scan statistics, while ``/v1/dashboard/overview`` on the management plane
returns target counts. Both are reachable from :class:`RedTeamClient`; neither is
reachable from the other's base URL.
"""

from __future__ import annotations

import os
from typing import Any, TypeAlias

import httpx

from prisma_airs._http.auth import OAuthAuth
from prisma_airs._http.transport import RequestSpec, request
from prisma_airs._http.types import AuthAdapter
from prisma_airs._utils import is_valid_uuid, validate_job_id
from prisma_airs.auth.oauth import OAuthClient, resolve_credentials
from prisma_airs.constants import (
    DEFAULT_RED_TEAM_DATA_ENDPOINT,
    DEFAULT_RED_TEAM_MGMT_ENDPOINT,
    DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_PREFIX_MGMT,
    ENV_PREFIX_RED_TEAM,
    MAX_NUMBER_OF_RETRIES,
    RED_TEAM_ADAPTER_PATH,
    RED_TEAM_ADAPTER_VALIDATE_PATH,
    RED_TEAM_CATEGORIES_PATH,
    RED_TEAM_DASHBOARD_PATH,
    RED_TEAM_ERROR_LOG_PATH,
    RED_TEAM_ERROR_LOG_TARGET_PROFILE_PATH,
    RED_TEAM_LANGUAGES_PATH,
    RED_TEAM_MGMT_DASHBOARD_PATH,
    RED_TEAM_QUOTA_PATH,
    RED_TEAM_REPORT_DYNAMIC_PATH,
    RED_TEAM_REPORT_PATH,
    RED_TEAM_REPORT_STATIC_PATH,
    RED_TEAM_SCAN_PATH,
    RED_TEAM_SENTIMENT_PATH,
    RED_TEAM_TARGET_PATH,
    RED_TEAM_TARGET_VALIDATE_AUTH_PATH,
    RED_TEAM_TEMPLATE_PATH,
)
from prisma_airs.errors import AISecPayloadError
from prisma_airs.models.red_team import (
    AdapterCreateRequest,
    AdapterList,
    AdapterResponse,
    AdapterUpdateRequest,
    AdapterValidateRequest,
    AdapterValidateResponse,
    AttackDetailResponse,
    AttackListResponse,
    AttackMultiTurnDetailResponse,
    BaseResponse,
    CategoryModel,
    DashboardOverviewResponse,
    DynamicJobReport,
    ErrorLogListResponse,
    GoalListResponse,
    JobAbortResponse,
    JobCreateRequest,
    JobListResponse,
    JobResponse,
    QuotaSummary,
    RemediationResponse,
    RuntimeSecurityProfileResponse,
    ScanStatisticsResponse,
    ScoreTrendResponse,
    SentimentRequest,
    SentimentResponse,
    StaticJobReport,
    StreamDetailResponse,
    StreamListResponse,
    TargetAuthValidationRequest,
    TargetAuthValidationResponse,
    TargetContextUpdate,
    TargetCreateRequest,
    TargetList,
    TargetProbeRequest,
    TargetProfileResponse,
    TargetResponse,
    TargetTemplateCollection,
    TargetUpdateRequest,
    TenantLanguagesResponse,
)
from prisma_airs.red_team.red_team_extras import (
    RedTeamCustomAttackReportsClient,
    RedTeamCustomAttacksClient,
    RedTeamEulaClient,
    RedTeamInstancesClient,
    RedTeamNetworkBrokerClient,
)

#: Return type of :meth:`RedTeamScansClient.get_categories`, aliased at module scope
#: because that class also defines a ``list`` method: inside the class body, a bare
#: ``list[...]`` annotation resolves to the method rather than to the builtin.
CategoryModelList: TypeAlias = list[CategoryModel]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _assert_uuid(value: str, field: str) -> None:
    """Reject a malformed identifier before it is interpolated into a path.

    Generalises :func:`prisma_airs._utils.validate_job_id` to the other identifier kinds
    this API takes -- target, attack, goal, stream, and adapter UUIDs. Beyond the better
    error message, this keeps a caller-supplied value from reshaping a path built by
    string interpolation.

    Args:
        value: The identifier to check.
        field: Human-readable field name, used in the error message.

    Raises:
        AISecPayloadError: If ``value`` is not a canonical 8-4-4-4-12 UUID.
    """
    if not is_valid_uuid(value):
        raise AISecPayloadError(f"Invalid {field}: {value}")


def _bool_param(value: bool) -> str:
    """Render a boolean as a query-string value.

    Python's :func:`str` renders ``True`` as ``'True'``; the reference client sends
    ``'true'``. Query-string booleans are parsed case-sensitively often enough that the
    difference is not cosmetic, so this never uses :func:`str`.
    """
    return "true" if value else "false"


def _listing_params(skip: int | None, limit: int | None, search: str | None) -> dict[str, str]:
    """Serialise the pagination fields every Red Team list endpoint accepts.

    Unset values are omitted rather than sent empty, matching the reference client.
    Callers merge their endpoint-specific filters into the returned mapping.
    """
    params: dict[str, str] = {}
    if skip is not None:
        params["skip"] = str(skip)
    if limit is not None:
        params["limit"] = str(limit)
    if search is not None:
        params["search"] = search
    return params


def _validate_retries(value: int) -> int:
    """Reject a retry count the transport cannot honour.

    The TypeScript reference silently clamps to ``[0, MAX_NUMBER_OF_RETRIES]``. This port
    raises instead, matching :class:`prisma_airs.scan.scanner.Scanner`: a typo that turns
    into a quietly different retry budget is harder to notice than an error.

    Raises:
        AISecPayloadError: If ``value`` is not an int in range.
    """
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= MAX_NUMBER_OF_RETRIES
    ):
        raise AISecPayloadError(
            f"num_retries must be an integer between 0 and {MAX_NUMBER_OF_RETRIES}"
        )
    return value


def _resolve_endpoint(explicit: str | None, env_suffix: str, default: str) -> str:
    """Resolve one base URL from an argument, the environment, then the built-in default.

    Args:
        explicit: Constructor argument, which wins outright.
        env_suffix: Suffix appended to ``PANW_RED_TEAM`` to form the variable name.
        default: The published endpoint for this plane.

    Returns:
        The base URL to send to.
    """
    if explicit:
        return explicit
    return os.environ.get(f"{ENV_PREFIX_RED_TEAM}_{env_suffix}") or default


class _RedTeamSubClient:
    """Shared plumbing for the Red Team sub-clients.

    Each sub-client is bound to exactly one plane's base URL at construction and shares
    the parent's auth adapter, retry budget, and HTTP client, so a
    :class:`RedTeamClient` owns one connection pool and one cached OAuth token no matter
    how many sub-clients it exposes.
    """

    def __init__(
        self,
        *,
        base_url: str,
        auth: AuthAdapter,
        num_retries: int,
        http_client: httpx.Client,
    ) -> None:
        self._base_url = base_url
        self._auth = auth
        self._num_retries = num_retries
        self._http = http_client

    @property
    def base_url(self) -> str:
        """The plane this sub-client sends to."""
        return self._base_url


# ---------------------------------------------------------------------------
# Data plane -- scans
# ---------------------------------------------------------------------------


class RedTeamScansClient(_RedTeamSubClient):
    """Data plane scan (job) operations."""

    def create(self, body: JobCreateRequest) -> JobResponse:
        """Start a red team scan.

        Args:
            body: The job definition. ``job_metadata`` must match ``job_type`` -- the
                service does not infer one from the other and rejects a mismatch.

        Returns:
            The newly queued job.
        """
        return request(
            RequestSpec[JobResponse](
                method="POST",
                base_url=self._base_url,
                path=RED_TEAM_SCAN_PATH,
                body=body,
                auth=self._auth,
                response_model=JobResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        status: str | None = None,
        job_type: str | None = None,
        target_id: str | None = None,
    ) -> JobListResponse:
        """List scan jobs, newest first.

        Args:
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter.
            status: Filter by job status, e.g. ``COMPLETED``.
            job_type: Filter by ``STATIC``, ``DYNAMIC``, or ``CUSTOM``.
            target_id: Filter to one target.

        Returns:
            A page of jobs. ``pagination.total_items`` is the only paging signal the
            service returns; there is no cursor, so advance with ``skip``.
        """
        params = _listing_params(skip, limit, search)
        if status is not None:
            params["status"] = status
        if job_type is not None:
            params["job_type"] = job_type
        if target_id is not None:
            params["target_id"] = target_id

        return request(
            RequestSpec[JobListResponse](
                method="GET",
                base_url=self._base_url,
                path=RED_TEAM_SCAN_PATH,
                params=params,
                auth=self._auth,
                response_model=JobListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, job_id: str) -> JobResponse:
        """Fetch one scan job.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[JobResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_SCAN_PATH}/{job_id}",
                auth=self._auth,
                response_model=JobResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def abort(self, job_id: str) -> JobAbortResponse:
        """Request that a running scan stop.

        Abort is asynchronous: this returns as soon as the request is accepted, and the
        job reaches ``ABORTED`` some time later. Poll :meth:`get` to observe it.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[JobAbortResponse](
                method="POST",
                base_url=self._base_url,
                path=f"{RED_TEAM_SCAN_PATH}/{job_id}/abort",
                auth=self._auth,
                response_model=JobAbortResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_categories(self) -> CategoryModelList:
        """List every attack category and its subcategories.

        Returns:
            A bare list, not a paginated envelope -- this endpoint is the exception.
        """
        return request(
            RequestSpec[CategoryModelList](
                method="GET",
                base_url=self._base_url,
                path=RED_TEAM_CATEGORIES_PATH,
                auth=self._auth,
                response_model=CategoryModelList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


# ---------------------------------------------------------------------------
# Data plane -- reports
# ---------------------------------------------------------------------------


class RedTeamReportsClient(_RedTeamSubClient):
    """Data plane report operations.

    Reports are split by job type: a STATIC job's findings are attacks under
    ``/report/static``, a DYNAMIC job's are goals and streams under ``/report/dynamic``.
    Asking for the wrong one returns an empty or 404 result rather than translating, so
    branch on ``job_type`` from :meth:`RedTeamScansClient.get` before calling.
    """

    # -- Static (attack library) reports ------------------------------------

    def list_attacks(
        self,
        job_id: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        sub_category: str | None = None,
        attack_type: str | None = None,
        threat: bool | None = None,
    ) -> AttackListResponse:
        """List the attacks a static scan ran.

        Args:
            job_id: The job UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter.
            status: Filter by attack status.
            severity: Filter by severity band.
            category: Filter by top-level category id.
            sub_category: Filter by subcategory id.
            attack_type: Filter by attack type.
            threat: When ``True``, return only attacks that breached the target.

        Returns:
            A page of attack rows, without their target outputs. Use
            :meth:`get_attack_detail` for those.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        params = _listing_params(skip, limit, search)
        if status is not None:
            params["status"] = status
        if severity is not None:
            params["severity"] = severity
        if category is not None:
            params["category"] = category
        if sub_category is not None:
            params["sub_category"] = sub_category
        if attack_type is not None:
            params["attack_type"] = attack_type
        if threat is not None:
            params["threat"] = _bool_param(threat)

        return request(
            RequestSpec[AttackListResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_STATIC_PATH}/{job_id}/list-attacks",
                params=params,
                auth=self._auth,
                response_model=AttackListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_attack_detail(self, job_id: str, attack_id: str) -> AttackDetailResponse:
        """Fetch one single-turn attack with the target's responses.

        Multi-turn attacks 404 here; :attr:`AttackListItem.multi_turn` says which
        endpoint an attack belongs to.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        validate_job_id(job_id)
        _assert_uuid(attack_id, "attack id")
        return request(
            RequestSpec[AttackDetailResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_STATIC_PATH}/{job_id}/attack/{attack_id}",
                auth=self._auth,
                response_model=AttackDetailResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_multi_turn_attack_detail(
        self, job_id: str, attack_id: str
    ) -> AttackMultiTurnDetailResponse:
        """Fetch one multi-turn attack and its conversation.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        validate_job_id(job_id)
        _assert_uuid(attack_id, "attack id")
        return request(
            RequestSpec[AttackMultiTurnDetailResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_STATIC_PATH}/{job_id}/attack-multi-turn/{attack_id}",
                auth=self._auth,
                response_model=AttackMultiTurnDetailResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_static_report(self, job_id: str) -> StaticJobReport:
        """Fetch the attack-library report for a static scan.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[StaticJobReport](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_STATIC_PATH}/{job_id}/report",
                auth=self._auth,
                response_model=StaticJobReport,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_static_remediation(self, job_id: str) -> RemediationResponse:
        """Fetch remediation recommendations for a static scan.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[RemediationResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_STATIC_PATH}/{job_id}/remediation",
                auth=self._auth,
                response_model=RemediationResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_static_runtime_policy(self, job_id: str) -> RuntimeSecurityProfileResponse:
        """Fetch the runtime security profile a static scan recommends.

        This is the bridge from red teaming back to runtime enforcement: the returned
        policies are what a Prisma AIRS profile would need to block what the scan found.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[RuntimeSecurityProfileResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_STATIC_PATH}/{job_id}/runtime-policy-config",
                auth=self._auth,
                response_model=RuntimeSecurityProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    # -- Dynamic (agent) reports --------------------------------------------

    def get_dynamic_report(self, job_id: str) -> DynamicJobReport:
        """Fetch the agent-scan report for a dynamic scan.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[DynamicJobReport](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_DYNAMIC_PATH}/{job_id}/report",
                auth=self._auth,
                response_model=DynamicJobReport,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_dynamic_remediation(self, job_id: str) -> RemediationResponse:
        """Fetch remediation recommendations for a dynamic scan.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[RemediationResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_DYNAMIC_PATH}/{job_id}/remediation",
                auth=self._auth,
                response_model=RemediationResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_dynamic_runtime_policy(self, job_id: str) -> RuntimeSecurityProfileResponse:
        """Fetch the runtime security profile a dynamic scan recommends.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[RuntimeSecurityProfileResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_DYNAMIC_PATH}/{job_id}/runtime-policy-config",
                auth=self._auth,
                response_model=RuntimeSecurityProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_goals(
        self,
        job_id: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        goal_type: str | None = None,
        status: str | None = None,
        count: bool | None = None,
    ) -> GoalListResponse:
        """List the goals a dynamic scan pursued.

        Args:
            job_id: The job UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter.
            goal_type: Filter by goal type.
            status: Filter by goal status.
            count: Ask the service for counts only.

        Returns:
            A page of goals.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        params = _listing_params(skip, limit, search)
        if goal_type is not None:
            params["goal_type"] = goal_type
        if status is not None:
            params["status"] = status
        if count is not None:
            params["count"] = _bool_param(count)

        return request(
            RequestSpec[GoalListResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_DYNAMIC_PATH}/{job_id}/list-goals",
                params=params,
                auth=self._auth,
                response_model=GoalListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_goal_streams(
        self,
        job_id: str,
        goal_id: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
    ) -> StreamListResponse:
        """List the attack streams that pursued one goal.

        Args:
            job_id: The job UUID.
            goal_id: The goal UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter.

        Returns:
            A page of streams. Rows carry ``first_threat_iteration`` but not the full
            turn-by-turn transcript; call :meth:`get_stream_detail` for that.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        validate_job_id(job_id)
        _assert_uuid(goal_id, "goal id")
        return request(
            RequestSpec[StreamListResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_DYNAMIC_PATH}/{job_id}/goal/{goal_id}/list-streams",
                params=_listing_params(skip, limit, search),
                auth=self._auth,
                response_model=StreamListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    # -- Endpoints shared by both report types ------------------------------

    def get_stream_detail(self, stream_id: str) -> StreamDetailResponse:
        """Fetch one attack stream and every iteration in it.

        Addressed by stream id alone -- no job or goal id -- but the path still sits
        under the *dynamic* report prefix, because streams only exist for dynamic scans.

        Raises:
            AISecPayloadError: If ``stream_id`` is not a UUID.
        """
        _assert_uuid(stream_id, "stream id")
        return request(
            RequestSpec[StreamDetailResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_DYNAMIC_PATH}/stream/{stream_id}",
                auth=self._auth,
                response_model=StreamDetailResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def download_report(self, job_id: str, file_format: str) -> Any:
        """Download a finished report in the requested file format.

        Args:
            job_id: The job UUID.
            file_format: Wire value for the ``file_format`` query parameter, e.g.
                ``pdf`` or ``csv``.

        Returns:
            The payload as parsed JSON, unvalidated: its shape follows ``file_format``
            and upstream publishes no schema for it.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[Any](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_PATH}/{job_id}/download",
                params={"file_format": file_format},
                auth=self._auth,
                # `object` accepts any JSON shape, where `None` would discard the body.
                response_model=object,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def generate_partial_report(self, job_id: str) -> Any:
        """Unlock a partial report for a scan that is still running.

        One-way: :attr:`StaticJobReportStats.partial_report_unlocked_at` records when it
        happened and there is no re-lock.

        Returns:
            The partial report payload, unvalidated -- upstream has not published a
            schema for it.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[Any](
                method="POST",
                base_url=self._base_url,
                path=f"{RED_TEAM_REPORT_PATH}/{job_id}/generate-partial-report",
                auth=self._auth,
                response_model=object,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


# ---------------------------------------------------------------------------
# Management plane -- targets
# ---------------------------------------------------------------------------


class RedTeamTargetsClient(_RedTeamSubClient):
    """Management plane target operations."""

    def create(self, body: TargetCreateRequest, *, validate: bool | None = None) -> TargetResponse:
        """Create a target.

        Args:
            body: The target definition. Credentials are write-only and are never read
                back on any subsequent call.
            validate: Probe the connection before saving. Sent only when supplied -- the
                reference omits the parameter entirely rather than defaulting it, so the
                service's own default applies. Contrast
                :meth:`RedTeamAdaptersClient.create`, which always sends it.

        Returns:
            The stored target.
        """
        params = {"validate": _bool_param(validate)} if validate is not None else None
        return request(
            RequestSpec[TargetResponse](
                method="POST",
                base_url=self._base_url,
                path=RED_TEAM_TARGET_PATH,
                params=params,
                body=body,
                auth=self._auth,
                response_model=TargetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        target_type: str | None = None,
        status: str | None = None,
    ) -> TargetList:
        """List targets.

        Args:
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter.
            target_type: Filter by target type, e.g. ``API``.
            status: Filter by target status.

        Returns:
            A page of target rows, which carry no context or profiling fields.
        """
        params = _listing_params(skip, limit, search)
        if target_type is not None:
            params["target_type"] = target_type
        if status is not None:
            params["status"] = status

        return request(
            RequestSpec[TargetList](
                method="GET",
                base_url=self._base_url,
                path=RED_TEAM_TARGET_PATH,
                params=params,
                auth=self._auth,
                response_model=TargetList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, uuid: str) -> TargetResponse:
        """Fetch one target.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "target uuid")
        return request(
            RequestSpec[TargetResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_TARGET_PATH}/{uuid}",
                auth=self._auth,
                response_model=TargetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update(
        self, uuid: str, body: TargetUpdateRequest, *, validate: bool | None = None
    ) -> TargetResponse:
        """Replace a target.

        A full replacement (PUT), not a patch: fields absent from ``body`` are cleared,
        not preserved. Read the target first if you mean to change one field.

        Args:
            uuid: The target UUID.
            body: The complete target definition.
            validate: Probe the connection before saving. Sent only when supplied.

        Returns:
            The stored target.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "target uuid")
        params = {"validate": _bool_param(validate)} if validate is not None else None
        return request(
            RequestSpec[TargetResponse](
                method="PUT",
                base_url=self._base_url,
                path=f"{RED_TEAM_TARGET_PATH}/{uuid}",
                params=params,
                body=body,
                auth=self._auth,
                response_model=TargetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, uuid: str) -> BaseResponse | None:
        """Delete a target.

        Returns:
            The message envelope, or ``None`` -- this endpoint answers 200 with a body
            or 204 with none, from the same call, so an empty body is not an error.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "target uuid")
        return request(
            RequestSpec[BaseResponse | None](
                method="DELETE",
                base_url=self._base_url,
                path=f"{RED_TEAM_TARGET_PATH}/{uuid}",
                auth=self._auth,
                response_model=BaseResponse | None,
                allow_empty_body=True,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def probe(self, body: TargetProbeRequest) -> TargetResponse:
        """Run profiling probes against a target.

        The body carries a whole target definition, so an unsaved draft can be exercised
        before it is created; set ``uuid`` on the body to probe a stored target instead.

        Returns:
            The target as the probe left it.
        """
        return request(
            RequestSpec[TargetResponse](
                method="POST",
                base_url=self._base_url,
                path=f"{RED_TEAM_TARGET_PATH}/probe",
                body=body,
                auth=self._auth,
                response_model=TargetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_profile(self, uuid: str) -> TargetProfileResponse:
        """Fetch the AI-generated profile for a target.

        ``ai_generated_fields`` names which context fields the service inferred rather
        than took from the tenant -- the difference decides what is safe to overwrite
        with :meth:`update_profile`.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "target uuid")
        return request(
            RequestSpec[TargetProfileResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_TARGET_PATH}/{uuid}/profile",
                auth=self._auth,
                response_model=TargetProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update_profile(self, uuid: str, body: TargetContextUpdate) -> TargetResponse:
        """Update a target's background and additional context.

        Touches context only -- connection settings and credentials are left alone, which
        is why this exists alongside :meth:`update`.

        Returns:
            The updated target, not the profile.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "target uuid")
        return request(
            RequestSpec[TargetResponse](
                method="PUT",
                base_url=self._base_url,
                path=f"{RED_TEAM_TARGET_PATH}/{uuid}/profile",
                body=body,
                auth=self._auth,
                response_model=TargetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def validate_auth(self, body: TargetAuthValidationRequest) -> TargetAuthValidationResponse:
        """Check a target's auth configuration without saving it.

        Returns:
            The outcome. ``token_preview`` is truncated by the service and only confirms
            which credential was used.
        """
        return request(
            RequestSpec[TargetAuthValidationResponse](
                method="POST",
                base_url=self._base_url,
                path=RED_TEAM_TARGET_VALIDATE_AUTH_PATH,
                body=body,
                auth=self._auth,
                response_model=TargetAuthValidationResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_target_metadata(self) -> dict[str, Any]:
        """Fetch the field definitions that drive target configuration.

        Returns:
            An open mapping of field name to definition. Left unvalidated because the
            service adds provider-specific fields without a version bump.
        """
        return request(
            RequestSpec[dict[str, Any]](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_TEMPLATE_PATH}/target-metadata",
                auth=self._auth,
                response_model=dict[str, Any],
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_target_templates(self) -> TargetTemplateCollection:
        """Fetch starter connection-parameter templates for every supported provider.

        Returns:
            Templates keyed by provider. The wire keys are upper case (``OPENAI``,
            ``HUGGING_FACE``); the model exposes snake_case aliases of them.
        """
        return request(
            RequestSpec[TargetTemplateCollection](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_TEMPLATE_PATH}/target-templates",
                auth=self._auth,
                response_model=TargetTemplateCollection,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


# ---------------------------------------------------------------------------
# Management plane -- custom target adapters
# ---------------------------------------------------------------------------


class RedTeamAdaptersClient(_RedTeamSubClient):
    """Management plane custom target adapter operations.

    Custom target adapters are Python scripts that run inside an adapter sidecar
    alongside the network broker client pod. They give full control over how attack
    prompts are delivered to targets that use non-standard protocols, dynamic auth, or
    multi-turn session handling.

    Every call that validates a script needs the network channel client (v1.4.0+) to be
    running and ONLINE; without it the script cannot be reached and the adapter falls
    back to DRAFT.
    """

    def create(self, body: AdapterCreateRequest, *, validate: bool = True) -> AdapterResponse:
        """Create a custom target adapter.

        Args:
            body: Name, base64 script, variables, and the sample prompt used to exercise
                the adapter end to end.
            validate: Run the script against its configured target during the save. The
                adapter is stored ACTIVE on success and DRAFT on failure. Unlike
                :meth:`RedTeamTargetsClient.create`, the parameter is *always* sent and
                defaults to ``True``, matching the reference client.

        Returns:
            The stored adapter.
        """
        return request(
            RequestSpec[AdapterResponse](
                method="POST",
                base_url=self._base_url,
                path=RED_TEAM_ADAPTER_PATH,
                params={"validate": _bool_param(validate)},
                body=body,
                auth=self._auth,
                response_model=AdapterResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
    ) -> AdapterList:
        """List adapters.

        Returns:
            A page of adapter rows. Rows carry no ``script_b64`` or ``variables``; call
            :meth:`get` for the full record.
        """
        return request(
            RequestSpec[AdapterList](
                method="GET",
                base_url=self._base_url,
                path=RED_TEAM_ADAPTER_PATH,
                params=_listing_params(skip, limit, search),
                auth=self._auth,
                response_model=AdapterList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, uuid: str) -> AdapterResponse:
        """Fetch one adapter, including its script.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "adapter uuid")
        return request(
            RequestSpec[AdapterResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{RED_TEAM_ADAPTER_PATH}/{uuid}",
                auth=self._auth,
                response_model=AdapterResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update(
        self, uuid: str, body: AdapterUpdateRequest, *, validate: bool = True
    ) -> AdapterResponse:
        """Replace an adapter.

        A full replacement (PUT), not a patch: ``name``, ``script_b64``, and ``prompt``
        are required exactly as on create. ``variables`` defines the complete desired key
        set -- a value sets it, a ``None`` value keeps the stored one (the only way to
        carry a secret across an update, since secrets are never read back), and omitting
        a key **deletes** that variable.

        A ``None`` value is dropped from the request body rather than sent as JSON
        ``null``; the service reads an absent key the same way, so both spellings mean
        "leave it alone".

        Args:
            uuid: The adapter UUID.
            body: The complete adapter definition.
            validate: Re-run the script during the save. Always sent; defaults to
                ``True``.

        Returns:
            The stored adapter.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "adapter uuid")
        return request(
            RequestSpec[AdapterResponse](
                method="PUT",
                base_url=self._base_url,
                path=f"{RED_TEAM_ADAPTER_PATH}/{uuid}",
                params={"validate": _bool_param(validate)},
                body=body,
                auth=self._auth,
                response_model=AdapterResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, uuid: str) -> BaseResponse | None:
        """Delete an adapter.

        Returns:
            The message envelope, or ``None`` when the service answers with no body.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "adapter uuid")
        return request(
            RequestSpec[BaseResponse | None](
                method="DELETE",
                base_url=self._base_url,
                path=f"{RED_TEAM_ADAPTER_PATH}/{uuid}",
                auth=self._auth,
                response_model=BaseResponse | None,
                allow_empty_body=True,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def validate(self, body: AdapterValidateRequest) -> AdapterValidateResponse:
        """Run an adapter script end to end without saving anything.

        A different request shape from create: there is no ``name``,
        ``network_broker_channel_uuid`` is required, and ``adapter_uuid`` may point at an
        existing adapter so redacted or ``None`` variable values resolve from its stored
        secrets before the run.

        Returns:
            The execution outcome -- ``validated`` plus the script's ``stdout``,
            ``stderr``, and ``traceback``. Not an adapter record. On failure the cause is
            usually in ``traceback``; ``stderr`` is often empty even when the script
            raised.
        """
        return request(
            RequestSpec[AdapterValidateResponse](
                method="POST",
                base_url=self._base_url,
                path=RED_TEAM_ADAPTER_VALIDATE_PATH,
                body=body,
                auth=self._auth,
                response_model=AdapterValidateResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


# ---------------------------------------------------------------------------
# Top-level client
# ---------------------------------------------------------------------------


class RedTeamClient:
    """Entry point for the AI Red Teaming API.

    Resolves credentials and all three base URLs once, then exposes plane-bound
    sub-clients over a single OAuth token and connection pool. Credentials come from the
    constructor, then ``PANW_RED_TEAM_*``, then ``PANW_MGMT_*``, so one service account
    drives every plane without being repeated.

    Sub-clients for prompt sets, custom attack reports, the EULA, licensing, and network
    broker channels live in ``red_team_extras`` and are built from
    :attr:`data_endpoint`, :attr:`mgmt_endpoint`, :attr:`network_broker_endpoint`, and
    this instance's auth adapter, retry budget, and HTTP client.

    Example:
        >>> rt = RedTeamClient()
        >>> scans = rt.scans.list(limit=5, status="COMPLETED")
        >>> scans.pagination.total_items
        12
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        tsg_id: str | None = None,
        data_endpoint: str | None = None,
        mgmt_endpoint: str | None = None,
        network_broker_endpoint: str | None = None,
        token_endpoint: str | None = None,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._data_endpoint = _resolve_endpoint(
            data_endpoint, "DATA_ENDPOINT", DEFAULT_RED_TEAM_DATA_ENDPOINT
        )
        self._mgmt_endpoint = _resolve_endpoint(
            mgmt_endpoint, "MGMT_ENDPOINT", DEFAULT_RED_TEAM_MGMT_ENDPOINT
        )
        self._network_broker_endpoint = _resolve_endpoint(
            network_broker_endpoint,
            "NETWORK_BROKER_ENDPOINT",
            DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT,
        )
        self._num_retries = _validate_retries(num_retries)

        self._owns_client = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)

        credentials = resolve_credentials(
            primary_env_prefix=ENV_PREFIX_RED_TEAM,
            fallback_env_prefix=ENV_PREFIX_MGMT,
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            token_endpoint=token_endpoint,
        )
        # The token client shares this instance's HTTP client, so closing the red team
        # client closes everything it opened. Red teaming is not the AI Gateway: a bearer
        # token is the whole story here, with no x-tsg-id header.
        self._oauth = OAuthClient(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            tsg_id=credentials.tsg_id,
            token_endpoint=credentials.token_endpoint,
            http_client=self._http,
            timeout=timeout,
        )
        self._auth: AuthAdapter = OAuthAuth(self._oauth)

        self.scans = RedTeamScansClient(
            base_url=self._data_endpoint,
            auth=self._auth,
            num_retries=self._num_retries,
            http_client=self._http,
        )
        self.reports = RedTeamReportsClient(
            base_url=self._data_endpoint,
            auth=self._auth,
            num_retries=self._num_retries,
            http_client=self._http,
        )
        self.targets = RedTeamTargetsClient(
            base_url=self._mgmt_endpoint,
            auth=self._auth,
            num_retries=self._num_retries,
            http_client=self._http,
        )
        self.adapters = RedTeamAdaptersClient(
            base_url=self._mgmt_endpoint,
            auth=self._auth,
            num_retries=self._num_retries,
            http_client=self._http,
        )

        # eula and instances are implemented in red_team_extras but belong on this client,
        # matching the reference. They take a resolved token manager rather than an auth
        # adapter, so they share this client's token cache and connection pool.
        self.eula = RedTeamEulaClient(
            endpoint=self._mgmt_endpoint,
            oauth_client=self._oauth,
            http_client=self._http,
            num_retries=self._num_retries,
        )
        self.instances = RedTeamInstancesClient(
            endpoint=self._mgmt_endpoint,
            oauth_client=self._oauth,
            http_client=self._http,
            num_retries=self._num_retries,
        )
        self.custom_attacks = RedTeamCustomAttacksClient(
            endpoint=self._mgmt_endpoint,
            oauth_client=self._oauth,
            http_client=self._http,
            num_retries=self._num_retries,
        )
        # Custom attacks are defined on the management plane but reported on the data
        # plane -- the two halves of the same feature sit on different base URLs.
        self.custom_attack_reports = RedTeamCustomAttackReportsClient(
            endpoint=self._data_endpoint,
            oauth_client=self._oauth,
            http_client=self._http,
            num_retries=self._num_retries,
        )
        self.network_broker = RedTeamNetworkBrokerClient(
            endpoint=self._network_broker_endpoint,
            oauth_client=self._oauth,
            http_client=self._http,
            num_retries=self._num_retries,
        )

    @property
    def data_endpoint(self) -> str:
        """Base URL for scans, attacks, goals, streams, and the scan dashboard."""
        return self._data_endpoint

    @property
    def mgmt_endpoint(self) -> str:
        """Base URL for targets, adapters, templates, and the target dashboard."""
        return self._mgmt_endpoint

    @property
    def network_broker_endpoint(self) -> str:
        """Base URL for broker channels.

        Resolved here rather than in the broker client so all three endpoints follow the
        same argument-then-environment-then-default rule in one place.
        """
        return self._network_broker_endpoint

    # -- Data plane convenience ---------------------------------------------

    def get_scan_statistics(
        self, *, date_range: str | None = None, target_id: str | None = None
    ) -> ScanStatisticsResponse:
        """Fetch tenant-wide scan counters and the risk profile.

        Args:
            date_range: Window to aggregate over, e.g. ``30d``.
            target_id: Narrow the aggregate to one target.

        Returns:
            The scan statistics. Not UUID-checked: ``target_id`` is a filter here rather
            than a path segment, and the reference passes it through untouched.
        """
        params: dict[str, str] = {}
        if date_range is not None:
            params["date_range"] = date_range
        if target_id is not None:
            params["target_id"] = target_id

        return request(
            RequestSpec[ScanStatisticsResponse](
                method="GET",
                base_url=self._data_endpoint,
                path=f"{RED_TEAM_DASHBOARD_PATH}/scan-statistics",
                params=params,
                auth=self._auth,
                response_model=ScanStatisticsResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_score_trend(self, target_id: str) -> ScoreTrendResponse:
        """Fetch the score trend for one target.

        Returns:
            Shared x-axis labels plus one series per target. A ``None`` in a series is a
            bucket where the target was not scanned -- a gap, not a zero.

        Raises:
            AISecPayloadError: If ``target_id`` is not a UUID.
        """
        _assert_uuid(target_id, "target id")
        return request(
            RequestSpec[ScoreTrendResponse](
                method="GET",
                base_url=self._data_endpoint,
                path=f"{RED_TEAM_DASHBOARD_PATH}/score-trend",
                params={"target_id": target_id},
                auth=self._auth,
                response_model=ScoreTrendResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_quota(self) -> QuotaSummary:
        """Fetch scan quota for all three scan types.

        A POST despite being a pure read -- that is how the metering endpoint is defined
        upstream, and a GET to the same path does not answer.

        Returns:
            Allocation and consumption per scan type. Check ``unlimited`` before reading
            ``allocated``, which carries no meaning when the flag is set.
        """
        return request(
            RequestSpec[QuotaSummary](
                method="POST",
                base_url=self._data_endpoint,
                path=RED_TEAM_QUOTA_PATH,
                auth=self._auth,
                response_model=QuotaSummary,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_error_logs(
        self,
        job_id: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
    ) -> ErrorLogListResponse:
        """List the errors recorded while running one scan job.

        Returns:
            A page of error log entries. Each carries ``target_object``, a snapshot of
            the target configuration in force when the error fired -- which is what makes
            these diagnosable after the target has been edited.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[ErrorLogListResponse](
                method="GET",
                base_url=self._data_endpoint,
                path=f"{RED_TEAM_ERROR_LOG_PATH}/{job_id}",
                params=_listing_params(skip, limit, search),
                auth=self._auth,
                response_model=ErrorLogListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_target_profile_error_logs(
        self,
        target_id: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
    ) -> ErrorLogListResponse:
        """List the errors recorded while profiling one target.

        A separate log from :meth:`get_error_logs`: profiling failures happen before any
        job exists, so they are keyed by target rather than by job.

        Returns:
            A page of error log entries.

        Raises:
            AISecPayloadError: If ``target_id`` is not a UUID.
        """
        _assert_uuid(target_id, "target id")
        return request(
            RequestSpec[ErrorLogListResponse](
                method="GET",
                base_url=self._data_endpoint,
                path=f"{RED_TEAM_ERROR_LOG_TARGET_PROFILE_PATH}/{target_id}",
                params=_listing_params(skip, limit, search),
                auth=self._auth,
                response_model=ErrorLogListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_languages(self) -> TenantLanguagesResponse:
        """Fetch the tenant's allowed scan languages from the data plane.

        Returns:
            The entitlement. ``supported_job_types`` scopes it: multilingual can be on
            for STATIC while DYNAMIC stays English-only.
        """
        return request(
            RequestSpec[TenantLanguagesResponse](
                method="GET",
                base_url=self._data_endpoint,
                path=RED_TEAM_LANGUAGES_PATH,
                auth=self._auth,
                response_model=TenantLanguagesResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update_sentiment(self, body: SentimentRequest) -> SentimentResponse:
        """Record a thumbs up or down on a scan report.

        Returns:
            The stored sentiment.
        """
        return request(
            RequestSpec[SentimentResponse](
                method="POST",
                base_url=self._data_endpoint,
                path=RED_TEAM_SENTIMENT_PATH,
                body=body,
                auth=self._auth,
                response_model=SentimentResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_sentiment(self, job_id: str) -> SentimentResponse:
        """Fetch the recorded sentiment for a scan report.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[SentimentResponse](
                method="GET",
                base_url=self._data_endpoint,
                path=f"{RED_TEAM_SENTIMENT_PATH}/{job_id}",
                auth=self._auth,
                response_model=SentimentResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    # -- Management plane convenience ---------------------------------------

    def get_management_languages(self) -> TenantLanguagesResponse:
        """Fetch the tenant's allowed scan languages from the management plane.

        Same path and same response shape as :meth:`get_languages`, served from the
        management endpoint. Both are kept because the two planes can be pointed at
        different hosts, and the UI reads whichever one it is already talking to.
        """
        return request(
            RequestSpec[TenantLanguagesResponse](
                method="GET",
                base_url=self._mgmt_endpoint,
                path=RED_TEAM_LANGUAGES_PATH,
                auth=self._auth,
                response_model=TenantLanguagesResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_dashboard_overview(self) -> DashboardOverviewResponse:
        """Fetch target counts for the management dashboard.

        Distinct from :meth:`get_scan_statistics`: this counts targets on the management
        plane, that counts scans on the data plane, and neither path resolves on the
        other's base URL.
        """
        return request(
            RequestSpec[DashboardOverviewResponse](
                method="GET",
                base_url=self._mgmt_endpoint,
                path=RED_TEAM_MGMT_DASHBOARD_PATH,
                auth=self._auth,
                response_model=DashboardOverviewResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    # -- Lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP client, if this instance created it."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> RedTeamClient:
        """Enter a context that closes the HTTP client on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the HTTP client if this instance owns it."""
        self.close()
