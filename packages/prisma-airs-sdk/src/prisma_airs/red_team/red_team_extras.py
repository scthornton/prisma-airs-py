"""Red Team clients for custom attacks, reports, EULA, licensing, and the network broker.

These five clients sit on three different base URLs. Custom attacks, the EULA, and
instances are management plane; custom attack reports are data plane; the network broker
has a base URL of its own. They share one OAuth service account, so a caller that needs
several of them should pass a single :class:`~prisma_airs.auth.oauth.OAuthClient` to each
and get one token cache instead of five.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import BinaryIO, ClassVar, TypeVar
from urllib.parse import quote

import httpx

from prisma_airs._http.auth import OAuthAuth
from prisma_airs._http.retry import execute_with_retry
from prisma_airs._http.transport import RequestSpec, build_url, request
from prisma_airs._http.types import AuthAdapter, PreparedRequest
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
    RED_TEAM_CHANNELS_PATH,
    RED_TEAM_CHANNELS_STATS_PATH,
    RED_TEAM_CUSTOM_ATTACK_PATH,
    RED_TEAM_CUSTOM_ATTACKS_REPORT_PATH,
    RED_TEAM_EULA_PATH,
    RED_TEAM_INSTANCES_PATH,
    RED_TEAM_REGISTRY_CREDENTIALS_PATH,
    USER_AGENT,
)
from prisma_airs.errors import AISecPayloadError
from prisma_airs.models.red_team import (
    BaseResponse,
    Channel,
    ChannelListResponse,
    ChannelStats,
    CreateChannelRequest,
    CustomAttackOutput,
    CustomAttackReportResponse,
    CustomAttacksListResponse,
    CustomPromptCreateRequest,
    CustomPromptList,
    CustomPromptResponse,
    CustomPromptSetArchiveRequest,
    CustomPromptSetCreateRequest,
    CustomPromptSetList,
    CustomPromptSetListActive,
    CustomPromptSetReference,
    CustomPromptSetResponse,
    CustomPromptSetUpdateRequest,
    CustomPromptSetVersionInfo,
    CustomPromptUpdateRequest,
    DeviceRequest,
    DeviceResponse,
    EulaAcceptRequest,
    EulaContentResponse,
    EulaResponse,
    InstanceGetResponse,
    InstanceRequest,
    InstanceResponse,
    PromptDetailResponse,
    PromptSetsReportResponse,
    PropertyNameCreateRequest,
    PropertyNamesListResponse,
    PropertyStatistic,
    PropertyValueCreateRequest,
    PropertyValuesMultipleResponse,
    PropertyValuesResponse,
    RegistryCredentials,
    UpdateChannelRequest,
)

#: Content type declared for the prompt CSV upload part. The service sniffs the part
#: rather than trusting it, but omitting it makes the multipart body harder to read in a
#: capture.
_CSV_CONTENT_TYPE = "text/csv"

#: Status the service reports when an upload succeeds without returning an envelope.
_UPLOAD_CREATED_STATUS = 201

#: Preserves the concrete subclass through ``with``. ``typing.Self`` would say this more
#: directly but arrived in 3.11, and this package still supports 3.10.
_ClientT = TypeVar("_ClientT", bound="_RedTeamPlaneClient")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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
    """Reject a malformed identifier before it is interpolated into a path.

    Args:
        value: The candidate identifier.
        field: Name used in the error message, matching the reference implementation.

    Raises:
        AISecPayloadError: If ``value`` is not a canonically formatted UUID.
    """
    if not is_valid_uuid(value):
        raise AISecPayloadError(f"Invalid {field}: {value}")


def _bool_param(value: bool) -> str:
    """Render a boolean the way these APIs read it.

    Python's ``str(True)`` produces ``True``, which the services treat as an unrecognised
    value and silently ignore rather than reject -- the filter simply stops applying.
    """
    return "true" if value else "false"


def _listing_params(
    *, skip: int | None, limit: int | None, search: str | None
) -> dict[str, str | Sequence[str]]:
    """Serialise the pagination and search fields shared by every Red Team list endpoint.

    ``skip=0`` is a meaningful value, so presence is tested against ``None`` rather than
    truthiness.

    Returns:
        A mutable params dict that callers extend with endpoint-specific filters.
    """
    params: dict[str, str | Sequence[str]] = {}
    if skip is not None:
        params["skip"] = str(skip)
    if limit is not None:
        params["limit"] = str(limit)
    if search is not None:
        params["search"] = search
    return params


class _RedTeamPlaneClient:
    """Construction and lifecycle shared by the Red Team plane clients.

    Credentials come from the constructor, then ``PANW_RED_TEAM_*``, then ``PANW_MGMT_*``,
    each field resolving independently. Pass ``oauth_client`` to share one token cache
    across several clients; pass ``http_client`` to share a connection pool.

    Args:
        client_id: OAuth2 client ID.
        client_secret: OAuth2 client secret.
        tsg_id: Tenant Service Group ID.
        endpoint: Base URL override for this plane.
        token_endpoint: OAuth2 token endpoint override.
        num_retries: Retry budget, 0 to 5.
        timeout: Per-request timeout in seconds.
        oauth_client: Pre-built token manager to reuse.
        http_client: Pre-built HTTP client to reuse. Not closed by :meth:`close`.

    Raises:
        AISecMissingVariableError: If credentials could not be resolved.
        AISecPayloadError: If ``num_retries`` is outside 0 to 5.
    """

    #: The plane this client talks to. Set by each concrete subclass.
    _DEFAULT_ENDPOINT: ClassVar[str]

    def __init__(
        self,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        tsg_id: str | None = None,
        endpoint: str | None = None,
        token_endpoint: str | None = None,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        oauth_client: OAuthClient | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        if oauth_client is None:
            credentials = resolve_credentials(
                primary_env_prefix=ENV_PREFIX_RED_TEAM,
                client_id=client_id,
                client_secret=client_secret,
                tsg_id=tsg_id,
                token_endpoint=token_endpoint,
                fallback_env_prefix=ENV_PREFIX_MGMT,
            )
            oauth_client = OAuthClient(
                client_id=credentials.client_id,
                client_secret=credentials.client_secret,
                tsg_id=credentials.tsg_id,
                token_endpoint=credentials.token_endpoint,
                timeout=timeout,
            )
            self._owns_oauth = True
        else:
            self._owns_oauth = False

        self._oauth = oauth_client
        # Red Team is not the AI Gateway: the tenant is carried in the token's scope, so
        # there is no x-tsg-id header to add on top.
        self._auth: AuthAdapter = OAuthAuth(oauth_client)
        self._endpoint = endpoint or self._DEFAULT_ENDPOINT
        self._num_retries = _validate_retries(num_retries)
        self._owns_client = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)

    @property
    def endpoint(self) -> str:
        """The base URL this client sends to."""
        return self._endpoint

    @property
    def oauth(self) -> OAuthClient:
        """The token manager, so it can be shared with a sibling client."""
        return self._oauth

    def close(self) -> None:
        """Close the HTTP and token clients this instance created."""
        if self._owns_client:
            self._http.close()
        if self._owns_oauth:
            self._oauth.close()

    def __enter__(self: _ClientT) -> _ClientT:
        """Enter a context that closes owned clients on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close any clients this instance owns."""
        self.close()


# ---------------------------------------------------------------------------
# Management plane -- custom attacks
# ---------------------------------------------------------------------------


class RedTeamCustomAttacksClient(_RedTeamPlaneClient):
    """Manages custom prompt sets, the prompts inside them, and their properties.

    A prompt set is the unit a CUSTOM job runs against. Properties are the slicing
    dimension for the resulting report: declare the names on the set, tag each prompt,
    and the report breaks the attack success rate down by value.

    Every method here goes through the shared transport except :meth:`download_template`,
    which returns CSV rather than JSON. See its docstring.

    Example:
        >>> client = RedTeamCustomAttacksClient()
        >>> client.list_prompt_sets(limit=10, active=True).pagination.total_items
        2
    """

    _DEFAULT_ENDPOINT: ClassVar[str] = DEFAULT_RED_TEAM_MGMT_ENDPOINT

    # -- Prompt sets --------------------------------------------------------

    def create_prompt_set(self, body: CustomPromptSetCreateRequest) -> CustomPromptSetResponse:
        """Create a custom prompt set.

        Args:
            body: Name, description, and the property names prompts may be tagged with.

        Returns:
            The created prompt set.
        """
        return request(
            RequestSpec[CustomPromptSetResponse](
                method="POST",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/custom-prompt-set",
                body=body,
                auth=self._auth,
                response_model=CustomPromptSetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_prompt_sets(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        status: str | None = None,
        active: bool | None = None,
        archive: bool | None = None,
    ) -> CustomPromptSetList:
        """List custom prompt sets.

        The listing path is ``list-custom-prompt-sets``, not the ``custom-prompt-set``
        resource path used by every other method here.

        Args:
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter.
            status: Filter by prompt set status.
            active: Filter by active flag.
            archive: Filter by archive flag. Archived sets are hidden by default.

        Returns:
            One page of prompt sets, with the total in ``pagination``.
        """
        params = _listing_params(skip=skip, limit=limit, search=search)
        if status is not None:
            params["status"] = status
        if active is not None:
            params["active"] = _bool_param(active)
        if archive is not None:
            params["archive"] = _bool_param(archive)

        return request(
            RequestSpec[CustomPromptSetList](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/list-custom-prompt-sets",
                params=params,
                auth=self._auth,
                response_model=CustomPromptSetList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_prompt_set(self, uuid: str) -> CustomPromptSetResponse:
        """Get one prompt set.

        Args:
            uuid: The prompt set UUID.

        Returns:
            The prompt set.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "prompt set uuid")
        return request(
            RequestSpec[CustomPromptSetResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/custom-prompt-set/{uuid}",
                auth=self._auth,
                response_model=CustomPromptSetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update_prompt_set(
        self, uuid: str, body: CustomPromptSetUpdateRequest
    ) -> CustomPromptSetResponse:
        """Update a prompt set.

        Args:
            uuid: The prompt set UUID.
            body: A patch body -- send only the keys being changed.

        Returns:
            The updated prompt set.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "prompt set uuid")
        return request(
            RequestSpec[CustomPromptSetResponse](
                method="PUT",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/custom-prompt-set/{uuid}",
                body=body,
                auth=self._auth,
                response_model=CustomPromptSetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def archive_prompt_set(
        self, uuid: str, body: CustomPromptSetArchiveRequest
    ) -> CustomPromptSetResponse:
        """Archive or unarchive a prompt set.

        Archiving hides a set from the default listing; it is not a delete, and jobs that
        already ran against it keep resolving their snapshot.

        Args:
            uuid: The prompt set UUID.
            body: ``archive`` true to hide, false to restore.

        Returns:
            The updated prompt set.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "prompt set uuid")
        return request(
            RequestSpec[CustomPromptSetResponse](
                method="PUT",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/custom-prompt-set/{uuid}/archive",
                body=body,
                auth=self._auth,
                response_model=CustomPromptSetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_prompt_set_reference(self, uuid: str) -> CustomPromptSetReference:
        """Resolve a prompt set to the reference a data plane job carries.

        The reference is a flat record with no pagination envelope, and it is what a job
        payload should quote rather than the full prompt set.

        Args:
            uuid: The prompt set UUID.

        Returns:
            The prompt set reference.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "prompt set uuid")
        return request(
            RequestSpec[CustomPromptSetReference](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/custom-prompt-set/{uuid}/reference",
                auth=self._auth,
                response_model=CustomPromptSetReference,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_prompt_set_version_info(
        self, uuid: str, *, version: str | None = None
    ) -> CustomPromptSetVersionInfo:
        """Get version information for a prompt set.

        Prompt sets are versioned by snapshot so a finished job keeps reporting against
        the prompts as they were when it ran. Omit ``version`` for the live snapshot.

        Args:
            uuid: The prompt set UUID.
            version: A specific snapshot identifier.

        Returns:
            The snapshot's status, stats, and whether it is the latest.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "prompt set uuid")
        params: dict[str, str | Sequence[str]] = {}
        if version is not None:
            params["version"] = version

        return request(
            RequestSpec[CustomPromptSetVersionInfo](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/custom-prompt-set/{uuid}/version-info",
                params=params or None,
                auth=self._auth,
                response_model=CustomPromptSetVersionInfo,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_active_prompt_sets(self) -> CustomPromptSetListActive:
        """List the prompt sets a CUSTOM job may reference.

        Unpaginated and unfiltered: this is the eligibility list, not a view of the
        catalogue. Use :meth:`list_prompt_sets` to browse.

        Returns:
            The active prompt sets, as references.
        """
        return request(
            RequestSpec[CustomPromptSetListActive](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/active-custom-prompt-sets",
                auth=self._auth,
                response_model=CustomPromptSetListActive,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def download_template(self, uuid: str) -> str:
        """Download the CSV template for a prompt set.

        The template's header row names the columns :meth:`upload_prompts_csv` expects for
        this particular set, so the round trip is: create the set, download the template,
        fill it in, upload it.

        This is the one method here that does not go through the shared transport. The
        response is ``text/csv`` and the transport validates every 2xx body as JSON, so
        the request is assembled by hand -- as the reference implementation also does for
        this endpoint. The retry budget and error mapping are still the shared ones, so a
        5xx is retried and a 4xx raises the same error type as any other call. The
        ``service-name`` header the transport adds is omitted here, matching the
        reference. A ``raw_text`` mode on the transport would retire all of this.

        Args:
            uuid: The prompt set UUID.

        Returns:
            The CSV text, unparsed.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
            AISecClientError: If the service answers 4xx.
            AISecServerError: If the service answers 5xx and the retry budget runs out.
        """
        _assert_uuid(uuid, "prompt set uuid")
        path = f"{RED_TEAM_CUSTOM_ATTACK_PATH}/download-template/{uuid}"
        # One free re-auth per call, matching the transport: a token expiring mid-run is
        # expected, but an endpoint answering 403 for some other reason must not loop.
        auth_retry_used = False

        def attempt(_attempt: int) -> httpx.Response:
            prepared = self._auth.prepare(
                PreparedRequest(
                    method="GET",
                    url=build_url(self._endpoint, path, None),
                    headers={"User-Agent": USER_AGENT},
                )
            )
            return self._http.request(prepared.method, prepared.url, headers=prepared.headers)

        def on_retryable_failure(response: httpx.Response) -> bool:
            nonlocal auth_retry_used
            if auth_retry_used or not self._auth.on_unauthorized(response):
                return False
            auth_retry_used = True
            return True

        response = execute_with_retry(
            max_retries=self._num_retries,
            execute=attempt,
            on_retryable_failure=on_retryable_failure,
        )
        return response.text

    def upload_prompts_csv(
        self,
        prompt_set_uuid: str,
        file: bytes | BinaryIO,
        *,
        filename: str = "prompts.csv",
    ) -> BaseResponse:
        """Bulk-load prompts into a prompt set from a CSV file.

        The target set is named in the query string rather than the path, and the body is
        multipart rather than JSON.

        Args:
            prompt_set_uuid: The prompt set UUID.
            file: CSV bytes, or an open binary file.
            filename: Part filename. Cosmetic, but it shows up in service-side logs.

        Returns:
            The upload envelope. A successful upload sometimes returns no body at all,
            which is reported as a synthesised ``201``.

        Raises:
            AISecPayloadError: If ``prompt_set_uuid`` is not a UUID.
        """
        _assert_uuid(prompt_set_uuid, "prompt set uuid")
        result = request(
            RequestSpec[BaseResponse | None](
                method="POST",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/upload-custom-prompts-csv",
                params={"prompt_set_uuid": prompt_set_uuid},
                files={"file": (filename, file, _CSV_CONTENT_TYPE)},
                auth=self._auth,
                response_model=BaseResponse,
                allow_empty_body=True,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )
        if result is None:
            return BaseResponse(message="ok", status=_UPLOAD_CREATED_STATUS)
        return result

    # -- Prompts ------------------------------------------------------------

    def create_prompt(self, body: CustomPromptCreateRequest) -> CustomPromptResponse:
        """Add one prompt to a prompt set.

        The path nests under ``custom-prompt-set`` with no set id in it -- the set is
        named by ``prompt_set_id`` in the body instead.

        Args:
            body: The prompt text, its set, and any goal or property tags.

        Returns:
            The created prompt.
        """
        return request(
            RequestSpec[CustomPromptResponse](
                method="POST",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/custom-prompt-set/custom-prompt",
                body=body,
                auth=self._auth,
                response_model=CustomPromptResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_prompts(
        self,
        prompt_set_uuid: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        status: str | None = None,
        active: bool | None = None,
    ) -> CustomPromptList:
        """List the prompts in one prompt set.

        Args:
            prompt_set_uuid: The prompt set UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter over prompt text.
            status: Filter by prompt status.
            active: Filter by active flag.

        Returns:
            One page of prompts. Rows carry no ``prompt_set_id`` -- the list is scoped.

        Raises:
            AISecPayloadError: If ``prompt_set_uuid`` is not a UUID.
        """
        _assert_uuid(prompt_set_uuid, "prompt set uuid")
        params = _listing_params(skip=skip, limit=limit, search=search)
        if status is not None:
            params["status"] = status
        if active is not None:
            params["active"] = _bool_param(active)

        return request(
            RequestSpec[CustomPromptList](
                method="GET",
                base_url=self._endpoint,
                path=(
                    f"{RED_TEAM_CUSTOM_ATTACK_PATH}/custom-prompt-set"
                    f"/{prompt_set_uuid}/list-custom-prompts"
                ),
                params=params,
                auth=self._auth,
                response_model=CustomPromptList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_prompt(self, prompt_set_uuid: str, prompt_uuid: str) -> CustomPromptResponse:
        """Get one prompt.

        Args:
            prompt_set_uuid: The prompt set UUID.
            prompt_uuid: The prompt UUID.

        Returns:
            The prompt.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        _assert_uuid(prompt_set_uuid, "prompt set uuid")
        _assert_uuid(prompt_uuid, "prompt uuid")
        return request(
            RequestSpec[CustomPromptResponse](
                method="GET",
                base_url=self._endpoint,
                path=self._prompt_path(prompt_set_uuid, prompt_uuid),
                auth=self._auth,
                response_model=CustomPromptResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update_prompt(
        self, prompt_set_uuid: str, prompt_uuid: str, body: CustomPromptUpdateRequest
    ) -> CustomPromptResponse:
        """Update a prompt.

        Args:
            prompt_set_uuid: The prompt set UUID.
            prompt_uuid: The prompt UUID.
            body: A patch body -- send only the keys being changed.

        Returns:
            The updated prompt.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        _assert_uuid(prompt_set_uuid, "prompt set uuid")
        _assert_uuid(prompt_uuid, "prompt uuid")
        return request(
            RequestSpec[CustomPromptResponse](
                method="PUT",
                base_url=self._endpoint,
                path=self._prompt_path(prompt_set_uuid, prompt_uuid),
                body=body,
                auth=self._auth,
                response_model=CustomPromptResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete_prompt(self, prompt_set_uuid: str, prompt_uuid: str) -> BaseResponse | None:
        """Delete a prompt.

        Args:
            prompt_set_uuid: The prompt set UUID.
            prompt_uuid: The prompt UUID.

        Returns:
            The delete envelope, or ``None`` -- the service answers 200 with a body or 204
            with none, from the same call.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        _assert_uuid(prompt_set_uuid, "prompt set uuid")
        _assert_uuid(prompt_uuid, "prompt uuid")
        return request(
            RequestSpec[BaseResponse | None](
                method="DELETE",
                base_url=self._endpoint,
                path=self._prompt_path(prompt_set_uuid, prompt_uuid),
                auth=self._auth,
                response_model=BaseResponse,
                allow_empty_body=True,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    @staticmethod
    def _prompt_path(prompt_set_uuid: str, prompt_uuid: str) -> str:
        """Build the get/update/delete path for one prompt."""
        return (
            f"{RED_TEAM_CUSTOM_ATTACK_PATH}/custom-prompt-set"
            f"/{prompt_set_uuid}/custom-prompt/{prompt_uuid}"
        )

    # -- Properties ---------------------------------------------------------

    def get_property_names(self) -> PropertyNamesListResponse:
        """List every property name declared for the tenant.

        Returns:
            The declared names. A prompt set may only reference names from this list.
        """
        return request(
            RequestSpec[PropertyNamesListResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/property-names",
                auth=self._auth,
                response_model=PropertyNamesListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create_property_name(self, body: PropertyNameCreateRequest) -> BaseResponse | None:
        """Declare a new property name for the tenant.

        Args:
            body: The name to declare.

        Returns:
            The creation envelope, or ``None`` when the service answers with no body.
        """
        return request(
            RequestSpec[BaseResponse | None](
                method="POST",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/property-names",
                body=body,
                auth=self._auth,
                response_model=BaseResponse,
                allow_empty_body=True,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_property_values(self, property_name: str) -> PropertyValuesResponse:
        """List the values declared for one property name.

        The name is a path segment, so it is percent-encoded: property names are
        tenant-authored and may contain spaces or slashes.

        Args:
            property_name: The declared property name.

        Returns:
            The name and its allowed values.
        """
        encoded = quote(property_name, safe="")
        return request(
            RequestSpec[PropertyValuesResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/property-values/{encoded}",
                auth=self._auth,
                response_model=PropertyValuesResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_property_values_multiple(
        self, property_names: Sequence[str]
    ) -> PropertyValuesMultipleResponse:
        """List values for several property names at once.

        Names go out as a repeated ``property_names`` key, not a comma-joined value -- a
        comma is legal inside a property name.

        Args:
            property_names: The declared property names to look up.

        Returns:
            Values keyed by property name.
        """
        return request(
            RequestSpec[PropertyValuesMultipleResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/property-values",
                params={"property_names": list(property_names)},
                auth=self._auth,
                response_model=PropertyValuesMultipleResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create_property_value(self, body: PropertyValueCreateRequest) -> BaseResponse:
        """Declare an allowed value for an existing property name.

        Args:
            body: The property name and the value to allow.

        Returns:
            The creation envelope.
        """
        return request(
            RequestSpec[BaseResponse](
                method="POST",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACK_PATH}/property-values",
                body=body,
                auth=self._auth,
                response_model=BaseResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


# ---------------------------------------------------------------------------
# Data plane -- custom attack reports
# ---------------------------------------------------------------------------


class RedTeamCustomAttackReportsClient(_RedTeamPlaneClient):
    """Reads the report a CUSTOM job produced.

    The paths split on prefix rather than on the identifier: prompt-shaped views hang off
    ``report/{job_id}`` and attack-shaped views off ``job/{job_id}``, with the same job
    UUID in both. Using the wrong prefix is a 404, not a redirect.

    Example:
        >>> client = RedTeamCustomAttackReportsClient()
        >>> client.get_report("550e8400-e29b-41d4-a716-446655440000").asr
        0.15
    """

    _DEFAULT_ENDPOINT: ClassVar[str] = DEFAULT_RED_TEAM_DATA_ENDPOINT

    def get_report(self, job_id: str) -> CustomAttackReportResponse:
        """Get the custom attack report for a job.

        Args:
            job_id: The job UUID.

        Returns:
            Totals, score, attack success rate, and the per-prompt-set breakdown.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[CustomAttackReportResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACKS_REPORT_PATH}/report/{job_id}",
                auth=self._auth,
                response_model=CustomAttackReportResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_prompt_sets(self, job_id: str) -> PromptSetsReportResponse:
        """Get the prompt-set breakdown for a job.

        Args:
            job_id: The job UUID.

        Returns:
            One summary per prompt set, plus the filters the service applied.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[PromptSetsReportResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACKS_REPORT_PATH}/report/{job_id}/prompt-sets",
                auth=self._auth,
                response_model=PromptSetsReportResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_prompts_by_set(
        self,
        job_id: str,
        prompt_set_id: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        is_threat: bool | None = None,
    ) -> list[PromptDetailResponse]:
        """List the prompts a job ran from one prompt set.

        Args:
            job_id: The job UUID.
            prompt_set_id: The prompt set UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter over prompt text.
            is_threat: Keep only prompts that did, or did not, breach the target.

        Returns:
            The prompt details, as a bare array -- this endpoint sends no pagination
            envelope even though it takes pagination parameters.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        validate_job_id(job_id)
        _assert_uuid(prompt_set_id, "prompt set id")

        params = _listing_params(skip=skip, limit=limit, search=search)
        if is_threat is not None:
            params["is_threat"] = _bool_param(is_threat)

        return request(
            RequestSpec[list[PromptDetailResponse]](
                method="GET",
                base_url=self._endpoint,
                path=(
                    f"{RED_TEAM_CUSTOM_ATTACKS_REPORT_PATH}/report/{job_id}"
                    f"/prompt-set/{prompt_set_id}/prompts"
                ),
                params=params,
                auth=self._auth,
                response_model=list[PromptDetailResponse],
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_prompt_detail(self, job_id: str, prompt_id: str) -> PromptDetailResponse:
        """Get everything a job learned about one prompt.

        Args:
            job_id: The job UUID.
            prompt_id: The prompt UUID.

        Returns:
            The prompt, its goal, its property tags, and the target's responses.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        validate_job_id(job_id)
        _assert_uuid(prompt_id, "prompt id")
        return request(
            RequestSpec[PromptDetailResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACKS_REPORT_PATH}/report/{job_id}/prompt/{prompt_id}",
                auth=self._auth,
                response_model=PromptDetailResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_custom_attacks(
        self,
        job_id: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        threat: bool | None = None,
        prompt_set_id: str | None = None,
        property_value: str | None = None,
    ) -> CustomAttacksListResponse:
        """List the attacks a job ran.

        Filtering by ``property_value`` takes the value alone, not ``name=value``: values
        are unique across the tenant, and a name-qualified string matches nothing.

        Args:
            job_id: The job UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter.
            threat: Keep only attacks that did, or did not, breach the target.
            prompt_set_id: Restrict to one prompt set.
            property_value: Restrict to prompts tagged with this property value.

        Returns:
            One page of attacks. Row shape follows the filters, so ``data`` is untyped.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        params = _listing_params(skip=skip, limit=limit, search=search)
        if threat is not None:
            params["threat"] = _bool_param(threat)
        if prompt_set_id is not None:
            params["prompt_set_id"] = prompt_set_id
        if property_value is not None:
            params["property_value"] = property_value

        return request(
            RequestSpec[CustomAttacksListResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACKS_REPORT_PATH}/job/{job_id}/list-custom-attacks",
                params=params,
                auth=self._auth,
                response_model=CustomAttacksListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_attack_outputs(self, job_id: str, attack_id: str) -> list[CustomAttackOutput]:
        """Get every target response recorded for one attack.

        One attack fans out to one output per target, so this is a list even for a job
        with a single target.

        Args:
            job_id: The job UUID.
            attack_id: The attack UUID.

        Returns:
            The recorded outputs.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        validate_job_id(job_id)
        _assert_uuid(attack_id, "attack id")
        return request(
            RequestSpec[list[CustomAttackOutput]](
                method="GET",
                base_url=self._endpoint,
                path=(
                    f"{RED_TEAM_CUSTOM_ATTACKS_REPORT_PATH}/job/{job_id}"
                    f"/attack/{attack_id}/list-outputs"
                ),
                auth=self._auth,
                response_model=list[CustomAttackOutput],
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_property_stats(self, job_id: str) -> list[PropertyStatistic]:
        """Get the per-property success breakdown for a job.

        Args:
            job_id: The job UUID.

        Returns:
            One entry per property name, each carrying its value-level success rates.

        Raises:
            AISecPayloadError: If ``job_id`` is not a UUID.
        """
        validate_job_id(job_id)
        return request(
            RequestSpec[list[PropertyStatistic]](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CUSTOM_ATTACKS_REPORT_PATH}/job/{job_id}/property-stats",
                auth=self._auth,
                response_model=list[PropertyStatistic],
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


# ---------------------------------------------------------------------------
# Management plane -- EULA
# ---------------------------------------------------------------------------


class RedTeamEulaClient(_RedTeamPlaneClient):
    """Reads and accepts the Red Team end user license agreement.

    Scans are refused tenant-wide until the EULA is accepted, and the refusal surfaces as
    a permission error rather than anything that mentions a license -- so check
    :meth:`get_status` first when a freshly provisioned tenant will not scan.

    Example:
        >>> client = RedTeamEulaClient()
        >>> client.accept(EulaAcceptRequest(eula_content=client.get_content().content))
        EulaResponse(is_accepted=True, ...)
    """

    _DEFAULT_ENDPOINT: ClassVar[str] = DEFAULT_RED_TEAM_MGMT_ENDPOINT

    def get_content(self) -> EulaContentResponse:
        """Get the current EULA text.

        Returns:
            The agreement text to present and then echo back to :meth:`accept`.
        """
        return request(
            RequestSpec[EulaContentResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_EULA_PATH}/content",
                auth=self._auth,
                response_model=EulaContentResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_status(self) -> EulaResponse:
        """Get the tenant's acceptance state.

        Returns:
            Whether the EULA is accepted, and by whom.
        """
        return request(
            RequestSpec[EulaResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_EULA_PATH}/status",
                auth=self._auth,
                response_model=EulaResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def accept(self, body: EulaAcceptRequest) -> EulaResponse:
        """Accept the EULA on behalf of the tenant.

        The text is echoed back in ``eula_content`` so the service can record which
        revision was accepted; pass the string from :meth:`get_content` unmodified.

        Args:
            body: The agreement text, and optionally an acceptance timestamp.

        Returns:
            The resulting acceptance state.
        """
        return request(
            RequestSpec[EulaResponse](
                method="POST",
                base_url=self._endpoint,
                path=f"{RED_TEAM_EULA_PATH}/accept",
                body=body,
                auth=self._auth,
                response_model=EulaResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


# ---------------------------------------------------------------------------
# Management plane -- instances, devices, and registry credentials
# ---------------------------------------------------------------------------


class RedTeamInstancesClient(_RedTeamPlaneClient):
    """Provisions tenant instances, registers licensed devices, and mints registry tokens.

    Tenant IDs here are licensing identifiers rather than UUIDs, so they are deliberately
    not format-checked -- validating them as UUIDs would reject values the service
    accepts.

    Example:
        >>> client = RedTeamInstancesClient()
        >>> client.get_registry_credentials().token
        'eyJ...'
    """

    _DEFAULT_ENDPOINT: ClassVar[str] = DEFAULT_RED_TEAM_MGMT_ENDPOINT

    def create_instance(self, body: InstanceRequest) -> InstanceResponse:
        """Provision a Red Team instance for a tenant.

        Args:
            body: Tenant, app, and region, plus any licensing extras.

        Returns:
            The provisioning acknowledgement.
        """
        return request(
            RequestSpec[InstanceResponse](
                method="POST",
                base_url=self._endpoint,
                path=RED_TEAM_INSTANCES_PATH,
                body=body,
                auth=self._auth,
                response_model=InstanceResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_instance(self, tenant_id: str) -> InstanceGetResponse:
        """Get a provisioned instance.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            The instance, including its deployment profiles.
        """
        return request(
            RequestSpec[InstanceGetResponse](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_INSTANCES_PATH}/{tenant_id}",
                auth=self._auth,
                response_model=InstanceGetResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update_instance(self, tenant_id: str, body: InstanceRequest) -> InstanceResponse:
        """Update a provisioned instance.

        The body is the full instance, not a patch: PUT replaces.

        Args:
            tenant_id: The tenant identifier.
            body: The complete instance definition.

        Returns:
            The acknowledgement.
        """
        return request(
            RequestSpec[InstanceResponse](
                method="PUT",
                base_url=self._endpoint,
                path=f"{RED_TEAM_INSTANCES_PATH}/{tenant_id}",
                body=body,
                auth=self._auth,
                response_model=InstanceResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete_instance(self, tenant_id: str) -> InstanceResponse:
        """Deprovision a tenant instance.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            The acknowledgement.
        """
        return request(
            RequestSpec[InstanceResponse](
                method="DELETE",
                base_url=self._endpoint,
                path=f"{RED_TEAM_INSTANCES_PATH}/{tenant_id}",
                auth=self._auth,
                response_model=InstanceResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create_devices(self, tenant_id: str, body: DeviceRequest) -> DeviceResponse:
        """Register devices against an instance.

        Registration is partial-success: the envelope can report success while individual
        entries in ``devices`` carry an error, so check each one.

        Args:
            tenant_id: The tenant identifier.
            body: The owning instance and the devices to register.

        Returns:
            Per-device outcomes.
        """
        return request(
            RequestSpec[DeviceResponse](
                method="POST",
                base_url=self._endpoint,
                path=f"{RED_TEAM_INSTANCES_PATH}/{tenant_id}/devices",
                body=body,
                auth=self._auth,
                response_model=DeviceResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update_devices(self, tenant_id: str, body: DeviceRequest) -> DeviceResponse:
        """Update registered devices.

        PATCH here, where :meth:`update_instance` is PUT -- the device collection is
        merged, not replaced, so omitted devices are left alone rather than deregistered.

        Args:
            tenant_id: The tenant identifier.
            body: The owning instance and the devices to update.

        Returns:
            Per-device outcomes.
        """
        return request(
            RequestSpec[DeviceResponse](
                method="PATCH",
                base_url=self._endpoint,
                path=f"{RED_TEAM_INSTANCES_PATH}/{tenant_id}/devices",
                body=body,
                auth=self._auth,
                response_model=DeviceResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete_devices(self, tenant_id: str, serial_numbers: str) -> DeviceResponse:
        """Deregister devices by serial number.

        Args:
            tenant_id: The tenant identifier.
            serial_numbers: Comma-separated serial numbers, sent as a single query
                parameter. Repeated keys are not accepted here.

        Returns:
            Per-device outcomes.
        """
        return request(
            RequestSpec[DeviceResponse](
                method="DELETE",
                base_url=self._endpoint,
                path=f"{RED_TEAM_INSTANCES_PATH}/{tenant_id}/devices",
                params={"serial_numbers": serial_numbers},
                auth=self._auth,
                response_model=DeviceResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_registry_credentials(self) -> RegistryCredentials:
        """Mint credentials for the network broker container registry.

        A POST despite reading like a getter: each call mints a fresh short-lived token
        rather than returning a stored one. Fetch per pull; do not cache.

        Returns:
            The registry token and its expiry.
        """
        return request(
            RequestSpec[RegistryCredentials](
                method="POST",
                base_url=self._endpoint,
                path=RED_TEAM_REGISTRY_CREDENTIALS_PATH,
                auth=self._auth,
                response_model=RegistryCredentials,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


# ---------------------------------------------------------------------------
# Network broker
# ---------------------------------------------------------------------------


class RedTeamNetworkBrokerClient(_RedTeamPlaneClient):
    """Manages the network broker channels used to reach targets on private networks.

    Sits on its own base URL -- a sub-path of the data plane -- but authenticates with the
    same Red Team service account, so it can share an ``oauth_client`` with the others.

    Example:
        >>> client = RedTeamNetworkBrokerClient()
        >>> client.list_channels(status=["ONLINE", "DRAFT"], limit=10).pagination.total_items
        2
    """

    _DEFAULT_ENDPOINT: ClassVar[str] = DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT

    def list_channels(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        status: str | Sequence[str] | None = None,
        include_all_if_empty: bool | None = None,
    ) -> ChannelListResponse:
        """List network broker channels.

        ``status`` goes out as a repeated key even when only one value is given, because
        the endpoint reads it as a set. A comma-joined string is treated as one unknown
        status and matches nothing.

        Args:
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text filter over channel name.
            status: One status, or several to match any of.
            include_all_if_empty: Return every channel when the filters match none,
                rather than an empty page.

        Returns:
            One page of channels. ``data`` is an empty list when the tenant has none.
        """
        params = _listing_params(skip=skip, limit=limit, search=search)
        if status is not None:
            params["status"] = [status] if isinstance(status, str) else list(status)
        if include_all_if_empty is not None:
            params["include_all_if_empty"] = _bool_param(include_all_if_empty)

        return request(
            RequestSpec[ChannelListResponse](
                method="GET",
                base_url=self._endpoint,
                path=RED_TEAM_CHANNELS_PATH,
                params=params,
                auth=self._auth,
                response_model=ChannelListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create_channel(self, body: CreateChannelRequest) -> Channel:
        """Create a network broker channel.

        A new channel starts in ``DRAFT`` and only reaches ``ONLINE`` once a broker client
        connects to it, so the returned status is not yet usable for a scan.

        Args:
            body: Channel name, and an optional description.

        Returns:
            The created channel.
        """
        return request(
            RequestSpec[Channel](
                method="POST",
                base_url=self._endpoint,
                path=RED_TEAM_CHANNELS_PATH,
                body=body,
                auth=self._auth,
                response_model=Channel,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_channel_stats(self) -> ChannelStats:
        """Get broker infrastructure details and channel counts.

        ``stats`` is a sibling path of the channel collection, not a channel id -- the
        server would resolve it as one, so it has a constant of its own.

        Returns:
            Counts, plus the registry, chart, and image coordinates needed to deploy a
            broker client.
        """
        return request(
            RequestSpec[ChannelStats](
                method="GET",
                base_url=self._endpoint,
                path=RED_TEAM_CHANNELS_STATS_PATH,
                auth=self._auth,
                response_model=ChannelStats,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_channel(self, channel_id: str) -> Channel:
        """Get one channel.

        Args:
            channel_id: The channel UUID.

        Returns:
            The channel.

        Raises:
            AISecPayloadError: If ``channel_id`` is not a UUID.
        """
        _assert_uuid(channel_id, "channel id")
        return request(
            RequestSpec[Channel](
                method="GET",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CHANNELS_PATH}/{channel_id}",
                auth=self._auth,
                response_model=Channel,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update_channel(self, channel_id: str, body: UpdateChannelRequest) -> Channel:
        """Rename a channel or change its description.

        Only the name and description are writable; status and connection state are
        server-owned.

        Args:
            channel_id: The channel UUID.
            body: The fields to change.

        Returns:
            The updated channel.

        Raises:
            AISecPayloadError: If ``channel_id`` is not a UUID.
        """
        _assert_uuid(channel_id, "channel id")
        return request(
            RequestSpec[Channel](
                method="PATCH",
                base_url=self._endpoint,
                path=f"{RED_TEAM_CHANNELS_PATH}/{channel_id}",
                body=body,
                auth=self._auth,
                response_model=Channel,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


__all__ = [
    "RedTeamCustomAttackReportsClient",
    "RedTeamCustomAttacksClient",
    "RedTeamEulaClient",
    "RedTeamInstancesClient",
    "RedTeamNetworkBrokerClient",
]
