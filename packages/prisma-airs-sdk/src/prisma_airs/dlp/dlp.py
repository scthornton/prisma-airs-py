"""Clients for the DLP administration APIs served under ``/v2/api``.

Data Loss Prevention runs on its own host, ``api.dlp.paloaltonetworks.com``, but shares the
management plane's OAuth2 service account: one set of ``PANW_MGMT_*`` credentials covers
both, and there is no DLP-specific environment prefix. The endpoint is a constructor
argument for that reason -- there is no environment variable to override it with.

:class:`DlpClient` owns the credentials and the connection; the four resource clients hang
off it as ``data_patterns``, ``data_profiles``, ``data_filtering_profiles``, and
``dictionaries``.

Every list endpoint answers with the Spring ``Page`` envelope, and it is returned verbatim
so callers can read ``total_elements`` and ``pageable`` without a second round trip.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal, TypeAlias
from urllib.parse import quote

import httpx

from prisma_airs._http.auth import OAuthAuth
from prisma_airs._http.transport import RequestSpec, request, serialize_body
from prisma_airs._http.types import AuthAdapter
from prisma_airs.auth.oauth import OAuthClient, resolve_credentials
from prisma_airs.constants import (
    CONTENT_TYPE_MERGE_PATCH,
    DEFAULT_DLP_ENDPOINT,
    DEFAULT_TIMEOUT_SECONDS,
    DLP_DATA_FILTERING_PROFILES_PATH,
    DLP_DATA_PATTERNS_PATH,
    DLP_DATA_PROFILES_PATH,
    DLP_DICTIONARIES_PATH,
    ENV_PREFIX_MGMT,
    MAX_NUMBER_OF_RETRIES,
)
from prisma_airs.errors import AISecPayloadError
from prisma_airs.models.dlp import (
    AdvancedDataProfileRequest,
    DataFilteringProfileRequest,
    DataFilteringProfileResponse,
    DataPatternPatchRequest,
    DataPatternRequest,
    DataPatternResponse,
    DataProfilePatchRequest,
    DataProfileResponse,
    DictionaryPatchRequest,
    DictionaryRequest,
    DictionaryResponse,
    PageDataFilteringProfileResponse,
    PageDataPatternResponse,
    PageDataProfileResponse,
    PageDictionaryResponse,
)

#: A dictionary's keyword file: text, which is sent as UTF-8, or raw bytes.
DictionaryFile: TypeAlias = str | bytes

#: Query parameters as the transport takes them -- a string, or a sequence of strings that
#: expands to repeated keys.
_QueryParams: TypeAlias = dict[str, str | Sequence[str]]


class _DlpSubclient:
    """Shared connection state for the four DLP resource clients.

    All four resources sit on one host behind one token, so they share a single HTTP client
    and a single auth adapter instead of each resolving credentials of their own.
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


class DataPatternsClient(_DlpSubclient):
    """The DLP data patterns resource (``/v2/api/data-patterns``).

    The full CRUD surface: list, create, get, replace, patch, delete. DELETE is a soft
    delete -- the pattern is archived server-side rather than erased.
    """

    def list(
        self,
        *,
        page: int | None = None,
        size: int | None = None,
        sort: Sequence[str] | None = None,
    ) -> PageDataPatternResponse:
        """List data patterns.

        Args:
            page: Zero-based page index. The server defaults to 0.
            size: Page size. The server defaults to 20.
            sort: ``property,(asc|desc)`` entries, one per sort field.

        Returns:
            One page of patterns, in the Spring ``Page`` envelope.

        Raises:
            AISecPayloadError: If ``sort`` is a bare string.
        """
        return request(
            RequestSpec[PageDataPatternResponse](
                method="GET",
                base_url=self._base_url,
                path=DLP_DATA_PATTERNS_PATH,
                params=_page_params(page, size, sort),
                auth=self._auth,
                response_model=PageDataPatternResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create(self, body: DataPatternRequest) -> DataPatternResponse:
        """Create a custom data pattern.

        Args:
            body: The pattern to create.

        Returns:
            The created pattern, carrying its server-assigned ``id``.
        """
        return request(
            RequestSpec[DataPatternResponse](
                method="POST",
                base_url=self._base_url,
                path=DLP_DATA_PATTERNS_PATH,
                body=body,
                auth=self._auth,
                response_model=DataPatternResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, resource_id: str) -> DataPatternResponse:
        """Fetch one data pattern.

        Args:
            resource_id: Server-assigned pattern id.

        Returns:
            The pattern.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DataPatternResponse](
                method="GET",
                base_url=self._base_url,
                path=_item_path(DLP_DATA_PATTERNS_PATH, resource_id),
                auth=self._auth,
                response_model=DataPatternResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def replace(self, resource_id: str, body: DataPatternRequest) -> DataPatternResponse:
        """Replace a data pattern wholesale (PUT).

        A PUT is a full replace: fields absent from ``body`` are not preserved. Use
        :meth:`patch` to change one field and leave the rest alone.

        Args:
            resource_id: Pattern to replace.
            body: The complete new pattern.

        Returns:
            The updated pattern as the service echoes it back.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DataPatternResponse](
                method="PUT",
                base_url=self._base_url,
                path=_item_path(DLP_DATA_PATTERNS_PATH, resource_id),
                body=body,
                auth=self._auth,
                response_model=DataPatternResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def patch(self, resource_id: str, body: DataPatternPatchRequest) -> DataPatternResponse:
        """Partially update a data pattern with a JSON Merge Patch (RFC 7396).

        The body goes out as ``body.merge_patch_dump()`` rather than as the model. The
        transport's model path dumps with ``exclude_none=True``, which strips exactly the
        ``null`` that tells the service to clear a field -- handing it the model would turn
        "clear the description" into a silent no-op.

        Args:
            resource_id: Pattern to update.
            body: Fields to change. An omitted field is left alone; one explicitly set to
                ``None`` is cleared server-side.

        Returns:
            The updated pattern.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DataPatternResponse](
                method="PATCH",
                base_url=self._base_url,
                path=_item_path(DLP_DATA_PATTERNS_PATH, resource_id),
                body=body.merge_patch_dump(),
                content_type=CONTENT_TYPE_MERGE_PATCH,
                auth=self._auth,
                response_model=DataPatternResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, resource_id: str) -> None:
        """Soft-delete (archive) a data pattern.

        Args:
            resource_id: Pattern to archive.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        request(
            RequestSpec[None](
                method="DELETE",
                base_url=self._base_url,
                path=_item_path(DLP_DATA_PATTERNS_PATH, resource_id),
                auth=self._auth,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class DataProfilesClient(_DlpSubclient):
    """The DLP data profiles resource (``/v2/api/data-profiles``).

    CRUD without the D: list, create, get, replace, patch. The API exposes no DELETE for
    data profiles -- retiring one means patching it to a deleted lifecycle state
    (``profile_status: "deleted"``), not calling a delete endpoint that does not exist.
    """

    def list(
        self,
        *,
        page: int | None = None,
        size: int | None = None,
        sort: Sequence[str] | None = None,
    ) -> PageDataProfileResponse:
        """List data profiles.

        Args:
            page: Zero-based page index. The server defaults to 0.
            size: Page size. The server defaults to 20.
            sort: ``property,(asc|desc)`` entries, one per sort field.

        Returns:
            One page of profiles, in the Spring ``Page`` envelope.

        Raises:
            AISecPayloadError: If ``sort`` is a bare string.
        """
        return request(
            RequestSpec[PageDataProfileResponse](
                method="GET",
                base_url=self._base_url,
                path=DLP_DATA_PROFILES_PATH,
                params=_page_params(page, size, sort),
                auth=self._auth,
                response_model=PageDataProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create(self, body: AdvancedDataProfileRequest) -> DataProfileResponse:
        """Create a data profile.

        Args:
            body: The profile to create, including its detection rules.

        Returns:
            The created profile, carrying its server-assigned ``id``.
        """
        return request(
            RequestSpec[DataProfileResponse](
                method="POST",
                base_url=self._base_url,
                path=DLP_DATA_PROFILES_PATH,
                body=body,
                auth=self._auth,
                response_model=DataProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, resource_id: str) -> DataProfileResponse:
        """Fetch one data profile.

        Args:
            resource_id: Server-assigned profile id.

        Returns:
            The profile.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DataProfileResponse](
                method="GET",
                base_url=self._base_url,
                path=_item_path(DLP_DATA_PROFILES_PATH, resource_id),
                auth=self._auth,
                response_model=DataProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def replace(self, resource_id: str, body: AdvancedDataProfileRequest) -> DataProfileResponse:
        """Replace a data profile wholesale (PUT).

        Args:
            resource_id: Profile to replace.
            body: The complete new profile. Fields absent from it are not preserved.

        Returns:
            The updated profile as the service echoes it back.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DataProfileResponse](
                method="PUT",
                base_url=self._base_url,
                path=_item_path(DLP_DATA_PROFILES_PATH, resource_id),
                body=body,
                auth=self._auth,
                response_model=DataProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def patch(self, resource_id: str, body: DataProfilePatchRequest) -> DataProfileResponse:
        """Partially update a data profile with a JSON Merge Patch (RFC 7396).

        Serialised with ``body.merge_patch_dump()`` for the reason spelled out on
        :meth:`DataPatternsClient.patch`: the transport's model path would drop the very
        ``null`` that clears a field.

        Args:
            resource_id: Profile to update.
            body: Fields to change. An omitted field is left alone; one explicitly set to
                ``None`` is cleared server-side.

        Returns:
            The updated profile.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DataProfileResponse](
                method="PATCH",
                base_url=self._base_url,
                path=_item_path(DLP_DATA_PROFILES_PATH, resource_id),
                body=body.merge_patch_dump(),
                content_type=CONTENT_TYPE_MERGE_PATCH,
                auth=self._auth,
                response_model=DataProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class DataFilteringProfilesClient(_DlpSubclient):
    """The DLP data filtering profiles resource (``/v2/api/data-filtering-profiles``).

    Read and full-replace only. There is no create and no delete: these profiles come into
    existence with the deployment, and the API offers no way to add or remove one.
    """

    def list(
        self,
        *,
        page: int | None = None,
        size: int | None = None,
        sort: Sequence[str] | None = None,
        status: Literal["enabled", "disabled"] | None = None,
        name: str | None = None,
    ) -> PageDataFilteringProfileResponse:
        """List data filtering profiles.

        Args:
            page: Zero-based page index. The server defaults to 0.
            size: Page size. The server defaults to 20.
            sort: ``property,(asc|desc)`` entries, one per sort field.
            status: Restrict to enabled or disabled profiles.
            name: Partial-match filter on the profile name.

        Returns:
            One page of filtering profiles, in the Spring ``Page`` envelope.

        Raises:
            AISecPayloadError: If ``sort`` is a bare string.
        """
        params = _page_params(page, size, sort)
        if status is not None:
            params["status"] = status
        if name is not None:
            params["name"] = name

        return request(
            RequestSpec[PageDataFilteringProfileResponse](
                method="GET",
                base_url=self._base_url,
                path=DLP_DATA_FILTERING_PROFILES_PATH,
                params=params,
                auth=self._auth,
                response_model=PageDataFilteringProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, resource_id: str) -> DataFilteringProfileResponse:
        """Fetch one data filtering profile.

        Args:
            resource_id: Server-assigned profile id.

        Returns:
            The filtering profile.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DataFilteringProfileResponse](
                method="GET",
                base_url=self._base_url,
                path=_item_path(DLP_DATA_FILTERING_PROFILES_PATH, resource_id),
                auth=self._auth,
                response_model=DataFilteringProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def replace(
        self, resource_id: str, body: DataFilteringProfileRequest
    ) -> DataFilteringProfileResponse:
        """Replace a data filtering profile wholesale (PUT).

        This is the only way to change one of these profiles -- there is no PATCH -- so
        ``body`` has to carry every field that should survive the call.

        Args:
            resource_id: Profile to replace.
            body: The complete new profile.

        Returns:
            The updated profile as the service echoes it back.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DataFilteringProfileResponse](
                method="PUT",
                base_url=self._base_url,
                path=_item_path(DLP_DATA_FILTERING_PROFILES_PATH, resource_id),
                body=body,
                auth=self._auth,
                response_model=DataFilteringProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class DictionariesClient(_DlpSubclient):
    """The DLP dictionaries resource (``/v2/api/dictionaries``).

    Create and replace upload the keyword file as multipart, patch is a JSON Merge Patch,
    and delete answers 204. The keyword list itself is only ever returned when the request
    asks for it: without ``keywords=true`` the response omits it entirely, which reads the
    same as a dictionary that has none.
    """

    def list(
        self,
        *,
        page: int | None = None,
        size: int | None = None,
        sort: Sequence[str] | None = None,
        keywords: bool | None = None,
    ) -> PageDictionaryResponse:
        """List dictionaries.

        Args:
            page: Zero-based page index. The server defaults to 0.
            size: Page size. The server defaults to 20.
            sort: ``property,(asc|desc)`` entries, one per sort field.
            keywords: Include each dictionary's keyword array in the response. Named for
                the query parameter it sets, which the other methods here expose as
                ``include_keywords``.

        Returns:
            One page of dictionaries, in the Spring ``Page`` envelope.

        Raises:
            AISecPayloadError: If ``sort`` is a bare string.
        """
        params = _page_params(page, size, sort)
        if keywords is not None:
            params["keywords"] = _bool_param(keywords)

        return request(
            RequestSpec[PageDictionaryResponse](
                method="GET",
                base_url=self._base_url,
                path=DLP_DICTIONARIES_PATH,
                params=params,
                auth=self._auth,
                response_model=PageDictionaryResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create(
        self,
        *,
        metadata: DictionaryRequest,
        file: DictionaryFile,
        include_keywords: bool | None = None,
    ) -> DictionaryResponse:
        """Create a dictionary by uploading its keyword file.

        Args:
            metadata: The ``json`` part of the upload.
            file: The keyword file: text, encoded as UTF-8, or raw bytes.
            include_keywords: Return the stored keyword list in the response.

        Returns:
            The created dictionary, carrying its server-assigned ``id``.
        """
        return request(
            RequestSpec[DictionaryResponse](
                method="POST",
                base_url=self._base_url,
                path=DLP_DICTIONARIES_PATH,
                params=_keywords_param(include_keywords),
                files=_multipart(metadata, file),
                auth=self._auth,
                response_model=DictionaryResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, resource_id: str, *, include_keywords: bool | None = None) -> DictionaryResponse:
        """Fetch one dictionary.

        Args:
            resource_id: Server-assigned dictionary id.
            include_keywords: Return the stored keyword list. Left off, the response has no
                ``keywords`` field at all.

        Returns:
            The dictionary.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DictionaryResponse](
                method="GET",
                base_url=self._base_url,
                path=_item_path(DLP_DICTIONARIES_PATH, resource_id),
                params=_keywords_param(include_keywords),
                auth=self._auth,
                response_model=DictionaryResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def replace(
        self,
        resource_id: str,
        *,
        metadata: DictionaryRequest,
        file: DictionaryFile,
        include_keywords: bool | None = None,
    ) -> DictionaryResponse | None:
        """Replace a dictionary and its keyword file (PUT).

        Args:
            resource_id: Dictionary to replace.
            metadata: The ``json`` part of the upload.
            file: The replacement keyword file.
            include_keywords: Return the stored keyword list in the response.

        Returns:
            The updated dictionary, or ``None``. This endpoint answers either 200 with the
            resource or 204 with no body at all, and both are normal -- a ``None`` here
            means the replace succeeded, not that anything went wrong.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DictionaryResponse | None](
                method="PUT",
                base_url=self._base_url,
                path=_item_path(DLP_DICTIONARIES_PATH, resource_id),
                params=_keywords_param(include_keywords),
                files=_multipart(metadata, file),
                auth=self._auth,
                response_model=DictionaryResponse,
                allow_empty_body=True,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def patch(self, resource_id: str, body: DictionaryPatchRequest) -> DictionaryResponse:
        """Partially update a dictionary's metadata with a JSON Merge Patch (RFC 7396).

        Metadata only: the keyword file is replaced through :meth:`replace`, which is the
        multipart route. Serialised with ``body.merge_patch_dump()`` for the reason spelled
        out on :meth:`DataPatternsClient.patch`.

        Args:
            resource_id: Dictionary to update.
            body: Fields to change. An omitted field is left alone; one explicitly set to
                ``None`` is cleared server-side.

        Returns:
            The updated dictionary.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        return request(
            RequestSpec[DictionaryResponse](
                method="PATCH",
                base_url=self._base_url,
                path=_item_path(DLP_DICTIONARIES_PATH, resource_id),
                body=body.merge_patch_dump(),
                content_type=CONTENT_TYPE_MERGE_PATCH,
                auth=self._auth,
                response_model=DictionaryResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, resource_id: str) -> None:
        """Delete a dictionary.

        Args:
            resource_id: Dictionary to delete.

        Raises:
            AISecPayloadError: If ``resource_id`` is blank.
        """
        request(
            RequestSpec[None](
                method="DELETE",
                base_url=self._base_url,
                path=_item_path(DLP_DICTIONARIES_PATH, resource_id),
                auth=self._auth,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class DlpClient:
    """Entry point for the four DLP administration resources.

    Credentials resolve from the arguments, then from ``PANW_MGMT_*``. DLP has no prefix of
    its own -- it authenticates as the management service account -- so that is the only
    prefix consulted, and a missing credential names ``PANW_MGMT_CLIENT_ID`` rather than a
    DLP-specific variable that does not exist.

    Example:
        >>> dlp = DlpClient()
        >>> page = dlp.data_patterns.list(size=5, sort=["name,asc"])
        >>> page.total_elements
        1.0
    """

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
        http_client: httpx.Client | None = None,
        oauth_client: OAuthClient | None = None,
    ) -> None:
        """Resolve credentials and build the four resource clients.

        Args:
            client_id: OAuth2 client ID. Falls back to ``PANW_MGMT_CLIENT_ID``.
            client_secret: OAuth2 client secret. Falls back to ``PANW_MGMT_CLIENT_SECRET``.
            tsg_id: Tenant Service Group ID. Falls back to ``PANW_MGMT_TSG_ID``.
            endpoint: DLP base URL. There is no environment override for this one.
            token_endpoint: OAuth2 token URL. Falls back to ``PANW_MGMT_TOKEN_ENDPOINT``.
            num_retries: Retry budget for every call, 0 to 5.
            timeout: Request timeout, in seconds. Ignored when ``http_client`` is supplied.
            http_client: An HTTP client to send through. The caller keeps ownership of it.
            oauth_client: A token manager to reuse. Supply one to share a single token with
                other clients; the credential arguments are then unused.

        Raises:
            AISecPayloadError: If ``num_retries`` is outside 0 to 5.
            AISecMissingVariableError: If credentials could not be resolved.
        """
        retries = _validate_retries(num_retries)

        self._endpoint = endpoint or DEFAULT_DLP_ENDPOINT
        self._num_retries = retries
        self._owns_client = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)
        self._oauth = _resolve_oauth_client(
            oauth_client,
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            token_endpoint=token_endpoint,
            http_client=self._http,
            timeout=timeout,
        )

        # Plain bearer auth. DLP is not the AI Gateway: it takes no x-tsg-id header, and
        # the tenant it acts on is the one the token was scoped to.
        auth = OAuthAuth(self._oauth)

        self.data_patterns = DataPatternsClient(
            base_url=self._endpoint, auth=auth, num_retries=retries, http_client=self._http
        )
        self.data_profiles = DataProfilesClient(
            base_url=self._endpoint, auth=auth, num_retries=retries, http_client=self._http
        )
        self.data_filtering_profiles = DataFilteringProfilesClient(
            base_url=self._endpoint, auth=auth, num_retries=retries, http_client=self._http
        )
        self.dictionaries = DictionariesClient(
            base_url=self._endpoint, auth=auth, num_retries=retries, http_client=self._http
        )

    @property
    def endpoint(self) -> str:
        """The DLP base URL this client sends to."""
        return self._endpoint

    @property
    def oauth(self) -> OAuthClient:
        """The token manager backing all four resource clients."""
        return self._oauth

    def close(self) -> None:
        """Close the underlying HTTP client, if this instance created it."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> DlpClient:
        """Enter a context that closes the HTTP client on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the HTTP client if this instance owns it."""
        self.close()


def _resolve_oauth_client(
    oauth_client: OAuthClient | None,
    *,
    client_id: str | None,
    client_secret: str | None,
    tsg_id: str | None,
    token_endpoint: str | None,
    http_client: httpx.Client,
    timeout: float,
) -> OAuthClient:
    """Return the supplied token manager, or build one from resolved credentials.

    DLP authenticates as the management service account. ``PANW_MGMT`` is therefore the
    primary prefix and there is no fallback: naming it twice would only make a missing
    credential report ``PANW_MGMT_CLIENT_ID (or PANW_MGMT_CLIENT_ID)``.

    Args:
        oauth_client: A token manager to reuse, if the caller has one.
        client_id: OAuth2 client ID.
        client_secret: OAuth2 client secret.
        tsg_id: Tenant Service Group ID.
        token_endpoint: OAuth2 token URL.
        http_client: Client the token fetch shares, so there is one connection pool, one
            thing to close, and one transport for a test to intercept.
        timeout: Timeout for the token request.

    Returns:
        A token manager.

    Raises:
        AISecMissingVariableError: If credentials could not be resolved.
    """
    if oauth_client is not None:
        return oauth_client

    credentials = resolve_credentials(
        primary_env_prefix=ENV_PREFIX_MGMT,
        client_id=client_id,
        client_secret=client_secret,
        tsg_id=tsg_id,
        token_endpoint=token_endpoint,
        fallback_env_prefix=None,
    )
    return OAuthClient(
        client_id=credentials.client_id,
        client_secret=credentials.client_secret,
        tsg_id=credentials.tsg_id,
        token_endpoint=credentials.token_endpoint,
        http_client=http_client,
        timeout=timeout,
    )


def _page_params(page: int | None, size: int | None, sort: Sequence[str] | None) -> _QueryParams:
    """Build the pagination query shared by all four list endpoints.

    Only what the caller set is emitted, so the server's own defaults apply to the rest.
    The checks are against ``None`` rather than truthiness on purpose: ``page=0`` is the
    first page, not an absent value.

    Args:
        page: Zero-based page index.
        size: Page size.
        sort: ``property,(asc|desc)`` entries. Each goes out as its own ``sort=`` key --
            an entry already contains a comma, so joining entries with commas would be
            indistinguishable from one malformed entry.

    Returns:
        The query parameters, ready for the transport.

    Raises:
        AISecPayloadError: If ``sort`` is a bare string, which would otherwise be expanded
            one character at a time into as many ``sort=`` keys.
    """
    params: _QueryParams = {}
    if page is not None:
        params["page"] = str(page)
    if size is not None:
        params["size"] = str(size)
    if sort is not None:
        if isinstance(sort, str):
            raise AISecPayloadError(
                "sort must be a sequence of 'property,(asc|desc)' entries, not a bare string"
            )
        params["sort"] = list(sort)
    return params


def _keywords_param(include_keywords: bool | None) -> _QueryParams:
    """Build the ``keywords`` query for the single-dictionary endpoints."""
    return {} if include_keywords is None else {"keywords": _bool_param(include_keywords)}


def _bool_param(value: bool) -> str:
    """Render a boolean as the lowercase literal every other client of this API sends.

    ``str(True)`` gives ``"True"``, which is not that literal. Routing every flag through
    here keeps the query string in the spelling the service is used to receiving.
    """
    return "true" if value else "false"


def _item_path(collection_path: str, resource_id: str) -> str:
    """Build the item path for ``resource_id`` under ``collection_path``.

    Args:
        collection_path: A DLP collection path from :mod:`prisma_airs.constants`.
        resource_id: Server-assigned identifier, percent-encoded into one path segment.

    Returns:
        The path to a single resource.

    Raises:
        AISecPayloadError: If ``resource_id`` is empty or whitespace. A blank id collapses
            the item path back onto the collection, so a DELETE meant for one resource
            would be sent at the collection endpoint instead.
    """
    if not resource_id.strip():
        raise AISecPayloadError("resource_id must be a non-empty string")
    return f"{collection_path}/{quote(resource_id, safe='')}"


def _multipart(
    metadata: DictionaryRequest, file: DictionaryFile
) -> dict[str, tuple[str, bytes, str]]:
    """Build the two-part upload body for a dictionary create or replace.

    The ``json`` part is named ``metadata.json`` and the keyword part is named after
    ``metadata.original_file_name`` -- that field is what ties the metadata to the bytes,
    so it is sent, not inferred.

    Both content types are set explicitly rather than left to httpx, which would derive
    them from the part file names and so label identical bytes differently depending on
    the extension a caller happened to record.

    Args:
        metadata: The dictionary metadata.
        file: The keyword file.

    Returns:
        The multipart parts, ``json`` first, in the order the reference sends them.
    """
    if isinstance(file, str):
        payload, content_type = file.encode(), "text/plain"
    else:
        payload, content_type = file, "application/octet-stream"
    return {
        "json": ("metadata.json", serialize_body(metadata).encode(), "application/json"),
        "file": (metadata.original_file_name, payload, content_type),
    }


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
