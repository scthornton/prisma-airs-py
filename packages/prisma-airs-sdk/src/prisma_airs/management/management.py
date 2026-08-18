"""Clients for the Prisma AIRS management API.

The management plane is one OAuth2-authenticated surface split across nine resource
clients: security profiles, custom topics, API keys, customer applications, the DLP
profile lookup, deployment profiles, scan logs, OAuth token administration, and the SCM
dashboard. :class:`ManagementClient` constructs all nine against a single token, HTTP
client, and retry budget, so credentials are configured once. The DLP administration
resources hang off the same client as ``mgmt.dlp``: they authenticate as the management
service account but live on their own host, so they share the token and the connection
pool while taking a base URL of their own.

Several endpoints here are inconsistent in ways that are easy to get wrong and hard to
diagnose -- query parameters that are camelCase on one endpoint and snake_case on the
next, list endpoints that take the tenant ID in the path rather than from the token, and
a "get one profile" operation the API simply does not offer. Those quirks are documented
at the method that carries them.
"""

from __future__ import annotations

import os
from typing import Literal, TypeVar
from urllib.parse import quote

import httpx

from prisma_airs._http.auth import OAuthAuth
from prisma_airs._http.transport import RequestSpec, request
from prisma_airs._http.types import AuthAdapter
from prisma_airs._utils import is_valid_uuid
from prisma_airs.auth.oauth import OAuthClient, resolve_credentials
from prisma_airs.constants import (
    DEFAULT_MGMT_ENDPOINT,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_MGMT_ENDPOINT,
    ENV_PREFIX_MGMT,
    MAX_NUMBER_OF_RETRIES,
    MGMT_API_KEY_PATH,
    MGMT_API_KEYS_TSG_PATH,
    MGMT_CUSTOMER_APP_PATH,
    MGMT_CUSTOMER_APPS_TSG_PATH,
    MGMT_DASHBOARD_APPLICATION_PATH,
    MGMT_DASHBOARD_APPLICATION_VIOLATION_BREAKDOWN_PATH,
    MGMT_DASHBOARD_APPLICATIONS_OVERVIEW_PATH,
    MGMT_DEPLOYMENT_PROFILES_PATH,
    MGMT_DLP_PROFILES_PATH,
    MGMT_OAUTH_INVALIDATE_PATH,
    MGMT_OAUTH_TOKEN_PATH,
    MGMT_PROFILE_PATH,
    MGMT_PROFILES_TSG_PATH,
    MGMT_SCAN_LOGS_PATH,
    MGMT_TOPIC_FORCE_PATH,
    MGMT_TOPIC_PATH,
    MGMT_TOPICS_TSG_PATH,
)
from prisma_airs.dlp.dlp import DlpClient
from prisma_airs.errors import AISecPayloadError
from prisma_airs.models.management import (
    ApiKey,
    ApiKeyCreateRequest,
    ApiKeyDeleteResponse,
    ApiKeyListResponse,
    ApiKeyRegenerateRequest,
    ClientIdAndCustomerApp,
    CreateCustomTopicRequest,
    CreateSecurityProfileRequest,
    CustomerApp,
    CustomerAppDeleteResponse,
    CustomerAppListResponse,
    CustomTopic,
    CustomTopicListResponse,
    DashboardApplication,
    DashboardApplicationsOverview,
    DashboardApplicationViolationBreakdown,
    DeleteProfileResponse,
    DeleteTopicResponse,
    DeploymentProfilesResponse,
    DlpProfileListResponse,
    Oauth2Token,
    PaginatedScanResults,
    SecurityProfile,
    SecurityProfileListResponse,
)

_SubClientT = TypeVar("_SubClientT", bound="_MgmtSubClient")


def resolve_management_endpoint(endpoint: str | None = None) -> str:
    """Resolve the management API base URL.

    Args:
        endpoint: Explicit base URL, which wins outright.

    Returns:
        The argument, then ``PANW_MGMT_ENDPOINT``, then the public SCM endpoint.
    """
    return endpoint or os.environ.get(ENV_MGMT_ENDPOINT) or DEFAULT_MGMT_ENDPOINT


class _MgmtSubClient:
    """Transport state shared by every management resource client.

    Constructed by :class:`ManagementClient`, which owns the token, the HTTP client, and
    the retry budget these all share. Instantiating one directly is supported but means
    building an :class:`~prisma_airs._http.types.AuthAdapter` by hand.
    """

    def __init__(
        self,
        *,
        base_url: str,
        auth: AuthAdapter,
        tsg_id: str,
        num_retries: int,
        http: httpx.Client,
    ) -> None:
        self._base_url = base_url
        self._auth = auth
        self._tsg_id = tsg_id
        self._num_retries = num_retries
        self._http = http


class ProfilesClient(_MgmtSubClient):
    """Create, read, update, and delete AIRS security profiles.

    Profiles are versioned in place: an update mints a new ``revision`` under the same
    name rather than replacing the old one, so a name can resolve to several records.
    """

    def create(self, body: CreateSecurityProfileRequest) -> SecurityProfile:
        """Create a security profile.

        Args:
            body: Profile configuration. ``profile_name`` is the only required field.

        Returns:
            The created profile, carrying the server-assigned ``profile_id`` and
            ``revision``.
        """
        return request(
            RequestSpec[SecurityProfile](
                method="POST",
                base_url=self._base_url,
                path=MGMT_PROFILE_PATH,
                body=body,
                auth=self._auth,
                response_model=SecurityProfile,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list(self, *, offset: int = 0, limit: int = 100) -> SecurityProfileListResponse:
        """List the security profiles belonging to this tenant.

        The tenant is named in the path rather than inferred from the token, so this is
        the one list endpoint that changes shape if the client is reconfigured.

        Args:
            offset: Starting offset.
            limit: Maximum profiles to return.

        Returns:
            One page of profiles. ``next_offset`` is present only when more remain.
        """
        return request(
            RequestSpec[SecurityProfileListResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MGMT_PROFILES_TSG_PATH}/{self._tsg_id}",
                params={"offset": str(offset), "limit": str(limit)},
                auth=self._auth,
                response_model=SecurityProfileListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, profile_id: str) -> SecurityProfile:
        """Fetch one security profile by UUID.

        The API offers no single-profile endpoint, so this lists and filters client-side.
        It therefore only sees the first page: a tenant with more than 100 profiles needs
        :meth:`list` with an explicit ``limit``.

        Args:
            profile_id: UUID of the profile.

        Returns:
            The matching profile.

        Raises:
            AISecPayloadError: If no profile on the first page has that ID.
        """
        for profile in self.list().ai_profiles:
            if profile.profile_id == profile_id:
                return profile
        raise AISecPayloadError(f"Profile not found: {profile_id}")

    def get_by_name(self, profile_name: str) -> SecurityProfile:
        """Fetch the live revision of a security profile by name.

        Args:
            profile_name: Name of the profile.

        Returns:
            The highest-revision profile with that name. Older revisions remain listed,
            so returning the first match would hand back a superseded policy.

        Raises:
            AISecPayloadError: If no profile on the first page has that name.
        """
        matches = [p for p in self.list().ai_profiles if p.profile_name == profile_name]
        if not matches:
            raise AISecPayloadError(f"Profile not found: {profile_name}")
        # Ties keep the earliest match, matching the reference implementation's reduce.
        return max(matches, key=lambda p: p.revision if p.revision is not None else 0.0)

    def update(self, profile_id: str, body: CreateSecurityProfileRequest) -> SecurityProfile:
        """Replace a security profile, creating a new revision.

        Args:
            profile_id: UUID of the profile to update.
            body: The whole resource, not a patch.

        Returns:
            The updated profile at its new revision.

        Raises:
            AISecPayloadError: If ``profile_id`` is not a UUID.
        """
        _assert_uuid(profile_id, "profile_id")
        return request(
            RequestSpec[SecurityProfile](
                method="PUT",
                base_url=self._base_url,
                # Update takes `/profile/uuid/{id}`; delete takes `/profile/{id}`. The
                # extra segment is not symmetric and is not optional.
                path=f"{MGMT_PROFILE_PATH}/uuid/{profile_id}",
                body=body,
                auth=self._auth,
                response_model=SecurityProfile,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, profile_id: str) -> DeleteProfileResponse:
        """Delete a security profile.

        Args:
            profile_id: UUID of the profile to delete.

        Returns:
            The deletion acknowledgement.

        Raises:
            AISecPayloadError: If ``profile_id`` is not a UUID.
        """
        _assert_uuid(profile_id, "profile_id")
        return request(
            RequestSpec[DeleteProfileResponse](
                method="DELETE",
                base_url=self._base_url,
                path=f"{MGMT_PROFILE_PATH}/{profile_id}",
                auth=self._auth,
                response_model=DeleteProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def force_delete(self, profile_id: str, updated_by: str) -> DeleteProfileResponse:
        """Delete a security profile, bypassing the reference check.

        A plain :meth:`delete` fails with 409 while any policy still references the
        profile; the conflict body names the blockers. This removes it regardless, so the
        referencing policies lose their profile.

        Args:
            profile_id: UUID of the profile to delete.
            updated_by: Email of the operator, recorded in the audit trail. Required
                here, unlike on :meth:`TopicsClient.force_delete`.

        Returns:
            The deletion acknowledgement.

        Raises:
            AISecPayloadError: If ``profile_id`` is not a UUID.
        """
        _assert_uuid(profile_id, "profile_id")
        return request(
            RequestSpec[DeleteProfileResponse](
                method="DELETE",
                base_url=self._base_url,
                path=f"{MGMT_PROFILE_PATH}/{profile_id}/force",
                params={"updated_by": updated_by},
                auth=self._auth,
                response_model=DeleteProfileResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class TopicsClient(_MgmtSubClient):
    """Create, read, update, and delete the custom topics used by topic guardrails."""

    def create(self, body: CreateCustomTopicRequest) -> CustomTopic:
        """Create a custom topic.

        Args:
            body: Topic definition. ``description`` and ``examples`` are what the
                classifier matches against, so a topic without them guards nothing.

        Returns:
            The created topic.
        """
        return request(
            RequestSpec[CustomTopic](
                method="POST",
                base_url=self._base_url,
                path=MGMT_TOPIC_PATH,
                body=body,
                auth=self._auth,
                response_model=CustomTopic,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list(self, *, offset: int = 0, limit: int = 100) -> CustomTopicListResponse:
        """List the custom topics belonging to this tenant.

        Args:
            offset: Starting offset.
            limit: Maximum topics to return.

        Returns:
            One page of topics.
        """
        return request(
            RequestSpec[CustomTopicListResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MGMT_TOPICS_TSG_PATH}/{self._tsg_id}",
                params={"offset": str(offset), "limit": str(limit)},
                auth=self._auth,
                response_model=CustomTopicListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update(self, topic_id: str, body: CreateCustomTopicRequest) -> CustomTopic:
        """Replace a custom topic, creating a new revision.

        Profiles pin topics by ``(topic_id, revision)``, so an update does not change
        what existing profiles enforce until they are re-saved against the new revision.

        Args:
            topic_id: UUID of the topic to update.
            body: The whole topic definition.

        Returns:
            The updated topic at its new revision.

        Raises:
            AISecPayloadError: If ``topic_id`` is not a UUID.
        """
        _assert_uuid(topic_id, "topic_id")
        return request(
            RequestSpec[CustomTopic](
                method="PUT",
                base_url=self._base_url,
                path=f"{MGMT_TOPIC_PATH}/uuid/{topic_id}",
                body=body,
                auth=self._auth,
                response_model=CustomTopic,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, topic_id: str) -> DeleteTopicResponse:
        """Delete a custom topic, failing if a profile still references it.

        Args:
            topic_id: UUID of the topic to delete.

        Returns:
            The deletion acknowledgement.

        Raises:
            AISecPayloadError: If ``topic_id`` is not a UUID.
        """
        _assert_uuid(topic_id, "topic_id")
        return request(
            RequestSpec[DeleteTopicResponse](
                method="DELETE",
                base_url=self._base_url,
                path=f"{MGMT_TOPIC_PATH}/{topic_id}",
                auth=self._auth,
                response_model=DeleteTopicResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def force_delete(self, topic_id: str, *, updated_by: str | None = None) -> DeleteTopicResponse:
        """Delete a custom topic, detaching it from every profile that references it.

        The force path is a different endpoint (``/topic/force/{id}``), not a flag on the
        plain delete.

        Args:
            topic_id: UUID of the topic to delete.
            updated_by: Email of the operator. Optional here, unlike on
                :meth:`ProfilesClient.force_delete`; omitted entirely when not supplied.

        Returns:
            The deletion acknowledgement.

        Raises:
            AISecPayloadError: If ``topic_id`` is not a UUID.
        """
        _assert_uuid(topic_id, "topic_id")
        return request(
            RequestSpec[DeleteTopicResponse](
                method="DELETE",
                base_url=self._base_url,
                path=f"{MGMT_TOPIC_FORCE_PATH}/{topic_id}",
                params={"updated_by": updated_by} if updated_by else None,
                auth=self._auth,
                response_model=DeleteTopicResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class ApiKeysClient(_MgmtSubClient):
    """Mint, list, rotate, and delete the API keys that authenticate scan requests."""

    def create(self, body: ApiKeyCreateRequest) -> ApiKey:
        """Mint an API key.

        Args:
            body: Key request, including the deployment ``auth_code`` and the rotation
                interval.

        Returns:
            The new key. This is the only response that carries the secret itself --
            list responses expose ``api_key_last8`` and nothing more.
        """
        return request(
            RequestSpec[ApiKey](
                method="POST",
                base_url=self._base_url,
                path=MGMT_API_KEY_PATH,
                body=body,
                auth=self._auth,
                response_model=ApiKey,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list(self, *, offset: int = 0, limit: int = 100) -> ApiKeyListResponse:
        """List the API keys belonging to this tenant.

        Args:
            offset: Starting offset.
            limit: Maximum keys to return.

        Returns:
            One page of key records, without their secrets.
        """
        return request(
            RequestSpec[ApiKeyListResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MGMT_API_KEYS_TSG_PATH}/{self._tsg_id}",
                params={"offset": str(offset), "limit": str(limit)},
                auth=self._auth,
                response_model=ApiKeyListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, api_key_name: str, updated_by: str) -> ApiKeyDeleteResponse:
        """Delete an API key by name.

        Deletion is by name, while :meth:`regenerate` is by ID -- the two identifiers are
        not interchangeable.

        Args:
            api_key_name: Name of the key. Percent-encoded into the path, so spaces and
                other punctuation are safe.
            updated_by: Email of the operator, recorded in the audit trail.

        Returns:
            The deletion acknowledgement.

        Raises:
            AISecPayloadError: If ``api_key_name`` is empty, which would otherwise
                address a different route.
        """
        _assert_present(api_key_name, "api_key_name")
        return request(
            RequestSpec[ApiKeyDeleteResponse](
                method="DELETE",
                base_url=self._base_url,
                path=f"{MGMT_API_KEY_PATH}/delete/{quote(api_key_name, safe='')}",
                params={"updated_by": updated_by},
                auth=self._auth,
                response_model=ApiKeyDeleteResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def regenerate(self, api_key_id: str, body: ApiKeyRegenerateRequest) -> ApiKey:
        """Rotate an API key, returning a fresh secret under the same record.

        Args:
            api_key_id: Identifier of the key. Not a UUID, so it is not format-checked.
            body: New rotation interval and unit.

        Returns:
            The rotated key, carrying the new secret.

        Raises:
            AISecPayloadError: If ``api_key_id`` is empty.
        """
        _assert_present(api_key_id, "api_key_id")
        return request(
            RequestSpec[ApiKey](
                method="POST",
                base_url=self._base_url,
                path=f"{MGMT_API_KEY_PATH}/regenerate/{quote(api_key_id, safe='')}",
                body=body,
                auth=self._auth,
                response_model=ApiKey,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class CustomerAppsClient(_MgmtSubClient):
    """Read, update, and delete registered customer applications.

    Registration happens when an API key is minted, so there is no create operation here.
    """

    def get(self, app_name: str) -> CustomerApp:
        """Fetch one customer application by name.

        The name travels as a query parameter, not a path segment -- this endpoint has no
        by-ID form.

        Args:
            app_name: Registered application name.

        Returns:
            The application record.
        """
        return request(
            RequestSpec[CustomerApp](
                method="GET",
                base_url=self._base_url,
                path=MGMT_CUSTOMER_APP_PATH,
                params={"app_name": app_name},
                auth=self._auth,
                response_model=CustomerApp,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list(self, *, offset: int = 0, limit: int = 100) -> CustomerAppListResponse:
        """List the customer applications registered to this tenant.

        Args:
            offset: Starting offset.
            limit: Maximum applications to return.

        Returns:
            One page of applications, each with the API keys minted against it.
        """
        return request(
            RequestSpec[CustomerAppListResponse](
                method="GET",
                base_url=self._base_url,
                # The only TSG-scoped path the reference implementation percent-encodes.
                # Immaterial for the numeric IDs the service issues; kept for parity.
                path=f"{MGMT_CUSTOMER_APPS_TSG_PATH}/{quote(self._tsg_id, safe='')}",
                params={"offset": str(offset), "limit": str(limit)},
                auth=self._auth,
                response_model=CustomerAppListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update(self, customer_app_id: str, body: CustomerApp) -> CustomerApp:
        """Update a customer application.

        Args:
            customer_app_id: The application's ``customer_appId``, sent as a query
                parameter.
            body: The whole application record.

        Returns:
            The updated application.
        """
        return request(
            RequestSpec[CustomerApp](
                method="PUT",
                base_url=self._base_url,
                path=MGMT_CUSTOMER_APP_PATH,
                params={"customer_app_id": customer_app_id},
                body=body,
                auth=self._auth,
                response_model=CustomerApp,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, app_name: str, updated_by: str) -> CustomerAppDeleteResponse:
        """Delete a customer application and every API key issued against it.

        Args:
            app_name: Registered application name.
            updated_by: Email of the operator, recorded in the audit trail.

        Returns:
            The deletion acknowledgement. The service answers with a bare JSON string,
            which the response model normalises to an object.
        """
        return request(
            RequestSpec[CustomerAppDeleteResponse](
                method="DELETE",
                base_url=self._base_url,
                path=MGMT_CUSTOMER_APP_PATH,
                params={"app_name": app_name, "updated_by": updated_by},
                auth=self._auth,
                response_model=CustomerAppDeleteResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class DlpProfilesClient(_MgmtSubClient):
    """Read the DLP data profiles a security profile may reference."""

    def list(self) -> DlpProfileListResponse:
        """List every DLP data profile available to this tenant.

        Unpaginated: the endpoint takes no offset or limit.

        Returns:
            The available DLP profiles. Reference one from a security profile by its
            ``uuid`` -- the separate ``id`` field is not interchangeable with it.
        """
        return request(
            RequestSpec[DlpProfileListResponse](
                method="GET",
                base_url=self._base_url,
                path=MGMT_DLP_PROFILES_PATH,
                auth=self._auth,
                response_model=DlpProfileListResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class DeploymentProfilesClient(_MgmtSubClient):
    """Read the deployment profiles that API keys are minted against."""

    def list(self, *, unactivated: bool | None = None) -> DeploymentProfilesResponse:
        """List the deployment profiles visible to this tenant.

        Args:
            unactivated: Include deployment profiles that have not been activated. Sent
                only when supplied, since the parameter's absence and its ``false`` value
                are distinct to the service.

        Returns:
            The deployment profiles and the lookup status. Each entry pairs a ``dp_name``
            with the ``auth_code`` that :meth:`ApiKeysClient.create` requires.
        """
        params: dict[str, str] | None = None
        if unactivated is not None:
            # str(True) is "True"; this endpoint wants the JSON spelling.
            params = {"unactivated": "true" if unactivated else "false"}
        return request(
            RequestSpec[DeploymentProfilesResponse](
                method="GET",
                base_url=self._base_url,
                path=MGMT_DEPLOYMENT_PROFILES_PATH,
                params=params,
                auth=self._auth,
                response_model=DeploymentProfilesResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class ScanLogsClient(_MgmtSubClient):
    """Query the scan-log view that backs the SCM transaction dashboard."""

    def query(
        self,
        *,
        time_interval: int,
        time_unit: str,
        page_number: int,
        page_size: int,
        verdict_filter: str,
        page_token: str | None = None,
    ) -> PaginatedScanResults:
        """Retrieve a page of scan logs over a look-back window.

        A POST with every filter in the query string: the body carries only the
        continuation token. Note the mixed casing on the wire, which is not a typo here
        -- ``time_interval`` and ``time_unit`` are snake_case while ``pageNumber`` and
        ``pageSize`` are camelCase.

        Args:
            time_interval: Look-back window length.
            time_unit: Look-back window unit, such as ``hour`` or ``day``.
            page_number: One-based page number. Sent as ``pageNumber``.
            page_size: Records per page. Sent as ``pageSize``.
            verdict_filter: ``all``, ``benign``, or ``threat``. Sent as ``filter``.
            page_token: Encrypted continuation token from a previous response. Walk pages
                with this rather than by incrementing ``page_number``: the reported
                ``page_number`` and ``total_pages`` are display values.

        Returns:
            One page of scan results plus the dashboard's aggregate counters. A window
            with no traffic returns an empty body, which hydrates to an all-null page
            rather than an error.
        """
        return request(
            RequestSpec[PaginatedScanResults](
                method="POST",
                base_url=self._base_url,
                path=MGMT_SCAN_LOGS_PATH,
                params={
                    "time_interval": str(time_interval),
                    "time_unit": time_unit,
                    "pageNumber": str(page_number),
                    "pageSize": str(page_size),
                    "filter": verdict_filter,
                },
                body={"page_token": page_token} if page_token else None,
                auth=self._auth,
                response_model=PaginatedScanResults,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class OAuthManagementClient(_MgmtSubClient):
    """Mint and invalidate the OAuth tokens issued to customer applications.

    These are tokens the tenant hands to its own applications. They are unrelated to the
    client-credentials token this SDK uses to authenticate, which
    :class:`~prisma_airs.auth.oauth.OAuthClient` manages.
    """

    def invalidate_token(self, token: str, body: ClientIdAndCustomerApp) -> str:
        """Invalidate an issued OAuth token.

        Args:
            token: The token to invalidate, sent as a query parameter.
            body: The client ID and customer application the token belongs to.

        Returns:
            The service's confirmation message. This endpoint answers with a bare JSON
            string rather than an object.
        """
        return request(
            RequestSpec[str](
                method="POST",
                base_url=self._base_url,
                path=MGMT_OAUTH_INVALIDATE_PATH,
                params={"token": token},
                body=body,
                auth=self._auth,
                response_model=str,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_access_token(
        self,
        body: ClientIdAndCustomerApp,
        *,
        token_ttl_interval: int | None = None,
        token_ttl_unit: str | None = None,
    ) -> Oauth2Token:
        """Issue an OAuth token for a customer application.

        Args:
            body: The client ID and customer application to issue against.
            token_ttl_interval: Token lifetime. Sent as ``tokenTtlInterval``; the service
                applies its default when omitted.
            token_ttl_unit: Lifetime unit, such as ``hours``. Sent as ``tokenTtlUnit``.

        Returns:
            The issued token. Its ``expires_in`` is a string on the wire, unlike the
            client-credentials token response.
        """
        params: dict[str, str] = {}
        if token_ttl_interval is not None:
            params["tokenTtlInterval"] = str(token_ttl_interval)
        if token_ttl_unit is not None:
            params["tokenTtlUnit"] = token_ttl_unit

        return request(
            RequestSpec[Oauth2Token](
                method="POST",
                base_url=self._base_url,
                path=MGMT_OAUTH_TOKEN_PATH,
                params=params or None,
                body=body,
                auth=self._auth,
                response_model=Oauth2Token,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class DashboardClient(_MgmtSubClient):
    """Read the SCM "AI Security > Runtime > API Applications" dashboard.

    The dashboard buckets traffic by the literal ``metadata.app_name`` each scan payload
    sent, not by the registered application. One registered customer app can therefore
    appear as several buckets -- one per distinct payload name. Enumerate the buckets
    with :meth:`applications_overview`, then drill into a specific ``(id, name)`` pair
    with :meth:`application` or :meth:`application_violation_breakdown`.
    """

    def application(
        self,
        *,
        app_id: str,
        app_name: str,
        time_interval: Literal[7, 30, 60] = 30,
        time_unit: Literal["days"] = "days",
    ) -> DashboardApplication:
        """Fetch token consumption and session activity for one dashboard bucket.

        Args:
            app_id: The registered ``customer_appId`` UUID, sent as ``appid``.
            app_name: The name the dashboard tracks -- the literal ``metadata.app_name``
                scan payloads sent, which is not always ``customer_apps.app_name``. Sent
                as ``appname``.
            time_interval: Look-back window. The API takes an enum-like set, not an
                arbitrary integer: 7, 30, and 60 were accepted on 2026-05-28 and 1, 3,
                14, 21, 28, and 90 all returned 400.
            time_unit: Look-back unit. Only ``days`` is accepted on this endpoint;
                ``hours`` and ``minutes`` return 400.

        Returns:
            The bucket's overview, including ``token_stats`` and ``session_stats``.

        Raises:
            AISecPayloadError: If ``app_id`` or ``app_name`` is empty. Both failure modes
                are silent otherwise -- an empty ``appname`` returns 400 and an absent one
                returns an all-null body that reads like an idle application.
        """
        _assert_present(app_id, "app_id")
        _assert_present(app_name, "app_name")
        return request(
            RequestSpec[DashboardApplication](
                method="GET",
                base_url=self._base_url,
                path=MGMT_DASHBOARD_APPLICATION_PATH,
                params=_dashboard_app_params(app_id, app_name, time_interval, time_unit),
                auth=self._auth,
                response_model=DashboardApplication,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def application_violation_breakdown(
        self,
        *,
        app_id: str,
        app_name: str,
        time_interval: Literal[7, 30, 60] = 30,
        time_unit: Literal["days"] = "days",
    ) -> DashboardApplicationViolationBreakdown:
        """Fetch per-detector violation counts for one dashboard bucket.

        Args:
            app_id: The registered ``customer_appId`` UUID, sent as ``appid``.
            app_name: The name the dashboard tracks, sent as ``appname``.
            time_interval: Look-back window; same accepted set as :meth:`application`.
            time_unit: Look-back unit; only ``days`` is accepted.

        Returns:
            One entry per detector that has data, plus ``total_violating``. The detector
            set evolves, so an unfamiliar ``detection_type`` is data, not an error.

        Raises:
            AISecPayloadError: If ``app_id`` or ``app_name`` is empty.
        """
        _assert_present(app_id, "app_id")
        _assert_present(app_name, "app_name")
        return request(
            RequestSpec[DashboardApplicationViolationBreakdown](
                method="GET",
                base_url=self._base_url,
                path=MGMT_DASHBOARD_APPLICATION_VIOLATION_BREAKDOWN_PATH,
                params=_dashboard_app_params(app_id, app_name, time_interval, time_unit),
                auth=self._auth,
                response_model=DashboardApplicationViolationBreakdown,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def applications_overview(
        self,
        *,
        time_interval: Literal[1, 7, 30, 60] = 30,
        time_unit: Literal["days", "day", "hour"] = "days",
        limit: int = 25,
        offset: int = 0,
    ) -> DashboardApplicationsOverview:
        """Enumerate every dashboard bucket this tenant has data for.

        This, not :meth:`CustomerAppsClient.list`, is the inventory to report against:
        the customer-apps endpoint lists registrations, while a registration with one API
        key can produce several buckets.

        Args:
            time_interval: Look-back window. The accepted value depends on ``time_unit``:
                ``days`` takes 7, 30, or 60, while ``day`` and ``hour`` take only 1. Other
                combinations return 400.
            time_unit: Look-back unit. This endpoint accepts the singular ``day`` and
                ``hour`` as well as ``days`` -- unlike :meth:`application`, which takes
                ``days`` alone.
            limit: Maximum buckets to return.
            offset: Buckets to skip.

        Returns:
            One item per bucket, plus pagination metadata. Items carry session counts but
            no token data; fetch that per bucket with :meth:`application`.
        """
        return request(
            RequestSpec[DashboardApplicationsOverview](
                method="GET",
                base_url=self._base_url,
                path=MGMT_DASHBOARD_APPLICATIONS_OVERVIEW_PATH,
                params={
                    "time_interval": str(time_interval),
                    "time_unit": time_unit,
                    "limit": str(limit),
                    "offset": str(offset),
                },
                auth=self._auth,
                response_model=DashboardApplicationsOverview,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class ManagementClient:
    """Client for the Prisma AIRS management API.

    Authenticates with the OAuth2 client-credentials flow. Credentials come from the
    constructor or from ``PANW_MGMT_CLIENT_ID`` / ``PANW_MGMT_CLIENT_SECRET`` /
    ``PANW_MGMT_TSG_ID``; the base URL additionally honours ``PANW_MGMT_ENDPOINT``. The
    ``dlp_endpoint`` argument overrides the DLP host that :attr:`dlp` sends to and
    defaults to ``https://api.dlp.paloaltonetworks.com``; it has no environment override,
    since DLP has no prefix of its own to hang one off.

    Attributes:
        profiles: Security profile CRUD.
        topics: Custom topic CRUD.
        api_keys: API key issuance and rotation.
        customer_apps: Registered customer applications.
        dlp_profiles: DLP data profile lookup, on the management host.
        deployment_profiles: Deployment profiles and their auth codes.
        scan_logs: Scan-log queries.
        oauth: OAuth tokens issued to customer applications.
        dashboard: SCM dashboard reporting.
        dlp: DLP administration -- data patterns, data profiles, data filtering
            profiles, and dictionaries -- on the separate DLP host. Not the same thing
            as :attr:`dlp_profiles`, which is the management plane's read-only lookup of
            the profiles a security profile may reference.

    Example:
        >>> mgmt = ManagementClient()  # reads PANW_MGMT_* from the environment
        >>> page = mgmt.profiles.list(limit=5)
        >>> [p.profile_name for p in page.ai_profiles]
        ['prod']
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        tsg_id: str | None = None,
        endpoint: str | None = None,
        dlp_endpoint: str | None = None,
        token_endpoint: str | None = None,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        credentials = resolve_credentials(
            primary_env_prefix=ENV_PREFIX_MGMT,
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            token_endpoint=token_endpoint,
            # PANW_MGMT_* is the prefix every other plane falls back to, so for this
            # client there is nothing further to fall back to.
            fallback_env_prefix=None,
        )

        self._endpoint = resolve_management_endpoint(endpoint)
        self._tsg_id = credentials.tsg_id
        self._num_retries = _validate_retries(num_retries)
        self._owns_client = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)

        # The token exchange rides the same HTTP client as the API calls, so one
        # connection pool serves both and a caller-supplied client -- proxy, custom
        # transport, instrumentation -- covers the token endpoint too.
        self._oauth_client = OAuthClient(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            tsg_id=credentials.tsg_id,
            token_endpoint=credentials.token_endpoint,
            http_client=self._http,
        )
        auth = OAuthAuth(self._oauth_client)

        def build(sub_client: type[_SubClientT]) -> _SubClientT:
            return sub_client(
                base_url=self._endpoint,
                auth=auth,
                tsg_id=credentials.tsg_id,
                num_retries=self._num_retries,
                http=self._http,
            )

        self.profiles = build(ProfilesClient)
        self.topics = build(TopicsClient)
        self.api_keys = build(ApiKeysClient)
        self.customer_apps = build(CustomerAppsClient)
        self.dlp_profiles = build(DlpProfilesClient)
        self.deployment_profiles = build(DeploymentProfilesClient)
        self.scan_logs = build(ScanLogsClient)
        self.oauth = build(OAuthManagementClient)
        self.dashboard = build(DashboardClient)

        # DLP is the one resource group that does not live on the management host. It
        # authenticates as the same service account, so it reuses this client's token and
        # connection pool rather than resolving credentials again -- but its base URL is
        # constructor-only, with no environment override, because there is no DLP-specific
        # prefix for one to belong to.
        self.dlp = DlpClient(
            endpoint=dlp_endpoint,
            oauth_client=self._oauth_client,
            http_client=self._http,
            num_retries=self._num_retries,
        )

    @property
    def endpoint(self) -> str:
        """The management endpoint this client sends to."""
        return self._endpoint

    @property
    def tsg_id(self) -> str:
        """The Tenant Service Group this client is scoped to."""
        return self._tsg_id

    def close(self) -> None:
        """Close the underlying HTTP client, if this instance created it."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> ManagementClient:
        """Enter a context that closes the HTTP client on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the HTTP client if this instance owns it."""
        self.close()


def _dashboard_app_params(
    app_id: str, app_name: str, time_interval: int, time_unit: str
) -> dict[str, str]:
    """Build the query for the two per-application dashboard endpoints.

    The identity parameters are lowercase and unseparated -- ``appid`` and ``appname``,
    not ``app_id`` or ``appId`` -- while the window parameters beside them are snake_case.
    """
    return {
        "appid": app_id,
        "appname": app_name,
        "time_interval": str(time_interval),
        "time_unit": time_unit,
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


def _assert_uuid(value: str, field: str) -> None:
    """Reject a malformed identifier before it is interpolated into a path."""
    if not is_valid_uuid(value):
        raise AISecPayloadError(f"Invalid {field}: {value}")


def _assert_present(value: str, field: str) -> None:
    """Reject an empty identifier, which would silently address a different endpoint."""
    if not value:
        raise AISecPayloadError(f"{field} is required")
