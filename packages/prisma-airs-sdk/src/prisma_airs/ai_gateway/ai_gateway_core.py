"""Entry-point client and core resource clients for the Prisma AIRS AI Gateway.

The gateway spans two planes over a single credential set. This module carries
:class:`AIGatewayClient` plus the five resource clients rooted on the data plane
(``/ai_gw/v2``): workspaces -- whose writes are admin-only -- configs, guardrails,
providers, and API keys. Organisation-level resources and telemetry live alongside in this
package.

Three behaviours explain most otherwise-surprising responses from this API:

* Every request needs ``x-tsg-id`` as well as the bearer token, so every client here shares
  one :class:`~prisma_airs._http.auth.TsgHeaderAuth` adapter.
* Creates return a short receipt, not the record they created. ``workspaces.create()`` is
  the single exception. Re-read with ``get()`` when the full record matters.
* The data plane only ever shows what the caller's SCM workspace-scope grant covers. A
  workspace outside it answers ``403 AB03``, never ``404``.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final, Literal, TypeAlias

import httpx
from pydantic import BaseModel

from prisma_airs._http.auth import OAuthAuth, TsgHeaderAuth
from prisma_airs._http.transport import RequestSpec, request
from prisma_airs._http.types import AuthAdapter
from prisma_airs._utils import is_valid_uuid
from prisma_airs.ai_gateway.ai_gateway_admin import (
    AIGatewayAuditLogsClient,
    AIGatewayDeploymentsClient,
    AIGatewayIntegrationsClient,
    AIGatewayMcpIntegrationsClient,
    AIGatewayOrganisationsClient,
    AIGatewayPluginsClient,
    AIGatewayTelemetryClient,
)
from prisma_airs.auth.oauth import OAuthClient, resolve_credentials
from prisma_airs.constants import (
    AI_GW_API_KEYS_SERVICE_PATH,
    AI_GW_API_KEYS_USER_PATH,
    AI_GW_CONFIGS_PATH,
    AI_GW_GUARDRAILS_PATH,
    AI_GW_PROVIDERS_PATH,
    AI_GW_WORKSPACES_PATH,
    DEFAULT_AI_GW_ADMIN_ENDPOINT,
    DEFAULT_AI_GW_DATA_ENDPOINT,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_AI_GW_ADMIN_ENDPOINT,
    ENV_AI_GW_DATA_ENDPOINT,
    ENV_PREFIX_AI_GW,
    ENV_PREFIX_MGMT,
    MAX_NUMBER_OF_RETRIES,
)
from prisma_airs.errors import AISecPayloadError
from prisma_airs.models.ai_gateway import (
    GatewayConfigCreateResponse,
    GatewayConfigDetail,
    GatewayGuardrailCreateResponse,
    GatewayGuardrailDetail,
    GatewayProviderCreateResponse,
    GatewayRateLimit,
    GatewayUsageLimit,
    GatewayWorkspaceCreateResponse,
    GatewayWorkspaceDetail,
    GatewayWriteResponse,
    GuardrailActions,
    GuardrailCheck,
    ListApiKeysResponse,
    ListConfigsResponse,
    ListGuardrailsResponse,
    ListProvidersResponse,
    ListWorkspacesResponse,
)

#: Which plane to route a request through.
#:
#: ``data`` -- ``/ai_gw/v2``, scoped to the workspaces the caller holds a grant on.
#: ``admin`` -- ``/ai_gw/admin/v2``, the whole tenant, and the only plane that accepts
#: workspace writes.
AIGatewayPlane: TypeAlias = Literal["data", "admin"]

#: Workspace lifecycle filter. Lowercase on the wire.
AIGatewayWorkspaceStatus: TypeAlias = Literal["active", "archived"]

#: Free-form request fragments. The gateway takes several open blobs -- a routing config,
#: guardrail actions, workspace defaults -- and a caller may supply either the matching
#: model or a plain mapping.
_Payload: TypeAlias = BaseModel | Mapping[str, Any]

# Not exported by prisma_airs.constants, which carries only the prefix. Composed from it
# the same way resolve_credentials() composes its own lookups, rather than spelling the
# variable names out here.

_PLANE_ENDPOINTS: Final[dict[str, tuple[str, str]]] = {
    "data": (ENV_AI_GW_DATA_ENDPOINT, DEFAULT_AI_GW_DATA_ENDPOINT),
    "admin": (ENV_AI_GW_ADMIN_ENDPOINT, DEFAULT_AI_GW_ADMIN_ENDPOINT),
}

#: Deliberately loose -- the server owns the real slug format -- but it still rejects
#: anything holding ``/`` or ``..``, so a caller-supplied ref cannot reshape a path built
#: by interpolation.
_WORKSPACE_SLUG_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def resolve_gateway_endpoint(plane: AIGatewayPlane, endpoint: str | None = None) -> str:
    """Resolve one plane's base URL from an argument, the environment, then the default.

    Args:
        plane: ``data`` or ``admin``.
        endpoint: Explicit base URL, which wins outright.

    Returns:
        The base URL for that plane. ``api.apps`` and ``api.sase`` front the same host, so
        the environment override exists mainly to reuse an existing egress allowlist.
    """
    env_name, default = _PLANE_ENDPOINTS[plane]
    return endpoint or os.environ.get(env_name) or default


def _assert_uuid(value: str, field: str) -> None:
    """Reject a malformed UUID before the request goes out."""
    if not is_valid_uuid(value):
        raise AISecPayloadError(f"Invalid {field}: {value}")


def _validate_retries(value: int) -> int:
    """Reject a retry count the transport cannot honour.

    The TypeScript reference silently clamps this into range. Every client in this SDK
    rejects it instead, so that a caller asking for a budget they will not get hears about
    it here rather than wondering why the run gave up early.
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


def _assert_workspace_ref(value: str, field: str) -> None:
    """Reject a value that is neither a workspace UUID nor a workspace slug.

    Workspace endpoints accept both forms -- upstream documents the path parameter as
    "Workspace UUID. Workspace slug is also accepted for backward compatibility", and a
    well-formed but unknown slug answers ``404`` rather than ``400``. A UUID check alone
    would therefore reject identifiers the API honours.
    """
    if not is_valid_uuid(value) and not _WORKSPACE_SLUG_RE.match(value):
        raise AISecPayloadError(f"Invalid {field}: {value} (expected a workspace UUID or slug)")


def _as_payload(value: _Payload) -> dict[str, Any]:
    """Render a model or a raw mapping into a JSON-ready request fragment.

    Models are dumped by alias, so :class:`GuardrailActions` emits ``async`` rather than
    the ``async_`` the Python keyword forces on the attribute.
    """
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    return dict(value)


def _as_payloads(values: Sequence[_Payload]) -> list[dict[str, Any]]:
    """Render a sequence of models or mappings, preserving order."""
    return [_as_payload(value) for value in values]


class AIGatewaySubClient:
    """Shared plumbing for every AI Gateway resource client.

    Ported from the TypeScript ``AIGatewaySubClientOptions``, which lives in a module of
    its own for the same reason this base does: every resource client consumes it,
    including the admin-plane clients defined outside this module.
    """

    def __init__(
        self,
        *,
        base_url: str,
        auth: AuthAdapter,
        http: httpx.Client,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
    ) -> None:
        self._base_url = base_url
        self._auth = auth
        self._http = http
        self._num_retries = num_retries


class AIGatewayWorkspacesClient(AIGatewaySubClient):
    """Client for AI Gateway workspaces.

    The only resource client spanning both planes: reads default to the data plane but can
    be routed to the admin plane, and every write is admin-only. Every other resource
    client is wired to exactly one plane.
    """

    def __init__(
        self,
        *,
        base_url: str,
        admin_base_url: str,
        auth: AuthAdapter,
        http: httpx.Client,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
    ) -> None:
        super().__init__(base_url=base_url, auth=auth, http=http, num_retries=num_retries)
        self._admin_base_url = admin_base_url

    def _url_for(self, plane: AIGatewayPlane) -> str:
        return self._admin_base_url if plane == "admin" else self._base_url

    def list(
        self,
        *,
        status: AIGatewayWorkspaceStatus | None = None,
        plane: AIGatewayPlane = "data",
    ) -> ListWorkspacesResponse:
        """List workspaces.

        Two defaults are worth knowing, because each one hides rows:

        1. **Active only.** Without ``status``, archived workspaces are omitted. Pass
           ``status="archived"`` to see them -- that is where :meth:`delete` leaves a
           workspace.
        2. **Your scope only.** The data plane returns just the workspaces the service
           account holds a workspace-scope grant on. Pass ``plane="admin"`` to enumerate
           the whole tenant.

        Args:
            status: Lifecycle filter. Omitted entirely from the query when unset.
            plane: ``data`` (default) or ``admin``.

        Returns:
            Workspaces, each carrying the ``scope_name`` that grants data-plane access.
        """
        return request(
            RequestSpec[ListWorkspacesResponse](
                method="GET",
                base_url=self._url_for(plane),
                path=AI_GW_WORKSPACES_PATH,
                params={"status": status} if status else None,
                auth=self._auth,
                response_model=ListWorkspacesResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, workspace_ref: str, *, plane: AIGatewayPlane = "data") -> GatewayWorkspaceDetail:
        """Fetch one workspace, including its security and rate-limit settings.

        **Archived workspaces are not retrievable here.** Once :meth:`delete` has archived
        a workspace this answers ``404 AB08`` for both its UUID and its slug, on either
        plane (verified live 2026-08-01), even though :meth:`list` still returns the row
        under ``status="archived"``. Treat a 404 after a delete as expected.

        Args:
            workspace_ref: Workspace UUID **or** slug; the API accepts both.
            plane: ``data`` (default) or ``admin``. A workspace outside the caller's
                workspace scope answers ``403 AB03`` on the data plane, not ``404``;
                re-read it with ``plane="admin"``.

        Returns:
            Workspace detail. List rows do not carry the settings blocks.

        Raises:
            AISecPayloadError: If ``workspace_ref`` is neither a UUID nor a slug.
        """
        _assert_workspace_ref(workspace_ref, "workspace_ref")
        return request(
            RequestSpec[GatewayWorkspaceDetail](
                method="GET",
                base_url=self._url_for(plane),
                path=f"{AI_GW_WORKSPACES_PATH}/{workspace_ref}",
                auth=self._auth,
                response_model=GatewayWorkspaceDetail,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create(
        self,
        *,
        name: str,
        scope_name: str,
        description: str | None = None,
        icon: str | None = None,
        defaults: Mapping[str, Any] | None = None,
        users: Sequence[str] | None = None,
        usage_limits: Sequence[GatewayUsageLimit | Mapping[str, Any]] | None = None,
        rate_limits: Sequence[GatewayRateLimit | Mapping[str, Any]] | None = None,
    ) -> GatewayWorkspaceCreateResponse:
        """Create a workspace. **Admin plane** -- needs a tenant-root admin role.

        Args:
            name: Display name. Required.
            scope_name: SCM role scope granting data-plane access to the new workspace,
                e.g. ``ws_production_bx7qw0``. Required, and **specific to Prisma AIRS** --
                upstream Portkey has no such field. It is not derived from ``name``, and a
                workspace created with a scope nobody holds is invisible to :meth:`list` on
                the data plane while still appearing under ``plane="admin"``.
            description: Free text.
            icon: Display icon.
            defaults: Workspace defaults; ``metadata`` is a flat string map applied to
                every request.
            users: User ids to seed the workspace with.
            usage_limits: Usage-limit policies. A **list**, not a single object. A
                :class:`GatewayUsageLimit` declares its numeric fields as floats, so
                ``100`` leaves as ``100.0``, and a field left ``None`` is omitted rather
                than sent as ``null``. Pass a mapping to fix the wire form exactly.
            rate_limits: Rate-limit policies. A **list**, not a single object, under the
                same model-versus-mapping rules as ``usage_limits``.

        Returns:
            The created workspace. Unlike configs, guardrails, and providers -- which
            return short receipts -- this returns most of the record, but not ``status``,
            ``is_default``, ``icon``, ``usage_limits``, ``rate_limits``, or the settings
            blocks. Call :meth:`get` when those matter.

        Raises:
            AISecPayloadError: If ``name`` or ``scope_name`` is empty. The API rejects a
                body missing either, so this saves a round trip.
        """
        if not name:
            raise AISecPayloadError("Missing name")
        if not scope_name:
            raise AISecPayloadError("Missing scope_name")

        body: dict[str, Any] = {"name": name, "scope_name": scope_name}
        body.update(
            _workspace_fields(
                description=description,
                icon=icon,
                defaults=defaults,
                usage_limits=usage_limits,
                rate_limits=rate_limits,
            )
        )
        if users is not None:
            body["users"] = list(users)

        return request(
            RequestSpec[GatewayWorkspaceCreateResponse](
                method="POST",
                base_url=self._admin_base_url,
                path=AI_GW_WORKSPACES_PATH,
                body=body,
                auth=self._auth,
                response_model=GatewayWorkspaceCreateResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update(
        self,
        workspace_ref: str,
        *,
        name: str | None = None,
        description: str | None = None,
        icon: str | None = None,
        defaults: Mapping[str, Any] | None = None,
        usage_limits: Sequence[GatewayUsageLimit | Mapping[str, Any]] | None = None,
        rate_limits: Sequence[GatewayRateLimit | Mapping[str, Any]] | None = None,
    ) -> GatewayWriteResponse:
        """Update a workspace. **Admin plane.** Partial patch -- send only what changes.

        The API enumerates the fields it accepts in its own rejection message: ``name``,
        ``description``, ``icon``, ``defaults``, ``rate_limits``. ``usage_limits`` is
        accepted by upstream Portkey but missing from that message, so it is offered here
        and may be ignored server-side.

        Args:
            workspace_ref: Workspace UUID or slug.
            name: New display name.
            description: New description.
            icon: New icon.
            defaults: Replacement workspace defaults.
            usage_limits: Replacement usage-limit policies, under the model-versus-mapping
                rules described on :meth:`create`.
            rate_limits: Replacement rate-limit policies, likewise.

        Returns:
            An **empty object** -- the API acknowledges the write without echoing the
            record (verified live 2026-08-01). The change does persist; re-read with
            :meth:`get` to see it.

        Raises:
            AISecPayloadError: If ``workspace_ref`` is malformed, or no field was supplied.
                An empty patch is rejected locally, mirroring the API's own "No update
                fields provided", so a typo'd caller fails without a round trip.
        """
        _assert_workspace_ref(workspace_ref, "workspace_ref")
        body = _workspace_fields(
            name=name,
            description=description,
            icon=icon,
            defaults=defaults,
            usage_limits=usage_limits,
            rate_limits=rate_limits,
        )
        if not body:
            raise AISecPayloadError(
                "Empty update: provide at least one of name, description, icon, defaults, "
                "usage_limits, rate_limits"
            )

        return request(
            RequestSpec[GatewayWriteResponse](
                method="PUT",
                base_url=self._admin_base_url,
                path=f"{AI_GW_WORKSPACES_PATH}/{workspace_ref}",
                body=body,
                auth=self._auth,
                response_model=GatewayWriteResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, workspace_ref: str) -> None:
        """Delete a workspace, on the **admin plane**.

        This is a **soft delete**: the workspace is archived, not destroyed. It vanishes
        from a default :meth:`list` but stays visible under ``status="archived"``, which is
        the only way to see it afterwards -- :meth:`get` answers ``404 AB08`` for an
        archived workspace. Same semantics as ``deployments.delete()``, and the opposite of
        configs, guardrails, and providers, which hard delete. There is no hard delete for
        workspaces.

        Takes no query parameters, unlike ``integrations.delete()`` and
        ``deployments.delete()``, which both require ``organisation_id``.

        Args:
            workspace_ref: Workspace UUID or slug.

        Raises:
            AISecPayloadError: If ``workspace_ref`` is neither a UUID nor a slug.
        """
        _assert_workspace_ref(workspace_ref, "workspace_ref")
        request(
            RequestSpec[None](
                method="DELETE",
                base_url=self._admin_base_url,
                path=f"{AI_GW_WORKSPACES_PATH}/{workspace_ref}",
                auth=self._auth,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


def _workspace_fields(
    *,
    name: str | None = None,
    description: str | None = None,
    icon: str | None = None,
    defaults: Mapping[str, Any] | None = None,
    usage_limits: Sequence[GatewayUsageLimit | Mapping[str, Any]] | None = None,
    rate_limits: Sequence[GatewayRateLimit | Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Collect the mutable workspace fields that were actually supplied.

    Shared by create and update so the update path's "was anything supplied?" check reads
    the same body the request will carry. An unset field is omitted rather than sent as
    ``null``, because the API treats an explicit null as a value.
    """
    fields: dict[str, Any] = {}
    if name is not None:
        fields["name"] = name
    if description is not None:
        fields["description"] = description
    if icon is not None:
        fields["icon"] = icon
    if defaults is not None:
        fields["defaults"] = dict(defaults)
    if usage_limits is not None:
        fields["usage_limits"] = _as_payloads(usage_limits)
    if rate_limits is not None:
        fields["rate_limits"] = _as_payloads(rate_limits)
    return fields


class AIGatewayConfigsClient(AIGatewaySubClient):
    """Client for AI Gateway config operations (data plane)."""

    def list(self, *, workspace_id: str) -> ListConfigsResponse:
        """List the configs in one workspace.

        List rows are a strict 12-field subset of the detail read: they do NOT carry
        ``config``, ``format``, ``type``, or ``version_id``. Call :meth:`get` for those.

        Args:
            workspace_id: Workspace UUID. Required -- omitting it returns ``404 AB02``.

        Returns:
            Config list rows.

        Raises:
            AISecPayloadError: If ``workspace_id`` is not a UUID.
        """
        _assert_uuid(workspace_id, "workspace_id")
        return request(
            RequestSpec[ListConfigsResponse](
                method="GET",
                base_url=self._base_url,
                path=AI_GW_CONFIGS_PATH,
                params={"workspace_id": workspace_id},
                auth=self._auth,
                response_model=ListConfigsResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, config_id: str) -> GatewayConfigDetail:
        """Fetch one config.

        Args:
            config_id: Config UUID.

        Returns:
            The config detail, adding ``config``, ``format``, ``type``, and ``version_id``
            on top of the list row. ``config`` comes back as a JSON-encoded **string**,
            not an object, even though creates send an object -- ``json.loads`` it.

        Raises:
            AISecPayloadError: If ``config_id`` is not a UUID.
        """
        _assert_uuid(config_id, "config_id")
        return request(
            RequestSpec[GatewayConfigDetail](
                method="GET",
                base_url=self._base_url,
                path=f"{AI_GW_CONFIGS_PATH}/{config_id}",
                auth=self._auth,
                response_model=GatewayConfigDetail,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create(
        self, *, name: str, workspace_id: str, config: Mapping[str, Any]
    ) -> GatewayConfigCreateResponse:
        """Create a config.

        Args:
            name: Display name.
            workspace_id: Workspace UUID the config belongs to.
            config: The gateway routing config, sent as an **object**. Note the API returns
                it as a JSON-encoded string on reads.

        Returns:
            A **creation receipt** -- ``{id, version_id, slug, object}`` -- not a
            :class:`GatewayConfigDetail`. Verified live 2026-07-28. Call :meth:`get` for
            the full record.

        Raises:
            AISecPayloadError: If ``workspace_id`` is not a UUID.
        """
        _assert_uuid(workspace_id, "workspace_id")
        return request(
            RequestSpec[GatewayConfigCreateResponse](
                method="POST",
                base_url=self._base_url,
                path=AI_GW_CONFIGS_PATH,
                body={"name": name, "workspace_id": workspace_id, "config": dict(config)},
                auth=self._auth,
                response_model=GatewayConfigCreateResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update(
        self, config_id: str, *, name: str, workspace_id: str, config: Mapping[str, Any]
    ) -> GatewayWriteResponse:
        """Update a config.

        The body is the same shape create takes, not a patch: send every field.

        Args:
            config_id: Config UUID.
            name: Replacement display name.
            workspace_id: Workspace UUID the config belongs to.
            config: Replacement routing config object.

        Returns:
            The raw update response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If ``config_id`` or ``workspace_id`` is not a UUID.
        """
        _assert_uuid(config_id, "config_id")
        _assert_uuid(workspace_id, "workspace_id")
        return request(
            RequestSpec[GatewayWriteResponse](
                method="PUT",
                base_url=self._base_url,
                path=f"{AI_GW_CONFIGS_PATH}/{config_id}",
                body={"name": name, "workspace_id": workspace_id, "config": dict(config)},
                auth=self._auth,
                response_model=GatewayWriteResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, config_id: str) -> None:
        """Delete a config.

        A **hard delete** -- unlike ``deployments.delete()``, which archives, the config
        disappears from :meth:`list` entirely. Verified live 2026-07-28. No
        ``organisation_id`` query parameter, unlike deployments and integrations.

        Args:
            config_id: Config UUID.

        Raises:
            AISecPayloadError: If ``config_id`` is not a UUID.
        """
        _assert_uuid(config_id, "config_id")
        # The API answers 200 with an empty body; declaring no response model discards it.
        request(
            RequestSpec[None](
                method="DELETE",
                base_url=self._base_url,
                path=f"{AI_GW_CONFIGS_PATH}/{config_id}",
                auth=self._auth,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class AIGatewayGuardrailsClient(AIGatewaySubClient):
    """Client for AI Gateway guardrail operations (data plane)."""

    def list(self, *, workspace_id: str) -> ListGuardrailsResponse:
        """List the guardrails in one workspace.

        Args:
            workspace_id: Workspace UUID. Required -- omitting it returns ``404 AB02``.

        Returns:
            Guardrail list rows, which carry neither ``checks``, ``actions``, nor
            ``version_id``. Call :meth:`get` for those.

        Raises:
            AISecPayloadError: If ``workspace_id`` is not a UUID.
        """
        _assert_uuid(workspace_id, "workspace_id")
        return request(
            RequestSpec[ListGuardrailsResponse](
                method="GET",
                base_url=self._base_url,
                path=AI_GW_GUARDRAILS_PATH,
                params={"workspace_id": workspace_id},
                auth=self._auth,
                response_model=ListGuardrailsResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, guardrail_id: str) -> GatewayGuardrailDetail:
        """Fetch one guardrail.

        Args:
            guardrail_id: Guardrail UUID.

        Returns:
            Guardrail detail, adding ``checks``, ``actions``, and ``version_id`` on top of
            the list row.

        Raises:
            AISecPayloadError: If ``guardrail_id`` is not a UUID.
        """
        _assert_uuid(guardrail_id, "guardrail_id")
        return request(
            RequestSpec[GatewayGuardrailDetail](
                method="GET",
                base_url=self._base_url,
                path=f"{AI_GW_GUARDRAILS_PATH}/{guardrail_id}",
                auth=self._auth,
                response_model=GatewayGuardrailDetail,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create(
        self,
        *,
        workspace_id: str,
        name: str,
        checks: Sequence[GuardrailCheck | Mapping[str, Any]],
        actions: GuardrailActions | Mapping[str, Any],
    ) -> GatewayGuardrailCreateResponse:
        """Create a guardrail.

        Args:
            workspace_id: Workspace UUID the guardrail belongs to.
            name: Display name.
            checks: Check bindings, e.g. one :class:`GuardrailCheck` carrying
                ``panw-prisma-airs.intercept`` and its profile parameters.
            actions: What the gateway does when the checks resolve. A
                :class:`GuardrailActions` is dumped by alias, so its ``async_`` attribute
                goes on the wire as ``async``; a mapping is sent as given.

        Returns:
            A **creation receipt** -- ``{id, version_id, slug, object}`` -- not a
            :class:`GatewayGuardrailDetail`. Verified live 2026-07-28. Call :meth:`get`
            for the full record.

        Raises:
            AISecPayloadError: If ``workspace_id`` is not a UUID.
        """
        _assert_uuid(workspace_id, "workspace_id")
        return request(
            RequestSpec[GatewayGuardrailCreateResponse](
                method="POST",
                base_url=self._base_url,
                path=AI_GW_GUARDRAILS_PATH,
                body={
                    "workspace_id": workspace_id,
                    "name": name,
                    "checks": _as_payloads(checks),
                    "actions": _as_payload(actions),
                },
                auth=self._auth,
                response_model=GatewayGuardrailCreateResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, guardrail_id: str) -> None:
        """Delete a guardrail.

        A **hard delete** -- unlike ``deployments.delete()``, which archives, the guardrail
        disappears from :meth:`list` entirely. Verified live 2026-07-28. No
        ``organisation_id`` query parameter, unlike deployments and integrations.

        Args:
            guardrail_id: Guardrail UUID.

        Raises:
            AISecPayloadError: If ``guardrail_id`` is not a UUID.
        """
        _assert_uuid(guardrail_id, "guardrail_id")
        # The API answers 200 with an empty body; declaring no response model discards it.
        request(
            RequestSpec[None](
                method="DELETE",
                base_url=self._base_url,
                path=f"{AI_GW_GUARDRAILS_PATH}/{guardrail_id}",
                auth=self._auth,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class AIGatewayProvidersClient(AIGatewaySubClient):
    """Client for AI Gateway provider operations (data plane).

    A provider is an organisation-level integration bound into one workspace, so creating
    one takes the integration's id as well as the workspace's.
    """

    def list(self, *, workspace_id: str) -> ListProvidersResponse:
        """List the providers bound into one workspace.

        Args:
            workspace_id: Workspace UUID. Required -- omitting it returns ``404 AB02``.

        Returns:
            Provider bindings for that workspace.

        Raises:
            AISecPayloadError: If ``workspace_id`` is not a UUID.
        """
        _assert_uuid(workspace_id, "workspace_id")
        return request(
            RequestSpec[ListProvidersResponse](
                method="GET",
                base_url=self._base_url,
                path=AI_GW_PROVIDERS_PATH,
                params={"workspace_id": workspace_id},
                auth=self._auth,
                response_model=ListProvidersResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def create(
        self,
        *,
        workspace_id: str,
        ai_provider_id: str,
        name: str,
        integration_id: str,
        slug: str,
        note: str | None = None,
        expires_at: str | None = None,
    ) -> GatewayProviderCreateResponse:
        """Bind an organisation integration into a workspace as a provider.

        Args:
            workspace_id: Workspace UUID to bind into.
            ai_provider_id: Upstream AI provider UUID, e.g. the OpenAI or Vertex provider.
            name: Display name.
            integration_id: Org-level integration this provider draws credentials from.
            slug: Provider slug, used to address the provider from a routing config.
            note: Free text.
            expires_at: Expiry timestamp. Omitted from the body when unset.

        Returns:
            A **creation receipt** -- ``{id, slug, object}``. It has **no** ``version_id``,
            unlike the config and guardrail receipts. Verified live 2026-07-28.

        Raises:
            AISecPayloadError: If ``workspace_id``, ``ai_provider_id``, or
                ``integration_id`` is not a UUID.
        """
        _assert_uuid(workspace_id, "workspace_id")
        _assert_uuid(ai_provider_id, "ai_provider_id")
        _assert_uuid(integration_id, "integration_id")

        body: dict[str, Any] = {
            "workspace_id": workspace_id,
            "ai_provider_id": ai_provider_id,
            "name": name,
            "integration_id": integration_id,
            "slug": slug,
        }
        if note is not None:
            body["note"] = note
        if expires_at is not None:
            body["expires_at"] = expires_at

        return request(
            RequestSpec[GatewayProviderCreateResponse](
                method="POST",
                base_url=self._base_url,
                path=AI_GW_PROVIDERS_PATH,
                body=body,
                auth=self._auth,
                response_model=GatewayProviderCreateResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, provider_id: str) -> None:
        """Delete a provider.

        A **hard delete** -- unlike ``deployments.delete()``, which archives, the provider
        disappears from :meth:`list` entirely. Verified live 2026-07-28. No
        ``organisation_id`` query parameter, unlike deployments and integrations.

        Args:
            provider_id: Provider UUID.

        Raises:
            AISecPayloadError: If ``provider_id`` is not a UUID.
        """
        _assert_uuid(provider_id, "provider_id")
        # The API answers 200 with an empty body; declaring no response model discards it.
        request(
            RequestSpec[None](
                method="DELETE",
                base_url=self._base_url,
                path=f"{AI_GW_PROVIDERS_PATH}/{provider_id}",
                auth=self._auth,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


def _api_key_body(
    *,
    name: str,
    scopes: Sequence[str],
    organisation_id: str,
    workspace_id: str,
    key_type: str,
    description: str | None = None,
    expires_at: str | None = None,
    defaults: Mapping[str, Any] | None = None,
    rotation_policy: Mapping[str, Any] | None = None,
    user_id: str | None = None,
) -> dict[str, Any]:
    """Assemble an API-key request body, omitting the optional fields left unset.

    ``key_type`` is spelled ``type`` on the wire; the argument is renamed only because
    ``type`` shadows a builtin.
    """
    body: dict[str, Any] = {
        "name": name,
        "scopes": list(scopes),
        "organisation_id": organisation_id,
        "workspace_id": workspace_id,
        "type": key_type,
    }
    if description is not None:
        body["description"] = description
    if expires_at is not None:
        body["expires_at"] = expires_at
    if defaults is not None:
        body["defaults"] = dict(defaults)
    if rotation_policy is not None:
        body["rotation_policy"] = dict(rotation_policy)
    if user_id is not None:
        body["user_id"] = user_id
    return body


class AIGatewayApiKeysClient(AIGatewaySubClient):
    """Client for AI Gateway API-key operations (data plane).

    Service and user keys are separate sub-collections; there is no combined ``api-keys``
    endpoint -- it is OPA-denied.
    """

    def _list_at(self, path: str, workspace_id: str) -> ListApiKeysResponse:
        _assert_uuid(workspace_id, "workspace_id")
        return request(
            RequestSpec[ListApiKeysResponse](
                method="GET",
                base_url=self._base_url,
                path=path,
                params={"workspace_id": workspace_id},
                auth=self._auth,
                response_model=ListApiKeysResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def _write_at(
        self, method: Literal["POST", "PUT"], path: str, body: dict[str, Any]
    ) -> GatewayWriteResponse:
        workspace_id: str = body["workspace_id"]
        _assert_uuid(workspace_id, "workspace_id")
        return request(
            RequestSpec[GatewayWriteResponse](
                method=method,
                base_url=self._base_url,
                path=path,
                body=body,
                auth=self._auth,
                response_model=GatewayWriteResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_service(self, *, workspace_id: str) -> ListApiKeysResponse:
        """List the service API keys in one workspace.

        Args:
            workspace_id: Workspace UUID.

        Returns:
            Service keys. The secret itself is only ever returned at creation.

        Raises:
            AISecPayloadError: If ``workspace_id`` is not a UUID.
        """
        return self._list_at(AI_GW_API_KEYS_SERVICE_PATH, workspace_id)

    def list_user(self, *, workspace_id: str) -> ListApiKeysResponse:
        """List the user API keys in one workspace.

        Args:
            workspace_id: Workspace UUID.

        Returns:
            User-scoped keys.

        Raises:
            AISecPayloadError: If ``workspace_id`` is not a UUID.
        """
        return self._list_at(AI_GW_API_KEYS_USER_PATH, workspace_id)

    def create_service(
        self,
        *,
        name: str,
        scopes: Sequence[str],
        organisation_id: str,
        workspace_id: str,
        key_type: str,
        description: str | None = None,
        expires_at: str | None = None,
        defaults: Mapping[str, Any] | None = None,
        rotation_policy: Mapping[str, Any] | None = None,
    ) -> GatewayWriteResponse:
        """Create a service API key.

        Args:
            name: Display name.
            scopes: e.g. ``completions.write``, ``mcp.invoke``, ``prompts.render``,
                ``agents.invoke``, ``logs.write``.
            organisation_id: The TSG as a numeric string -- **not** the organisation UUID
                returned on reads.
            workspace_id: Workspace UUID.
            key_type: Usually ``workspace``. Sent as ``type``.
            description: Free text.
            expires_at: Expiry timestamp.
            defaults: Per-key request defaults.
            rotation_policy: Key rotation policy.

        Returns:
            The raw create response -- the only place the key secret appears. Capture it.

        Raises:
            AISecPayloadError: If ``workspace_id`` is not a UUID.
        """
        return self._write_at(
            "POST",
            AI_GW_API_KEYS_SERVICE_PATH,
            _api_key_body(
                name=name,
                scopes=scopes,
                organisation_id=organisation_id,
                workspace_id=workspace_id,
                key_type=key_type,
                description=description,
                expires_at=expires_at,
                defaults=defaults,
                rotation_policy=rotation_policy,
            ),
        )

    def create_user(
        self,
        *,
        name: str,
        scopes: Sequence[str],
        organisation_id: str,
        workspace_id: str,
        key_type: str,
        user_id: str,
        description: str | None = None,
        expires_at: str | None = None,
        defaults: Mapping[str, Any] | None = None,
        rotation_policy: Mapping[str, Any] | None = None,
    ) -> GatewayWriteResponse:
        """Create a user API key.

        Args:
            name: Display name.
            scopes: Key scopes, as for :meth:`create_service`.
            organisation_id: The TSG as a numeric string.
            workspace_id: Workspace UUID.
            key_type: Usually ``workspace``. Sent as ``type``.
            user_id: The user the key belongs to. Required for user keys only, which is
                the one field that separates this call from :meth:`create_service`.
            description: Free text.
            expires_at: Expiry timestamp.
            defaults: Per-key request defaults.
            rotation_policy: Key rotation policy.

        Returns:
            The raw create response -- the only place the key secret appears. Capture it.

        Raises:
            AISecPayloadError: If ``workspace_id`` is not a UUID.
        """
        return self._write_at(
            "POST",
            AI_GW_API_KEYS_USER_PATH,
            _api_key_body(
                name=name,
                scopes=scopes,
                organisation_id=organisation_id,
                workspace_id=workspace_id,
                key_type=key_type,
                description=description,
                expires_at=expires_at,
                defaults=defaults,
                rotation_policy=rotation_policy,
                user_id=user_id,
            ),
        )

    def update_service(
        self,
        key_id: str,
        *,
        name: str,
        scopes: Sequence[str],
        organisation_id: str,
        workspace_id: str,
        key_type: str,
        description: str | None = None,
        expires_at: str | None = None,
        defaults: Mapping[str, Any] | None = None,
        rotation_policy: Mapping[str, Any] | None = None,
    ) -> GatewayWriteResponse:
        """Update a service API key.

        The body is the same shape create takes, not a patch: send every field.

        Args:
            key_id: Key UUID.
            name: Replacement display name.
            scopes: Replacement scopes.
            organisation_id: The TSG as a numeric string.
            workspace_id: Workspace UUID.
            key_type: Usually ``workspace``. Sent as ``type``.
            description: Free text.
            expires_at: Expiry timestamp.
            defaults: Per-key request defaults.
            rotation_policy: Key rotation policy.

        Returns:
            The raw update response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If ``key_id`` or ``workspace_id`` is not a UUID.
        """
        _assert_uuid(key_id, "key_id")
        return self._write_at(
            "PUT",
            f"{AI_GW_API_KEYS_SERVICE_PATH}/{key_id}",
            _api_key_body(
                name=name,
                scopes=scopes,
                organisation_id=organisation_id,
                workspace_id=workspace_id,
                key_type=key_type,
                description=description,
                expires_at=expires_at,
                defaults=defaults,
                rotation_policy=rotation_policy,
            ),
        )

    def update_user(
        self,
        key_id: str,
        *,
        name: str,
        scopes: Sequence[str],
        organisation_id: str,
        workspace_id: str,
        key_type: str,
        user_id: str,
        description: str | None = None,
        expires_at: str | None = None,
        defaults: Mapping[str, Any] | None = None,
        rotation_policy: Mapping[str, Any] | None = None,
    ) -> GatewayWriteResponse:
        """Update a user API key.

        Args:
            key_id: Key UUID.
            name: Replacement display name.
            scopes: Replacement scopes.
            organisation_id: The TSG as a numeric string.
            workspace_id: Workspace UUID.
            key_type: Usually ``workspace``. Sent as ``type``.
            user_id: The user the key belongs to.
            description: Free text.
            expires_at: Expiry timestamp.
            defaults: Per-key request defaults.
            rotation_policy: Key rotation policy.

        Returns:
            The raw update response. Shape unverified against a live tenant.

        Raises:
            AISecPayloadError: If ``key_id`` or ``workspace_id`` is not a UUID.
        """
        _assert_uuid(key_id, "key_id")
        return self._write_at(
            "PUT",
            f"{AI_GW_API_KEYS_USER_PATH}/{key_id}",
            _api_key_body(
                name=name,
                scopes=scopes,
                organisation_id=organisation_id,
                workspace_id=workspace_id,
                key_type=key_type,
                description=description,
                expires_at=expires_at,
                defaults=defaults,
                rotation_policy=rotation_policy,
                user_id=user_id,
            ),
        )


class AIGatewayClient:
    """Client for the Prisma AIRS AI Gateway, managed through Strata Cloud Manager.

    Spans two planes over one credential set: the **data plane** (``/ai_gw/v2``) for
    workspace-scoped config and runtime telemetry, and the **admin plane**
    (``/ai_gw/admin/v2``) for organisation-level config.

    The two planes authorize against **different SCM role scopes**, and the service account
    needs both grants or half the API returns 403:

    * an admin role at **tenant root** scope -> ``/ai_gw/admin/v2/*``
    * ``view_only_admin`` or higher on the **``main_airs_workspace_<TSG>``** scope ->
      ``/ai_gw/v2/*``

    Both can coexist on one account, but SCM's Access Management UI edits an existing role
    row by default -- use *Add Role* to add the second, or you will move the first instead
    of adding to it. A ``403`` whose body carries ``errorCode: "AB03"`` means the
    workspace-scope grant is missing; a ``403`` carrying ``x-opa-decision: false`` means the
    tenant-root grant is.

    Credentials resolve from the constructor, then ``PANW_AI_GW_*``, then ``PANW_MGMT_*``,
    each field independently.

    Example:
        >>> gw = AIGatewayClient()
        >>> gw.workspaces.list().data[0].scope_name
        'main_airs_workspace_1852583913'
    """

    #: Workspace reads (data plane by default) and writes (admin plane only).
    workspaces: AIGatewayWorkspacesClient
    #: Gateway routing configs.
    configs: AIGatewayConfigsClient
    #: Workspace guardrails.
    guardrails: AIGatewayGuardrailsClient
    #: Workspace-scoped provider bindings.
    providers: AIGatewayProvidersClient
    #: Service and user API keys.
    api_keys: AIGatewayApiKeysClient

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
            fallback_env_prefix=ENV_PREFIX_MGMT,
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            token_endpoint=token_endpoint,
        )

        self._data_endpoint = resolve_gateway_endpoint("data", data_endpoint)
        self._admin_endpoint = resolve_gateway_endpoint("admin", admin_endpoint)
        self._num_retries = _validate_retries(num_retries)

        self._oauth = OAuthClient(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            tsg_id=credentials.tsg_id,
            token_endpoint=credentials.token_endpoint,
            timeout=timeout,
        )
        # Every AI Gateway endpoint requires x-tsg-id on top of the bearer token.
        self._auth: AuthAdapter = TsgHeaderAuth(OAuthAuth(self._oauth), credentials.tsg_id)

        self._owns_client = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)

        # Workspaces is the one resource spanning both planes; the rest are data-plane only.
        self.workspaces = AIGatewayWorkspacesClient(
            base_url=self._data_endpoint,
            admin_base_url=self._admin_endpoint,
            auth=self._auth,
            http=self._http,
            num_retries=self._num_retries,
        )
        self.configs = AIGatewayConfigsClient(
            base_url=self._data_endpoint,
            auth=self._auth,
            http=self._http,
            num_retries=self._num_retries,
        )
        self.guardrails = AIGatewayGuardrailsClient(
            base_url=self._data_endpoint,
            auth=self._auth,
            http=self._http,
            num_retries=self._num_retries,
        )
        self.providers = AIGatewayProvidersClient(
            base_url=self._data_endpoint,
            auth=self._auth,
            http=self._http,
            num_retries=self._num_retries,
        )
        self.api_keys = AIGatewayApiKeysClient(
            base_url=self._data_endpoint,
            auth=self._auth,
            http=self._http,
            num_retries=self._num_retries,
        )

        # The admin-plane sub-clients are implemented in ai_gateway_admin, but the
        # reference exposes them from this same entry client. Composing them here keeps a
        # single AI Gateway client rather than making callers hold two, and they share the
        # token cache and connection pool with everything above.
        # Telemetry is the one admin-package client that reads the data plane, and the
        # only one needing the tenant id separately -- it interpolates it into paths
        # rather than relying solely on the x-tsg-id header.
        self.telemetry = AIGatewayTelemetryClient(
            base_url=self._data_endpoint,
            auth=self._auth,
            http_client=self._http,
            tsg_id=credentials.tsg_id,
            num_retries=self._num_retries,
        )
        self.integrations = AIGatewayIntegrationsClient(
            base_url=self._admin_endpoint,
            auth=self._auth,
            http_client=self._http,
            num_retries=self._num_retries,
        )
        self.deployments = AIGatewayDeploymentsClient(
            base_url=self._admin_endpoint,
            auth=self._auth,
            http_client=self._http,
            num_retries=self._num_retries,
        )
        self.plugins = AIGatewayPluginsClient(
            base_url=self._admin_endpoint,
            auth=self._auth,
            http_client=self._http,
            num_retries=self._num_retries,
        )
        self.organisations = AIGatewayOrganisationsClient(
            base_url=self._admin_endpoint,
            auth=self._auth,
            http_client=self._http,
            num_retries=self._num_retries,
        )
        self.mcp_integrations = AIGatewayMcpIntegrationsClient(
            base_url=self._admin_endpoint,
            auth=self._auth,
            http_client=self._http,
            num_retries=self._num_retries,
        )
        self.audit_logs = AIGatewayAuditLogsClient(
            base_url=self._admin_endpoint,
            auth=self._auth,
            http_client=self._http,
            num_retries=self._num_retries,
        )

    @property
    def data_endpoint(self) -> str:
        """Base URL of the data plane (``/ai_gw/v2``)."""
        return self._data_endpoint

    @property
    def admin_endpoint(self) -> str:
        """Base URL of the admin plane (``/ai_gw/admin/v2``)."""
        return self._admin_endpoint

    @property
    def tsg_id(self) -> str:
        """The tenant every request is scoped to, sent as ``x-tsg-id``."""
        return self._oauth.tsg_id

    @property
    def num_retries(self) -> int:
        """Retry budget every sub-client applies, not counting the initial attempt."""
        return self._num_retries

    @property
    def auth(self) -> AuthAdapter:
        """Bearer-token-plus-tenant-header adapter shared by every sub-client.

        Exposed so the admin-plane resource clients, which are constructed outside this
        module, can attach to the same credentials and token cache instead of opening a
        second OAuth session against the same tenant.
        """
        return self._auth

    @property
    def http(self) -> httpx.Client:
        """The HTTP client every sub-client sends through."""
        return self._http

    def close(self) -> None:
        """Close the OAuth session, and the HTTP client if this instance created it."""
        self._oauth.close()
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> AIGatewayClient:
        """Enter a context that closes the HTTP clients on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the OAuth session and any HTTP client this instance owns."""
        self.close()
