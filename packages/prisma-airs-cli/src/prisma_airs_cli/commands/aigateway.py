"""``airs aigateway`` -- AI Gateway workspaces and runtime telemetry.

The gateway spans two planes over one credential set, and which plane a read lands on
decides what it can see: the data plane shows only the workspaces the service account
holds an SCM workspace-scope grant on, while the admin plane sees the whole tenant. Every
command here therefore says which plane it used when the answer could be surprising, and
turns a 403 into the specific missing grant rather than a bare status code.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Annotated, Any, Final

import typer

from prisma_airs import AIGatewayClient
from prisma_airs.ai_gateway.ai_gateway_core import AIGatewayPlane, AIGatewayWorkspaceStatus
from prisma_airs.errors import AISecPayloadError, AISecSDKException
from prisma_airs.models.ai_gateway import (
    GatewayWorkspace,
    GatewayWorkspaceCreateResponse,
    GatewayWorkspaceDetail,
    RateLimits,
    UsageLimits,
)
from prisma_airs_cli.confirm import confirm_or_abort
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.output import OutputFormat
from prisma_airs_cli.renderers.aigateway import (
    CostRecord,
    CostReport,
    WorkspaceDetail,
    WorkspaceRow,
    render_cost_report,
    render_header,
    render_workspace_detail,
    render_workspace_list,
)
from prisma_airs_cli.ui import ui

aigateway_app = typer.Typer(
    name="aigateway",
    help="AI Gateway operations.",
    no_args_is_help=True,
)

workspace_app = typer.Typer(
    name="workspace",
    help="Manage AI Gateway workspaces.",
    no_args_is_help=True,
)

telemetry_app = typer.Typer(
    name="telemetry",
    help="AI Gateway runtime telemetry (data plane).",
    no_args_is_help=True,
)

aigateway_app.add_typer(workspace_app)
aigateway_app.add_typer(telemetry_app)

#: A single record with nested settings blocks has no honest tabular form, so the detail
#: views take the three formats the reference documents for them and reject the other two
#: rather than quietly emitting YAML for ``--output csv``.
_DETAIL_FORMATS: Final[tuple[OutputFormat, ...]] = (
    OutputFormat.PRETTY,
    OutputFormat.JSON,
    OutputFormat.YAML,
)

#: Rolling telemetry window when ``--days`` is not given.
_DEFAULT_COST_DAYS: Final = 7

#: A workspace name shorter than this carries too little signal to judge a scope against.
_MIN_SCOPE_TOKEN_LENGTH: Final = 4

#: The gateway answers 403 for a missing SCM grant and 404 for a ref it cannot resolve.
_HTTP_FORBIDDEN: Final = 403
_HTTP_NOT_FOUND: Final = 404


class Plane(str, Enum):
    """Which plane a workspace read is served from."""

    DATA = "data"
    ADMIN = "admin"


class WorkspaceStatus(str, Enum):
    """Workspace lifecycle state."""

    ACTIVE = "active"
    ARCHIVED = "archived"


def _plane_arg(plane: Plane | None) -> AIGatewayPlane:
    """Narrow the CLI enum to the SDK literal, defaulting to the data plane."""
    return "admin" if plane is Plane.ADMIN else "data"


def _status_arg(status: WorkspaceStatus | None) -> AIGatewayWorkspaceStatus | None:
    """Narrow the CLI enum to the SDK literal. ``None`` means "do not filter"."""
    if status is None:
        return None
    return "archived" if status is WorkspaceStatus.ARCHIVED else "active"


# ---------------------------------------------------------------------------
# Failure reporting
# ---------------------------------------------------------------------------


def _grant_hint(err: AISecSDKException) -> str | None:
    """Name the SCM grant a 403 is really about, or ``None`` for any other error.

    Both planes answer 403 for a missing grant, but they are different grants and fixing
    the wrong one costs an afternoon. ``errorCode AB03`` -- which the SDK appends to the
    message -- identifies the data-plane workspace scope; anything else at 403 is the
    tenant-root admin role.
    """
    if err.status_code != _HTTP_FORBIDDEN:
        return None
    grant = (
        "the service account is missing a workspace-scope grant (data plane, /ai_gw/v2)"
        if "AB03" in err.raw_message
        else "the service account is missing a tenant-root admin grant (admin plane, "
        "/ai_gw/admin/v2)"
    )
    return (
        f"{grant}. SCM Access Management edits the existing role row by default — "
        'use "Add Role" so the account ends up with both role rows, not one row moved.'
    )


def _fail_with_grant_hint(err: AISecSDKException) -> typer.Exit:
    """Report a failed call, prefixed with the grant hint when the gateway answered 403."""
    hint = _grant_hint(err)
    if hint is not None:
        ui.warn(f"403: {hint}")
    return fail(err)


# ---------------------------------------------------------------------------
# Wire shapes -> display shapes
# ---------------------------------------------------------------------------


def _limits(value: UsageLimits | RateLimits) -> list[dict[str, Any]]:
    """Normalise a limits field to a list.

    Both limit fields are ``array | object | null`` on the wire: the array of policy
    objects is canonical and the single-object form is legacy, so the display shape only
    ever sees a list.
    """
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    return [item.model_dump(mode="json", by_alias=True, exclude_none=True) for item in value]


def _row(workspace: GatewayWorkspace) -> WorkspaceRow:
    """Flatten a list row for display. ``is_default`` arrives as 0/1, not a boolean."""
    return WorkspaceRow(
        id=workspace.id,
        slug=workspace.slug,
        name=workspace.name,
        status=workspace.status,
        is_default=bool(workspace.is_default),
        scope_name=workspace.scope_name,
    )


def _detail(workspace: GatewayWorkspaceDetail) -> WorkspaceDetail:
    """Flatten a detail record for display.

    ``scope_name`` is not part of the declared detail schema but a live tenant returns it,
    so it is read out of the preserved extra fields rather than dropped -- it is the one
    field that explains why a workspace is or is not visible on the data plane.
    """
    extra = workspace.model_extra or {}
    scope_name = extra.get("scope_name")
    return WorkspaceDetail(
        id=workspace.id,
        slug=workspace.slug,
        name=workspace.name,
        status=workspace.status,
        is_default=bool(workspace.is_default),
        icon=workspace.icon,
        description=workspace.description,
        created_at=workspace.created_at,
        last_updated_at=workspace.last_updated_at,
        scope_name=scope_name if isinstance(scope_name, str) else None,
        defaults=workspace.defaults,
        usage_limits=_limits(workspace.usage_limits),
        rate_limits=_limits(workspace.rate_limits),
        security_settings=workspace.security_settings,
        data_plane_security_settings=workspace.data_plane_security_settings,
        settings=workspace.settings,
    )


def _detail_from_create(created: GatewayWorkspaceCreateResponse) -> WorkspaceDetail:
    """Fall back to what a create returned when the re-read is not permitted.

    Create answers with most of the record but not ``status``, ``is_default``, ``icon``,
    the limit arrays, or the settings blocks. Showing that beats showing nothing.
    """
    return WorkspaceDetail(
        id=created.id,
        slug=created.slug,
        name=created.name,
        description=created.description,
        created_at=created.created_at,
        last_updated_at=created.last_updated_at,
        scope_name=created.scope_name,
        defaults=created.defaults,
    )


# ---------------------------------------------------------------------------
# Flag parsing
# ---------------------------------------------------------------------------


def _parse_json_flag(raw: str | None, flag: str) -> Any:
    """Parse a JSON-valued flag, or ``None`` when it was not supplied."""
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as err:
        raise usage_error(f"{flag} must be valid JSON") from err


def _json_object(raw: str | None, flag: str) -> dict[str, Any] | None:
    """Parse a flag the API requires to be a JSON object."""
    value = _parse_json_flag(raw, flag)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise usage_error(f"{flag} must be a JSON object")
    return value


def _json_policy_array(raw: str | None, flag: str) -> list[dict[str, Any]] | None:
    """Parse a limit-policy flag, which the API requires to be an array of objects.

    Rejected here rather than forwarded, because a lone policy object is accepted by the
    JSON parser and then fails deep inside serialisation with an error naming neither the
    flag nor the shape it wanted.
    """
    value = _parse_json_flag(raw, flag)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise usage_error(f"{flag} must be a JSON array of policy objects")
    return value


@dataclass(frozen=True)
class _WriteFields:
    """The mutable workspace fields a create or update actually supplied.

    Only fields the caller passed are set, so an update stays a true partial patch and a
    create never sends stray nulls -- the API treats an explicit null as a value.
    """

    name: str | None = None
    description: str | None = None
    icon: str | None = None
    defaults: dict[str, Any] | None = None
    users: list[str] | None = None
    usage_limits: list[dict[str, Any]] | None = None
    rate_limits: list[dict[str, Any]] | None = None

    def is_empty(self) -> bool:
        """Whether nothing at all was supplied."""
        return all(value is None for value in asdict(self).values())


def _write_fields(
    *,
    name: str | None = None,
    description: str | None = None,
    icon: str | None = None,
    metadata: str | None = None,
    defaults: str | None = None,
    users: str | None = None,
    usage_limits: str | None = None,
    rate_limits: str | None = None,
) -> _WriteFields:
    """Collect the workspace write fields from raw flag values.

    ``--metadata`` is sugar for ``defaults.metadata``, which is where the API actually
    keeps it, and it wins over ``--defaults`` on that one key.
    """
    parsed_defaults = _json_object(defaults, "--defaults")
    parsed_metadata = _json_object(metadata, "--metadata")
    merged: dict[str, Any] | None = None
    if parsed_defaults is not None or parsed_metadata is not None:
        merged = dict(parsed_defaults or {})
        if parsed_metadata is not None:
            merged["metadata"] = parsed_metadata

    return _WriteFields(
        name=name,
        description=description,
        icon=icon,
        defaults=merged,
        users=None if users is None else [u.strip() for u in users.split(",") if u.strip()],
        usage_limits=_json_policy_array(usage_limits, "--usage-limits"),
        rate_limits=_json_policy_array(rate_limits, "--rate-limits"),
    )


def scope_name_looks_unrelated(name: str, scope_name: str) -> bool:
    """Whether a scope name shares no token with the workspace name.

    ``scope_name`` is not derived from ``name``, and a workspace created with a scope
    nobody holds silently vanishes from data-plane lists -- the most common way a fresh
    workspace "goes missing". Names too short to compare are never flagged, since a
    two-letter name would match almost anything.
    """
    token = "".join(character for character in name.lower() if character.isalnum())
    if len(token) < _MIN_SCOPE_TOKEN_LENGTH:
        return False
    scope_token = "".join(character for character in scope_name.lower() if character.isalnum())
    return token not in scope_token


def _report_written(message: str, fmt: OutputFormat) -> None:
    """Confirm a write without corrupting a structured rendering.

    The confirmation is commentary, not the result. Printed to stdout ahead of the JSON a
    pipeline is about to parse it would break the parse, so in any format but ``pretty``
    it goes to stderr instead of being dropped.
    """
    if fmt is OutputFormat.PRETTY:
        ui.success(message)
    else:
        ui.status(message)


def _check_detail_format(fmt: OutputFormat) -> None:
    """Reject a format this view cannot honestly produce."""
    if fmt not in _DETAIL_FORMATS:
        raise usage_error(f"--output {fmt.value} is not available here. Use pretty, json, or yaml")


# ---------------------------------------------------------------------------
# Lookups shared by several commands
# ---------------------------------------------------------------------------


def _resolve_ref(client: AIGatewayClient, ref: str, planes: Sequence[AIGatewayPlane]) -> str:
    """Turn a workspace display name into a slug the API will accept.

    The API takes only a UUID or a slug; addressed by display name a write answers a
    misleading ``400 AB01`` ("No update fields provided"). Matching the ref against the
    workspace list makes name, slug, and UUID all work. An unmatched ref passes through
    untouched so the API's own error stands rather than a guess replacing it.

    Raises:
        typer.Exit: If the name matches more than one workspace. Picking one would be a
            coin flip on which workspace gets modified.
    """
    for plane in planes:
        try:
            rows = [_row(workspace) for workspace in client.workspaces.list(plane=plane).data]
        except AISecSDKException:
            continue  # no grant on this plane, most likely -- try the next one
        if any(ref in (row.id, row.slug) for row in rows):
            return ref
        matches = [row for row in rows if row.name == ref]
        if len(matches) > 1:
            slugs = ", ".join(row.slug for row in matches)
            raise usage_error(f"workspace name '{ref}' is ambiguous ({slugs}) — use a slug or UUID")
        if matches:
            return matches[0].slug
    return ref


def _get_detail(client: AIGatewayClient, ref: str, *, plane: AIGatewayPlane) -> WorkspaceDetail:
    """Fetch one workspace, retrying once against a resolved ref.

    A display name is neither a UUID nor a slug, so the SDK rejects it before the request
    goes out; a well-formed but unknown slug reaches the API and 404s. Both mean the same
    thing to a user who typed a name, so both get one resolution attempt.
    """
    try:
        return _detail(client.workspaces.get(ref, plane=plane))
    except AISecSDKException as err:
        if not isinstance(err, AISecPayloadError) and err.status_code != _HTTP_NOT_FOUND:
            raise
        planes: tuple[AIGatewayPlane, ...] = (plane,) if plane == "admin" else (plane, "admin")
        resolved = _resolve_ref(client, ref, planes)
        if resolved == ref:
            raise
        return _detail(client.workspaces.get(resolved, plane=plane))


# ---------------------------------------------------------------------------
# workspace
# ---------------------------------------------------------------------------


@workspace_app.command("list")
def list_workspaces(
    *,
    plane: Annotated[
        Plane | None,
        typer.Option("--plane", help="Plane to read from: data (scoped) or admin (whole tenant)."),
    ] = None,
    status: Annotated[
        WorkspaceStatus | None,
        typer.Option("--status", help="Filter by lifecycle state: active or archived."),
    ] = None,
    # The CLI flag stays `--all`; the parameter is renamed off the builtin.
    merge_all: Annotated[
        bool,
        typer.Option(
            "--all", help="Merge active + archived admin-plane reads (whole tenant, both states)."
        ),
    ] = False,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List workspaces (default: active workspaces you are scoped to).

    Examples:
        $ airs aigateway workspace list
        $ airs aigateway workspace list --plane admin
        $ airs aigateway workspace list --plane admin --status archived
        $ airs aigateway workspace list --all --output json
    """
    if output is OutputFormat.PRETTY:
        render_header()
    if merge_all and (plane is not None or status is not None):
        raise usage_error(
            "--all already merges admin-plane active + archived; drop --plane/--status"
        )

    try:
        with AIGatewayClient() as client:
            if merge_all:
                # No single call returns both states: the API filters to active unless
                # asked otherwise, and only the admin plane sees the whole tenant.
                pages = (
                    client.workspaces.list(plane="admin"),
                    client.workspaces.list(plane="admin", status="archived"),
                )
                rows = [_row(workspace) for page in pages for workspace in page.data]
            else:
                page = client.workspaces.list(plane=_plane_arg(plane), status=_status_arg(status))
                rows = [_row(workspace) for workspace in page.data]
    except AISecSDKException as err:
        raise _fail_with_grant_hint(err) from err

    render_workspace_list(rows, output)
    if output is OutputFormat.PRETTY and not merge_all and plane is not Plane.ADMIN:
        ui.status(
            "Data-plane list shows only active workspaces you are scoped to — "
            "use --plane admin or --all for the whole tenant."
        )


@workspace_app.command("get")
def get_workspace(
    ref: Annotated[str, typer.Argument(help="Workspace UUID, slug, or display name.")],
    *,
    plane: Annotated[
        Plane | None,
        typer.Option("--plane", help="Plane to read from: data (scoped) or admin (whole tenant)."),
    ] = None,
    output: Annotated[
        OutputFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = OutputFormat.PRETTY,
) -> None:
    """Get one workspace by UUID or slug (includes settings blocks).

    Examples:
        $ airs aigateway workspace get ws-main-a-349e0e
        $ airs aigateway workspace get 16f7e90d-382a-4e78-b577-1b01eb5f8297 --plane admin
    """
    _check_detail_format(output)
    if output is OutputFormat.PRETTY:
        render_header()

    try:
        with AIGatewayClient() as client:
            workspace = _get_detail(client, ref, plane=_plane_arg(plane))
    except AISecSDKException as err:
        raise _fail_with_grant_hint(err) from err

    render_workspace_detail(workspace, output)


@workspace_app.command("create")
def create_workspace(
    *,
    name: Annotated[str, typer.Option("--name", help="Display name.")],
    scope_name: Annotated[
        str,
        typer.Option(
            "--scope-name",
            help="SCM role scope granting data-plane access (e.g. ws_production_bx7qw0) "
            "— not derived from --name.",
        ),
    ],
    description: Annotated[
        str | None, typer.Option("--description", help="Workspace description.")
    ] = None,
    icon: Annotated[str | None, typer.Option("--icon", help="Workspace icon.")] = None,
    metadata: Annotated[
        str | None,
        typer.Option("--metadata", help="Sugar for defaults.metadata (flat string map)."),
    ] = None,
    defaults: Annotated[
        str | None, typer.Option("--defaults", help="Workspace defaults object.")
    ] = None,
    users: Annotated[
        str | None,
        typer.Option("--users", help="Comma-separated user ids to seed the workspace with."),
    ] = None,
    usage_limits: Annotated[
        str | None,
        typer.Option(
            "--usage-limits", help="Usage-limit policies — a JSON ARRAY of policy objects."
        ),
    ] = None,
    rate_limits: Annotated[
        str | None,
        typer.Option("--rate-limits", help="Rate-limit policies — a JSON ARRAY of policy objects."),
    ] = None,
    output: Annotated[
        OutputFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = OutputFormat.PRETTY,
) -> None:
    """Create a workspace (admin plane).

    Examples:
        $ airs aigateway workspace create --name Production --scope-name ws_production_bx7qw0
        $ airs aigateway workspace create --name Staging --scope-name ws_staging_a1b2c3
          --metadata '{"env":"staging"}' --rate-limits '[{"type":"requests","unit":"rpm"}]'
    """
    _check_detail_format(output)
    if output is OutputFormat.PRETTY:
        render_header()
    if scope_name_looks_unrelated(name, scope_name):
        ui.warn(
            f"--scope-name '{scope_name}' shares no token with --name '{name}'. "
            "A workspace created with a scope nobody holds will not appear in data-plane lists."
        )

    fields = _write_fields(
        description=description,
        icon=icon,
        metadata=metadata,
        defaults=defaults,
        users=users,
        usage_limits=usage_limits,
        rate_limits=rate_limits,
    )

    try:
        with AIGatewayClient() as client:
            created = client.workspaces.create(
                name=name,
                scope_name=scope_name,
                description=fields.description,
                icon=fields.icon,
                defaults=fields.defaults,
                users=fields.users,
                usage_limits=fields.usage_limits,
                rate_limits=fields.rate_limits,
            )
            # Create omits status, is_default, icon, both limit arrays, and the settings
            # blocks. Re-read on the admin plane, because a brand-new workspace's scope
            # may not be granted to this service account yet.
            try:
                workspace = _get_detail(client, created.id, plane="admin")
            except AISecSDKException:
                workspace = _detail_from_create(created)
    except AISecSDKException as err:
        raise _fail_with_grant_hint(err) from err

    _report_written(f"Workspace created: {workspace.id}", output)
    render_workspace_detail(workspace, output)


@workspace_app.command("update")
def update_workspace(
    ref: Annotated[str, typer.Argument(help="Workspace UUID, slug, or display name.")],
    *,
    name: Annotated[str | None, typer.Option("--name", help="New display name.")] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="New description.")
    ] = None,
    icon: Annotated[str | None, typer.Option("--icon", help="New icon.")] = None,
    metadata: Annotated[
        str | None,
        typer.Option("--metadata", help="Sugar for defaults.metadata (flat string map)."),
    ] = None,
    defaults: Annotated[
        str | None, typer.Option("--defaults", help="Workspace defaults object.")
    ] = None,
    usage_limits: Annotated[
        str | None,
        typer.Option(
            "--usage-limits", help="Usage-limit policies — a JSON ARRAY of policy objects."
        ),
    ] = None,
    rate_limits: Annotated[
        str | None,
        typer.Option("--rate-limits", help="Rate-limit policies — a JSON ARRAY of policy objects."),
    ] = None,
    output: Annotated[
        OutputFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = OutputFormat.PRETTY,
) -> None:
    """Update a workspace (admin plane, partial patch).

    Examples:
        $ airs aigateway workspace update ws-produc-985697 --description 'Production, us-east'
    """
    _check_detail_format(output)
    if output is OutputFormat.PRETTY:
        render_header()

    fields = _write_fields(
        name=name,
        description=description,
        icon=icon,
        metadata=metadata,
        defaults=defaults,
        usage_limits=usage_limits,
        rate_limits=rate_limits,
    )
    if fields.is_empty():
        raise usage_error(
            "Specify at least one of --name --description --icon --metadata --defaults "
            "--usage-limits --rate-limits"
        )

    try:
        with AIGatewayClient() as client:
            resolved = _resolve_ref(client, ref, ("admin",))
            client.workspaces.update(
                resolved,
                name=fields.name,
                description=fields.description,
                icon=fields.icon,
                defaults=fields.defaults,
                usage_limits=fields.usage_limits,
                rate_limits=fields.rate_limits,
            )
            # Update acknowledges with a literal `{}`; the write lands, but there is
            # nothing in the response to show, so re-read it.
            workspace = _get_detail(client, resolved, plane="admin")
    except AISecSDKException as err:
        raise _fail_with_grant_hint(err) from err

    _report_written(f"Workspace updated: {workspace.id}", output)
    render_workspace_detail(workspace, output)


@workspace_app.command("delete")
def delete_workspace(
    ref: Annotated[str, typer.Argument(help="Workspace UUID, slug, or display name.")],
    *,
    force: Annotated[bool, typer.Option("--force", help="Skip confirmation prompt.")] = False,
) -> None:
    """Archive a workspace (soft delete — there is no hard delete).

    Examples:
        $ airs aigateway workspace delete ws-produc-985697 --force
    """
    render_header()
    confirm_or_abort(
        f"Archive workspace {ref}? (soft delete — the row remains under --status archived)",
        force=force,
        action=f"archive workspace {ref}",
    )

    try:
        with AIGatewayClient() as client:
            resolved = _resolve_ref(client, ref, ("admin",))
            # Deliberately no verify-by-get: an archived workspace answers 404 AB08 on
            # both planes even though `list --status archived` still shows it.
            client.workspaces.delete(resolved)
    except AISecSDKException as err:
        raise _fail_with_grant_hint(err) from err

    ui.success(f"Workspace archived: {ref}")
    ui.status(
        "This is a soft delete — the workspace remains visible via "
        "`workspace list --plane admin --status archived`. A `get` on it now answers 404; "
        "that is expected."
    )


# ---------------------------------------------------------------------------
# telemetry
# ---------------------------------------------------------------------------


@telemetry_app.command("cost")
def telemetry_cost(
    *,
    workspace: Annotated[
        str,
        typer.Option("--workspace", help="Workspace slug (not UUID), e.g. ws-main-a-349e0e."),
    ],
    days: Annotated[
        int, typer.Option("--days", help="Rolling window in days, counted back from now.")
    ] = _DEFAULT_COST_DAYS,
    output: Annotated[
        OutputFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = OutputFormat.PRETTY,
) -> None:
    """Total and per-day spend for a workspace (API reports cents; pretty output shows dollars).

    Examples:
        $ airs aigateway telemetry cost --workspace ws-main-a-349e0e
        $ airs aigateway telemetry cost --workspace ws-main-a-349e0e --days 30 --output json
    """
    _check_detail_format(output)
    if output is OutputFormat.PRETTY:
        render_header()
    if days <= 0:
        raise usage_error(f"Invalid --days '{days}'. Expected a positive integer")

    try:
        with AIGatewayClient() as client:
            slug = _resolve_ref(client, workspace, ("data", "admin"))
            chart = client.telemetry.cost(workspace_slug=slug, days=days)
    except AISecSDKException as err:
        raise _fail_with_grant_hint(err) from err

    report = CostReport(
        workspace_slug=slug,
        days=days,
        total_cents=chart.data.total,
        avg_cents=chart.data.avg,
        quota_exceeded=chart.data.is_quota_exceeded,
        records=[CostRecord(date=point.x, cost_cents=point.y) for point in chart.data.records],
    )
    render_cost_report(report, output)
