"""``airs redteam`` -- adversarial scan operations against a configured target.

The largest group in the CLI, and the one with the most moving parts: scans, reports,
targets, prompt sets, custom target adapters, network broker channels, and the
tenant-level plumbing (EULA, instances, devices) that has to be in place before any of it
works. Every subcommand talks to :class:`prisma_airs.RedTeamClient`; nothing here builds a
request by hand.
"""

from __future__ import annotations

import base64
import json
import re
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Final, TypeVar

import typer
import yaml

from prisma_airs import RedTeamClient
from prisma_airs.errors import AISecSDKException
from prisma_airs.models.red_team import (
    AdapterCreateRequest,
    AdapterUpdateRequest,
    AdapterValidateRequest,
    AdapterVar,
    AdapterVarResponse,
    AdapterVarType,
    CategoryModel,
    CreateChannelRequest,
    CustomJobMetadata,
    CustomPromptCreateRequest,
    CustomPromptSetArchiveRequest,
    CustomPromptSetCreateRequest,
    CustomPromptSetUpdateRequest,
    CustomPromptUpdateRequest,
    DeviceRequest,
    DynamicJobMetadata,
    EulaAcceptRequest,
    InstanceRequest,
    JobCreateRequest,
    JobMetadata,
    JobResponse,
    PropertyNameCreateRequest,
    PropertyValueCreateRequest,
    StaticJobMetadata,
    TargetAuthValidationRequest,
    TargetContextUpdate,
    TargetCreateRequest,
    TargetJobRequest,
    TargetListItem,
    TargetProbeRequest,
    TargetResponse,
    TargetUpdateRequest,
    UpdateChannelRequest,
)
from prisma_airs_cli.config import load_config, resolve
from prisma_airs_cli.confirm import confirm_or_abort
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.exit_codes import EXIT_BLOCKED
from prisma_airs_cli.output import OutputFormat
from prisma_airs_cli.renderers.redteam import (
    BackupResult,
    DetailFormat,
    RestoreResult,
    as_output_format,
    build_attack_list_footnote,
    render_adapter_detail,
    render_adapter_list,
    render_adapter_validation,
    render_attack_list,
    render_auth_validation,
    render_backup_header,
    render_backup_summary,
    render_categories,
    render_channel_detail,
    render_channel_list,
    render_channel_stats,
    render_custom_attack_list,
    render_custom_report,
    render_document,
    render_dynamic_report,
    render_error_logs,
    render_eula_content,
    render_eula_status,
    render_instance_detail,
    render_instance_response,
    render_languages,
    render_prompt_detail,
    render_prompt_list,
    render_prompt_set_detail,
    render_prompt_set_list,
    render_property_names,
    render_property_values,
    render_redteam_header,
    render_registry_credentials,
    render_restore_summary,
    render_scan_list,
    render_scan_progress,
    render_scan_status,
    render_static_report,
    render_target_detail,
    render_target_list,
    render_target_templates,
    render_version_info,
    render_version_info_unavailable,
    sanitize_target_metadata,
)
from prisma_airs_cli.ui import ui

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Statuses a scan never leaves. ``FAILED`` is terminal too, but is reported as an error
#: rather than returned, so it is handled separately.
_TERMINAL_STATUSES: Final[frozenset[str]] = frozenset(
    {"COMPLETED", "PARTIALLY_COMPLETE", "FAILED", "ABORTED"}
)

#: How long to wait between status polls while ``--wait`` is in effect.
_POLL_INTERVAL_SECONDS: Final = 5.0

#: Page size used to walk the target list, which the CLI always reads in full.
_TARGET_PAGE_SIZE: Final = 100

#: Every provider ``targets init`` can scaffold a config for.
VALID_TARGET_PROVIDERS: Final[tuple[str, ...]] = (
    "OPENAI",
    "HUGGING_FACE",
    "DATABRICKS",
    "BEDROCK",
    "REST",
    "STREAMING",
    "WEBSOCKET",
    "CUSTOM_TARGET_ADAPTER",
)

#: Providers reached over a plain HTTP endpoint. These take the REST connection shape
#: (``api_endpoint`` / ``response_key``) rather than a native SDK provider config.
_REST_PROVIDERS: Final[frozenset[str]] = frozenset(
    {"REST", "STREAMING", "WEBSOCKET", "HUGGING_FACE"}
)

#: Envelope version and discriminator written into every backup file.
BACKUP_VERSION: Final = "1"
BACKUP_RESOURCE_TYPE: Final = "redteam-target"

#: Fields the service owns. Sending them back on a restore is at best ignored and at
#: worst rejected, so they are stripped from every payload.
_SERVER_DERIVED_FIELDS: Final[tuple[str, ...]] = (
    "uuid",
    "tsg_id",
    "status",
    "active",
    "validated",
    "version",
    "secret_version",
    "created_at",
    "updated_at",
    "created_by_user_id",
    "updated_by_user_id",
)

_BACKUP_SUFFIXES: Final[tuple[str, ...]] = (".json", ".yaml", ".yml")


class ScanJobType(str, Enum):
    """The three kinds of scan a target can be put through."""

    STATIC = "STATIC"
    DYNAMIC = "DYNAMIC"
    CUSTOM = "CUSTOM"


class BackupFormat(str, Enum):
    """Serialisation used for backup files on disk."""

    JSON = "json"
    YAML = "yaml"


# ---------------------------------------------------------------------------
# Typer applications
# ---------------------------------------------------------------------------

redteam_app = typer.Typer(name="redteam", help="AI Red Team scan operations.", no_args_is_help=True)
eula_app = typer.Typer(name="eula", help="Manage Red Team EULA.", no_args_is_help=True)
instances_app = typer.Typer(
    name="instances", help="Manage Red Team instances.", no_args_is_help=True
)
devices_app = typer.Typer(name="devices", help="Manage Red Team devices.", no_args_is_help=True)
prompt_sets_app = typer.Typer(
    name="prompt-sets", help="Manage custom prompt sets.", no_args_is_help=True
)
prompts_app = typer.Typer(
    name="prompts", help="Manage prompts within prompt sets.", no_args_is_help=True
)
properties_app = typer.Typer(
    name="properties", help="Manage custom attack properties.", no_args_is_help=True
)
targets_app = typer.Typer(name="targets", help="Manage red team targets.", no_args_is_help=True)
adapter_app = typer.Typer(
    name="adapter",
    help="Manage custom target adapters (scripted targets run via the network broker).",
    no_args_is_help=True,
)
network_broker_app = typer.Typer(
    name="network-broker", help="Manage red team network broker channels.", no_args_is_help=True
)
channels_app = typer.Typer(
    name="channels", help="Manage network broker channels.", no_args_is_help=True
)

network_broker_app.add_typer(channels_app)
redteam_app.add_typer(eula_app)
redteam_app.add_typer(instances_app)
redteam_app.add_typer(devices_app)
redteam_app.add_typer(prompt_sets_app)
redteam_app.add_typer(prompts_app)
redteam_app.add_typer(properties_app)
redteam_app.add_typer(targets_app)
redteam_app.add_typer(adapter_app)
redteam_app.add_typer(network_broker_app)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _client() -> RedTeamClient:
    """Build a Red Team client from the config file and the environment.

    Raises:
        typer.Exit: If ``num_retries`` in the config file is not an integer.
    """
    retries = resolve("num_retries", None, config=load_config())
    if retries is None:
        return RedTeamClient()
    try:
        return RedTeamClient(num_retries=int(retries))
    except (TypeError, ValueError) as err:
        raise usage_error(f"config num_retries is not an integer: {retries!r}") from err


def _as_json(model: Any) -> Any:
    """Reduce a pydantic model to plain JSON-safe data."""
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)


def _header_if_pretty(fmt: OutputFormat) -> None:
    """Print the banner only when a human is reading, so JSON stays parseable."""
    if fmt is OutputFormat.PRETTY:
        render_redteam_header()


def _read_json_file(path: Path, flag: str) -> Any:
    """Read and parse a JSON file named by a flag.

    Raises:
        typer.Exit: If the file cannot be read or is not valid JSON. Naming the flag in
            the message is what makes a typo in a long invocation findable.
    """
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as err:
        raise usage_error(f"{flag}: {err}") from err


def slice_client_side(items: list[T], limit: int | None, offset: int | None) -> list[T]:
    """Apply limit and offset locally.

    Some Red Team list endpoints return everything in one response with no paging
    parameters at all. Slicing here keeps ``--limit`` and ``--offset`` meaning the same
    thing across the whole group rather than silently doing nothing on those commands.
    """
    start = offset or 0
    return items[start:] if limit is None else items[start : start + limit]


def _paging(limit: int | None, offset: int | None) -> tuple[int | None, int | None]:
    """Validate a limit/offset pair and return it as the ``(skip, limit)`` the SDK takes.

    Raises:
        typer.Exit: If the limit is not positive or the offset is negative.
    """
    if limit is not None and limit <= 0:
        raise usage_error(f'--limit: expected a positive integer, got "{limit}"')
    if offset is not None and offset < 0:
        raise usage_error(f'--offset: expected a non-negative integer, got "{offset}"')
    return offset, limit


def parse_attack_goals(raw: str) -> list[str]:
    """Parse ``--goals`` as an inline JSON array or as a path to a JSON file.

    A value starting with ``[`` is treated as inline JSON; anything else is a filename.
    That distinction is unambiguous because a path cannot start with a bracket in any
    shell that would have expanded it.

    Raises:
        typer.Exit: If the file cannot be read, the JSON is malformed, or the result is
            not an array of non-empty strings.
    """
    trimmed = raw.strip()
    if trimmed.startswith("["):
        text = trimmed
    else:
        try:
            text = Path(trimmed).read_text()
        except OSError as err:
            raise usage_error(f"--goals: {err}") from err
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as err:
        raise usage_error(f"--goals: invalid JSON ({err})") from err
    if not isinstance(parsed, list) or not all(isinstance(g, str) and g for g in parsed):
        raise usage_error("--goals: expected a JSON array of non-empty strings")
    goals: list[str] = parsed
    return goals


def build_default_categories(categories: list[CategoryModel]) -> dict[str, list[str]]:
    """Select every category and subcategory except ``MULTI_TURN``.

    Multi-turn attacks need a target that declares multi-turn support, so including them
    in an unqualified default would fail the scan for most targets.
    """
    return {
        category.id: [sub.id for sub in category.sub_categories if sub.id != "MULTI_TURN"]
        for category in categories
    }


def build_target_scaffold(provider: str, templates: dict[str, Any]) -> dict[str, Any]:
    """Build a target config skeleton for one provider.

    Raises:
        typer.Exit: If the provider is not one of :data:`VALID_TARGET_PROVIDERS`.
    """
    key = provider.upper()
    if key not in VALID_TARGET_PROVIDERS:
        raise usage_error(
            f'Unknown provider "{provider}". Valid providers: {", ".join(VALID_TARGET_PROVIDERS)}'
        )

    if key == "CUSTOM_TARGET_ADAPTER":
        return {
            "name": "",
            "target_type": "AGENT",
            "connection_type": "CUSTOM_TARGET_ADAPTER",
            "api_endpoint_type": "NETWORK_BROKER",
            "network_broker_channel_uuid": "<channel-uuid>",
            "adapter_uuid": "<adapter-uuid>",
            # An array of {key, value, type} objects, not a mapping.
            "adapter_variable_overrides": [],
            "target_background": {"use_case": ""},
            "additional_context": {},
        }

    if key in _REST_PROVIDERS:
        return _rest_target_scaffold(key, templates.get(key) or {})

    return {
        "name": "",
        "target_type": "APPLICATION",
        "connection_type": key,
        "api_endpoint_type": "PUBLIC",
        "response_mode": "REST",
        "auth_type": "HEADERS",
        "auth_config": {"auth_header": {"Authorization": "Bearer <token>"}},
        "connection_params": {"target_connection_config": templates.get(key) or {}},
        "target_background": {},
        "additional_context": {},
    }


def _rest_target_scaffold(key: str, template: dict[str, Any]) -> dict[str, Any]:
    """Build the REST-family scaffold.

    The template endpoint still returns a legacy ``url`` field; the create API wants
    ``api_endpoint`` and ``response_key``, so the shapes are translated here rather than
    handing the user something the API will reject.
    """
    response_mode = {"STREAMING": "STREAMING", "WEBSOCKET": "WEBSOCKET"}.get(key, "REST")
    return {
        "name": "",
        "target_type": "APPLICATION",
        "connection_type": "CUSTOM",
        "api_endpoint_type": "PUBLIC",
        "response_mode": response_mode,
        "auth_type": "HEADERS",
        "auth_config": {"auth_header": {"Authorization": "Bearer <token>"}},
        "connection_params": {
            "api_endpoint": template.get("url") or "",
            "request_headers": {"Content-Type": "application/json"},
            "request_json": template.get("request_json")
            or {"messages": [{"role": "user", "content": "{INPUT}"}]},
            "response_json": template.get("response_json")
            or {"choices": [{"message": {"content": "{RESPONSE}"}}]},
            "response_key": "choices.0.message.content",
        },
        "target_background": {},
        "additional_context": {},
    }


def resolve_script_b64(script_file: Path | None, script_b64: str | None) -> str:
    """Resolve ``--script-file`` / ``--script-b64`` to a base64 script.

    Raises:
        typer.Exit: If both or neither were supplied, or the file cannot be read.
    """
    if script_file is not None and script_b64 is not None:
        raise usage_error("--script-file and --script-b64 are mutually exclusive")
    if script_b64 is not None:
        return script_b64
    if script_file is not None:
        try:
            return base64.b64encode(script_file.read_bytes()).decode()
        except OSError as err:
            raise usage_error(f"--script-file: {err}") from err
    raise usage_error("one of --script-file or --script-b64 is required")


def parse_adapter_variables(raw: str) -> list[AdapterVar]:
    """Parse ``--variables`` as a JSON array of ``{key, value?, type}`` objects.

    Raises:
        typer.Exit: If the JSON is malformed or any entry is the wrong shape.
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as err:
        raise usage_error(f"--variables: invalid JSON ({err})") from err
    if not isinstance(parsed, list) or not all(
        isinstance(item, dict)
        and isinstance(item.get("key"), str)
        and item.get("type") in ("VAR", "SECRET")
        for item in parsed
    ):
        raise usage_error(
            '--variables: expected a JSON array of { "key": string, "value"?: string|null, '
            '"type": "VAR"|"SECRET" }'
        )
    return [
        AdapterVar(key=item["key"], value=item.get("value"), type=AdapterVarType(item["type"]))
        for item in parsed
    ]


def preserve_variables_for_update(variables: list[AdapterVarResponse]) -> list[AdapterVar]:
    """Map stored adapter variables into a resend-safe array.

    A redacted or valueless variable becomes ``value=None``, which upstream reads as "keep
    the stored value". Without this an update -- a full-replacement PUT -- would wipe every
    secret the adapter holds, because secrets are never read back.
    """
    return [
        AdapterVar(
            key=variable.key,
            value=None if variable.is_redacted else variable.value,
            type=variable.type,
        )
        for variable in variables
    ]


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


@redteam_app.command("abort")
def abort(*, job_id: Annotated[str, typer.Argument(help="Scan job UUID.")]) -> None:
    """Abort a running scan.

    Abort is asynchronous upstream: the request is acknowledged immediately and the job
    reaches ``ABORTED`` a little later, so follow up with ``redteam status``.
    """
    try:
        render_redteam_header()
        with _client() as client:
            client.scans.abort(job_id)
        ui.success(f"Scan {job_id} aborted.")
    except AISecSDKException as err:
        raise fail(err) from err


@redteam_app.command("categories")
def categories() -> None:
    """List available attack categories."""
    try:
        render_redteam_header()
        with _client() as client:
            render_categories(client.scans.get_categories())
    except AISecSDKException as err:
        raise fail(err) from err


@redteam_app.command("status")
def status(*, job_id: Annotated[str, typer.Argument(help="Scan job UUID.")]) -> None:
    """Check scan status."""
    try:
        render_redteam_header()
        with _client() as client:
            render_scan_status(client.scans.get(job_id))
    except AISecSDKException as err:
        raise fail(err) from err


@redteam_app.command("list")
def list_scans(
    *,
    job_status: Annotated[
        str | None,
        typer.Option(
            "--status", help="Filter by status (QUEUED, RUNNING, COMPLETED, FAILED, ABORTED)."
        ),
    ] = None,
    # `--type` keeps the reference's flag name; the parameter is renamed to avoid
    # shadowing the `type` builtin.
    job_type: Annotated[
        str | None, typer.Option("--type", help="Filter by job type (STATIC, DYNAMIC, CUSTOM).")
    ] = None,
    target: Annotated[str | None, typer.Option("--target", help="Filter by target UUID.")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = 10,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List recent scans."""
    _header_if_pretty(output)
    try:
        with _client() as client:
            scans = client.scans.list(
                status=job_status, job_type=job_type, target_id=target, limit=limit
            )
        render_scan_list(scans.data, output)
    except AISecSDKException as err:
        raise fail(err) from err


def _report_custom(client: RedTeamClient, job_id: str, attacks: bool, limit: int) -> None:
    """Render a CUSTOM job's report, and optionally its prompt-level results."""
    render_custom_report(client.custom_attack_reports.get_report(job_id))
    if attacks:
        listing = client.custom_attack_reports.list_custom_attacks(job_id, limit=limit)
        render_custom_attack_list(listing.data)


def _report_static(
    client: RedTeamClient, job_id: str, attacks: bool, severity: str | None, limit: int
) -> None:
    """Render a STATIC job's report, and optionally the attacks behind it."""
    report = client.reports.get_static_report(job_id)
    render_static_report(report)
    if not attacks:
        return
    listing = client.reports.list_attacks(job_id, severity=severity, limit=limit)
    footnote = build_attack_list_footnote(
        severity, listing.pagination.total_items, report.severity_report.stats
    )
    render_attack_list(listing.data, footnote)


@redteam_app.command("report")
def report(
    *,
    job_id: Annotated[str, typer.Argument(help="Scan job UUID.")],
    attacks: Annotated[bool, typer.Option("--attacks", help="Include attack list.")] = False,
    severity: Annotated[
        str | None, typer.Option("--severity", help="Filter attacks by severity.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max attacks to show.")] = 20,
) -> None:
    """View scan report.

    The three job types produce three different reports on three different endpoints, so
    the job is fetched first and its type decides which one to read.
    """
    try:
        render_redteam_header()
        with _client() as client:
            job = client.scans.get(job_id)
            render_scan_status(job)
            if job.job_type == ScanJobType.CUSTOM.value:
                _report_custom(client, job_id, attacks, limit)
            elif job.job_type == ScanJobType.DYNAMIC.value:
                render_dynamic_report(client.reports.get_dynamic_report(job_id))
            else:
                _report_static(client, job_id, attacks, severity, limit)
    except AISecSDKException as err:
        raise fail(err) from err


def _job_metadata(
    job_type: ScanJobType,
    *,
    categories_filter: dict[str, Any] | None,
    prompt_sets: list[str] | None,
    goals: list[str] | None,
    depth: int,
    breadth: int,
) -> JobMetadata:
    """Build the ``job_metadata`` block matching the requested job type.

    The service does not infer one from the other and rejects a mismatch, so the shape is
    chosen here rather than left to the caller.
    """
    if job_type is ScanJobType.STATIC:
        return StaticJobMetadata(categories=categories_filter or {})
    if job_type is ScanJobType.CUSTOM:
        return CustomJobMetadata(custom_prompt_sets=list(prompt_sets or []))
    return DynamicJobMetadata(
        stream_breadth=breadth, stream_depth=depth, attack_goals=list(goals) if goals else None
    )


def _wait_for_completion(client: RedTeamClient, job_id: str) -> JobResponse:
    """Poll a scan until it stops moving, reporting progress on stderr.

    Raises:
        typer.Exit: If the scan reaches ``FAILED`` -- a failed scan is not a result to
            report on, and treating it as one would hide the failure behind an empty
            report.
    """
    while True:
        job = client.scans.get(job_id)
        render_scan_progress(job)
        if job.status == "FAILED":
            raise fail(RuntimeError(f"Scan {job_id} failed"))
        if job.status in _TERMINAL_STATUSES:
            return job
        time.sleep(_POLL_INTERVAL_SECONDS)


def _default_categories(client: RedTeamClient) -> dict[str, list[str]]:
    """Select every available category, and say so -- a full scan is not free."""
    selected = build_default_categories(client.scans.get_categories())
    total = sum(len(subs) for subs in selected.values())
    ui.status(
        f"No --categories given — defaulting to all {total} categories (MULTI_TURN excluded). "
        "Pass --categories to narrow the scan."
    )
    return selected


@redteam_app.command("scan")
def scan(
    *,
    target: Annotated[str, typer.Option("--target", help="Target UUID.")],
    name: Annotated[str, typer.Option("--name", help="Scan name.")],
    job_type: Annotated[
        ScanJobType, typer.Option("--type", help="Job type: STATIC, DYNAMIC, or CUSTOM.")
    ] = ScanJobType.STATIC,
    categories_json: Annotated[
        str | None, typer.Option("--categories", help="Category filter JSON (STATIC scans).")
    ] = None,
    prompt_sets: Annotated[
        str | None,
        typer.Option("--prompt-sets", help="Comma-separated prompt set UUIDs (CUSTOM scans)."),
    ] = None,
    goals: Annotated[
        str | None,
        typer.Option(
            "--goals", help="JSON file or inline JSON array of attack goals (DYNAMIC scans)."
        ),
    ] = None,
    depth: Annotated[
        int, typer.Option("--depth", help="Max conversation turns per goal (DYNAMIC scans).")
    ] = 10,
    breadth: Annotated[
        int, typer.Option("--breadth", help="Parallel agents per goal (DYNAMIC scans).")
    ] = 6,
    no_wait: Annotated[
        bool, typer.Option("--no-wait", help="Submit scan without waiting for completion.")
    ] = False,
) -> None:
    """Execute a red team scan against a target.

    Examples:
        airs redteam scan --target <target-uuid> --name "nightly-static"

        airs redteam scan --target <uuid> --name "custom-run" --type CUSTOM --prompt-sets <set>

        airs redteam scan --target <uuid> --name "agent-probe" --type DYNAMIC --goals g.json
    """
    if depth <= 0:
        raise usage_error(f'--depth: expected a positive integer, got "{depth}"')
    if breadth <= 0:
        raise usage_error(f'--breadth: expected a positive integer, got "{breadth}"')

    selected: dict[str, Any] | None = None
    if categories_json:
        try:
            selected = json.loads(categories_json)
        except json.JSONDecodeError as err:
            raise usage_error(f"--categories: invalid JSON ({err})") from err
    attack_goals = parse_attack_goals(goals) if goals else None
    sets = [part.strip() for part in prompt_sets.split(",")] if prompt_sets else None

    try:
        render_redteam_header()
        with _client() as client:
            if job_type is ScanJobType.STATIC and selected is None:
                selected = dict(_default_categories(client))
            ui.status(f'Creating {job_type.value} scan "{name}"...')
            job = client.scans.create(
                JobCreateRequest(
                    name=name,
                    target=TargetJobRequest(uuid=target),
                    job_type=job_type.value,
                    job_metadata=_job_metadata(
                        job_type,
                        categories_filter=selected,
                        prompt_sets=sets,
                        goals=attack_goals,
                        depth=depth,
                        breadth=breadth,
                    ),
                )
            )
            render_scan_status(job)
            if no_wait:
                ui.key_value([("Job ID", job.uuid)])
                ui.dim("Run `airs redteam status <jobId>` to check progress.")
                return
            ui.status("Waiting for completion...")
            completed = _wait_for_completion(client, job.uuid)
        render_scan_status(completed)
        ui.key_value([("Job ID", completed.uuid)])
        ui.dim("Run `airs redteam report <jobId>` to view results.")
    except AISecSDKException as err:
        raise fail(err) from err


# ---------------------------------------------------------------------------
# EULA
# ---------------------------------------------------------------------------


@eula_app.command("status")
def eula_status() -> None:
    """Check EULA acceptance status."""
    try:
        render_redteam_header()
        with _client() as client:
            render_eula_status(client.eula.get_status())
    except AISecSDKException as err:
        raise fail(err) from err


@eula_app.command("content")
def eula_content() -> None:
    """Display EULA content."""
    try:
        render_redteam_header()
        with _client() as client:
            render_eula_content(client.eula.get_content())
    except AISecSDKException as err:
        raise fail(err) from err


@eula_app.command("accept")
def eula_accept(
    *, force: Annotated[bool, typer.Option("--force", help="Skip confirmation prompt.")] = False
) -> None:
    """Accept the EULA.

    Without ``--force`` this only prints the agreement: accepting a licence on someone's
    behalf is not something a mistyped command should be able to do.
    """
    try:
        render_redteam_header()
        with _client() as client:
            content = client.eula.get_content()
            if not force:
                render_eula_content(content)
                ui.dim("Pass --force to accept.")
                return
            result = client.eula.accept(
                EulaAcceptRequest(
                    eula_content=content.content,
                    accepted_at=datetime.now(tz=timezone.utc).isoformat(),
                )
            )
        render_eula_status(result)
        ui.success("EULA accepted.")
    except AISecSDKException as err:
        raise fail(err) from err


# ---------------------------------------------------------------------------
# Instances and devices
# ---------------------------------------------------------------------------


@instances_app.command("create")
def instances_create(
    *,
    tsg_id: Annotated[str, typer.Option("--tsg-id", help="TSG ID.")],
    tenant_id: Annotated[str, typer.Option("--tenant-id", help="Tenant ID.")],
    app_id: Annotated[str, typer.Option("--app-id", help="App ID.")],
    region: Annotated[str, typer.Option("--region", help="Region.")],
) -> None:
    """Create an instance."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.instances.create_instance(
                InstanceRequest(tsg_id=tsg_id, tenant_id=tenant_id, app_id=app_id, region=region)
            )
        render_instance_response(result)
    except AISecSDKException as err:
        raise fail(err) from err


@instances_app.command("get")
def instances_get(
    *,
    tenant_id: Annotated[str, typer.Argument(help="Tenant ID.")],
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Get instance details."""
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            result = client.instances.get_instance(tenant_id)
        render_instance_detail(result, fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@instances_app.command("update")
def instances_update(
    *,
    tenant_id: Annotated[str, typer.Argument(help="Tenant ID.")],
    tsg_id: Annotated[str, typer.Option("--tsg-id", help="TSG ID.")],
    app_id: Annotated[str, typer.Option("--app-id", help="App ID.")],
    region: Annotated[str, typer.Option("--region", help="Region.")],
) -> None:
    """Update an instance."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.instances.update_instance(
                tenant_id,
                InstanceRequest(tsg_id=tsg_id, tenant_id=tenant_id, app_id=app_id, region=region),
            )
        render_instance_response(result)
    except AISecSDKException as err:
        raise fail(err) from err


@instances_app.command("delete")
def instances_delete(*, tenant_id: Annotated[str, typer.Argument(help="Tenant ID.")]) -> None:
    """Delete an instance."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.instances.delete_instance(tenant_id)
        render_instance_response(result)
        ui.success(f"Instance {tenant_id} deleted.")
    except AISecSDKException as err:
        raise fail(err) from err


@devices_app.command("create")
def devices_create(
    *,
    tenant_id: Annotated[str, typer.Argument(help="Tenant ID.")],
    config: Annotated[
        Path, typer.Option("--config", help="JSON file with device request.", exists=True)
    ],
) -> None:
    """Create devices for an instance."""
    body = DeviceRequest.model_validate(_read_json_file(config, "--config"))
    try:
        render_redteam_header()
        with _client() as client:
            result = client.instances.create_devices(tenant_id, body)
        ui.success("Devices created:")
        render_document(_as_json(result))
    except AISecSDKException as err:
        raise fail(err) from err


@devices_app.command("update")
def devices_update(
    *,
    tenant_id: Annotated[str, typer.Argument(help="Tenant ID.")],
    config: Annotated[
        Path, typer.Option("--config", help="JSON file with device request.", exists=True)
    ],
) -> None:
    """Update devices for an instance (PATCH)."""
    body = DeviceRequest.model_validate(_read_json_file(config, "--config"))
    try:
        render_redteam_header()
        with _client() as client:
            result = client.instances.update_devices(tenant_id, body)
        ui.success("Devices updated:")
        render_document(_as_json(result))
    except AISecSDKException as err:
        raise fail(err) from err


@devices_app.command("delete")
def devices_delete(
    *,
    tenant_id: Annotated[str, typer.Argument(help="Tenant ID.")],
    serial_numbers: Annotated[
        str, typer.Option("--serial-numbers", help="Comma-separated serial numbers.")
    ],
) -> None:
    """Delete devices by serial numbers."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.instances.delete_devices(tenant_id, serial_numbers)
        ui.success("Devices deleted:")
        render_document(_as_json(result))
    except AISecSDKException as err:
        raise fail(err) from err


@redteam_app.command("registry-credentials")
def registry_credentials(
    *,
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Get or create registry credentials.

    Each call mints a fresh short-lived token rather than returning a stored one, so run
    this per pull rather than caching the output.
    """
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            creds = client.instances.get_registry_credentials()
        render_registry_credentials(creds, fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@redteam_app.command("languages")
def languages(
    *,
    management: Annotated[
        bool,
        typer.Option(
            "--management",
            help="Query the management-plane endpoint instead of the data plane.",
        ),
    ] = False,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List tenant languages and supported job types."""
    _header_if_pretty(output)
    try:
        with _client() as client:
            data = client.get_management_languages() if management else client.get_languages()
        render_languages(data, output)
    except AISecSDKException as err:
        raise fail(err) from err


# ---------------------------------------------------------------------------
# Prompt sets
# ---------------------------------------------------------------------------


@prompt_sets_app.command("list")
def prompt_sets_list(
    *,
    limit: Annotated[int | None, typer.Option("--limit", help="Max results (client-side).")] = None,
    offset: Annotated[
        int | None, typer.Option("--offset", help="Starting offset (client-side).")
    ] = None,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List custom prompt sets."""
    _paging(limit, offset)
    _header_if_pretty(output)
    try:
        with _client() as client:
            listing = client.custom_attacks.list_prompt_sets()
        render_prompt_set_list(slice_client_side(listing.data or [], limit, offset), output)
    except AISecSDKException as err:
        raise fail(err) from err


@prompt_sets_app.command("get")
def prompt_sets_get(
    *,
    uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Get prompt set details.

    Version info is fetched separately and tolerated when it fails: that endpoint has
    been answering 500 upstream, and losing the whole command over a supplementary lookup
    is worse than reporting it as unavailable.
    """
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            prompt_set = client.custom_attacks.get_prompt_set(uuid)
            try:
                info = client.custom_attacks.get_prompt_set_version_info(uuid)
            except AISecSDKException:
                info = None
    except AISecSDKException as err:
        raise fail(err) from err

    if fmt is not OutputFormat.PRETTY:
        render_prompt_set_detail(prompt_set, fmt, info)
        return
    render_prompt_set_detail(prompt_set)
    if info is None:
        render_version_info_unavailable()
    else:
        render_version_info(info)


@prompt_sets_app.command("create")
def prompt_sets_create(
    *,
    name: Annotated[str, typer.Option("--name", help="Prompt set name.")],
    description: Annotated[
        str | None, typer.Option("--description", help="Prompt set description.")
    ] = None,
) -> None:
    """Create a new prompt set."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.custom_attacks.create_prompt_set(
                CustomPromptSetCreateRequest(name=name, description=description)
            )
        ui.success(f"Prompt set created: {result.uuid}")
        ui.key_value([("Name", result.name)])
    except AISecSDKException as err:
        raise fail(err) from err


@prompt_sets_app.command("update")
def prompt_sets_update(
    *,
    uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    name: Annotated[str | None, typer.Option("--name", help="New name.")] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="New description.")
    ] = None,
) -> None:
    """Update a prompt set."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.custom_attacks.update_prompt_set(
                uuid, CustomPromptSetUpdateRequest(name=name, description=description)
            )
        render_prompt_set_detail(result)
    except AISecSDKException as err:
        raise fail(err) from err


@prompt_sets_app.command("archive")
def prompt_sets_archive(
    *,
    uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    unarchive: Annotated[bool, typer.Option("--unarchive", help="Unarchive instead.")] = False,
) -> None:
    """Archive a prompt set."""
    archive = not unarchive
    try:
        render_redteam_header()
        with _client() as client:
            client.custom_attacks.archive_prompt_set(
                uuid, CustomPromptSetArchiveRequest(archive=archive)
            )
        ui.success(f"Prompt set {uuid} {'archived' if archive else 'unarchived'}.")
    except AISecSDKException as err:
        raise fail(err) from err


@prompt_sets_app.command("download")
def prompt_sets_download(
    *,
    uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    output_file: Annotated[
        Path | None, typer.Option("--output-file", help="Output file path.")
    ] = None,
) -> None:
    """Download CSV template for a prompt set."""
    destination = output_file or Path(f"{uuid}-template.csv")
    try:
        render_redteam_header()
        with _client() as client:
            csv_text = client.custom_attacks.download_template(uuid)
        destination.write_text(csv_text)
        ui.success(f"Template saved to {destination}")
    except AISecSDKException as err:
        raise fail(err) from err
    except OSError as err:
        raise usage_error(f"--output-file: {err}") from err


@prompt_sets_app.command("upload")
def prompt_sets_upload(
    *,
    uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    file: Annotated[Path, typer.Argument(help="CSV file of prompts to upload.", exists=True)],
) -> None:
    """Upload CSV prompts to a prompt set."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.custom_attacks.upload_prompts_csv(
                uuid, file.read_bytes(), filename=file.name
            )
        ui.success(result.message)
    except AISecSDKException as err:
        raise fail(err) from err


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


@prompts_app.command("list")
def prompts_list(
    *,
    set_uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = 50,
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """List prompts in a prompt set."""
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            listing = client.custom_attacks.list_prompts(set_uuid, limit=limit)
        render_prompt_list(listing.data or [], fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@prompts_app.command("get")
def prompts_get(
    *,
    set_uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    prompt_uuid: Annotated[str, typer.Argument(help="Prompt UUID.")],
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Get prompt details."""
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            render_prompt_detail(client.custom_attacks.get_prompt(set_uuid, prompt_uuid), fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@prompts_app.command("add")
def prompts_add(
    *,
    set_uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    prompt: Annotated[str, typer.Option("--prompt", help="Prompt text.")],
    goal: Annotated[str | None, typer.Option("--goal", help="Prompt goal.")] = None,
) -> None:
    """Add a prompt to a prompt set."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.custom_attacks.create_prompt(
                CustomPromptCreateRequest(prompt=prompt, prompt_set_id=set_uuid, goal=goal)
            )
        ui.success(f"Prompt added: {result.uuid}")
    except AISecSDKException as err:
        raise fail(err) from err


@prompts_app.command("update")
def prompts_update(
    *,
    set_uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    prompt_uuid: Annotated[str, typer.Argument(help="Prompt UUID.")],
    prompt: Annotated[str | None, typer.Option("--prompt", help="New prompt text.")] = None,
    goal: Annotated[str | None, typer.Option("--goal", help="New goal.")] = None,
) -> None:
    """Update a prompt."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.custom_attacks.update_prompt(
                set_uuid, prompt_uuid, CustomPromptUpdateRequest(prompt=prompt, goal=goal)
            )
        render_prompt_detail(result)
    except AISecSDKException as err:
        raise fail(err) from err


@prompts_app.command("delete")
def prompts_delete(
    *,
    set_uuid: Annotated[str, typer.Argument(help="Prompt set UUID.")],
    prompt_uuid: Annotated[str, typer.Argument(help="Prompt UUID.")],
) -> None:
    """Delete a prompt."""
    try:
        render_redteam_header()
        with _client() as client:
            client.custom_attacks.delete_prompt(set_uuid, prompt_uuid)
        ui.success(f"Prompt {prompt_uuid} deleted.")
    except AISecSDKException as err:
        raise fail(err) from err


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


@properties_app.command("list")
def properties_list(
    *,
    limit: Annotated[int | None, typer.Option("--limit", help="Max results (client-side).")] = None,
    offset: Annotated[
        int | None, typer.Option("--offset", help="Starting offset (client-side).")
    ] = None,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List property names."""
    _paging(limit, offset)
    _header_if_pretty(output)
    try:
        with _client() as client:
            names = client.custom_attacks.get_property_names().data or []
        render_property_names(slice_client_side(names, limit, offset), output)
    except AISecSDKException as err:
        raise fail(err) from err


@properties_app.command("create")
def properties_create(
    *, name: Annotated[str, typer.Option("--name", help="Property name.")]
) -> None:
    """Create a property name."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.custom_attacks.create_property_name(
                PropertyNameCreateRequest(name=name)
            )
        ui.success(result.message if result else f"Property name {name} created.")
    except AISecSDKException as err:
        raise fail(err) from err


@properties_app.command("values")
def properties_values(
    *,
    name: Annotated[str, typer.Argument(help="Property name.")],
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """List values for a property."""
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            render_property_values(client.custom_attacks.get_property_values(name), fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@properties_app.command("add-value")
def properties_add_value(
    *,
    name: Annotated[str, typer.Option("--name", help="Property name.")],
    value: Annotated[str, typer.Option("--value", help="Property value.")],
) -> None:
    """Create a property value."""
    try:
        render_redteam_header()
        with _client() as client:
            result = client.custom_attacks.create_property_value(
                PropertyValueCreateRequest(property_name=name, property_value=value)
            )
        ui.success(result.message)
    except AISecSDKException as err:
        raise fail(err) from err


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


def _all_targets(client: RedTeamClient) -> list[TargetListItem]:
    """Read every target, walking the pages the service returns.

    The CLI's target commands all work by name or over the whole set, and the listing
    endpoint has no "give me everything" mode, so the walk happens here once.
    """
    collected: list[TargetListItem] = []
    skip = 0
    while True:
        page = client.targets.list(skip=skip, limit=_TARGET_PAGE_SIZE)
        rows = page.data or []
        collected.extend(rows)
        total = page.pagination.total_items
        if len(rows) < _TARGET_PAGE_SIZE or (total is not None and len(collected) >= total):
            return collected
        skip += _TARGET_PAGE_SIZE


@targets_app.command("list")
def targets_list(
    *,
    limit: Annotated[int | None, typer.Option("--limit", help="Max results (client-side).")] = None,
    offset: Annotated[
        int | None, typer.Option("--offset", help="Starting offset (client-side).")
    ] = None,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List configured red team targets.

    Examples:
        airs redteam targets list

        airs redteam targets list --output json

        airs redteam targets list --limit 5
    """
    _paging(limit, offset)
    _header_if_pretty(output)
    try:
        with _client() as client:
            targets = _all_targets(client)
        render_target_list(slice_client_side(targets, limit, offset), output)
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("get")
def targets_get(
    *,
    uuid: Annotated[str, typer.Argument(help="Target UUID.")],
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Get target details."""
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            render_target_detail(client.targets.get(uuid), fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("create")
def targets_create(
    *,
    config: Annotated[
        Path, typer.Option("--config", help="JSON file with target configuration.", exists=True)
    ],
    validate: Annotated[
        bool, typer.Option("--validate", help="Validate target connection before saving.")
    ] = False,
) -> None:
    """Create a new red team target."""
    body = TargetCreateRequest.model_validate(_read_json_file(config, "--config"))
    try:
        render_redteam_header()
        with _client() as client:
            target = client.targets.create(body, validate=True if validate else None)
        ui.success(f"Target created: {target.uuid}")
        render_target_detail(target)
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("update")
def targets_update(
    *,
    uuid: Annotated[str, typer.Argument(help="Target UUID.")],
    config: Annotated[
        Path, typer.Option("--config", help="JSON file with target updates.", exists=True)
    ],
    validate: Annotated[
        bool, typer.Option("--validate", help="Validate target connection before saving.")
    ] = False,
) -> None:
    """Update a red team target.

    A full replacement upstream, not a patch -- send the whole target, not just the field
    being changed.
    """
    body = TargetUpdateRequest.model_validate(_read_json_file(config, "--config"))
    try:
        render_redteam_header()
        with _client() as client:
            target = client.targets.update(uuid, body, validate=True if validate else None)
        ui.success(f"Target updated: {target.uuid}")
        render_target_detail(target)
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("delete")
def targets_delete(
    *,
    uuid: Annotated[str, typer.Argument(help="Target UUID.")],
    force: Annotated[bool, typer.Option("--force", help="Skip confirmation prompt.")] = False,
) -> None:
    """Delete a red team target."""
    confirm_or_abort(f"Delete red team target {uuid}?", force=force, action=f"delete target {uuid}")
    try:
        render_redteam_header()
        with _client() as client:
            client.targets.delete(uuid)
        ui.success(f"Target {uuid} deleted.")
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("probe")
def targets_probe(
    *,
    config: Annotated[
        Path, typer.Option("--config", help="JSON file with connection params.", exists=True)
    ],
) -> None:
    """Test target connection without saving."""
    body = TargetProbeRequest.model_validate(_read_json_file(config, "--config"))
    try:
        render_redteam_header()
        with _client() as client:
            result = client.targets.probe(body)
        payload = _as_json(result)
        payload["target_metadata"] = sanitize_target_metadata(payload.get("target_metadata"))
        ui.dim("Probe result:")
        render_document({k: v for k, v in payload.items() if v is not None})
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("profile")
def targets_profile(*, uuid: Annotated[str, typer.Argument(help="Target UUID.")]) -> None:
    """View target profile."""
    try:
        render_redteam_header()
        with _client() as client:
            profile = client.targets.get_profile(uuid)
        ui.dim("Target Profile:")
        render_document(_as_json(profile))
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("update-profile")
def targets_update_profile(
    *,
    uuid: Annotated[str, typer.Argument(help="Target UUID.")],
    config: Annotated[
        Path, typer.Option("--config", help="JSON file with profile updates.", exists=True)
    ],
) -> None:
    """Update target profile."""
    body = TargetContextUpdate.model_validate(_read_json_file(config, "--config"))
    try:
        render_redteam_header()
        with _client() as client:
            result = client.targets.update_profile(uuid, body)
        ui.success("Profile updated:")
        render_document(_as_json(result))
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("validate-auth")
def targets_validate_auth(
    *,
    auth_type: Annotated[
        str, typer.Option("--auth-type", help="Auth type: HEADERS, BASIC_AUTH, OAUTH2.")
    ],
    config: Annotated[
        Path, typer.Option("--config", help="JSON file with auth_config.", exists=True)
    ],
    target_id: Annotated[
        str | None, typer.Option("--target-id", help="Existing target UUID.")
    ] = None,
) -> None:
    """Validate target auth credentials."""
    auth_config = _read_json_file(config, "--config")
    try:
        render_redteam_header()
        with _client() as client:
            result = client.targets.validate_auth(
                TargetAuthValidationRequest(
                    auth_type=auth_type, auth_config=auth_config, target_id=target_id
                )
            )
        render_auth_validation(result)
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("metadata")
def targets_metadata() -> None:
    """Get target field metadata.

    Emits raw JSON with no banner: this output is meant to be piped into a generator or a
    schema check rather than read.
    """
    try:
        with _client() as client:
            render_document(client.targets.get_target_metadata())
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("templates")
def targets_templates() -> None:
    """Get provider-specific target templates."""
    try:
        render_redteam_header()
        with _client() as client:
            templates = client.targets.get_target_templates()
        render_target_templates(templates.model_dump(by_alias=True))
    except AISecSDKException as err:
        raise fail(err) from err


@targets_app.command("init")
def targets_init(
    *,
    provider: Annotated[str, typer.Argument(help=f"One of: {', '.join(VALID_TARGET_PROVIDERS)}.")],
    output_file: Annotated[
        Path | None, typer.Option("--output-file", help="Output file path.")
    ] = None,
) -> None:
    """Scaffold a target config JSON from a provider template."""
    if provider.upper() not in VALID_TARGET_PROVIDERS:
        raise usage_error(
            f'Unknown provider "{provider}". Valid providers: {", ".join(VALID_TARGET_PROVIDERS)}'
        )
    destination = (output_file or Path(f"{provider.lower()}-target.json")).resolve()
    if destination.exists():
        raise usage_error(
            f"File already exists: {destination} (use --output-file to specify a different path)"
        )

    try:
        render_redteam_header()
        with _client() as client:
            templates = client.targets.get_target_templates()
        scaffold = build_target_scaffold(provider, templates.model_dump(by_alias=True))
        destination.write_text(json.dumps(scaffold, indent=2) + "\n")
    except AISecSDKException as err:
        raise fail(err) from err
    except OSError as err:
        raise usage_error(f"--output-file: {err}") from err

    ui.success("Target config scaffolded")
    ui.key_value([("File", str(destination)), ("Provider", provider.upper())])
    ui.dim("Next steps: edit the file to fill in name and credentials, then run:")
    ui.dim(f"  airs redteam targets create --config {destination.name} --validate")


@targets_app.command("error-logs")
def targets_error_logs(
    *,
    target_id: Annotated[str, typer.Argument(help="Target UUID.")],
    limit: Annotated[int | None, typer.Option("--limit", help="Max results.")] = None,
    offset: Annotated[int | None, typer.Option("--offset", help="Starting offset.")] = None,
    search: Annotated[str | None, typer.Option("--search", help="Filter by search text.")] = None,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List target-profile error logs.

    Examples:
        airs redteam targets error-logs <targetId>
    """
    skip, page_limit = _paging(limit, offset)
    _header_if_pretty(output)
    try:
        with _client() as client:
            logs = client.get_target_profile_error_logs(
                target_id, skip=skip, limit=page_limit, search=search
            )
        render_error_logs(logs.data, output)
    except AISecSDKException as err:
        raise fail(err) from err


# ---------------------------------------------------------------------------
# Target backup and restore
# ---------------------------------------------------------------------------


def sanitize_filename(name: str) -> str:
    """Reduce a target name to a filesystem-safe stem.

    Also a containment measure: the name is server-supplied and is about to become a path
    segment, so anything outside ``[a-z0-9-]`` is replaced rather than escaped.
    """
    sanitized = re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9-]", "-", name.lower())).strip("-")
    return sanitized or "unnamed"


def resolve_output_dir(user_dir: Path | None, subdir: str) -> Path:
    """Resolve the backup destination, defaulting to ``./airs-backup/<subdir>``."""
    return user_dir.resolve() if user_dir else (Path("airs-backup") / subdir).resolve()


def _strip_nulls(value: Any) -> Any:
    """Drop null-valued keys recursively, so a backup carries only what was set."""
    if isinstance(value, list):
        return [_strip_nulls(item) for item in value]
    if isinstance(value, dict):
        return {k: _strip_nulls(v) for k, v in value.items() if v is not None}
    return value


def target_backup_data(target: TargetResponse) -> dict[str, Any]:
    """Reduce a stored target to the create-request shape a restore can replay."""
    payload = _as_json(target)
    data: dict[str, Any] = {"name": target.name, "target_type": target.target_type}
    for field in (
        "connection_type",
        "api_endpoint_type",
        "response_mode",
        "auth_type",
        "auth_config",
        "network_broker_channel_uuid",
        "session_supported",
        "extra_info",
        "connection_params",
        "target_background",
        "additional_context",
        "target_metadata",
    ):
        if payload.get(field) is not None:
            data[field] = payload[field]
    stripped: dict[str, Any] = _strip_nulls(data)
    return stripped


def write_backup_file(
    directory: Path, filename: str, envelope: dict[str, Any], fmt: BackupFormat
) -> str:
    """Serialise one envelope into the backup directory and return the file name."""
    directory.mkdir(parents=True, exist_ok=True)
    suffix = "yaml" if fmt is BackupFormat.YAML else "json"
    path = directory / f"{filename}.{suffix}"
    if fmt is BackupFormat.YAML:
        path.write_text(yaml.safe_dump(envelope, sort_keys=False, default_flow_style=False))
    else:
        path.write_text(json.dumps(envelope, indent=2) + "\n")
    return path.name


def read_backup_file(path: Path) -> dict[str, Any]:
    """Read one backup file, detecting the format from its extension.

    Raises:
        ValueError: If the extension is unknown or the envelope is missing its fields.
    """
    suffix = path.suffix.lower()
    if suffix not in _BACKUP_SUFFIXES:
        raise ValueError(f"Unsupported file format: {suffix} (expected .json, .yaml, or .yml)")
    raw = path.read_text()
    parsed = json.loads(raw) if suffix == ".json" else yaml.safe_load(raw)
    if not isinstance(parsed, dict) or "version" not in parsed or "data" not in parsed:
        raise ValueError(f"Invalid backup file: {path} (missing version or data)")
    return parsed


def read_backup_dir(directory: Path) -> list[dict[str, Any]]:
    """Read every red team target backup in a directory, ignoring anything else.

    Unreadable or unrelated files are skipped rather than fatal: a backup directory
    routinely holds other resources' exports alongside these.
    """
    envelopes: list[dict[str, Any]] = []
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in _BACKUP_SUFFIXES:
            continue
        try:
            envelope = read_backup_file(path)
        except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError):
            continue
        if envelope.get("resourceType") == BACKUP_RESOURCE_TYPE:
            envelopes.append(envelope)
    return envelopes


def prepare_target_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Strip server-owned fields and translate legacy key names for create/update."""
    clean = {k: v for k, v in data.items() if k not in _SERVER_DERIVED_FIELDS}
    for legacy, current in (("background", "target_background"), ("metadata", "target_metadata")):
        if legacy in clean:
            clean.setdefault(current, clean[legacy])
            del clean[legacy]
    return clean


def _backup_one(
    client: RedTeamClient, row: TargetListItem, directory: Path, fmt: BackupFormat
) -> BackupResult:
    """Back up a single target, reporting rather than raising on failure."""
    try:
        detail = client.targets.get(row.uuid)
        envelope = {
            "version": BACKUP_VERSION,
            "resourceType": BACKUP_RESOURCE_TYPE,
            "exportedAt": datetime.now(tz=timezone.utc).isoformat(),
            "data": target_backup_data(detail),
        }
        filename = write_backup_file(directory, sanitize_filename(row.name), envelope, fmt)
        return BackupResult(name=row.name, filename=filename, status="ok")
    except (AISecSDKException, OSError) as err:
        return BackupResult(name=row.name, filename="", status="failed", error=str(err))


@targets_app.command("backup")
def targets_backup(
    *,
    output_dir: Annotated[
        Path | None, typer.Option("--output-dir", help="Output directory.")
    ] = None,
    output: Annotated[
        BackupFormat, typer.Option("--output", help="Output format: json or yaml.")
    ] = BackupFormat.JSON,
    name: Annotated[
        str | None, typer.Option("--name", help="Backup a single target by name.")
    ] = None,
) -> None:
    """Backup red team targets to local JSON/YAML files.

    Exits 1 when any target failed to back up, so a scheduled job notices a partial
    backup instead of trusting an incomplete directory.
    """
    directory = resolve_output_dir(output_dir, "targets")
    try:
        render_backup_header()
        with _client() as client:
            rows = _all_targets(client)
            if name is not None:
                rows = [row for row in rows if row.name == name]
                if not rows:
                    raise usage_error(f"Target not found: {name}")
            results = [_backup_one(client, row, directory, output) for row in rows]
    except AISecSDKException as err:
        raise fail(err) from err

    render_backup_summary(results, str(directory))
    if any(result.status == "failed" for result in results):
        raise typer.Exit(EXIT_BLOCKED)


def _restore_one(
    client: RedTeamClient,
    envelope: dict[str, Any],
    existing: dict[str, str],
    *,
    overwrite: bool,
    validate: bool,
) -> RestoreResult:
    """Create or update one target from a backup envelope."""
    data = envelope.get("data") or {}
    name = str(data.get("name", ""))
    validate_flag = True if validate else None
    try:
        existing_uuid = existing.get(name)
        if existing_uuid and not overwrite:
            return RestoreResult(name=name, action="skipped")
        payload = prepare_target_payload(data)
        if existing_uuid:
            # The API requires the full routing tuple even on an update, and a backup
            # taken before those fields existed will not carry them.
            current = client.targets.get(existing_uuid)
            payload.setdefault("target_type", current.target_type)
            payload.setdefault("connection_type", current.connection_type or "CUSTOM")
            payload.setdefault("api_endpoint_type", current.api_endpoint_type or "PUBLIC")
            payload.setdefault("response_mode", current.response_mode or "REST")
            client.targets.update(
                existing_uuid, TargetUpdateRequest.model_validate(payload), validate=validate_flag
            )
            return RestoreResult(name=name, action="updated")
        payload.setdefault("connection_type", "CUSTOM")
        payload.setdefault("api_endpoint_type", "PUBLIC")
        payload.setdefault("response_mode", "REST")
        client.targets.create(TargetCreateRequest.model_validate(payload), validate=validate_flag)
        return RestoreResult(name=name, action="created")
    except (AISecSDKException, ValueError) as err:
        return RestoreResult(name=name, action="failed", error=str(err))


def _restore_envelopes(file: Path | None, input_dir: Path | None) -> list[dict[str, Any]]:
    """Collect the backup envelopes a restore should replay.

    Raises:
        typer.Exit: If a named file is not a valid red team target backup, or a directory
            contains none.
    """
    if file is not None:
        try:
            envelope = read_backup_file(file)
        except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as err:
            raise usage_error(f"--file: {err}") from err
        if (
            envelope.get("version") != BACKUP_VERSION
            or envelope.get("resourceType") != BACKUP_RESOURCE_TYPE
        ):
            raise usage_error(
                f"Invalid backup: version={envelope.get('version')}, "
                f"resourceType={envelope.get('resourceType')}"
            )
        return [envelope]

    if input_dir is None:
        raise usage_error("Specify --file <path> or --input-dir <path>")
    try:
        envelopes = read_backup_dir(input_dir)
    except OSError as err:
        raise usage_error(f"--input-dir: {err}") from err
    if not envelopes:
        raise usage_error("No valid backup files found")
    return envelopes


@targets_app.command("restore")
def targets_restore(
    *,
    input_dir: Annotated[
        Path | None, typer.Option("--input-dir", help="Directory containing backup files.")
    ] = None,
    file: Annotated[
        Path | None, typer.Option("--file", help="Single backup file to restore.")
    ] = None,
    overwrite: Annotated[
        bool,
        typer.Option("--overwrite", help="Update existing targets with same name (default: skip)."),
    ] = False,
    validate: Annotated[
        bool, typer.Option("--validate", help="Validate target connection before saving.")
    ] = False,
) -> None:
    """Restore red team targets from local JSON/YAML backup files.

    Exits 1 when any target failed to restore, so a half-applied restore is visible to
    whatever ran it.
    """
    envelopes = _restore_envelopes(file, input_dir)
    try:
        render_backup_header()
        with _client() as client:
            existing = {row.name: row.uuid for row in _all_targets(client)}
            results = [
                _restore_one(client, envelope, existing, overwrite=overwrite, validate=validate)
                for envelope in envelopes
            ]
    except AISecSDKException as err:
        raise fail(err) from err

    render_restore_summary(results)
    if any(result.action == "failed" for result in results):
        raise typer.Exit(EXIT_BLOCKED)


# ---------------------------------------------------------------------------
# Custom target adapters
# ---------------------------------------------------------------------------


def _assert_channel_online(client: RedTeamClient, channel_uuid: str) -> None:
    """Refuse to validate against a channel that is not ONLINE.

    Upstream answers a generic error when the broker is unreachable, which sends people
    looking at their script. A lookup that itself fails is ignored: the real operation's
    error is more informative than a speculative pre-check's.

    Raises:
        typer.Exit: If the channel exists and is not ONLINE.
    """
    try:
        status = client.network_broker.get_channel(channel_uuid).status
    except AISecSDKException:
        return
    if status and status != "ONLINE":
        raise fail(
            RuntimeError(
                f"network broker channel {channel_uuid} is {status} — adapter validation "
                "requires an ONLINE channel (network broker v1.4.0+). Check "
                "'airs redteam network-broker channels list'."
            )
        )


@adapter_app.command("list")
def adapter_list(
    *,
    limit: Annotated[int | None, typer.Option("--limit", help="Max results.")] = None,
    offset: Annotated[int | None, typer.Option("--offset", help="Starting offset.")] = None,
    search: Annotated[str | None, typer.Option("--search", help="Filter by search text.")] = None,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List custom target adapters."""
    skip, page_limit = _paging(limit, offset)
    _header_if_pretty(output)
    try:
        with _client() as client:
            listing = client.adapters.list(skip=skip, limit=page_limit, search=search)
        render_adapter_list(listing.data or [], output, listing.pagination.total_items)
    except AISecSDKException as err:
        raise fail(err) from err


@adapter_app.command("get")
def adapter_get(
    *,
    uuid: Annotated[str, typer.Argument(help="Adapter UUID.")],
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Get a custom target adapter."""
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            render_adapter_detail(client.adapters.get(uuid), fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@adapter_app.command("create")
def adapter_create(
    *,
    name: Annotated[str, typer.Option("--name", help="Adapter name.")],
    prompt: Annotated[
        str,
        typer.Option(
            "--prompt",
            help="Sample prompt used to exercise the adapter during validation (not stored).",
        ),
    ],
    script_file: Annotated[
        Path | None,
        typer.Option(
            "--script-file", help="Path to the adapter script (encoded to base64 for you)."
        ),
    ] = None,
    script_b64: Annotated[
        str | None, typer.Option("--script-b64", help="Adapter script, already base64-encoded.")
    ] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="Adapter description.")
    ] = None,
    channel: Annotated[
        str | None,
        typer.Option("--channel", help="Network broker channel UUID (required to activate)."),
    ] = None,
    variables: Annotated[
        str | None,
        typer.Option("--variables", help="JSON array of { key, value, type: VAR|SECRET }."),
    ] = None,
    draft: Annotated[
        bool, typer.Option("--draft", help="Save as DRAFT without running the validation script.")
    ] = False,
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Create a custom target adapter.

    Examples:
        airs redteam adapter create --name a --script-file ./adapter.py --channel <uuid>
        --prompt 'Hello' --variables '[{"key":"endpoint","value":"http://x","type":"VAR"}]'

        airs redteam adapter create --name a --script-file ./adapter.py --prompt Hello --draft
    """
    fmt = as_output_format(output)
    script = resolve_script_b64(script_file, script_b64)
    parsed_variables = parse_adapter_variables(variables) if variables else None
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            if not draft and channel:
                _assert_channel_online(client, channel)
            created = client.adapters.create(
                AdapterCreateRequest(
                    name=name,
                    script_b64=script,
                    prompt=prompt,
                    description=description,
                    network_broker_channel_uuid=channel,
                    variables=parsed_variables,
                ),
                validate=not draft,
            )
        ui.success(f"Adapter created: {created.uuid}")
        render_adapter_detail(created, fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@adapter_app.command("update")
def adapter_update(
    *,
    uuid: Annotated[str, typer.Argument(help="Adapter UUID.")],
    prompt: Annotated[
        str,
        typer.Option(
            "--prompt",
            help="Sample validation prompt — required on every update because upstream "
            "never stores it.",
        ),
    ],
    name: Annotated[str | None, typer.Option("--name", help="New adapter name.")] = None,
    script_file: Annotated[
        Path | None,
        typer.Option("--script-file", help="New adapter script file (encoded to base64 for you)."),
    ] = None,
    script_b64: Annotated[
        str | None,
        typer.Option("--script-b64", help="New adapter script, already base64-encoded."),
    ] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="New description.")
    ] = None,
    channel: Annotated[
        str | None, typer.Option("--channel", help="New network broker channel UUID.")
    ] = None,
    variables: Annotated[
        str | None,
        typer.Option(
            "--variables",
            help="REPLACES the whole variable set — omitted keys are deleted upstream. "
            "Omit this flag to preserve stored variables.",
        ),
    ] = None,
    draft: Annotated[
        bool,
        typer.Option("--draft", help="Save as DRAFT without re-running the validation script."),
    ] = False,
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Update a custom target adapter (read-modify-write; variables preserved).

    Upstream's update is a full-replacement PUT where an omitted variable key is
    *deleted*, so the current adapter is read first and merged with the flags given. Pass
    ``--variables`` only when you mean to replace the whole set.

    Examples:
        airs redteam adapter update <uuid> --description 'new description' --prompt 'Hello'
    """
    fmt = as_output_format(output)
    script = (
        resolve_script_b64(script_file, script_b64)
        if script_file is not None or script_b64 is not None
        else None
    )
    parsed_variables = parse_adapter_variables(variables) if variables else None
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            if not draft and channel:
                _assert_channel_online(client, channel)
            current = client.adapters.get(uuid)
            updated = client.adapters.update(
                uuid,
                AdapterUpdateRequest(
                    name=name or current.name,
                    script_b64=script or current.script_b64,
                    prompt=prompt,
                    description=description or current.description,
                    network_broker_channel_uuid=channel or current.network_broker_channel_uuid,
                    variables=parsed_variables
                    or preserve_variables_for_update(current.variables or []),
                ),
                validate=not draft,
            )
        ui.success(f"Adapter updated: {updated.uuid}")
        render_adapter_detail(updated, fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@adapter_app.command("delete")
def adapter_delete(
    *,
    uuid: Annotated[str, typer.Argument(help="Adapter UUID.")],
    force: Annotated[bool, typer.Option("--force", help="Skip confirmation prompt.")] = False,
) -> None:
    """Delete a custom target adapter."""
    render_redteam_header()
    confirm_or_abort(f"Delete adapter {uuid}?", force=force, action=f"delete adapter {uuid}")
    try:
        with _client() as client:
            client.adapters.delete(uuid)
        ui.success(f"Adapter {uuid} deleted.")
    except AISecSDKException as err:
        raise fail(err) from err


@adapter_app.command("validate")
def adapter_validate(
    *,
    channel: Annotated[
        str, typer.Option("--channel", help="Network broker channel UUID (must be ONLINE).")
    ],
    prompt: Annotated[
        str, typer.Option("--prompt", help="Sample prompt to send through the adapter.")
    ],
    script_file: Annotated[
        Path | None,
        typer.Option(
            "--script-file", help="Path to the adapter script (encoded to base64 for you)."
        ),
    ] = None,
    script_b64: Annotated[
        str | None, typer.Option("--script-b64", help="Adapter script, already base64-encoded.")
    ] = None,
    variables: Annotated[
        str | None,
        typer.Option(
            "--variables",
            help="JSON array of { key, value, type } — the FULL set the script needs.",
        ),
    ] = None,
    adapter: Annotated[
        str | None,
        typer.Option(
            "--adapter",
            help="Existing adapter: resolves redacted/null variable values from its stored "
            "secrets (and supplies its variable set when --variables is omitted).",
        ),
    ] = None,
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Run an adapter script end-to-end through the broker channel without saving.

    Exits 1 when the script did not validate, so this can gate a pipeline.

    Examples:
        airs redteam adapter validate --script-file ./adapter.py --channel <uuid>
        --prompt 'Hello' --variables '[{"key":"endpoint","value":"http://x","type":"VAR"}]'

        airs redteam adapter validate --script-file ./a.py --channel <uuid> --prompt 'Hi'
        --adapter <adapter-uuid>
    """
    fmt = as_output_format(output)
    script = resolve_script_b64(script_file, script_b64)
    parsed_variables = parse_adapter_variables(variables) if variables else None
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            _assert_channel_online(client, channel)
            if parsed_variables is None and adapter:
                # The endpoint needs the FULL variable set; adapter_uuid only resolves
                # redacted values within what is sent, so omitting them fails upstream
                # with a bare KeyError.
                stored = client.adapters.get(adapter)
                parsed_variables = preserve_variables_for_update(stored.variables or [])
            result = client.adapters.validate(
                AdapterValidateRequest(
                    script_b64=script,
                    network_broker_channel_uuid=channel,
                    prompt=prompt,
                    variables=parsed_variables,
                    adapter_uuid=adapter,
                )
            )
        render_adapter_validation(result, fmt)
    except AISecSDKException as err:
        raise fail(err) from err

    if not result.validated:
        raise typer.Exit(EXIT_BLOCKED)


# ---------------------------------------------------------------------------
# Network broker
# ---------------------------------------------------------------------------


@channels_app.command("list")
def channels_list(
    *,
    limit: Annotated[int | None, typer.Option("--limit", help="Max results.")] = None,
    offset: Annotated[int | None, typer.Option("--offset", help="Starting offset.")] = None,
    search: Annotated[str | None, typer.Option("--search", help="Filter by search text.")] = None,
    channel_status: Annotated[
        list[str] | None,
        typer.Option("--status", help="Filter by status (ONLINE, OFFLINE, DRAFT)."),
    ] = None,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List network broker channels."""
    skip, page_limit = _paging(limit, offset)
    _header_if_pretty(output)
    try:
        with _client() as client:
            listing = client.network_broker.list_channels(
                skip=skip, limit=page_limit, search=search, status=channel_status or None
            )
        render_channel_list(listing.data, output)
    except AISecSDKException as err:
        raise fail(err) from err


@channels_app.command("get")
def channels_get(
    *,
    channel_id: Annotated[str, typer.Argument(help="Channel UUID.")],
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Get a network broker channel."""
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            render_channel_detail(client.network_broker.get_channel(channel_id), fmt)
    except AISecSDKException as err:
        raise fail(err) from err


@channels_app.command("create")
def channels_create(
    *,
    name: Annotated[str, typer.Option("--name", help="Channel name.")],
    description: Annotated[
        str | None, typer.Option("--description", help="Channel description.")
    ] = None,
) -> None:
    """Create a network broker channel.

    A new channel starts in DRAFT and only reaches ONLINE once a broker client connects,
    so the status shown here is not yet usable for a scan.
    """
    try:
        render_redteam_header()
        with _client() as client:
            channel = client.network_broker.create_channel(
                CreateChannelRequest(name=name, description=description)
            )
        ui.success(f"Channel created: {channel.uuid}")
        render_channel_detail(channel)
    except AISecSDKException as err:
        raise fail(err) from err


@channels_app.command("update")
def channels_update(
    *,
    channel_id: Annotated[str, typer.Argument(help="Channel UUID.")],
    name: Annotated[str | None, typer.Option("--name", help="New channel name.")] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="New channel description.")
    ] = None,
) -> None:
    """Update a network broker channel."""
    if name is None and description is None:
        raise usage_error("Specify --name and/or --description to update")
    try:
        render_redteam_header()
        with _client() as client:
            channel = client.network_broker.update_channel(
                channel_id, UpdateChannelRequest(name=name, description=description)
            )
        ui.success(f"Channel updated: {channel.uuid}")
        render_channel_detail(channel)
    except AISecSDKException as err:
        raise fail(err) from err


@network_broker_app.command("stats")
def network_broker_stats(
    *,
    output: Annotated[
        DetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = DetailFormat.PRETTY,
) -> None:
    """Show network broker channel statistics."""
    fmt = as_output_format(output)
    _header_if_pretty(fmt)
    try:
        with _client() as client:
            render_channel_stats(client.network_broker.get_channel_stats(), fmt)
    except AISecSDKException as err:
        raise fail(err) from err
