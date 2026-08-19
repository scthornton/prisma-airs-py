"""``airs runtime api-keys`` and ``airs runtime deployment-profiles``.

An API key is minted against a deployment profile, so the two groups live together: the
``auth_code`` a ``create`` config file has to carry comes from the deployment profile
listing, and there is nowhere else to read it from.

Both groups are exported for the parent to mount under ``runtime``, which is where the
reference client nests them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, TypeVar

import typer
from pydantic import BaseModel, ValidationError

from prisma_airs import ManagementClient
from prisma_airs.errors import AISecSDKException
from prisma_airs.models.management import ApiKeyCreateRequest, ApiKeyRegenerateRequest
from prisma_airs_cli.confirm import confirm_or_abort
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.output import OutputFormat
from prisma_airs_cli.renderers.apikeys import (
    render_api_key_detail,
    render_api_key_list,
    render_deployment_profile_list,
    render_runtime_config_header,
)
from prisma_airs_cli.ui import ui

apikeys_app = typer.Typer(
    name="api-keys",
    help="Manage AIRS API keys.",
    no_args_is_help=True,
)
deployment_profiles_app = typer.Typer(
    name="deployment-profiles",
    help="List AIRS deployment profiles.",
    no_args_is_help=True,
)

ModelT = TypeVar("ModelT", bound=BaseModel)

OutputOpt = Annotated[
    OutputFormat,
    typer.Option("--output", metavar="FMT", help="Output format: pretty, table, csv, json, yaml."),
]


def _load_request(path: Path, model: type[ModelT], flag: str) -> ModelT:
    """Read a JSON file named by a flag and validate it against a request model.

    Validating locally turns a terse server-side 400 into a message naming the field that
    is missing, and naming the flag is what makes a typo findable in a long invocation.

    Raises:
        typer.Exit: If the file cannot be read, is not JSON, or does not satisfy ``model``.
    """
    try:
        document: Any = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as err:
        raise usage_error(f"{flag}: {err}") from err

    try:
        return model.model_validate(document)
    except ValidationError as err:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in item['loc']) or '(body)'}: {item['msg']}"
            for item in err.errors()
        )
        raise usage_error(f"{flag}: invalid API key configuration: {detail}") from err


# ---------------------------------------------------------------------------
# api-keys
# ---------------------------------------------------------------------------


@apikeys_app.command("list")
def list_api_keys(
    *,
    limit: Annotated[int, typer.Option("--limit", metavar="N", help="Max results.")] = 100,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """List API keys.

    Secrets are never in this response -- each key shows only its last eight characters,
    which is what the console displays and enough to tell two keys apart.
    """
    if limit < 1:
        raise usage_error("--limit must be a positive integer")

    # The banner would land in the middle of whatever a pipeline is parsing.
    if output is OutputFormat.PRETTY:
        render_runtime_config_header()

    try:
        with ManagementClient() as mgmt:
            page = mgmt.api_keys.list(limit=limit)
    except AISecSDKException as err:
        raise fail(err) from err

    render_api_key_list(page.api_keys or [], output)


@apikeys_app.command("create")
def create(
    *,
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            metavar="PATH",
            help="JSON file with API key configuration.",
            exists=True,
            dir_okay=False,
        ),
    ],
) -> None:
    """Create a new API key.

    The config file needs the ``auth_code`` of the deployment profile the key is minted
    against; ``runtime deployment-profiles list`` is where that value comes from. This is
    the only command whose output contains the secret itself, so capture it here or mint
    another key.
    """
    body = _load_request(config, ApiKeyCreateRequest, "--config")

    render_runtime_config_header()
    try:
        with ManagementClient() as mgmt:
            key = mgmt.api_keys.create(body)
    except AISecSDKException as err:
        raise fail(err) from err

    ui.success(f"API key created: {key.api_key_id}")
    render_api_key_detail(key)


@apikeys_app.command("regenerate")
def regenerate(
    *,
    api_key_id: Annotated[str, typer.Argument(help="ID of the API key to rotate.")],
    interval: Annotated[
        int, typer.Option("--interval", metavar="N", help="Rotation time interval.")
    ],
    unit: Annotated[
        str,
        typer.Option("--unit", metavar="UNIT", help="Rotation time unit (hours, days, months)."),
    ],
    updated_by: Annotated[
        str | None,
        typer.Option(
            "--updated-by", metavar="EMAIL", help="Email of user performing regeneration."
        ),
    ] = None,
) -> None:
    """Regenerate an API key.

    Rotation replaces the secret under the same record, so anything still presenting the
    old key starts failing authentication the moment this returns. Note that this
    addresses the key by ID while `delete` addresses it by name; the two are not
    interchangeable.
    """
    if interval < 1:
        raise usage_error("--interval must be a positive integer")

    render_runtime_config_header()
    try:
        with ManagementClient() as mgmt:
            key = mgmt.api_keys.regenerate(
                api_key_id,
                ApiKeyRegenerateRequest(
                    rotation_time_interval=interval,
                    rotation_time_unit=unit,
                    updated_by=updated_by,
                ),
            )
    except AISecSDKException as err:
        raise fail(err) from err

    ui.success(f"API key regenerated: {key.api_key_id}")
    render_api_key_detail(key)


@apikeys_app.command("delete")
def delete(
    *,
    api_key_name: Annotated[str, typer.Argument(help="Name of the API key to delete.")],
    updated_by: Annotated[
        str,
        typer.Option("--updated-by", metavar="EMAIL", help="Email of user performing deletion."),
    ],
    force: Annotated[bool, typer.Option("--force", help="Skip confirmation prompt.")] = False,
) -> None:
    """Delete an API key.

    Deletion is by name, not by the ID `regenerate` takes, and it is immediate: every
    caller still presenting this key starts failing authentication.
    """
    confirm_or_abort(
        f'Delete API key "{api_key_name}"?',
        force=force,
        action=f'delete API key "{api_key_name}"',
    )

    render_runtime_config_header()
    try:
        with ManagementClient() as mgmt:
            result = mgmt.api_keys.delete(api_key_name, updated_by)
    except AISecSDKException as err:
        raise fail(err) from err

    # The acknowledgement has been observed without a message, and a blank success line
    # reads as though nothing happened.
    ui.success(result.message or f"API key deleted: {api_key_name}")


# ---------------------------------------------------------------------------
# deployment-profiles
# ---------------------------------------------------------------------------


@deployment_profiles_app.command("list")
def list_deployment_profiles(
    *,
    unactivated: Annotated[
        bool, typer.Option("--unactivated", help="Include unactivated profiles.")
    ] = False,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """List deployment profiles.

    Each entry pairs a name with the ``auth_code`` that `api-keys create` requires.
    """
    if output is OutputFormat.PRETTY:
        render_runtime_config_header()

    try:
        with ManagementClient() as mgmt:
            # Absent and false are different to this endpoint, and the reference sends
            # nothing at all when the flag is omitted -- so does this.
            response = mgmt.deployment_profiles.list(unactivated=unactivated or None)
    except AISecSDKException as err:
        raise fail(err) from err

    render_deployment_profile_list(response.deployment_profiles, output)
