"""``airs model-security`` -- ML model supply chain security.

Model Security straddles two API planes behind one token: scans, files, models, and
labels on the data plane; security groups, the rule catalogue, and the scanner package's
PyPI credentials on the management plane. The SDK client hides that split, so the command
tree here is organised the way an operator thinks about the domain instead -- groups and
rules define policy, scans and their derivatives report against it.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # `install` shells out to uv/pip by design; see _run_step
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Final
from urllib.parse import urlsplit, urlunsplit

import typer
from pydantic import ValidationError

from prisma_airs import ModelSecurityClient
from prisma_airs.errors import AISecSDKException
from prisma_airs.models.model_security import (
    LabelsCreateRequest,
    ModelSecurityGroupCreateRequest,
    ModelSecurityGroupUpdateRequest,
    ModelSecurityRuleInstanceUpdateRequest,
    ScanCreateRequest,
)
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.output import OutputFormat
from prisma_airs_cli.renderers.modelsecurity import (
    render_evaluation_detail,
    render_evaluation_list,
    render_file_list,
    render_group_detail,
    render_group_list,
    render_install_plan,
    render_install_success,
    render_label_keys,
    render_label_values,
    render_model_detail,
    render_model_file_list,
    render_model_list,
    render_model_security_header,
    render_model_version_detail,
    render_model_version_list,
    render_pypi_auth,
    render_rule_detail,
    render_rule_instance_detail,
    render_rule_instance_list,
    render_rule_list,
    render_scan_detail,
    render_scan_list,
    render_violation_detail,
    render_violation_list,
)
from prisma_airs_cli.ui import ui

modelsecurity_app = typer.Typer(
    name="model-security",
    help="AI Model Security operations — groups, rules, scans.",
    no_args_is_help=True,
)

groups_app = typer.Typer(name="groups", help="Manage security groups.", no_args_is_help=True)
labels_app = typer.Typer(name="labels", help="Manage scan labels.", no_args_is_help=True)
rule_instances_app = typer.Typer(
    name="rule-instances", help="Manage rule instances in groups.", no_args_is_help=True
)
rules_app = typer.Typer(name="rules", help="Browse security rules.", no_args_is_help=True)
scans_app = typer.Typer(name="scans", help="Model security scan operations.", no_args_is_help=True)
models_app = typer.Typer(
    name="models", help="Browse the scanned model catalogue (read-only).", no_args_is_help=True
)

modelsecurity_app.add_typer(groups_app)
modelsecurity_app.add_typer(labels_app)
modelsecurity_app.add_typer(rule_instances_app)
modelsecurity_app.add_typer(rules_app)
modelsecurity_app.add_typer(scans_app)
modelsecurity_app.add_typer(models_app)

#: Default page size shared by every list command that the reference gives one to.
_DEFAULT_LIMIT: Final = 20

_OUTPUT_HELP: Final = "Output format: pretty, table, csv, json, yaml."
#: Detail views have nothing tabular to show, so table and csv fall back to pretty.
_DETAIL_OUTPUT_HELP: Final = "Output format: pretty, json, yaml."

_NO_INSTALLER: Final = "Neither uv nor python3 found on PATH. Install one first."


class InstallExtras(str, Enum):
    """Source-type extras published alongside ``model-security-client``."""

    ALL = "all"
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    ARTIFACTORY = "artifactory"
    GITLAB = "gitlab"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _csv_values(value: str | None) -> list[str] | None:
    """Split a comma-separated flag into trimmed values.

    Returns ``None`` for an unset flag so the SDK omits the query parameter entirely --
    an empty list would send an empty filter, which is not the same as no filter.
    """
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _check_paging(limit: int | None = None, offset: int | None = None) -> None:
    """Reject negative paging values.

    Deliberately not ``resolve_page_params``: that converts an offset into a page number,
    and these endpoints take a row offset (``skip``) directly. Running the value through
    the page arithmetic would quietly return a different slice than the caller asked for.

    Raises:
        typer.Exit: With ``EXIT_ERROR`` if either value is negative.
    """
    if limit is not None and limit < 0:
        raise usage_error(f"--limit must not be negative, got {limit}")
    if offset is not None and offset < 0:
        raise usage_error(f"--offset must not be negative, got {offset}")


def _load_json_file(path: Path) -> Any:
    """Read and parse a JSON configuration file.

    Raises:
        typer.Exit: With ``EXIT_ERROR`` if the file cannot be read or is not JSON.
    """
    try:
        text = path.read_text()
    except OSError as err:
        raise usage_error(f"Cannot read {path}: {err}") from err
    try:
        return json.loads(text)
    except json.JSONDecodeError as err:
        raise usage_error(f"{path} is not valid JSON: {err}") from err


def _require_object(parsed: Any, source: str) -> dict[str, Any]:
    """Insist a parsed JSON document is an object.

    Raises:
        typer.Exit: With ``EXIT_ERROR`` if it is anything else.
    """
    if not isinstance(parsed, dict):
        raise usage_error(f"{source} must contain a JSON object")
    return parsed


def _parse_labels(raw: str) -> LabelsCreateRequest:
    """Parse the ``--labels`` JSON array into a request body.

    Raises:
        typer.Exit: With ``EXIT_ERROR`` if the value is not a JSON array of
            ``{key, value}`` objects.
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as err:
        raise usage_error(f"--labels is not valid JSON: {err}") from err
    try:
        return LabelsCreateRequest(labels=parsed)
    except ValidationError as err:
        raise usage_error(
            "--labels must be a JSON array of {key, value} objects: "
            f"{err.error_count()} problem(s)"
        ) from err


# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------


@groups_app.command("list")
def list_groups(
    *,
    source_types: Annotated[
        str | None,
        typer.Option("--source-types", help="Filter by source types (comma-separated)."),
    ] = None,
    search: Annotated[str | None, typer.Option("--search", help="Search by name or UUID.")] = None,
    sort_field: Annotated[
        str | None, typer.Option("--sort-field", help="Sort field (created_at, updated_at).")
    ] = None,
    sort_dir: Annotated[
        str | None, typer.Option("--sort-dir", help="Sort direction (asc, desc).")
    ] = None,
    enabled_rules: Annotated[
        str | None,
        typer.Option("--enabled-rules", help="Filter by enabled rule UUIDs (comma-separated)."),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = _DEFAULT_LIMIT,
    output: Annotated[OutputFormat, typer.Option("--output", help=_OUTPUT_HELP)] = (
        OutputFormat.PRETTY
    ),
) -> None:
    """List security groups."""
    _check_paging(limit=limit)
    if output is OutputFormat.PRETTY:
        render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.security_groups.list(
                source_types=_csv_values(source_types),
                search_query=search,
                sort_field=sort_field,
                sort_dir=sort_dir,
                enabled_rules=_csv_values(enabled_rules),
                limit=limit,
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_group_list(result.security_groups, output)


@groups_app.command("get")
def get_group(
    uuid: Annotated[str, typer.Argument(help="Security group UUID.")],
    *,
    output: Annotated[OutputFormat, typer.Option("--output", help=_DETAIL_OUTPUT_HELP)] = (
        OutputFormat.PRETTY
    ),
) -> None:
    """Get security group details."""
    if output is OutputFormat.PRETTY:
        render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            group = client.security_groups.get(uuid)
    except AISecSDKException as err:
        raise fail(err) from err
    render_group_detail(group, output)


@groups_app.command("create")
def create_group(
    *,
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            help="JSON file with group configuration.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Create a security group from a JSON definition.

    The file's keys are the API's own: name, source_type, description, and
    rule_configurations.
    """
    render_model_security_header()
    document = _require_object(_load_json_file(config), str(config))
    try:
        body = ModelSecurityGroupCreateRequest.model_validate(document)
    except ValidationError as err:
        raise usage_error(f"{config} is not a valid group definition: {err}") from err
    try:
        with ModelSecurityClient() as client:
            group = client.security_groups.create(body)
    except AISecSDKException as err:
        raise fail(err) from err
    ui.success(f"Group created: {group.uuid}")
    render_group_detail(group)


@groups_app.command("update")
def update_group(
    uuid: Annotated[str, typer.Argument(help="Security group UUID.")],
    *,
    name: Annotated[str | None, typer.Option("--name", help="New name.")] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="New description.")
    ] = None,
) -> None:
    """Update a security group's name or description."""
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            group = client.security_groups.update(
                uuid, ModelSecurityGroupUpdateRequest(name=name, description=description)
            )
    except AISecSDKException as err:
        raise fail(err) from err
    ui.success(f"Group updated: {group.uuid}")
    render_group_detail(group)


@groups_app.command("delete")
def delete_group(
    uuid: Annotated[str, typer.Argument(help="Security group UUID.")],
) -> None:
    """Delete a security group, then report whether it is actually gone.

    The service soft-deletes: a successful DELETE does not remove the group, so scans
    that already referenced it still resolve. Re-reading afterwards is the only way to
    tell an operator what really happened rather than claiming an unconditional success.
    """
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            client.security_groups.delete(uuid)
            try:
                state: str | None = client.security_groups.get(uuid).state
            except AISecSDKException:
                # The group no longer resolves, which is the outcome the user wanted.
                state = None
    except AISecSDKException as err:
        raise fail(err) from err

    if state is None:
        ui.success(f"Group {uuid} deleted.")
    else:
        ui.warn(f"Delete request accepted, but group {uuid} still reports state '{state}'.")
        ui.dim(
            "Deletion is asynchronous (soft-delete) — re-check with "
            f"`model-security groups get {uuid}`."
        )


# ---------------------------------------------------------------------------
# install -- bootstrap the scanner package from the AIRS PyPI index
# ---------------------------------------------------------------------------


def _redact_index_url(url: str) -> str:
    """Mask the token embedded in an Artifact Registry index URL.

    The URL's userinfo carries a live access token. ``--dry-run`` prints commands to a
    terminal that is usually logged and always in shell history, so the token is masked
    there; running without ``--dry-run`` hands the real URL straight to uv or pip and
    never puts it on screen.
    """
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    userinfo, _, host = parts.netloc.rpartition("@")
    user, separator, _secret = userinfo.partition(":")
    if not separator:
        return url
    return urlunsplit((parts.scheme, f"{user}:***@{host}", parts.path, parts.query, parts.fragment))


def _quote_for_display(argument: str) -> str:
    """Quote an argument that a shell would otherwise mangle when pasted back."""
    return f'"{argument}"' if "[" in argument or " " in argument else argument


def _run_step(label: str, command: list[str]) -> None:
    """Run one install step with inherited stdio.

    Raises:
        typer.Exit: With ``EXIT_ERROR`` if the step cannot start or exits non-zero.
    """
    ui.status(f"→ {label}")
    try:
        # No shell is involved: the executable is an absolute path resolved from PATH by
        # shutil.which, and every argument is built here rather than taken from input.
        completed = subprocess.run(command, check=False)  # noqa: S603
    except OSError as err:
        raise fail(RuntimeError(f"Failed to start {command[0]}: {err}")) from err
    if completed.returncode != 0:
        raise fail(RuntimeError(f"{label} failed with exit code {completed.returncode}"))


@modelsecurity_app.command("install")
def install(
    *,
    extras: Annotated[
        InstallExtras,
        typer.Option("--extras", help="Source type extras to install."),
    ] = InstallExtras.ALL,
    directory: Annotated[
        # `--dir` is the wire name; `dir` is a Python builtin, so only the parameter is
        # renamed.
        Path,
        typer.Option("--dir", help="Directory to create the project in."),
    ] = Path("model-security"),
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the commands without executing.")
    ] = False,
) -> None:
    """Install the model-security-client Python package from AIRS PyPI.

    Prefers uv when it is on PATH and falls back to a plain venv plus pip, so the
    command works on a machine that has never seen uv.
    """
    render_model_security_header()

    uv = shutil.which("uv")
    python3 = shutil.which("python3")
    if uv is None and python3 is None:
        raise fail(RuntimeError(_NO_INSTALLER))

    try:
        with ModelSecurityClient() as client:
            auth = client.get_pypi_auth()
    except AISecSDKException as err:
        raise fail(err) from err

    package = f"model-security-client[{extras.value}]"
    target = str(directory)
    if uv is not None:
        steps = [
            ("uv init", [uv, "init", target]),
            ("uv add", [uv, "add", "--project", target, package, "--index", auth.url]),
        ]
    elif python3 is not None:
        pip = str(directory / ".venv" / "bin" / "pip")
        steps = [
            ("create venv", [python3, "-m", "venv", str(directory / ".venv")]),
            ("pip install", [pip, "install", package, "--extra-index-url", auth.url]),
        ]
    else:
        # Unreachable given the guard above, but stated rather than asserted so neither a
        # future edit nor the type checker has to take it on trust.
        raise fail(RuntimeError(_NO_INSTALLER))

    if dry_run:
        render_install_plan(
            [
                " ".join(_quote_for_display(_redact_index_url(argument)) for argument in command)
                for _label, command in steps
            ]
        )
        return

    for label, command in steps:
        _run_step(label, command)

    activate = (
        f"cd {target}" if uv is not None else f"source {directory / '.venv' / 'bin' / 'activate'}"
    )
    render_install_success(activate)


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


@labels_app.command("add")
def add_labels(
    scan_uuid: Annotated[str, typer.Argument(help="Scan UUID.")],
    *,
    labels: Annotated[str, typer.Option("--labels", help="JSON array of {key, value} labels.")],
) -> None:
    """Add labels to a scan, keeping the ones already there."""
    render_model_security_header()
    body = _parse_labels(labels)
    try:
        with ModelSecurityClient() as client:
            client.scans.add_labels(scan_uuid, body)
    except AISecSDKException as err:
        raise fail(err) from err
    ui.success("Labels added.")


@labels_app.command("set")
def set_labels(
    scan_uuid: Annotated[str, typer.Argument(help="Scan UUID.")],
    *,
    labels: Annotated[str, typer.Option("--labels", help="JSON array of {key, value} labels.")],
) -> None:
    """Replace every label on a scan.

    Labels missing from --labels are dropped; use "labels add" to merge instead.
    """
    render_model_security_header()
    body = _parse_labels(labels)
    try:
        with ModelSecurityClient() as client:
            client.scans.set_labels(scan_uuid, body)
    except AISecSDKException as err:
        raise fail(err) from err
    ui.success("Labels set.")


@labels_app.command("delete")
def delete_labels(
    scan_uuid: Annotated[str, typer.Argument(help="Scan UUID.")],
    *,
    keys: Annotated[str, typer.Option("--keys", help="Comma-separated label keys to delete.")],
) -> None:
    """Delete labels from a scan by key."""
    render_model_security_header()
    parsed = _csv_values(keys)
    if not parsed:
        raise usage_error("--keys must name at least one label key")
    try:
        with ModelSecurityClient() as client:
            client.scans.delete_labels(scan_uuid, parsed)
    except AISecSDKException as err:
        raise fail(err) from err
    ui.success("Labels deleted.")


@labels_app.command("keys")
def label_keys(
    *,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = _DEFAULT_LIMIT,
) -> None:
    """List available label keys."""
    _check_paging(limit=limit)
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.scans.get_label_keys(limit=limit)
    except AISecSDKException as err:
        raise fail(err) from err
    render_label_keys(result.keys)


@labels_app.command("values")
def label_values(
    key: Annotated[str, typer.Argument(help="Label key to enumerate.")],
    *,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = _DEFAULT_LIMIT,
) -> None:
    """List values for a label key."""
    _check_paging(limit=limit)
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.scans.get_label_values(key, limit=limit)
    except AISecSDKException as err:
        raise fail(err) from err
    render_label_values(key, result.values)


# ---------------------------------------------------------------------------
# PyPI authentication
# ---------------------------------------------------------------------------


@modelsecurity_app.command("pypi-auth")
def pypi_auth() -> None:
    """Get PyPI authentication URL for Google Artifact Registry."""
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            auth = client.get_pypi_auth()
    except AISecSDKException as err:
        raise fail(err) from err
    render_pypi_auth(auth)


# ---------------------------------------------------------------------------
# Rule instances
# ---------------------------------------------------------------------------


@rule_instances_app.command("list")
def list_rule_instances(
    group_uuid: Annotated[str, typer.Argument(help="Security group UUID.")],
    *,
    security_rule_uuid: Annotated[
        str | None, typer.Option("--security-rule-uuid", help="Filter by security rule UUID.")
    ] = None,
    state: Annotated[
        str | None,
        typer.Option("--state", help="Filter by state (DISABLED, ALLOWING, BLOCKING)."),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = _DEFAULT_LIMIT,
) -> None:
    """List rule instances in a security group."""
    _check_paging(limit=limit)
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.security_groups.list_rule_instances(
                group_uuid,
                security_rule_uuid=security_rule_uuid,
                state=state,
                limit=limit,
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_rule_instance_list(result.rule_instances)


@rule_instances_app.command("get")
def get_rule_instance(
    group_uuid: Annotated[str, typer.Argument(help="Security group UUID.")],
    instance_uuid: Annotated[str, typer.Argument(help="Rule instance UUID.")],
) -> None:
    """Get rule instance details."""
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            instance = client.security_groups.get_rule_instance(group_uuid, instance_uuid)
    except AISecSDKException as err:
        raise fail(err) from err
    render_rule_instance_detail(instance)


@rule_instances_app.command("update")
def update_rule_instance(
    group_uuid: Annotated[str, typer.Argument(help="Security group UUID.")],
    instance_uuid: Annotated[str, typer.Argument(help="Rule instance UUID.")],
    *,
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            help="JSON file with rule instance updates.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Update a rule instance's state or field values.

    The file carries "state" and "field_values"; the group UUID comes from the command
    line, because the service requires it in the body as well as in the path.
    """
    render_model_security_header()
    document = _require_object(_load_json_file(config), str(config))
    try:
        body = ModelSecurityRuleInstanceUpdateRequest(
            security_group_uuid=group_uuid,
            state=document.get("state"),
            field_values=document.get("field_values"),
        )
    except ValidationError as err:
        raise usage_error(f"{config} is not a valid rule instance update: {err}") from err
    try:
        with ModelSecurityClient() as client:
            instance = client.security_groups.update_rule_instance(group_uuid, instance_uuid, body)
    except AISecSDKException as err:
        raise fail(err) from err
    ui.success(f"Rule instance updated: {instance.uuid}")
    render_rule_instance_detail(instance)


# ---------------------------------------------------------------------------
# Security rules
# ---------------------------------------------------------------------------


@rules_app.command("list")
def list_rules(
    *,
    source_type: Annotated[
        str | None, typer.Option("--source-type", help="Filter by source type.")
    ] = None,
    search: Annotated[str | None, typer.Option("--search", help="Search by name or UUID.")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = _DEFAULT_LIMIT,
    output: Annotated[OutputFormat, typer.Option("--output", help=_OUTPUT_HELP)] = (
        OutputFormat.PRETTY
    ),
) -> None:
    """List available security rules."""
    _check_paging(limit=limit)
    if output is OutputFormat.PRETTY:
        render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.security_rules.list(
                source_type=source_type, search_query=search, limit=limit
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_rule_list(result.rules, output)


@rules_app.command("get")
def get_rule(
    uuid: Annotated[str, typer.Argument(help="Security rule UUID.")],
) -> None:
    """Get security rule details."""
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            rule = client.security_rules.get(uuid)
    except AISecSDKException as err:
        raise fail(err) from err
    render_rule_detail(rule)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


@scans_app.command("list")
def list_scans(
    *,
    eval_outcome: Annotated[
        str | None, typer.Option("--eval-outcome", help="Filter by eval outcome.")
    ] = None,
    source_type: Annotated[
        str | None, typer.Option("--source-type", help="Filter by source type.")
    ] = None,
    scan_origin: Annotated[
        str | None, typer.Option("--scan-origin", help="Filter by scan origin.")
    ] = None,
    search: Annotated[str | None, typer.Option("--search", help="Search scans.")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = _DEFAULT_LIMIT,
    output: Annotated[OutputFormat, typer.Option("--output", help=_OUTPUT_HELP)] = (
        OutputFormat.PRETTY
    ),
) -> None:
    """List model security scans.

    Examples:
        $ airs model-security scans list
        $ airs model-security scans list --eval-outcome BLOCKED --limit 10
        $ airs model-security scans list --output json
    """
    _check_paging(limit=limit)
    if output is OutputFormat.PRETTY:
        render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.scans.list(
                eval_outcomes=[eval_outcome] if eval_outcome else None,
                source_types=[source_type] if source_type else None,
                search=search,
                limit=limit,
            )
    except AISecSDKException as err:
        raise fail(err) from err

    scans = result.scans
    if scan_origin is not None:
        # The scan list endpoint has no scan_origin query parameter, so this narrows the
        # page the service returned rather than the query it ran. Raise --limit if a
        # filtered result looks short.
        scans = [scan for scan in scans if scan.scan_origin == scan_origin]
    render_scan_list(scans, output)


@scans_app.command("get")
def get_scan(
    uuid: Annotated[str, typer.Argument(help="Scan UUID.")],
) -> None:
    """Get scan details."""
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            scan = client.scans.get(uuid)
    except AISecSDKException as err:
        raise fail(err) from err
    render_scan_detail(scan)


@scans_app.command("create")
def create_scan(
    *,
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            help="JSON file with scan configuration.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ],
) -> None:
    """Create a model security scan from a JSON definition.

    The file's keys are the API's own; model_uri and security_group_uuid are the two it
    will not do without.
    """
    render_model_security_header()
    document = _require_object(_load_json_file(config), str(config))
    try:
        body = ScanCreateRequest.model_validate(document)
    except ValidationError as err:
        raise usage_error(f"{config} is not a valid scan definition: {err}") from err
    try:
        with ModelSecurityClient() as client:
            scan = client.scans.create(body)
    except AISecSDKException as err:
        raise fail(err) from err
    ui.success(f"Scan created: {scan.uuid}")
    render_scan_detail(scan)


@scans_app.command("evaluations")
def list_evaluations(
    scan_uuid: Annotated[str, typer.Argument(help="Scan UUID.")],
    *,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = _DEFAULT_LIMIT,
) -> None:
    """List rule evaluations for a scan."""
    _check_paging(limit=limit)
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.scans.get_evaluations(scan_uuid, limit=limit)
    except AISecSDKException as err:
        raise fail(err) from err
    render_evaluation_list(result.evaluations)


@scans_app.command("evaluation")
def get_evaluation(
    uuid: Annotated[str, typer.Argument(help="Evaluation UUID.")],
) -> None:
    """Get evaluation details."""
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            evaluation = client.scans.get_evaluation(uuid)
    except AISecSDKException as err:
        raise fail(err) from err
    render_evaluation_detail(evaluation)


@scans_app.command("violations")
def list_violations(
    scan_uuid: Annotated[str, typer.Argument(help="Scan UUID.")],
    *,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = _DEFAULT_LIMIT,
) -> None:
    """List violations for a scan."""
    _check_paging(limit=limit)
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.scans.get_violations(scan_uuid, limit=limit)
    except AISecSDKException as err:
        raise fail(err) from err
    render_violation_list(result.violations)


@scans_app.command("violation")
def get_violation(
    uuid: Annotated[str, typer.Argument(help="Violation UUID.")],
) -> None:
    """Get violation details."""
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            violation = client.scans.get_violation(uuid)
    except AISecSDKException as err:
        raise fail(err) from err
    render_violation_detail(violation)


@scans_app.command("files")
def list_scan_files(
    scan_uuid: Annotated[str, typer.Argument(help="Scan UUID.")],
    *,
    # `--type` is the wire name; `type` is a Python builtin, so only the parameter is
    # renamed.
    file_type: Annotated[str | None, typer.Option("--type", help="Filter by file type.")] = None,
    result_filter: Annotated[str | None, typer.Option("--result", help="Filter by result.")] = None,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = _DEFAULT_LIMIT,
) -> None:
    """List scanned files."""
    _check_paging(limit=limit)
    render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            page = client.scans.get_files(
                scan_uuid, file_type=file_type, result=result_filter, limit=limit
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_file_list(page.files)


# ---------------------------------------------------------------------------
# Model catalogue
# ---------------------------------------------------------------------------


@models_app.command("list")
def list_models(
    *,
    search: Annotated[str | None, typer.Option("--search", help="Filter by search text.")] = None,
    search_query: Annotated[
        str | None, typer.Option("--search-query", help="Filter by model UUID or name.")
    ] = None,
    sort_field: Annotated[
        str | None, typer.Option("--sort-field", help="Sort field: created_at, updated_at.")
    ] = None,
    sort_order: Annotated[
        str | None, typer.Option("--sort-order", help="Sort order: asc, desc.")
    ] = None,
    limit: Annotated[int | None, typer.Option("--limit", help="Max results.")] = None,
    offset: Annotated[int | None, typer.Option("--offset", help="Starting offset.")] = None,
    output: Annotated[OutputFormat, typer.Option("--output", help=_OUTPUT_HELP)] = (
        OutputFormat.PRETTY
    ),
) -> None:
    """List models in the catalogue.

    Examples:
        $ airs model-security models list
    """
    _check_paging(limit=limit, offset=offset)
    if output is OutputFormat.PRETTY:
        render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.models.list_models(
                search=search,
                search_query=search_query,
                sort_field=sort_field,
                sort_order=sort_order,
                limit=limit,
                skip=offset,
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_model_list(result.models, output)


@models_app.command("get")
def get_model(
    uuid: Annotated[str, typer.Argument(help="Model UUID.")],
    *,
    output: Annotated[OutputFormat, typer.Option("--output", help=_DETAIL_OUTPUT_HELP)] = (
        OutputFormat.PRETTY
    ),
) -> None:
    """Get a model by UUID."""
    if output is OutputFormat.PRETTY:
        render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            model = client.models.get_model(uuid)
    except AISecSDKException as err:
        raise fail(err) from err
    render_model_detail(model, output)


@models_app.command("versions")
def list_model_versions(
    model_uuid: Annotated[str, typer.Argument(help="Model UUID.")],
    *,
    sort_order: Annotated[
        str | None, typer.Option("--sort-order", help="Sort order: asc, desc.")
    ] = None,
    limit: Annotated[int | None, typer.Option("--limit", help="Max results.")] = None,
    offset: Annotated[int | None, typer.Option("--offset", help="Starting offset.")] = None,
    output: Annotated[OutputFormat, typer.Option("--output", help=_OUTPUT_HELP)] = (
        OutputFormat.PRETTY
    ),
) -> None:
    """List versions of a model."""
    _check_paging(limit=limit, offset=offset)
    if output is OutputFormat.PRETTY:
        render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.models.list_model_versions(
                model_uuid, sort_order=sort_order, limit=limit, skip=offset
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_model_version_list(result.model_versions, output)


@models_app.command("version")
def get_model_version(
    uuid: Annotated[str, typer.Argument(help="Model version UUID.")],
    *,
    output: Annotated[OutputFormat, typer.Option("--output", help=_DETAIL_OUTPUT_HELP)] = (
        OutputFormat.PRETTY
    ),
) -> None:
    """Get a model version by UUID."""
    if output is OutputFormat.PRETTY:
        render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            version = client.models.get_model_version(uuid)
    except AISecSDKException as err:
        raise fail(err) from err
    render_model_version_detail(version, output)


@models_app.command("files")
def list_model_version_files(
    model_version_uuid: Annotated[str, typer.Argument(help="Model version UUID.")],
    *,
    limit: Annotated[int | None, typer.Option("--limit", help="Max results.")] = None,
    offset: Annotated[int | None, typer.Option("--offset", help="Starting offset.")] = None,
    output: Annotated[OutputFormat, typer.Option("--output", help=_OUTPUT_HELP)] = (
        OutputFormat.PRETTY
    ),
) -> None:
    """List files in a model version."""
    _check_paging(limit=limit, offset=offset)
    if output is OutputFormat.PRETTY:
        render_model_security_header()
    try:
        with ModelSecurityClient() as client:
            result = client.models.list_model_version_files(
                model_version_uuid, limit=limit, skip=offset
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_model_file_list(result.files, output)
