"""``airs runtime profiles`` -- the security profiles a scan is evaluated against.

A profile is a named bundle of detectors and the action each one takes. It is versioned in
place: every update mints a new revision under the same name rather than replacing the old
one, which is why `get` and `update` resolve a name to its *highest* revision and why
`cleanup` exists at all.

The two dozen `create`/`update` flags are a flat spelling of a deeply nested policy
document, assembled by the builders below. `update` is a read-modify-write: the API takes
the whole resource back, so the current policy is fetched, the named sections are merged
into it, and the result is sent in full. Anything the flags do not mention -- topic
guardrails above all -- survives untouched, which is the only reason `update` is safe to
run against a profile that `topics apply` also writes to.

Two wire-level differences from the reference client, both forced by the SDK and neither
observable to the API. The SDK's serialiser drops nulls, so the placeholder ``member:
null`` and ``database-security: null`` the reference writes into a new profile's data
protection are absent rather than explicitly null -- equivalent to every consumer, since
neither an absent key nor a null one is iterable. And ``max-inline-latency`` is typed
``float``, so the default sends ``5.0`` where the reference sends ``5``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Final

import typer
from pydantic import ValidationError

from prisma_airs import ManagementClient
from prisma_airs._utils import is_valid_uuid
from prisma_airs.errors import AISecSDKException
from prisma_airs.models.management import CreateSecurityProfileRequest, Policy, SecurityProfile
from prisma_airs_cli.commands.ops import profiles_cleanup
from prisma_airs_cli.confirm import confirm_or_abort
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.output import OutputFormat
from prisma_airs_cli.renderers.profiles import (
    render_next_offset,
    render_profile_detail,
    render_profile_list,
    render_profiles_header,
)
from prisma_airs_cli.ui import ui

profiles_app = typer.Typer(
    name="profiles",
    help="Manage AIRS security profiles.",
    no_args_is_help=True,
)

#: HTTP status AIRS answers when a profile of that name already exists -- sometimes after
#: having created it anyway. See :func:`_create_profile`.
_CONFLICT: Final = 409

_LIST_EPILOG: Final = (
    "Examples:\n\n"
    "$ airs runtime profiles list\n\n"
    "$ airs runtime profiles list --output json\n\n"
    "$ airs runtime profiles list --limit 20 --offset 20"
)


class ProfileDetailFormat(str, Enum):
    """How ``profiles get`` renders the profile it found.

    A deliberate subset of :class:`~prisma_airs_cli.output.OutputFormat`, matching the
    reference: one record has no tabular form, so offering ``table`` or ``csv`` would
    advertise output that does not exist.
    """

    PRETTY = "pretty"
    JSON = "json"
    YAML = "yaml"


# ---------------------------------------------------------------------------
# Policy builders -- flat flags in, nested policy document out
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ProfileFlags:
    """The protection flags `create` and `update` share, as parsed off the command line.

    The two booleans carry no "unset" state because neither flag can be given a value: the
    reference registers them as bare switches with no negative form, so absent and false
    are the same instruction and both mean "do not write this key".
    """

    prompt_injection: str | None = None
    toxic_content: str | None = None
    contextual_grounding: str | None = None
    malicious_code: str | None = None
    url_action: str | None = None
    allow_url_categories: str | None = None
    block_url_categories: str | None = None
    alert_url_categories: str | None = None
    agent_security: str | None = None
    dlp_action: str | None = None
    dlp_profiles: str | None = None
    mask_data_inline: bool = False
    db_security_create: str | None = None
    db_security_read: str | None = None
    db_security_update: str | None = None
    db_security_delete: str | None = None
    inline_timeout_action: str | None = None
    max_inline_latency: float | None = None
    mask_data_in_storage: bool = False


def _parse_list(value: str | None) -> list[str] | None:
    """Split a comma-separated flag into trimmed entries.

    Returns ``None`` only when the flag was never given. A flag holding nothing but
    separators yields an empty list, which is a real instruction -- "this bucket has no
    members" -- and is written to the policy as such.
    """
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _model_protection(flags: _ProfileFlags) -> list[dict[str, Any]] | None:
    """Build the model-protection entries, or ``None`` when no flag asked for one."""
    items: list[dict[str, Any]] = []

    if flags.prompt_injection:
        items.append({"name": "prompt-injection", "action": flags.prompt_injection})
    if flags.toxic_content:
        # The console stores toxic content per severity and cannot read a bare action, so
        # a single value is expanded to cover both severities it offers.
        action = flags.toxic_content
        if ":" not in action:
            action = f"high:{action}, moderate:{action}"
        items.append({"name": "toxic-content", "action": action})
    if flags.contextual_grounding:
        items.append({"name": "contextual-grounding", "action": flags.contextual_grounding})

    return items or None


def _app_protection(flags: _ProfileFlags) -> dict[str, Any] | None:
    """Build the app-protection section, or ``None`` when no flag asked for one."""
    section: dict[str, Any] = {}

    if flags.malicious_code:
        section["malicious-code-protection"] = {
            "name": "malicious-code-detection",
            "action": flags.malicious_code,
        }
    if flags.url_action:
        section["url-detected-action"] = flags.url_action
    for key, raw in (
        ("allow-url-category", flags.allow_url_categories),
        ("block-url-category", flags.block_url_categories),
        ("alert-url-category", flags.alert_url_categories),
    ):
        categories = _parse_list(raw)
        if categories is not None:
            section[key] = {"member": categories}

    return section or None


def _agent_protection(flags: _ProfileFlags) -> list[dict[str, Any]] | None:
    """Build the agent-protection entries, or ``None`` when no flag asked for one."""
    if not flags.agent_security:
        return None
    return [{"name": "agent-security", "action": flags.agent_security}]


def _data_protection(flags: _ProfileFlags) -> dict[str, Any] | None:
    """Build the data-protection section, or ``None`` when no flag asked for one.

    ``--dlp-profiles`` and ``--mask-data-inline`` hang off ``--dlp-action``: they are
    settings of the data-leak rule, and without an action there is no rule to attach them
    to. Given alone they are silently inert, matching the reference.
    """
    section: dict[str, Any] = {}

    if flags.dlp_action:
        rule: dict[str, Any] = {"action": flags.dlp_action}
        profiles = _parse_list(flags.dlp_profiles)
        if profiles is not None:
            rule["member"] = [{"text": name} for name in profiles]
        if flags.mask_data_inline:
            rule["mask-data-inline"] = flags.mask_data_inline
        section["data-leak-detection"] = rule

    operations = [
        {"name": f"database-security-{operation}", "action": action}
        for operation, action in (
            ("create", flags.db_security_create),
            ("read", flags.db_security_read),
            ("update", flags.db_security_update),
            ("delete", flags.db_security_delete),
        )
        if action
    ]
    if operations:
        section["database-security"] = operations

    return section or None


def _latency(flags: _ProfileFlags) -> dict[str, Any] | None:
    """Build the latency section, or ``None`` when no flag asked for one."""
    section: dict[str, Any] = {}
    if flags.inline_timeout_action:
        section["inline-timeout-action"] = flags.inline_timeout_action
    if flags.max_inline_latency is not None:
        section["max-inline-latency"] = flags.max_inline_latency
    return section or None


def _has_protection_flag(flags: _ProfileFlags) -> bool:
    """Whether any flag asks for policy at all.

    ``--mask-data-inline`` is excluded deliberately: it only ever writes inside the
    data-leak rule, so on its own it would produce a policy document with nothing in it.
    """
    return any(
        (
            flags.prompt_injection,
            flags.toxic_content,
            flags.contextual_grounding,
            flags.malicious_code,
            flags.url_action,
            flags.allow_url_categories,
            flags.block_url_categories,
            flags.alert_url_categories,
            flags.agent_security,
            flags.dlp_action,
            flags.db_security_create,
            flags.db_security_read,
            flags.db_security_update,
            flags.db_security_delete,
            flags.inline_timeout_action,
            flags.max_inline_latency is not None,
            flags.mask_data_in_storage,
        )
    )


def _model_configuration(flags: _ProfileFlags) -> dict[str, Any]:
    """Assemble a model configuration, carrying only the sections the flags populated."""
    configuration: dict[str, Any] = {}

    for key, section in (
        ("model-protection", _model_protection(flags)),
        ("app-protection", _app_protection(flags)),
        ("agent-protection", _agent_protection(flags)),
        ("data-protection", _data_protection(flags)),
        ("latency", _latency(flags)),
    ):
        if section is not None:
            configuration[key] = section

    if flags.mask_data_in_storage:
        configuration["mask-data-in-storage"] = flags.mask_data_in_storage

    return configuration


def _wrap_policy(configuration: dict[str, Any]) -> dict[str, Any]:
    """Wrap a model configuration in the one-entry policy envelope the API expects."""
    return {
        "ai-security-profiles": [{"model-type": "default", "model-configuration": configuration}]
    }


def _add_console_defaults(configuration: dict[str, Any]) -> None:
    """Fill in the sections the AIRS console iterates over unconditionally.

    A profile whose policy omits any of them renders as "is not iterable" in the console,
    so a new policy always carries all four even when no flag asked for one. Only sections
    the flags left empty are filled -- ``setdefault`` never overwrites a real setting.
    """
    configuration.setdefault(
        "app-protection",
        {"default-url-category": {"member": ["malicious"]}, "url-detected-action": "block"},
    )
    configuration.setdefault(
        "data-protection",
        {
            "data-leak-detection": {"action": "", "mask-data-inline": False, "member": None},
            "database-security": None,
        },
    )
    configuration.setdefault("latency", {"inline-timeout-action": "block", "max-inline-latency": 5})
    configuration.setdefault("mask-data-in-storage", False)


def build_create_request(
    name: str, *, active: bool, flags: _ProfileFlags
) -> CreateSecurityProfileRequest:
    """Build the body for ``profiles create`` from the command line alone.

    A profile with no protection flags is created bare -- name and activation only -- which
    is the reference's behaviour and leaves the tenant's own defaults to apply. As soon as
    one flag asks for policy, the console's required sections are filled in around it.
    """
    body: dict[str, Any] = {"profile_name": name, "active": active}

    if _has_protection_flag(flags):
        configuration = _model_configuration(flags)
        _add_console_defaults(configuration)
        body["policy"] = _wrap_policy(configuration)

    return CreateSecurityProfileRequest.model_validate(body)


def build_overrides(flags: _ProfileFlags) -> dict[str, Any] | None:
    """Build the partial policy ``profiles update`` merges, or ``None`` for no change.

    Unlike :func:`build_create_request` this fills in no defaults: the profile being
    updated already has whatever sections it needs, and inventing them here would overwrite
    settings the caller never mentioned.
    """
    if not _has_protection_flag(flags):
        return None
    return _wrap_policy(_model_configuration(flags))


def _merge_by_name(base: list[Any], overrides: list[Any]) -> list[Any]:
    """Merge two lists of named rules, updating matches in place and appending the rest.

    Keyed on ``name`` rather than position because these lists are sets in disguise: the
    API returns them in whatever order it likes, and a positional merge would silently
    retarget one rule's action onto another.
    """
    merged = list(base)
    for override in overrides:
        match = next((item for item in merged if item.get("name") == override.get("name")), None)
        if match is None:
            merged.append(override)
        else:
            match.update(override)
    return merged


def merge_policy(existing: Policy | None, overrides: dict[str, Any] | None) -> Policy:
    """Overlay flag-derived overrides onto a profile's current policy.

    The API replaces the whole resource on update, so everything not mentioned has to be
    carried across intact. Each section merges the way its shape demands: rule lists by
    name, plain sections field by field, and topic guardrails not at all -- they live in
    ``model-protection`` under a name no flag here produces, so the keyed merge leaves them
    exactly as they were. That is what keeps ``profiles update`` from silently detaching
    every topic ``topics apply`` attached.
    """
    # Dumped with nulls intact so the result validates back into a Policy: several fields
    # are required-but-nullable, and dropping them here would fail the round trip. The
    # transport strips them again on the way out.
    base: dict[str, Any] = (
        existing.model_dump(mode="json", by_alias=True) if existing is not None else {}
    )

    override_entries = (overrides or {}).get("ai-security-profiles") or []
    if not override_entries:
        return Policy.model_validate(base)

    if not base.get("ai-security-profiles"):
        base["ai-security-profiles"] = [{"model-type": "default", "model-configuration": {}}]
    entries = base["ai-security-profiles"]
    configuration: dict[str, Any] = entries[0].get("model-configuration") or {}
    override_configuration: dict[str, Any] = override_entries[0].get("model-configuration") or {}

    for key in ("model-protection", "agent-protection"):
        if override_configuration.get(key):
            configuration[key] = _merge_by_name(
                configuration.get(key) or [], override_configuration[key]
            )

    for key in ("app-protection", "latency"):
        if override_configuration.get(key):
            section: dict[str, Any] = configuration.get(key) or {}
            section.update(override_configuration[key])
            configuration[key] = section

    if override_configuration.get("data-protection"):
        override_data: dict[str, Any] = override_configuration["data-protection"]
        data: dict[str, Any] = configuration.get("data-protection") or {}
        if override_data.get("data-leak-detection"):
            # Replaced whole rather than merged: the DLP member list and its action are one
            # decision, and half-updating them would leave a rule nobody asked for.
            data["data-leak-detection"] = override_data["data-leak-detection"]
        if override_data.get("database-security"):
            data["database-security"] = _merge_by_name(
                data.get("database-security") or [], override_data["database-security"]
            )
        configuration["data-protection"] = data

    if override_configuration.get("mask-data-in-storage") is not None:
        configuration["mask-data-in-storage"] = override_configuration["mask-data-in-storage"]

    entries[0]["model-configuration"] = configuration
    return Policy.model_validate(base)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _resolve_profile(client: ManagementClient, name_or_id: str) -> SecurityProfile:
    """Look a profile up by UUID or by name.

    The shape of the argument decides which: a UUID-shaped value is never a profile name
    worth searching for, and a name is never an ID worth asking about. Resolving by name
    returns the live revision, not the first one stored under it.
    """
    if is_valid_uuid(name_or_id):
        return client.profiles.get(name_or_id)
    return client.profiles.get_by_name(name_or_id)


def _require_id(profile: SecurityProfile) -> str:
    """Return the ID every write needs, or fail naming the record that arrived without one.

    ``profile_id`` is optional in the response schema but mandatory for update and delete,
    and "None is not a valid UUID" three frames later is a worse error than saying which
    profile came back incomplete.
    """
    if not profile.profile_id:
        raise fail(RuntimeError(f'Profile "{profile.profile_name}" has no profile_id'))
    return profile.profile_id


def _load_profile_config(path: Path) -> CreateSecurityProfileRequest:
    """Read a whole profile definition from a JSON file.

    The file's keys are the API's own, so a document produced by ``profiles get --output
    json`` can be fed straight back in.

    Raises:
        typer.Exit: If the file is not JSON, or not a profile the API would accept.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise usage_error(f"{path} could not be read as JSON: {err}") from err
    try:
        return CreateSecurityProfileRequest.model_validate(document)
    except ValidationError as err:
        raise usage_error(f"{path} is not a valid profile definition: {err}") from err


def _create_profile(
    client: ManagementClient, body: CreateSecurityProfileRequest, name: str
) -> SecurityProfile:
    """Create a profile, resolving the conflict AIRS sometimes reports after succeeding.

    The service can answer 409 having created the profile anyway, so a conflict is checked
    against reality rather than believed: if a profile of that name now exists, the create
    worked and that record is returned. Only when the lookup also fails is the conflict
    treated as a genuine "this name is taken".
    """
    try:
        return client.profiles.create(body)
    except AISecSDKException as err:
        if err.status_code != _CONFLICT:
            raise
    try:
        return client.profiles.get_by_name(name)
    except AISecSDKException:
        raise fail(
            RuntimeError(f"Profile \"{name}\" already exists. Use 'profiles update' to modify it.")
        ) from None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@profiles_app.command("list", epilog=_LIST_EPILOG)
def list_profiles(
    *,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = 100,
    offset: Annotated[int, typer.Option("--offset", help="Starting offset.")] = 0,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List security profiles.

    Every stored revision is listed, so a name that has been updated appears more than
    once. ``profiles cleanup`` removes the superseded ones.
    """
    # The reference passes these through unchecked; a negative offset is a mistake upstream
    # and reads better as a usage error here than as a 400 from the service.
    if limit < 0:
        raise usage_error(f"--limit must not be negative, got {limit}")
    if offset < 0:
        raise usage_error(f"--offset must not be negative, got {offset}")

    if output is OutputFormat.PRETTY:
        render_profiles_header()

    try:
        with ManagementClient() as client:
            page = client.profiles.list(limit=limit, offset=offset)
    except AISecSDKException as err:
        raise fail(err) from err

    render_profile_list(page.ai_profiles, output)
    if output is OutputFormat.PRETTY and page.next_offset is not None:
        render_next_offset(page.next_offset)


@profiles_app.command("get")
def get_profile(
    name_or_id: Annotated[str, typer.Argument(help="Profile name or UUID.")],
    *,
    output: Annotated[
        ProfileDetailFormat, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = ProfileDetailFormat.PRETTY,
) -> None:
    """Get a security profile by name or UUID.

    A name resolves to its highest revision, which is the one a scan would actually use.
    """
    if output is ProfileDetailFormat.PRETTY:
        render_profiles_header()

    try:
        with ManagementClient() as client:
            profile = _resolve_profile(client, name_or_id)
    except AISecSDKException as err:
        raise fail(err) from err

    render_profile_detail(profile, OutputFormat(output.value))


@profiles_app.command("create")
def create_profile(
    *,
    name: Annotated[str, typer.Option("--name", help="Profile name.")],
    # The reference registers only the negative form here, so this is a plain switch rather
    # than an `--active/--no-active` pair: adding the positive flag would add CLI surface.
    no_active: Annotated[
        bool, typer.Option("--no-active", help="Create profile as inactive.")
    ] = False,
    prompt_injection: Annotated[
        str | None,
        typer.Option("--prompt-injection", help="Prompt injection action (block/allow/alert)."),
    ] = None,
    toxic_content: Annotated[
        str | None,
        typer.Option(
            "--toxic-content", help='Toxic content action (e.g. "high:block, moderate:block").'
        ),
    ] = None,
    contextual_grounding: Annotated[
        str | None,
        typer.Option(
            "--contextual-grounding", help="Contextual grounding action (block/allow/alert)."
        ),
    ] = None,
    malicious_code: Annotated[
        str | None,
        typer.Option(
            "--malicious-code", help="Malicious code protection action (block/allow/alert)."
        ),
    ] = None,
    url_action: Annotated[
        str | None, typer.Option("--url-action", help="URL detected action (block/allow/alert).")
    ] = None,
    allow_url_categories: Annotated[
        str | None,
        typer.Option("--allow-url-categories", help="Comma-separated URL categories to allow."),
    ] = None,
    block_url_categories: Annotated[
        str | None,
        typer.Option("--block-url-categories", help="Comma-separated URL categories to block."),
    ] = None,
    alert_url_categories: Annotated[
        str | None,
        typer.Option("--alert-url-categories", help="Comma-separated URL categories to alert."),
    ] = None,
    agent_security: Annotated[
        str | None,
        typer.Option("--agent-security", help="Agent security action (block/allow/alert)."),
    ] = None,
    dlp_action: Annotated[
        str | None,
        typer.Option("--dlp-action", help="Data leak detection action (block/allow/alert)."),
    ] = None,
    dlp_profiles: Annotated[
        str | None, typer.Option("--dlp-profiles", help="Comma-separated DLP profile names.")
    ] = None,
    mask_data_inline: Annotated[
        bool, typer.Option("--mask-data-inline", help="Mask detected data inline.")
    ] = False,
    db_security_create: Annotated[
        str | None,
        typer.Option("--db-security-create", help="Database create action (block/allow/alert)."),
    ] = None,
    db_security_read: Annotated[
        str | None,
        typer.Option("--db-security-read", help="Database read action (block/allow/alert)."),
    ] = None,
    db_security_update: Annotated[
        str | None,
        typer.Option("--db-security-update", help="Database update action (block/allow/alert)."),
    ] = None,
    db_security_delete: Annotated[
        str | None,
        typer.Option("--db-security-delete", help="Database delete action (block/allow/alert)."),
    ] = None,
    inline_timeout_action: Annotated[
        str | None,
        typer.Option("--inline-timeout-action", help="Inline timeout action (block/allow)."),
    ] = None,
    max_inline_latency: Annotated[
        float | None,
        typer.Option("--max-inline-latency", help="Max inline latency in seconds."),
    ] = None,
    mask_data_in_storage: Annotated[
        bool, typer.Option("--mask-data-in-storage", help="Mask data in storage.")
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="JSON file with profile configuration (legacy).",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
) -> None:
    """Create a new security profile.

    ``--config`` bypasses every other flag and posts the file as the whole request body,
    which is the escape hatch for policy this command has no flag for.
    """
    render_profiles_header()

    flags = _ProfileFlags(
        prompt_injection=prompt_injection,
        toxic_content=toxic_content,
        contextual_grounding=contextual_grounding,
        malicious_code=malicious_code,
        url_action=url_action,
        allow_url_categories=allow_url_categories,
        block_url_categories=block_url_categories,
        alert_url_categories=alert_url_categories,
        agent_security=agent_security,
        dlp_action=dlp_action,
        dlp_profiles=dlp_profiles,
        mask_data_inline=mask_data_inline,
        db_security_create=db_security_create,
        db_security_read=db_security_read,
        db_security_update=db_security_update,
        db_security_delete=db_security_delete,
        inline_timeout_action=inline_timeout_action,
        max_inline_latency=max_inline_latency,
        mask_data_in_storage=mask_data_in_storage,
    )
    body = (
        _load_profile_config(config)
        if config is not None
        else build_create_request(name, active=not no_active, flags=flags)
    )

    try:
        with ManagementClient() as client:
            profile = _create_profile(client, body, name)
    except AISecSDKException as err:
        raise fail(err) from err

    ui.success(f"Profile created: {profile.profile_id}")
    render_profile_detail(profile)


@profiles_app.command("update")
def update_profile(
    name_or_id: Annotated[str, typer.Argument(help="Profile name or UUID.")],
    *,
    name: Annotated[str | None, typer.Option("--name", help="Update profile name.")] = None,
    active: Annotated[
        bool,
        typer.Option(
            "--active/--no-active",
            help="Set profile as active, or --no-active to set it inactive.",
        ),
    ] = True,
    prompt_injection: Annotated[
        str | None,
        typer.Option("--prompt-injection", help="Prompt injection action (block/allow/alert)."),
    ] = None,
    toxic_content: Annotated[
        str | None,
        typer.Option(
            "--toxic-content", help='Toxic content action (e.g. "high:block, moderate:block").'
        ),
    ] = None,
    contextual_grounding: Annotated[
        str | None,
        typer.Option(
            "--contextual-grounding", help="Contextual grounding action (block/allow/alert)."
        ),
    ] = None,
    malicious_code: Annotated[
        str | None,
        typer.Option(
            "--malicious-code", help="Malicious code protection action (block/allow/alert)."
        ),
    ] = None,
    url_action: Annotated[
        str | None, typer.Option("--url-action", help="URL detected action (block/allow/alert).")
    ] = None,
    allow_url_categories: Annotated[
        str | None,
        typer.Option("--allow-url-categories", help="Comma-separated URL categories to allow."),
    ] = None,
    block_url_categories: Annotated[
        str | None,
        typer.Option("--block-url-categories", help="Comma-separated URL categories to block."),
    ] = None,
    alert_url_categories: Annotated[
        str | None,
        typer.Option("--alert-url-categories", help="Comma-separated URL categories to alert."),
    ] = None,
    agent_security: Annotated[
        str | None,
        typer.Option("--agent-security", help="Agent security action (block/allow/alert)."),
    ] = None,
    dlp_action: Annotated[
        str | None,
        typer.Option("--dlp-action", help="Data leak detection action (block/allow/alert)."),
    ] = None,
    dlp_profiles: Annotated[
        str | None, typer.Option("--dlp-profiles", help="Comma-separated DLP profile names.")
    ] = None,
    mask_data_inline: Annotated[
        bool, typer.Option("--mask-data-inline", help="Mask detected data inline.")
    ] = False,
    db_security_create: Annotated[
        str | None,
        typer.Option("--db-security-create", help="Database create action (block/allow/alert)."),
    ] = None,
    db_security_read: Annotated[
        str | None,
        typer.Option("--db-security-read", help="Database read action (block/allow/alert)."),
    ] = None,
    db_security_update: Annotated[
        str | None,
        typer.Option("--db-security-update", help="Database update action (block/allow/alert)."),
    ] = None,
    db_security_delete: Annotated[
        str | None,
        typer.Option("--db-security-delete", help="Database delete action (block/allow/alert)."),
    ] = None,
    inline_timeout_action: Annotated[
        str | None,
        typer.Option("--inline-timeout-action", help="Inline timeout action (block/allow)."),
    ] = None,
    max_inline_latency: Annotated[
        float | None,
        typer.Option("--max-inline-latency", help="Max inline latency in seconds."),
    ] = None,
    mask_data_in_storage: Annotated[
        bool, typer.Option("--mask-data-in-storage", help="Mask data in storage.")
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="JSON file with profile updates (legacy).",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = None,
) -> None:
    """Update a security profile by name or UUID.

    Read-modify-write: the current policy is fetched, the sections these flags name are
    merged into it, and the whole resource is sent back as a new revision. Sections no flag
    mentions -- topic guardrails included -- are carried across unchanged.
    """
    render_profiles_header()

    flags = _ProfileFlags(
        prompt_injection=prompt_injection,
        toxic_content=toxic_content,
        contextual_grounding=contextual_grounding,
        malicious_code=malicious_code,
        url_action=url_action,
        allow_url_categories=allow_url_categories,
        block_url_categories=block_url_categories,
        alert_url_categories=alert_url_categories,
        agent_security=agent_security,
        dlp_action=dlp_action,
        dlp_profiles=dlp_profiles,
        mask_data_inline=mask_data_inline,
        db_security_create=db_security_create,
        db_security_read=db_security_read,
        db_security_update=db_security_update,
        db_security_delete=db_security_delete,
        inline_timeout_action=inline_timeout_action,
        max_inline_latency=max_inline_latency,
        mask_data_in_storage=mask_data_in_storage,
    )
    replacement = _load_profile_config(config) if config is not None else None

    try:
        with ManagementClient() as client:
            current = _resolve_profile(client, name_or_id)
            body = (
                replacement
                if replacement is not None
                else CreateSecurityProfileRequest(
                    profile_name=name or current.profile_name,
                    active=active,
                    policy=merge_policy(current.policy, build_overrides(flags)),
                )
            )
            profile = client.profiles.update(_require_id(current), body)
    except AISecSDKException as err:
        raise fail(err) from err

    ui.success(f"Profile updated: {profile.profile_id}")
    render_profile_detail(profile)


@profiles_app.command("delete")
def delete_profile(
    name_or_id: Annotated[str, typer.Argument(help="Profile name or UUID.")],
    *,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Skip confirmation and force delete (removes from referencing policies).",
        ),
    ] = False,
    updated_by: Annotated[
        str | None,
        typer.Option("--updated-by", help="Email of user performing force deletion."),
    ] = None,
) -> None:
    """Delete a security profile by name or UUID.

    ``--force`` is not only "do not ask": it switches to the force endpoint, which deletes
    the profile even while security policies still reference it, leaving those policies
    without one. That is why it demands an email for the audit trail.
    """
    render_profiles_header()

    # Checked before the lookup: a missing --updated-by is a usage error, and a usage error
    # should not cost a round trip to discover.
    audit_email: str | None = None
    if force:
        if not updated_by:
            raise usage_error("--updated-by <email> is required with --force")
        audit_email = updated_by

    try:
        with ManagementClient() as client:
            profile = _resolve_profile(client, name_or_id)
            profile_id = _require_id(profile)
            profile_name = profile.profile_name

            if audit_email is not None:
                client.profiles.force_delete(profile_id, audit_email)
            else:
                confirm_or_abort(
                    f'Delete security profile "{profile_name}" ({profile_id})?',
                    force=False,
                    action=f'delete profile "{profile_name}"',
                )
                client.profiles.delete(profile_id)
    except AISecSDKException as err:
        raise fail(err) from err

    ui.success(f"Profile deleted: {profile_name} ({profile_id})")


# `cleanup` is implemented in commands/ops.py, which owns the duplicate-revision logic and
# also exposes it as the top-level `airs profiles-cleanup`. Registering the same function
# here gives the reference's `runtime profiles cleanup` without a second implementation.
profiles_app.command("cleanup")(profiles_cleanup)

# The reference aliases `list` to `ls` and `delete` to `rm`. Click has no alias facility, so
# each is registered a second time under its alias and hidden from the command list -- the
# alias works, without a duplicate entry in `--help` claiming to be a separate command.
profiles_app.command("ls", hidden=True)(list_profiles)
profiles_app.command("rm", hidden=True)(delete_profile)
