"""Terminal rendering for ``airs runtime api-keys`` and ``runtime deployment-profiles``.

Two read surfaces and one detail block, all shaped like the reference client so someone
moving between the two reads the same output. Structured formats (``json``, ``yaml``,
``csv``, ``table``) go straight to stdout, unwrapped and unstyled: Rich would fold a long
row to the console width and read a bracket in a server-supplied name as markup, either of
which corrupts what a pipeline is parsing. Pretty output goes through
:data:`~prisma_airs_cli.ui.ui`, with server-supplied text escaped before it reaches a
markup-formatted line.

The structured column keys are transcribed from the reference rather than renamed to
Python conventions, because they are the contract a script parsing ``--output json``
already depends on.
"""

from __future__ import annotations

import sys
from typing import Final

from rich.markup import escape
from rich.text import Text

from prisma_airs.models.management import ApiKey, DeploymentProfileEntry
from prisma_airs_cli.output import Column, OutputFormat, format_output
from prisma_airs_cli.ui import ui

API_KEY_COLUMNS: Final[list[Column]] = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("last8", "Key (last 8)"),
    Column("createdAt", "Created"),
    Column("expiresAt", "Expires"),
]

DEPLOYMENT_PROFILE_COLUMNS: Final[list[Column]] = [
    Column("name", "Name"),
    Column("status", "Status"),
    Column("authCode", "Auth Code"),
]

#: A deployment profile that is anything other than active is worth not highlighting.
_ACTIVE: Final = "active"


def _write(text: str) -> None:
    """Write machine-consumable text to stdout verbatim."""
    sys.stdout.write(f"{text}\n")


def render_runtime_config_header() -> None:
    """Print the runtime-configuration banner.

    Shared by every command on the runtime configuration surface -- profiles, topics, API
    keys, deployment profiles -- and reproduced here rather than imported from another
    command group's renderer, which owns a copy named for its own command.
    """
    ui.header("Prisma AIRS — Runtime Configuration", "Security profile and topic management")


def _created_at(key: ApiKey) -> str:
    """Read the key's creation timestamp.

    The reference reads ``created_at``/``expires_at``, which this service never sends: an
    API key record carries ``creation_ts`` and ``expiration``, so those columns are always
    blank there. They are sourced from the real fields here.
    """
    return key.creation_ts or ""


def render_api_key_list(keys: list[ApiKey], fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Print a page of API keys."""
    if not keys:
        ui.empty_list("API keys")
        return

    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": key.api_key_id,
                "name": key.api_key_name or "",
                "last8": key.api_key_last8,
                "createdAt": _created_at(key),
                "expiresAt": key.expiration,
            }
            for key in keys
        ]
        _write(format_output(rows, API_KEY_COLUMNS, fmt))
        return

    ui.section("API Keys:")
    for key in keys:
        ui.dim(escape(key.api_key_id))
        line = Text("    ")
        line.append(key.api_key_name or "")
        if key.api_key_last8:
            line.append(f" key: …{key.api_key_last8}", style="dim")
        if key.expiration:
            line.append(f" expires: {key.expiration}", style="dim")
        ui.out.print(line)
    ui.out.print()


def render_api_key_detail(key: ApiKey) -> None:
    """Print one API key, including the secret when the response carried one.

    Only create and regenerate return the secret; every other response carries the last
    eight characters, which is what the console shows and all that is needed to tell two
    keys apart.
    """
    pairs: list[tuple[str, object]] = [
        ("ID", escape(key.api_key_id)),
        ("Name", escape(key.api_key_name or "")),
    ]
    if key.api_key:
        pairs.append(("Key", escape(key.api_key)))
    elif key.api_key_last8:
        pairs.append(("Key", f"…{escape(key.api_key_last8)}"))
    created = _created_at(key)
    if created:
        pairs.append(("Created", escape(created)))
    if key.expiration:
        pairs.append(("Expires", escape(key.expiration)))

    ui.section("API Key Detail:")
    ui.key_value(pairs)
    ui.out.print()


def render_deployment_profile_list(
    profiles: list[DeploymentProfileEntry], fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print the deployment profiles an API key can be minted against."""
    if not profiles:
        ui.empty_list("deployment profiles")
        return

    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "name": profile.dp_name,
                "status": profile.status or "",
                "authCode": profile.auth_code,
            }
            for profile in profiles
        ]
        _write(format_output(rows, DEPLOYMENT_PROFILE_COLUMNS, fmt))
        return

    ui.section("Deployment Profiles:")
    for profile in profiles:
        line = Text("    ")
        line.append(profile.dp_name)
        if profile.status:
            line.append("  ")
            line.append(profile.status, style="green" if profile.status == _ACTIVE else "dim")
        if profile.auth_code:
            line.append(f"  {profile.auth_code}", style="dim")
        ui.out.print(line)
    ui.out.print()
