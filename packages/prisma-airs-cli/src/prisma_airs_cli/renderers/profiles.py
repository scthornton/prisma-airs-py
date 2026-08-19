"""Terminal rendering for ``airs runtime profiles``.

These commands render the API's own :class:`~prisma_airs.models.management.SecurityProfile`
records rather than a result shape of the CLI's own, so the structured output keys on the
API's field names -- which is also what ``profiles create --config`` reads back in, making
``get --output json`` a round trip rather than a dead end.
"""

from __future__ import annotations

import sys
from typing import Any, Final

import yaml
from rich.markup import escape

from prisma_airs.models.management import SecurityProfile
from prisma_airs.serialization import dumps_indented, to_javascript_numbers
from prisma_airs_cli.output import Column, OutputFormat, format_output
from prisma_airs_cli.ui import ui

#: Columns for the machine-readable renderings of ``profiles list``.
PROFILE_COLUMNS: Final[list[Column]] = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("status", "Status"),
    Column("revision", "Revision"),
]


def _write(text: str) -> None:
    """Write result text to stdout verbatim.

    ``ui`` renders through Rich, which wraps at the terminal width and reads square
    brackets as markup -- both fatal to JSON, CSV, and YAML on their way into a pipe.
    """
    sys.stdout.write(text + "\n")


def render_profiles_header() -> None:
    """Print the runtime-configuration heading these commands share.

    Deliberately a copy of the identical heading in :mod:`prisma_airs_cli.renderers.ops`
    rather than an import of it: that one belongs to the cleanup command, and a shared
    helper would tie two unrelated command groups together for two lines of text.
    """
    ui.header("Prisma AIRS — Runtime Configuration", "Security profile and topic management")


def _status_label(active: bool | None) -> str:
    """Name a profile's activation state.

    ``active`` is optional in the response schema, and an absent value means the same
    thing as ``false`` to every consumer of a profile, so both read as inactive.
    """
    return "active" if active else "inactive"


def _status_markup(active: bool | None) -> str:
    """Colour the activation state, keeping the word so a pipe still carries it."""
    label = _status_label(active)
    return f"[green]{label}[/green]" if active else f"[yellow]{label}[/yellow]"


def _revision_number(revision: float | None) -> int | float | str:
    """A revision as the number the API sent, or ``""`` when the record carries none.

    Kept a number rather than text because ``--output json`` is read by machines: the
    reference emits ``"revision": 2``, and a quoted ``"2"`` is a different value to every
    consumer that compares or sorts it. Revisions arrive as JSON numbers and the SDK types
    them ``float``, so an unconverted value renders as ``2.0``; every observed revision is
    integral, and a fractional one is passed through untouched rather than rounded away.
    The empty string for an absent revision is the reference's own ``revision ?? ''``.
    """
    if revision is None:
        return ""
    return int(revision) if float(revision).is_integer() else revision


def _revision_label(revision: float | None) -> str:
    """The same revision as display text, empty when the record carries none."""
    return str(_revision_number(revision))


def profile_rows(profiles: list[SecurityProfile]) -> list[dict[str, Any]]:
    """Flatten profiles to one row each for the tabular and machine formats."""
    return [
        {
            "id": profile.profile_id or "",
            "name": profile.profile_name,
            "status": _status_label(profile.active),
            "revision": _revision_number(profile.revision),
        }
        for profile in profiles
    ]


def render_profile_list(
    profiles: list[SecurityProfile], fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Render a security profile list in the requested format."""
    if not profiles:
        ui.empty_list("profiles")
        return

    if fmt is not OutputFormat.PRETTY:
        _write(format_output(profile_rows(profiles), PROFILE_COLUMNS, fmt))
        return

    ui.section("Security Profiles:")
    for profile in profiles:
        ui.dim(profile.profile_id or "")
        revision = _revision_label(profile.revision)
        suffix = f" [dim]rev:{revision}[/dim]" if revision else ""
        ui.out.print(
            f"    {escape(profile.profile_name)}  {_status_markup(profile.active)}{suffix}"
        )
    ui.out.print()


def render_next_offset(next_offset: float) -> None:
    """Point at the next page, so a caller can walk a listing without guessing the stride.

    Offsets are counts, so the float the API sends is rendered as the integer it is.
    """
    ui.dim(f"Next offset: {int(next_offset)}")


def _policy_document(profile: SecurityProfile) -> dict[str, Any] | None:
    """The profile's policy in the API's own kebab-case wire form."""
    if profile.policy is None:
        return None
    document: dict[str, Any] = profile.policy.model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    return document


def render_profile_detail(
    profile: SecurityProfile, fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Render one security profile.

    JSON and YAML emit the whole record in the API's wire spelling, so the output feeds
    straight back into ``profiles create --config``. The reference builds its YAML by
    joining ``key: value`` strings and embeds the policy as a JSON blob inside it; this
    goes through PyYAML instead, for the reason ``docs/parity.md`` records under "Output
    formatting" -- the hand-rolled form mangles any value containing a colon.
    """
    if fmt is OutputFormat.JSON:
        # Not model_dump_json: pydantic renders a float field as 2.0 where the API sent 2
        # and the reference echoes 2. Routing through the shared serialiser keeps machine
        # output identical between the two clients.
        _write(dumps_indented(profile.model_dump(mode="json", by_alias=True, exclude_none=True)))
        return
    if fmt is OutputFormat.YAML:
        document = to_javascript_numbers(
            profile.model_dump(mode="json", by_alias=True, exclude_none=True)
        )
        _write(yaml.safe_dump(document, sort_keys=False).rstrip("\n"))
        return

    ui.section("Profile Detail:")
    pairs: list[tuple[str, Any]] = [
        ("ID", profile.profile_id or ""),
        ("Name", escape(profile.profile_name)),
        ("Status", _status_markup(profile.active)),
    ]
    if profile.revision is not None:
        pairs.append(("Revision", _revision_label(profile.revision)))
    if profile.created_by:
        pairs.append(("Created", escape(profile.created_by)))
    if profile.updated_by:
        pairs.append(("Updated", escape(profile.updated_by)))
    if profile.last_modified_ts:
        pairs.append(("Modified", escape(profile.last_modified_ts)))

    policy = _policy_document(profile)
    if policy is not None:
        # Indented to sit under the label, and escaped because JSON is all brackets and
        # `ui.key_value` prints through Rich's markup parser.
        rendered = dumps_indented(policy).replace("\n", "\n  ")
        pairs.append(("Policy", escape(rendered)))

    ui.key_value(pairs)
    ui.out.print()
