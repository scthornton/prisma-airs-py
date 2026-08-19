"""Terminal rendering for AI Gateway workspaces and telemetry.

Three conventions here are load-bearing.

Structured output (``json``, ``yaml``, ``csv``, ``table``) is written straight to stdout
rather than through Rich, so a pipe receives exactly the bytes the format promises: no
wrapping at the terminal width, and no markup interpretation of a workspace name that
happens to contain square brackets.

The display shapes below are flat dataclasses rather than SDK models, because one screen
is fed from three different wire shapes -- a list row, a detail record, and the partial
record a create returns -- and the renderer should not have to know which it was handed.

And every cost figure the gateway reports is in CENTS. Only the pretty renderer divides;
structured output keeps the raw cents, so a consumer is never handed a silently scaled
number.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Final

import yaml
from rich.markup import escape
from rich.text import Text

from prisma_airs_cli.output import Column, OutputFormat, format_output
from prisma_airs_cli.ui import ui

#: Lifecycle colours. Anything unrecognised is dimmed rather than guessed at.
_STATUS_STYLES: Final[dict[str, str]] = {"active": "green", "archived": "yellow"}

#: Columns for the structured renderings of a workspace list.
WORKSPACE_COLUMNS: Final[list[Column]] = [
    Column("id", "ID"),
    Column("slug", "Slug"),
    Column("name", "Name"),
    Column("status", "Status"),
    Column("is_default", "Default"),
    Column("scope_name", "Scope"),
]


@dataclass(frozen=True)
class WorkspaceRow:
    """One workspace as it appears in a list."""

    id: str
    slug: str
    name: str
    status: str | None = None
    is_default: bool = False
    scope_name: str | None = None


@dataclass(frozen=True)
class WorkspaceDetail:
    """One workspace with its settings blocks.

    ``usage_limits`` and ``rate_limits`` are ``array | object | null`` on the wire -- the
    array of policy objects is canonical and the single-object form is legacy -- so both
    arrive here normalised to a list.
    """

    id: str
    slug: str
    name: str
    status: str | None = None
    is_default: bool = False
    icon: str | None = None
    description: str | None = None
    created_at: str | None = None
    last_updated_at: str | None = None
    scope_name: str | None = None
    defaults: dict[str, Any] | None = None
    usage_limits: list[dict[str, Any]] = field(default_factory=list)
    rate_limits: list[dict[str, Any]] = field(default_factory=list)
    security_settings: dict[str, bool] | None = None
    data_plane_security_settings: dict[str, Any] | None = None
    settings: dict[str, Any] | None = None


@dataclass(frozen=True)
class CostRecord:
    """One day of spend, in cents."""

    date: str
    cost_cents: float


@dataclass(frozen=True)
class CostReport:
    """A workspace's spend over a rolling window, in cents throughout."""

    workspace_slug: str
    days: int
    total_cents: float
    avg_cents: float
    quota_exceeded: bool
    records: list[CostRecord] = field(default_factory=list)


def _write(text: str) -> None:
    """Write result text to stdout verbatim.

    ``ui`` renders through Rich, which wraps at the terminal width and reads square
    brackets as markup -- both fatal to JSON, CSV, and YAML on their way into a pipe.
    """
    sys.stdout.write(text + "\n")


def _dump(payload: Any, fmt: OutputFormat) -> str:
    """Serialise one record as JSON or YAML.

    Anything that is not JSON is rendered as YAML, matching the reference: these detail
    views have no tabular form to fall back to.
    """
    if fmt is OutputFormat.JSON:
        return json.dumps(payload, indent=2)
    dumped: str = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)
    return dumped.rstrip("\n")


def _status_label(status: str | None) -> str:
    """Name a workspace's lifecycle state.

    ``get`` reports a null status for a workspace ``list`` calls active, so a missing
    value renders as "unknown" -- never as inactive, which would read as a real state.
    """
    return status if status is not None else "unknown"


def _status_text(status: str | None) -> Text:
    """Colour a lifecycle state, keeping the word itself so a pipe still carries it."""
    label = _status_label(status)
    return Text(label, style=_STATUS_STYLES.get(label.lower(), "dim"))


def _status_markup(status: str | None) -> str:
    """Colour a lifecycle state for a renderer that takes markup rather than a ``Text``."""
    label = _status_label(status)
    return f"[{_STATUS_STYLES.get(label.lower(), 'dim')}]{escape(label)}[/]"


def render_header() -> None:
    """Print the standard heading for every ``aigateway`` command."""
    ui.header("Prisma AIRS — AI Gateway", "Gateway workspace operations")


def render_workspace_list(
    workspaces: list[WorkspaceRow], fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Render a workspace list in the requested format."""
    if not workspaces:
        ui.empty_list("workspaces")
        return

    if fmt is not OutputFormat.PRETTY:
        rows: list[dict[str, Any]] = [
            {
                "id": workspace.id,
                "slug": workspace.slug,
                "name": workspace.name,
                "status": _status_label(workspace.status),
                "is_default": workspace.is_default,
                "scope_name": workspace.scope_name or "",
            }
            for workspace in workspaces
        ]
        _write(format_output(rows, WORKSPACE_COLUMNS, fmt))
        return

    ui.section("AI Gateway Workspaces:")
    for workspace in workspaces:
        ui.dim(workspace.id)
        line = Text("    ")
        line.append(workspace.name)
        line.append("  ")
        line.append(workspace.slug, style="dim")
        line.append("  ")
        line.append_text(_status_text(workspace.status))
        if workspace.is_default:
            line.append("  default", style="cyan")
        ui.out.print(line)
        if workspace.scope_name:
            ui.out.print(Text(f"    scope: {workspace.scope_name}", style="dim"))
        ui.out.print()


def _block(label: str, payload: Any) -> None:
    """Print a JSON settings block under its own heading, unstyled by Rich markup."""
    ui.section(label)
    ui.out.print(Text(json.dumps(payload, indent=2), style="dim"))


def render_workspace_detail(
    workspace: WorkspaceDetail, fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Render one workspace, including whichever settings blocks it carries."""
    if fmt is not OutputFormat.PRETTY:
        _write(_dump(asdict(workspace), fmt))
        return

    ui.section("Workspace Detail:")
    pairs: list[tuple[str, Any]] = [
        ("ID", workspace.id),
        ("Slug", workspace.slug),
        ("Name", workspace.name),
        ("Status", _status_markup(workspace.status)),
        ("Default", "yes" if workspace.is_default else "no"),
    ]
    # Absent rather than blank: an empty "Description" line reads as a workspace whose
    # description was cleared, which is a different fact from one never set.
    if workspace.description is not None:
        pairs.append(("Description", escape(workspace.description)))
    if workspace.scope_name is not None:
        pairs.append(("Scope", escape(workspace.scope_name)))
    if workspace.created_at is not None:
        pairs.append(("Created", workspace.created_at))
    if workspace.last_updated_at is not None:
        pairs.append(("Updated", workspace.last_updated_at))
    ui.key_value(pairs)

    if workspace.defaults:
        _block("Defaults:", workspace.defaults)
    if workspace.usage_limits:
        _block("Usage Limits:", workspace.usage_limits)
    if workspace.rate_limits:
        _block("Rate Limits:", workspace.rate_limits)
    if workspace.security_settings:
        ui.section("Security Settings:")
        ui.key_value([(key, value) for key, value in workspace.security_settings.items()])
    ui.out.print()


def _dollars(cents: float) -> str:
    """Render a cents figure as dollars, for humans only."""
    return f"${cents / 100:.2f}"


def render_cost_report(report: CostReport, fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Render a telemetry cost report: dollars for humans, raw cents for machines."""
    if fmt is not OutputFormat.PRETTY:
        _write(_dump(asdict(report), fmt))
        return

    ui.section(f"Cost — {report.workspace_slug} (last {report.days}d):")
    ui.key_value(
        [
            ("Total", _dollars(report.total_cents)),
            ("Daily average", _dollars(report.avg_cents)),
        ]
    )
    if report.quota_exceeded:
        ui.warn("Telemetry quota exceeded — data may be truncated")
    if report.records:
        ui.section("Per day:")
        ui.key_value([(record.date, _dollars(record.cost_cents)) for record in report.records])
    ui.out.print()
