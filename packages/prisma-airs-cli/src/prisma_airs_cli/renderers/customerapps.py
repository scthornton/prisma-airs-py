"""Display shapes and terminal rendering for customer apps, consumption, and scan logs.

Three surfaces share this module because they share a header and a vocabulary: a customer
app is a registration, its consumption is what the dashboard observed under that name, and
a scan log is one of the transactions that produced it.

The display shapes are flat dataclasses rather than SDK models. A customer app arrives in
three different wire shapes -- a list row carrying API keys, a detail record, and the
record an update echoes back -- and the renderer should not have to know which it was
handed. The dashboard shapes go further: one screen is stitched from two endpoints, and
flattening happens once, in the command, rather than in every format branch here.

Structured output (``json``, ``yaml``, ``csv``, ``table``) is written straight to stdout
rather than through Rich, so a pipe receives exactly the bytes the format promises -- no
wrapping at the terminal width, and no markup interpretation of an app name that happens
to contain square brackets.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from rich.markup import escape
from rich.text import Text

from prisma_airs_cli.output import Column, OutputFormat, format_output
from prisma_airs_cli.ui import ui

#: Characters of the raw record shown by ``customer-apps get``. The record carries the
#: whole registration including its API keys; the head of it is what identifies the app,
#: and the rest belongs in ``--output json`` on a command that offers it.
MAX_DETAIL_JSON_CHARS: Final = 500

#: Description characters shown beside a name in the pretty list. Long enough to tell two
#: apps apart, short enough that the list stays one line per app.
MAX_LIST_DESCRIPTION_CHARS: Final = 80

#: Columns for the structured renderings of a customer app list.
CUSTOMER_APP_COLUMNS: Final[list[Column]] = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("description", "Description"),
]

#: Columns for the structured renderings of a consumption report. Every row repeats the
#: app-level fields so each one is self-contained, which is what makes the CSV usable in a
#: spreadsheet without a join.
CONSUMPTION_COLUMNS: Final[list[Column]] = [
    Column("app_name", "App"),
    Column("app_id", "AppId"),
    Column("monitoring_since", "MonitoringSince"),
    Column("daily_avg", "DailyAvg"),
    Column("monthly_total", "MonthlyTotal"),
    Column("sessions_total", "Sessions"),
    Column("sessions_violating", "Violating"),
    Column("detector", "Detector"),
    Column("critical", "C"),
    Column("high", "H"),
    Column("medium", "M"),
    Column("low", "L"),
    Column("total", "Total"),
]

#: Columns for the structured renderings of a scan log page.
SCAN_LOG_COLUMNS: Final[list[Column]] = [
    Column("scan_id", "Scan ID"),
    Column("timestamp", "Timestamp"),
    Column("action", "Action"),
    Column("profile", "Profile"),
    Column("app", "App"),
]

#: The verdict that reads as a refusal. Everything else is treated as permitted traffic,
#: so an action this client has never heard of is not coloured as an alarm.
_BLOCK_ACTION: Final = "block"


# ---------------------------------------------------------------------------
# Display shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CustomerAppRow:
    """One customer app as it appears in a list."""

    id: str
    name: str
    description: str | None = None


@dataclass(frozen=True)
class CustomerAppDetail:
    """One customer app, with the record it was built from.

    ``raw`` is kept because the registration carries fields no summary would show -- the
    deployment profiles its API keys were minted against, most usefully -- and there is no
    ``--output json`` on the commands that render this.
    """

    name: str
    raw: dict[str, Any]
    id: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class TokenUsage:
    """Token consumption over the requested window.

    The API reports a number and a scale qualifier separately (``12`` plus ``K``), so both
    are carried through to the point of display rather than being multiplied out into a
    figure the SCM panel never shows.
    """

    daily_average: float | None = None
    daily_average_scale: str | None = None
    monthly_total: float | None = None
    monthly_total_scale: str | None = None


@dataclass(frozen=True)
class SessionCounts:
    """Session activity over the requested window."""

    total: float = 0
    violating: float = 0


@dataclass(frozen=True)
class DetectorCounts:
    """One detector's violations, bucketed by severity."""

    detector: str
    critical: float = 0
    high: float = 0
    medium: float = 0
    low: float = 0
    total: float = 0


@dataclass(frozen=True)
class AppConsumption:
    """One dashboard bucket's token, session, and violation figures.

    Stitched from two endpoints -- the application overview and its violation breakdown --
    which are only ever read together.
    """

    app_id: str
    app_name: str
    tokens: TokenUsage
    sessions: SessionCounts
    total_violating: float = 0
    cloud: str | None = None
    source: str | None = None
    monitoring_since: str | None = None
    profiles: list[str] = field(default_factory=list)
    detectors: list[DetectorCounts] = field(default_factory=list)


@dataclass(frozen=True)
class ScanLogRow:
    """One scanned transaction as the scan-logs view reports it."""

    scan_id: str
    timestamp: str = ""
    action: str = ""
    profile: str = ""
    app: str = ""


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


def _write(text: str) -> None:
    """Write result text to stdout verbatim.

    ``ui`` renders through Rich, which wraps at the terminal width and reads square
    brackets as markup -- both fatal to JSON, CSV, and YAML on their way into a pipe.
    """
    if text:
        sys.stdout.write(text + "\n")


def count(value: float | None) -> int | float:
    """Render a count as the whole number the API meant.

    Every counter on these endpoints is typed as a JSON number, so an untouched value
    prints as ``12.0`` where the reference client and the SCM panel both show ``12``. A
    genuinely fractional value is passed through rather than rounded away.
    """
    if value is None:
        return 0
    return int(value) if float(value).is_integer() else value


def tokens(value: float | None, scale: str | None) -> str:
    """Render a token figure with the scale qualifier the API sends beside it.

    A missing figure renders as ``-`` rather than ``0``: the dashboard omits token stats
    for a window with no traffic, and zero tokens is a different claim from no data.
    """
    if value is None:
        return "-"
    return f"{count(value)}{scale or ''}"


def render_header() -> None:
    """Print the standard heading for the runtime configuration commands."""
    ui.header("Prisma AIRS — Runtime Configuration", "Security profile and topic management")


# ---------------------------------------------------------------------------
# Customer apps
# ---------------------------------------------------------------------------


def render_customer_app_list(
    apps: Sequence[CustomerAppRow], fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Render a customer app list in the requested format."""
    if not apps:
        ui.empty_list("customer apps")
        return

    if fmt is not OutputFormat.PRETTY:
        rows: list[dict[str, Any]] = [
            {"id": app.id, "name": app.name, "description": app.description or ""} for app in apps
        ]
        _write(format_output(rows, CUSTOMER_APP_COLUMNS, fmt))
        return

    ui.section("Customer Apps:")
    for app in apps:
        if app.id:
            ui.dim(app.id)
        line = Text(f"    {app.name}")
        if app.description:
            line.append(f" — {app.description[:MAX_LIST_DESCRIPTION_CHARS]}", style="dim")
        ui.out.print(line)
    ui.out.print()


def render_customer_app_detail(app: CustomerAppDetail) -> None:
    """Render one customer app, followed by the head of the record it came from."""
    ui.section("Customer App Detail:")
    pairs: list[tuple[str, Any]] = []
    if app.id:
        pairs.append(("ID", app.id))
    pairs.append(("Name", escape(app.name)))
    if app.description:
        pairs.append(("Desc", escape(app.description)))
    # Escaped, not passed through: the record holds free text, and an app named "[bold]"
    # would otherwise be swallowed by Rich's markup parser instead of being shown.
    pairs.append(("Data", escape(json.dumps(app.raw, indent=2)[:MAX_DETAIL_JSON_CHARS])))
    ui.key_value(pairs)
    ui.out.print()


# ---------------------------------------------------------------------------
# Consumption
# ---------------------------------------------------------------------------


def consumption_rows(app: AppConsumption) -> list[dict[str, Any]]:
    """Flatten one app's consumption into one row per detector.

    Every detector gets a row, including the quiet ones: a report that silently drops the
    detectors at zero cannot be told apart from one where they were never evaluated.
    """
    return [
        {
            "app_name": app.app_name,
            "app_id": app.app_id,
            "monitoring_since": app.monitoring_since or "",
            "daily_avg": tokens(app.tokens.daily_average, app.tokens.daily_average_scale),
            "monthly_total": tokens(app.tokens.monthly_total, app.tokens.monthly_total_scale),
            "sessions_total": count(app.sessions.total),
            "sessions_violating": count(app.sessions.violating),
            "detector": detector.detector,
            "critical": count(detector.critical),
            "high": count(detector.high),
            "medium": count(detector.medium),
            "low": count(detector.low),
            "total": count(detector.total),
        }
        for detector in app.detectors
    ]


def _render_consumption_pretty(app: AppConsumption) -> None:
    """Render one app's consumption as a screen: identity, tokens, sessions, detectors."""
    ui.header(escape(app.app_name), f"({app.app_id})")

    pairs: list[tuple[str, Any]] = []
    if app.monitoring_since:
        pairs.append(("Monitoring since", app.monitoring_since))
    if app.source:
        pairs.append(("Source", escape(app.source)))
    if app.cloud:
        pairs.append(("Cloud", escape(app.cloud)))
    if app.profiles:
        pairs.append(("Profiles", escape(", ".join(app.profiles))))
    ui.key_value(pairs)

    ui.section("Token consumption:")
    ui.key_value(
        [
            ("Daily avg", tokens(app.tokens.daily_average, app.tokens.daily_average_scale)),
            ("Monthly total", tokens(app.tokens.monthly_total, app.tokens.monthly_total_scale)),
        ]
    )

    ui.section("Sessions:")
    ui.key_value(
        [("Total", count(app.sessions.total)), ("Violating", count(app.sessions.violating))]
    )

    # Only the detectors that fired are tabulated. A tenant sees ten detectors and usually
    # two with data, so listing all ten buries the answer -- the count in the heading is
    # what says how much was left out.
    firing = [detector for detector in app.detectors if detector.total > 0]
    ui.section(
        f"Detectors ({count(app.total_violating)} violating, "
        f"{len(firing)}/{len(app.detectors)} firing):"
    )
    if not firing:
        ui.dim("no detector violations in window")
    else:
        ui.table(
            [
                Column("detector", "Detector"),
                Column("total", "Total"),
                Column("severity", "Severity"),
            ],
            [
                {
                    "detector": detector.detector,
                    "total": count(detector.total),
                    "severity": (
                        f"c={count(detector.critical)} h={count(detector.high)} "
                        f"m={count(detector.medium)} l={count(detector.low)}"
                    ),
                }
                for detector in firing
            ],
        )
    ui.out.print()


def render_consumption(
    apps: Sequence[AppConsumption], fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Render one or more consumption reports.

    Structured output is emitted as a single document covering every app, not one document
    per app. Concatenated CSV would repeat its header mid-file and concatenated JSON would
    not parse at all, so an all-apps report has to be assembled before it is serialised.
    """
    if not apps:
        return

    if fmt is not OutputFormat.PRETTY:
        rows = [row for app in apps for row in consumption_rows(app)]
        _write(format_output(rows, CONSUMPTION_COLUMNS, fmt))
        return

    for app in apps:
        _render_consumption_pretty(app)


# ---------------------------------------------------------------------------
# Scan logs
# ---------------------------------------------------------------------------


def render_scan_log_list(
    results: Sequence[ScanLogRow],
    page_token: str | None = None,
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render a page of scan logs, and the token that reaches the next one."""
    if not results:
        ui.empty_list("scan logs")
        return

    if fmt is not OutputFormat.PRETTY:
        rows: list[dict[str, Any]] = [
            {
                "scan_id": row.scan_id,
                "timestamp": row.timestamp,
                "action": row.action,
                "profile": row.profile,
                "app": row.app,
            }
            for row in results
        ]
        _write(format_output(rows, SCAN_LOG_COLUMNS, fmt))
        return

    ui.section(f"Scan Logs ({len(results)} results):")
    for row in results:
        if row.scan_id:
            ui.dim(row.scan_id)
        line = Text("    ")
        if row.timestamp:
            line.append(row.timestamp, style="dim")
            line.append("  ")
        if row.action:
            line.append(row.action, style="red" if row.action == _BLOCK_ACTION else "green")
            line.append("  ")
        if row.profile:
            line.append(f"[{row.profile}]")
            line.append("  ")
        line.append(row.app)
        ui.out.print(line)

    # The page number the service reports is a display value; this token is the only
    # reliable way back to the next page, so it is printed rather than assumed.
    if page_token:
        ui.out.print()
        ui.dim(f"Page token: {page_token}")
    ui.out.print()
