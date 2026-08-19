"""``airs runtime customer-apps`` and ``airs runtime scan-logs``.

A customer app is the registration an API key is minted against. These commands read,
amend, and retire those registrations, and report what the tenant's traffic actually did
under them.

The reporting half carries one trap worth stating up front. ``consumption`` and
``scan-logs`` are served by the SCM dashboard, which buckets traffic by the literal
``metadata.app_name`` a scan payload sent -- not by the registered application name. One
registration can therefore produce several dashboard buckets, and a registration that has
never been named in a scan payload produces none. The names ``consumption`` accepts are
the dashboard's, which is why it enumerates them for you when the one you gave is unknown.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Final, Literal

import typer
from pydantic import ValidationError

from prisma_airs import ManagementClient
from prisma_airs.errors import AISecSDKException
from prisma_airs.models.management import (
    CustomerApp,
    CustomerAppWithKeys,
    DashboardApplication,
    DashboardApplicationViolationBreakdown,
    ScanResultEntry,
)
from prisma_airs_cli.confirm import confirm_or_abort
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.output import OutputFormat
from prisma_airs_cli.pagination import resolve_page_params
from prisma_airs_cli.renderers.customerapps import (
    AppConsumption,
    CustomerAppDetail,
    CustomerAppRow,
    DetectorCounts,
    ScanLogRow,
    SessionCounts,
    TokenUsage,
    render_consumption,
    render_customer_app_detail,
    render_customer_app_list,
    render_header,
    render_scan_log_list,
)
from prisma_airs_cli.ui import ui

customerapps_app = typer.Typer(
    name="customer-apps",
    help="Manage AIRS customer apps.",
    no_args_is_help=True,
)

scanlogs_app = typer.Typer(
    name="scan-logs",
    help="Query AIRS scan logs.",
    no_args_is_help=True,
)


@scanlogs_app.callback()
def scan_logs() -> None:
    """Query AIRS scan logs.

    Declared only to keep this group a group. Typer folds a single-command app into that
    command, which would silently turn ``scan-logs query`` into ``scan-logs`` the moment
    the group is reached by any route other than the parent's ``add_typer``.
    """


#: Look-back windows the per-application dashboard endpoints accept. Not an arbitrary
#: integer: 1, 3, 14, 21, 28, and 90 all answer 400, so the value is checked here rather
#: than spent on a round trip.
_CONSUMPTION_INTERVALS: Final = (7, 30, 60)

#: Dashboard buckets fetched when resolving a name or enumerating every app, matching the
#: reference client. A tenant with more buckets than this needs paging, which neither
#: client offers on this command yet.
_OVERVIEW_LIMIT: Final = 100

#: Bucket names quoted in the "not found" message before it is summarised. Enough to see
#: the naming convention in use; not so many that the message scrolls.
_SAMPLE_NAMES: Final = 5

#: Default scan-log page size, matching the reference. Used both as the ``--limit`` default
#: and as the size sent when pagination resolves to nothing, so the two cannot drift.
_DEFAULT_SCAN_LOG_PAGE_SIZE: Final = 50

#: The scan-log API numbers its first page ``1``. Used both to convert ``--offset`` and as
#: the page sent when pagination resolves to nothing, for the same reason.
_FIRST_PAGE: Final[Literal[1]] = 1


class VerdictFilter(str, Enum):
    """Which transactions a scan-log query returns."""

    ALL = "all"
    BENIGN = "benign"
    THREAT = "threat"


@dataclass(frozen=True)
class _Bucket:
    """One dashboard bucket: the identity pair the per-application endpoints require.

    Both halves are mandatory on those endpoints, and only this listing pairs them -- an
    ``app_name`` alone cannot be turned into an ``app_id`` any other way.
    """

    app_id: str
    app_name: str


# ---------------------------------------------------------------------------
# Wire shapes -> display shapes
# ---------------------------------------------------------------------------


def _description(app: CustomerApp | CustomerAppWithKeys) -> str | None:
    """Read the description a live tenant returns but the schema does not declare."""
    value = (app.model_extra or {}).get("description")
    return value if isinstance(value, str) else None


def _row(app: CustomerAppWithKeys) -> CustomerAppRow:
    """Flatten a list row for display."""
    return CustomerAppRow(
        id=app.customer_app_id,
        name=app.app_name,
        description=_description(app),
    )


def _detail(app: CustomerApp) -> CustomerAppDetail:
    """Flatten a detail record for display, keeping the record itself alongside it."""
    return CustomerAppDetail(
        id=app.customer_app_id,
        name=app.app_name,
        description=_description(app),
        raw=app.model_dump(mode="json", by_alias=True, exclude_none=True),
    )


def _consumption(
    bucket: _Bucket,
    overview: DashboardApplication,
    breakdown: DashboardApplicationViolationBreakdown,
) -> AppConsumption:
    """Stitch the two per-application dashboard reads into one report."""
    token_stats = overview.token_stats
    session_stats = overview.session_stats
    return AppConsumption(
        app_id=bucket.app_id,
        app_name=bucket.app_name,
        cloud=overview.cloud,
        source=overview.source,
        monitoring_since=overview.created_at,
        profiles=list(overview.profiles or []),
        tokens=TokenUsage(
            daily_average=token_stats.average_daily_tokens if token_stats else None,
            daily_average_scale=token_stats.average_daily_tokens_scale if token_stats else None,
            monthly_total=token_stats.monthly_total_tokens if token_stats else None,
            monthly_total_scale=token_stats.monthly_total_tokens_scale if token_stats else None,
        ),
        sessions=SessionCounts(
            total=(session_stats.total if session_stats else None) or 0,
            violating=(session_stats.violating if session_stats else None) or 0,
        ),
        detectors=[
            DetectorCounts(
                # The detector set evolves server-side, so an entry that arrives without a
                # type is reported rather than dropped -- its counts are still real.
                detector=entry.detection_type or "unknown",
                critical=(entry.violation_breakdown.critical if entry.violation_breakdown else 0)
                or 0,
                high=(entry.violation_breakdown.high if entry.violation_breakdown else 0) or 0,
                medium=(entry.violation_breakdown.medium if entry.violation_breakdown else 0) or 0,
                low=(entry.violation_breakdown.low if entry.violation_breakdown else 0) or 0,
                total=(entry.violation_breakdown.total if entry.violation_breakdown else 0) or 0,
            )
            for entry in breakdown.detection_type_violation_breakdown or []
        ],
        total_violating=breakdown.total_violating or 0,
    )


def _scan_log_row(entry: ScanResultEntry) -> ScanLogRow:
    """Flatten one scan-log entry for display.

    ``action`` falls back to ``verdict`` because an entry the policy did not act on
    reports only the latter, and a blank action column reads as a scan that was skipped.
    """
    extra = entry.model_extra or {}
    timestamp = extra.get("timestamp")
    return ScanLogRow(
        scan_id=entry.scan_id,
        timestamp=entry.received_ts or (timestamp if isinstance(timestamp, str) else "") or "",
        action=entry.action or entry.verdict or "",
        profile=entry.profile_name or "",
        app=entry.app_name,
    )


# ---------------------------------------------------------------------------
# Dashboard lookups
# ---------------------------------------------------------------------------


def _interval(value: int) -> Literal[7, 30, 60]:
    """Narrow ``--time-interval`` to a window the dashboard endpoints accept.

    Written as an explicit match rather than a membership test so the literal type
    survives: the SDK types this parameter as the accepted set, not as ``int``.
    """
    if value == 7:  # noqa: PLR2004 - the accepted windows are the API's, not a magic number
        return 7
    if value == 30:  # noqa: PLR2004
        return 30
    if value == 60:  # noqa: PLR2004
        return 60
    raise usage_error(
        f"--time-interval must be {', '.join(str(i) for i in _CONSUMPTION_INTERVALS[:-1])}, "
        f"or {_CONSUMPTION_INTERVALS[-1]} (the API rejects other values)"
    )


def _dashboard_buckets(mgmt: ManagementClient) -> list[_Bucket]:
    """Enumerate every dashboard bucket this tenant has traffic for.

    Read from the applications overview rather than from ``customer_apps.list`` because
    the dashboard buckets by the scan payload's ``metadata.app_name``: a registration can
    span several buckets, and the SCM "AI Applications" view shows this list, not the
    registration list. Entries missing either half of the identity pair are dropped -- the
    per-application endpoints reject them, and a partial entry would fail once per app.
    """
    overview = mgmt.dashboard.applications_overview(limit=_OVERVIEW_LIMIT)
    return [
        _Bucket(app_id=item.id, app_name=item.name)
        for item in overview.items or []
        if item.id is not None and item.name is not None
    ]


def _match_bucket(buckets: Sequence[_Bucket], app_name: str) -> _Bucket:
    """Resolve a dashboard name to its identity pair, or explain what the names are.

    The failure is worth spelling out because the obvious guess is wrong: the name that
    works here is the one an integration puts in ``metadata.app_name``, which need not be
    the name the app is registered under.
    """
    match = next((bucket for bucket in buckets if bucket.app_name == app_name), None)
    if match is not None:
        return match

    sample = ", ".join(f'"{bucket.app_name}"' for bucket in buckets[:_SAMPLE_NAMES])
    more = f", ... ({len(buckets)} total)" if len(buckets) > _SAMPLE_NAMES else ""
    raise usage_error(
        f'Dashboard application not found: "{app_name}". '
        f"Available (as shown in SCM AI Applications view): {sample}{more}. "
        f"Note: the name to use is the literal value your integration sends in scan "
        f"metadata.app_name (which may differ from the SCM application name)."
    )


def _load_app_config(path: Path) -> CustomerApp:
    """Read an update body, failing on the file rather than deep inside serialisation.

    The endpoint replaces the whole registration, so a file holding only the fields being
    changed silently clears the rest. Validating here turns that into an error naming the
    fields the file is missing, before anything is sent.
    """
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise usage_error(f"{path} is not valid JSON: {err}") from err
    if not isinstance(payload, dict):
        raise usage_error(f"{path} must contain a JSON object describing the customer app")
    try:
        return CustomerApp.model_validate(payload)
    except ValidationError as err:
        fields = ", ".join(str(detail["loc"][0]) for detail in err.errors() if detail["loc"])
        raise usage_error(
            f"{path} is not a complete customer app -- the update replaces the whole "
            f"record. Check: {fields}"
        ) from err


# ---------------------------------------------------------------------------
# customer-apps
# ---------------------------------------------------------------------------


@customerapps_app.command("list")
def list_customer_apps(
    *,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = 100,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List customer apps.

    These are registrations, one per ``customer_appId``. What the dashboard reports on is
    a different list; see `customer-apps consumption`.
    """
    if output is OutputFormat.PRETTY:
        render_header()

    try:
        with ManagementClient() as mgmt:
            page = mgmt.customer_apps.list(limit=limit)
    except AISecSDKException as err:
        raise fail(err) from err

    render_customer_app_list([_row(app) for app in page.customer_apps or []], output)


# The reference gives every `list` an `ls` alias and every `delete` an `rm` one, applied
# program-wide by its `applyListDeleteAliases` walk rather than declared per command. Typer
# has no alias mechanism, so each is a second registration of the same callback, hidden so
# `--help` still lists each command once. Same treatment as topics and profiles.
customerapps_app.command("ls", hidden=True)(list_customer_apps)


@customerapps_app.command("get")
def get_customer_app(
    app_name: Annotated[
        str, typer.Argument(metavar="APP_NAME", help="Registered customer app name.")
    ],
) -> None:
    """Get customer app details.

    Addressed by name: this endpoint has no by-ID form.
    """
    render_header()

    try:
        with ManagementClient() as mgmt:
            app = mgmt.customer_apps.get(app_name)
    except AISecSDKException as err:
        raise fail(err) from err

    render_customer_app_detail(_detail(app))


@customerapps_app.command("update")
def update_customer_app(
    app_id: Annotated[
        str,
        typer.Argument(metavar="APP_ID", help="Customer app ID (the record's customer_appId)."),
    ],
    *,
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            help="JSON file with app updates.",
            exists=True,
            dir_okay=False,
        ),
    ],
) -> None:
    """Update a customer app.

    Addressed by ID, unlike every other command in this group, because that is what the
    endpoint takes. The file must describe the whole record: the update is a replacement,
    not a patch.
    """
    render_header()
    body = _load_app_config(config)

    try:
        with ManagementClient() as mgmt:
            app = mgmt.customer_apps.update(app_id, body)
    except AISecSDKException as err:
        raise fail(err) from err

    ui.success(f"Customer app updated: {app.app_name}")
    render_customer_app_detail(_detail(app))


@customerapps_app.command("delete")
def delete_customer_app(
    app_name: Annotated[
        str, typer.Argument(metavar="APP_NAME", help="Registered customer app name.")
    ],
    *,
    updated_by: Annotated[
        str, typer.Option("--updated-by", help="Email of user performing deletion.")
    ],
    force: Annotated[bool, typer.Option("--force", help="Skip confirmation prompt.")] = False,
) -> None:
    """Delete a customer app.

    Every API key issued against the app dies with it, so anything still scanning under
    those keys starts failing immediately. There is no undo and no soft-delete.
    """
    confirm_or_abort(
        f'Delete customer app "{app_name}" and every API key issued against it?',
        force=force,
        action=f'delete customer app "{app_name}"',
    )
    render_header()

    try:
        with ManagementClient() as mgmt:
            mgmt.customer_apps.delete(app_name, updated_by)
    except AISecSDKException as err:
        raise fail(err) from err

    # Reported from the requested name: the service acknowledges a delete with a bare
    # message, and the record it referred to no longer exists to be read back.
    ui.success(f'Customer app "{app_name}" deleted.')


# `rm`, like `ls` above: the reference's own alias, registered a second time and hidden.
customerapps_app.command("rm", hidden=True)(delete_customer_app)


@customerapps_app.command("consumption")
def consumption(
    app_name: Annotated[
        str | None,
        typer.Argument(
            metavar="[APP_NAME]",
            help="Dashboard application name — the literal scan-payload metadata.app_name, "
            "as shown in the SCM AI Applications view (may differ from the SCM-registered "
            "customer-app name). Omit to report every dashboard bucket.",
        ),
    ] = None,
    *,
    time_interval: Annotated[
        int, typer.Option("--time-interval", help="Window in days: 7, 30, or 60.")
    ] = 30,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """Show per-app token consumption + violation breakdown (SCM dashboard).

    Omit APP_NAME to scan all apps. A bucket that cannot be read is reported and the rest
    of the run continues, so one broken app does not cost the whole report.
    """
    interval = _interval(time_interval)
    if output is OutputFormat.PRETTY:
        render_header()

    reports: list[AppConsumption] = []
    try:
        with ManagementClient() as mgmt:
            buckets = _dashboard_buckets(mgmt)
            if app_name is not None:
                targets = [_match_bucket(buckets, app_name)]
            elif not buckets:
                ui.empty_list("dashboard applications")
                return
            else:
                targets = buckets

            for bucket in targets:
                try:
                    reports.append(
                        _consumption(
                            bucket,
                            mgmt.dashboard.application(
                                app_id=bucket.app_id,
                                app_name=bucket.app_name,
                                time_interval=interval,
                            ),
                            mgmt.dashboard.application_violation_breakdown(
                                app_id=bucket.app_id,
                                app_name=bucket.app_name,
                                time_interval=interval,
                            ),
                        )
                    )
                except AISecSDKException as err:
                    ui.error(f"[{bucket.app_name}] {err.raw_message}")
    except AISecSDKException as err:
        raise fail(err) from err

    render_consumption(reports, output)


# ---------------------------------------------------------------------------
# scan-logs
# ---------------------------------------------------------------------------


@scanlogs_app.command("query")
def query_scan_logs(
    *,
    interval: Annotated[int, typer.Option("--interval", help="Time interval.")],
    unit: Annotated[str, typer.Option("--unit", help="Time unit (hours).")],
    # `filter` is a builtin and the parameter cannot carry that name; the CLI flag is
    # unchanged. The SDK renames the same argument the same way, as `verdict_filter`.
    verdict_filter: Annotated[
        VerdictFilter, typer.Option("--filter", help="Filter: all, benign, threat.")
    ] = VerdictFilter.ALL,
    limit: Annotated[
        int, typer.Option("--limit", help="Max results per page (API page size).")
    ] = _DEFAULT_SCAN_LOG_PAGE_SIZE,
    offset: Annotated[
        int, typer.Option("--offset", help="Starting offset — rounds down to a page boundary.")
    ] = 0,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """Query scan logs.

    The API pages rather than offsets, so `--offset` is converted to the page that
    contains it and rounds down to that page's boundary.
    """
    params = resolve_page_params(limit, offset, index_base=_FIRST_PAGE)
    if output is OutputFormat.PRETTY:
        render_header()

    try:
        with ManagementClient() as mgmt:
            page = mgmt.scan_logs.query(
                time_interval=interval,
                time_unit=unit,
                # Both halves always resolve, because `--limit` and `--offset` each carry
                # a default; the fallbacks restate those defaults rather than inventing a
                # second pair that no flag would ever show.
                page_number=params.page if params.page is not None else _FIRST_PAGE,
                page_size=(params.size if params.size is not None else _DEFAULT_SCAN_LOG_PAGE_SIZE),
                verdict_filter=verdict_filter.value,
            )
    except AISecSDKException as err:
        raise fail(err) from err

    dashboard = page.scan_result_for_dashboard
    entries = (dashboard.scan_result_entries if dashboard else None) or []
    render_scan_log_list([_scan_log_row(entry) for entry in entries], page.page_token, output)
