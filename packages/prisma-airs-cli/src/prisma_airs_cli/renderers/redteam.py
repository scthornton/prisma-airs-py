"""Terminal rendering for the ``airs redteam`` command group.

Every shape here mirrors the reference client, so someone moving between the two clients
reads the same output. Two rules are enforced throughout. Anything a machine might parse --
JSON, YAML, CSV, the table -- is written straight to stdout, unwrapped and unstyled, because
Rich would otherwise fold a long line to the console width and turn ``["a"]`` into a markup
tag. And any value that came from the API is escaped before it reaches a markup-formatted
line, for the same reason: target names and prompt text routinely contain brackets.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

import yaml
from rich.markup import escape
from rich.text import Text

from prisma_airs.models.red_team import (
    AdapterListItem,
    AdapterResponse,
    AdapterValidateResponse,
    AttackListItem,
    CategoryModel,
    Channel,
    ChannelStats,
    CustomAttackReportResponse,
    CustomPromptListItem,
    CustomPromptResponse,
    CustomPromptSetListItem,
    CustomPromptSetResponse,
    CustomPromptSetVersionInfo,
    DynamicJobReport,
    ErrorLog,
    EulaContentResponse,
    EulaResponse,
    InstanceGetResponse,
    InstanceResponse,
    JobResponse,
    PropertyValuesResponse,
    RegistryCredentials,
    SeverityStats,
    StaticJobReport,
    TargetAuthValidationResponse,
    TargetListItem,
    TargetResponse,
    TenantLanguagesResponse,
)
from prisma_airs_cli.output import Column, OutputFormat, format_output
from prisma_airs_cli.ui import ui

__all__ = [
    "BackupResult",
    "DetailFormat",
    "RestoreResult",
    "as_output_format",
    "build_attack_list_footnote",
    "interpolate_report_summary",
    "render_adapter_detail",
    "render_adapter_list",
    "render_adapter_validation",
    "render_attack_list",
    "render_auth_validation",
    "render_backup_header",
    "render_backup_summary",
    "render_categories",
    "render_channel_detail",
    "render_channel_list",
    "render_channel_stats",
    "render_custom_attack_list",
    "render_custom_report",
    "render_document",
    "render_dynamic_report",
    "render_error_logs",
    "render_eula_content",
    "render_eula_status",
    "render_instance_detail",
    "render_instance_response",
    "render_languages",
    "render_prompt_detail",
    "render_prompt_list",
    "render_prompt_set_detail",
    "render_prompt_set_list",
    "render_property_names",
    "render_property_values",
    "render_redteam_header",
    "render_registry_credentials",
    "render_restore_summary",
    "render_scan_list",
    "render_scan_progress",
    "render_scan_status",
    "render_static_report",
    "render_target_detail",
    "render_target_list",
    "render_target_templates",
    "render_version_info",
    "render_version_info_unavailable",
    "sanitize_target_metadata",
]

# ---------------------------------------------------------------------------
# Formats and small presentation constants
# ---------------------------------------------------------------------------


class DetailFormat(str, Enum):
    """Formats offered by a command that renders one record rather than a result set.

    A single record has no rows to tabulate, so ``table`` and ``csv`` are not offered --
    matching the reference, whose detail commands advertise only these three.
    """

    PRETTY = "pretty"
    JSON = "json"
    YAML = "yaml"


def as_output_format(fmt: DetailFormat) -> OutputFormat:
    """Widen a detail format to the shared :class:`OutputFormat` the renderers take."""
    return OutputFormat(fmt.value)


#: Prompt text longer than this is elided in list views, so one verbose prompt cannot
#: push everything else off the screen.
_PROMPT_PREVIEW_LIMIT: Final = 80
_PROMPT_PREVIEW_KEEP: Final = 77

#: Severity labels are padded to a fixed column so the result words line up beneath
#: each other regardless of how long the severity name is.
_SEVERITY_COLUMN: Final = 10

#: Registry tokens are long and secret; only enough is shown to tell two apart.
_TOKEN_PREVIEW_CHARS: Final = 20

#: Progress bar geometry: twenty cells, so each cell is five percent.
_PROGRESS_CELLS: Final = 20
_PERCENT_PER_CELL: Final = 5
_FULL_PERCENT: Final = 100

_SEVERITY_STYLES: Final[dict[str, str]] = {
    "CRITICAL": "red",
    "HIGH": "magenta",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}

_STATUS_STYLES: Final[dict[str, str]] = {
    "COMPLETED": "green",
    "RUNNING": "blue",
    "QUEUED": "yellow",
    "INIT": "yellow",
    "FAILED": "red",
    "ABORTED": "red",
    "PARTIALLY_COMPLETE": "yellow",
}

_CHANNEL_STATUS_STYLES: Final[dict[str, str]] = {
    "ONLINE": "green",
    "DRAFT": "yellow",
    "OFFLINE": "red",
}

#: Upstream's report renderer occasionally ships these placeholders un-interpolated.
#: Unknown ``{{...}}`` tokens are deliberately left intact so a future upstream addition
#: stays visible instead of being silently stripped.
_REPORT_SUMMARY_TOKENS: Final[dict[str, str]] = {
    "{{CRITICAL_RISK}}": "critical risk",
    "{{HIGH_RISK}}": "high risk",
    "{{MEDIUM_RISK}}": "medium risk",
    "{{LOW_RISK}}": "low risk",
    "{{INFORMATIONAL_RISK}}": "informational risk",
}


# ---------------------------------------------------------------------------
# Result records shared with the command module
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BackupResult:
    """Outcome of backing up one target.

    Attributes:
        name: The target's name.
        filename: File written, or empty when the backup failed.
        status: ``ok`` or ``failed``.
        error: Why it failed, when it did.
    """

    name: str
    filename: str
    status: str
    error: str | None = None


@dataclass(frozen=True)
class RestoreResult:
    """Outcome of restoring one target.

    Attributes:
        name: The target's name.
        action: ``created``, ``updated``, ``skipped``, or ``failed``.
        error: Why it failed, when it did.
    """

    name: str
    action: str
    error: str | None = None


# ---------------------------------------------------------------------------
# Low-level output helpers
# ---------------------------------------------------------------------------


def _write(text: str) -> None:
    """Write a payload to stdout verbatim.

    Structured output has to survive a pipe byte for byte, so it bypasses the Rich
    console entirely rather than risk line wrapping or markup interpretation.
    """
    sys.stdout.write(f"{text}\n")


def _line(text: Text) -> None:
    """Print one pre-styled line. A :class:`Text` is never re-parsed for markup."""
    ui.out.print(text)


def _blank() -> None:
    """Print the blank separator line the reference emits between blocks."""
    ui.out.print()


def _dump(payload: Any, fmt: OutputFormat) -> None:
    """Emit one record as JSON or YAML; emit nothing for any other format.

    Mirrors the reference, whose detail renderers silently do nothing when handed a
    row-oriented format they cannot represent.
    """
    if fmt is OutputFormat.JSON:
        _write(json.dumps(payload, indent=2, default=str))
    elif fmt is OutputFormat.YAML:
        _write(yaml.safe_dump(payload, sort_keys=False, default_flow_style=False).rstrip("\n"))


def _payload(model: Any) -> Any:
    """Reduce a pydantic model to plain JSON-safe data for dumping."""
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)


def _extra(model: Any, key: str) -> Any:
    """Read a field the service sent but the model does not declare.

    The response models allow extra keys precisely so a server-side addition cannot break
    parsing; ``connection_params`` is one that the CLI renders even though it is not on
    the declared schema.
    """
    return (model.model_extra or {}).get(key)


def _severity_style(severity: str) -> str:
    """Return the style for a severity band."""
    return _SEVERITY_STYLES.get(severity.upper(), "dim")


def _status_style(status: str) -> str:
    """Return the style for a job status."""
    return _STATUS_STYLES.get(status, "white")


def _status_markup(status: str) -> str:
    """Render a job status as a styled markup fragment safe to embed in a value."""
    return f"[{_status_style(status)}]{escape(status)}[/]"


def _channel_status_markup(status: str) -> str:
    """Render a broker channel status as a styled markup fragment."""
    return f"[{_CHANNEL_STATUS_STYLES.get(status.upper(), 'white')}]{escape(status)}[/]"


def _active_state(active: bool) -> str:
    """Render an active/inactive flag as a styled markup fragment."""
    return "[green]active[/]" if active else "[red]inactive[/]"


def _yes_no(value: bool) -> str:
    """Render a boolean as a styled yes/no."""
    return "[green]yes[/]" if value else "[red]no[/]"


def _elide(text: str) -> str:
    """Shorten a long single-line preview, marking that it was cut."""
    if len(text) <= _PROMPT_PREVIEW_LIMIT:
        return text
    return f"{text[:_PROMPT_PREVIEW_KEEP]}..."


def _detail_value(value: Any) -> str:
    """Render one value of a nested object block.

    Objects and arrays are expanded as indented JSON rather than repr'd, because these
    blocks are what a user copies into a ``--config`` file.
    """
    if value is None or not isinstance(value, (dict, list)):
        return str(value)
    return json.dumps(value, indent=2, default=str).replace("\n", "\n  ")


def _key_value_object(obj: dict[str, Any], *, skip_nullish: bool = False) -> None:
    """Render a mapping as an aligned key/value block with JSON-expanded values."""
    pairs: list[tuple[str, Any]] = [
        (key, escape(_detail_value(value)))
        for key, value in obj.items()
        if not (skip_nullish and value is None)
    ]
    if pairs:
        ui.key_value(pairs)


def interpolate_report_summary(summary: str | None) -> str | None:
    """Replace the risk-band placeholders upstream sometimes leaves in a report summary."""
    if not summary:
        return summary
    for token, replacement in _REPORT_SUMMARY_TOKENS.items():
        summary = summary.replace(token, replacement)
    return summary


def sanitize_target_metadata(metadata: Any) -> Any:
    """Drop the multi-turn error message when multi-turn is off.

    ``multi_turn_error_message`` always comes back populated, but it only describes a real
    failure when ``multi_turn`` is true. Showing it otherwise reads as an error the user
    never opted into.
    """
    if not isinstance(metadata, dict):
        return metadata
    if metadata.get("multi_turn") is False and "multi_turn_error_message" in metadata:
        return {k: v for k, v in metadata.items() if k != "multi_turn_error_message"}
    return metadata


# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

SCAN_COLUMNS: Final[list[Column]] = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("status", "Status"),
    Column("type", "Type"),
    Column("score", "Score"),
    Column("createdAt", "Created"),
]

TARGET_COLUMNS: Final[list[Column]] = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("status", "Status"),
    Column("type", "Type"),
]

PROMPT_SET_COLUMNS: Final[list[Column]] = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("status", "Status"),
]

PROPERTY_NAME_COLUMNS: Final[list[Column]] = [Column("name", "Name")]

CHANNEL_COLUMNS: Final[list[Column]] = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("status", "Status"),
    Column("clients", "Clients"),
    Column("lastOnline", "Last Online"),
]

ERROR_LOG_COLUMNS: Final[list[Column]] = [
    Column("createdAt", "Created"),
    Column("errorType", "Type"),
    Column("errorSource", "Source"),
    Column("jobId", "Job"),
    Column("message", "Message"),
]

ADAPTER_COLUMNS: Final[list[Column]] = [
    Column("uuid", "UUID"),
    Column("name", "Name"),
    Column("status", "Status"),
    Column("targets", "Targets"),
    Column("updated", "Updated"),
]

LANGUAGE_COLUMNS: Final[list[Column]] = [
    Column("code", "Code"),
    Column("name", "Name"),
]


# ---------------------------------------------------------------------------
# Header and free-form documents
# ---------------------------------------------------------------------------


def render_redteam_header() -> None:
    """Print the red team banner."""
    ui.header("Prisma AIRS — AI Red Team", "Adversarial scan operations")


def render_backup_header() -> None:
    """Print the backup and restore banner."""
    ui.header("Prisma AIRS — Backup & Restore")


def render_document(payload: Any) -> None:
    """Print an arbitrary API payload as indented JSON.

    Used by the commands whose responses have no fixed shape worth formatting -- device
    registration, target probes, raw field metadata.
    """
    _write(json.dumps(payload, indent=2, default=str))


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


def render_scan_status(job: JobResponse) -> None:
    """Print a scan's status summary."""
    ui.section("Scan Status:")
    pairs: list[tuple[str, Any]] = [
        ("ID", job.uuid),
        ("Name", escape(job.name)),
        ("Type", job.job_type),
    ]
    if job.target.name:
        pairs.append(("Target", escape(job.target.name)))
    pairs.append(("Status", _status_markup(job.status or "")))
    if job.total is not None and job.completed is not None:
        pairs.append(("Progress", f"{job.completed}/{job.total}"))
    if job.score is not None:
        pairs.append(("Score", job.score))
    if job.asr is not None:
        pairs.append(("ASR", f"{job.asr:.1f}%"))
    ui.key_value(pairs)
    _blank()


def render_scan_progress(job: JobResponse) -> None:
    """Report polling progress on stderr, so it never lands in piped output."""
    status = job.status or ""
    if job.total and job.completed is not None:
        percent = round(job.completed / job.total * _FULL_PERCENT)
        filled = round(percent / _PERCENT_PER_CELL)
        bar = "█" * filled + "░" * (_PROGRESS_CELLS - filled)
        ui.status(f"{status} {bar} {percent}% ({job.completed}/{job.total})")
    else:
        ui.status(f"{status}...")


def render_scan_list(jobs: list[JobResponse], fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Print a list of scans."""
    if not jobs:
        ui.empty_list("scans")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": job.uuid,
                "name": job.name,
                "status": job.status or "",
                "type": job.job_type,
                "score": "" if job.score is None else job.score,
                "createdAt": job.created_at or "",
            }
            for job in jobs
        ]
        _write(format_output(rows, SCAN_COLUMNS, fmt))
        return

    ui.section("Recent Scans:")
    for job in jobs:
        ui.dim(job.uuid)
        line = Text("    ")
        line.append(job.name)
        line.append("  ")
        line.append(job.status or "", style=_status_style(job.status or ""))
        line.append(f"  {job.job_type}")
        if job.score is not None:
            line.append(f"  score: {job.score}")
        _line(line)
        if job.created_at:
            _line(Text(f"    {job.created_at}", style="dim"))
        _blank()


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def _render_severity_breakdown(stats: list[SeverityStats]) -> None:
    """Print the bypassed/blocked split per severity band."""
    ui.section("Severity Breakdown:")
    for row in stats:
        line = Text("    ")
        line.append(row.severity.ljust(_SEVERITY_COLUMN), style=_severity_style(row.severity))
        line.append(" ")
        line.append(f"{row.successful or 0} bypassed", style="red")
        line.append("  ")
        line.append(f"{row.failed or 0} blocked", style="green")
        _line(line)


def _category_rows(report: StaticJobReport) -> list[dict[str, Any]]:
    """Flatten the security report's subcategories into table rows.

    The service reports counts but not a rate, so the attack success rate is derived here
    -- and a subcategory with no attacks reads as 0%, not as a division by zero.
    """
    security = report.security_report
    rows: list[dict[str, Any]] = []
    for sub in security.sub_categories if security else []:
        successful = sub.successful
        total = sub.total if sub.total is not None else successful + sub.failed
        asr = (successful / total * _FULL_PERCENT) if total else 0.0
        rows.append(
            {
                "category": sub.display_name,
                "asr": f"{asr:.1f}%",
                "hits": f"{successful}/{total}",
            }
        )
    return rows


def render_static_report(report: StaticJobReport) -> None:
    """Print a static scan report."""
    ui.section("Static Scan Report:")
    pairs: list[tuple[str, Any]] = []
    if report.score is not None:
        pairs.append(("Score", report.score))
    if report.asr is not None:
        pairs.append(("ASR", f"{report.asr:.1f}%"))
    if pairs:
        ui.key_value(pairs)

    if report.severity_report.stats:
        _render_severity_breakdown(report.severity_report.stats)

    rows = _category_rows(report)
    if rows:
        ui.section("Categories:")
        ui.table(
            [
                Column("category", "Category"),
                Column("asr", "ASR"),
                Column("hits", "Bypassed/Total"),
            ],
            rows,
        )

    summary = interpolate_report_summary(report.report_summary)
    if summary:
        ui.section("Summary:")
        _write(f"    {summary}")
    _blank()


def render_dynamic_report(report: DynamicJobReport) -> None:
    """Print a dynamic scan report."""
    ui.section("Dynamic Scan Report:")
    pairs: list[tuple[str, Any]] = []
    if report.score is not None:
        pairs.append(("Score", report.score))
    if report.asr is not None:
        # Dynamic reports express ASR as a fraction where static reports use a percentage.
        pairs.append(("ASR", f"{report.asr * _FULL_PERCENT:.1f}%"))
    if report.total_goals is not None or report.goals_achieved is not None:
        pairs.append(
            ("Goals", f"{report.goals_achieved or 0} achieved / {report.total_goals or 0} total")
        )
    if report.total_streams is not None:
        pairs.append(("Streams", report.total_streams))
    if report.total_threats is not None:
        pairs.append(("Threats", report.total_threats))
    if pairs:
        ui.key_value(pairs)

    summary = interpolate_report_summary(report.report_summary)
    if summary:
        ui.section("Summary:")
        _write(f"    {summary}")
    _blank()


def render_custom_report(report: CustomAttackReportResponse) -> None:
    """Print a custom attack report."""
    ui.section("Custom Attack Report:")
    ui.key_value(
        [
            ("Score", report.score),
            ("ASR", f"{report.asr:.1f}%"),
            ("Attacks", report.total_attacks),
            ("Threats", report.total_threats),
        ]
    )

    prompt_sets = report.custom_attack_reports or []
    if prompt_sets:
        ui.section("Prompt Sets:")
        ui.table(
            [
                Column("promptSet", "Prompt Set"),
                Column("threats", "Threats"),
                Column("threatRate", "Threat Rate"),
            ],
            [
                {
                    "promptSet": summary.prompt_set_name,
                    "threats": f"{summary.total_threats}/{summary.total_prompts}",
                    "threatRate": f"{summary.threat_rate:.1f}%",
                }
                for summary in prompt_sets
            ],
        )
    _blank()


def build_attack_list_footnote(
    severity: str | None,
    total_items: int | None,
    severity_stats: list[SeverityStats],
) -> str | None:
    """Explain a short attack list, or return ``None`` when no explanation is warranted.

    The list-attacks endpoint returns fewer rows than the summary breakdown counts for the
    same severity, because it excludes some attack variants. Without this note the
    difference reads as data loss in the CLI.
    """
    if not severity or total_items is None:
        return None
    row = next((s for s in severity_stats if s.severity == severity), None)
    if row is None:
        return None
    expected = (row.successful or 0) + (row.failed or 0)
    if total_items >= expected:
        return None
    return (
        f"(showing {total_items} of {expected} expected for severity {severity} — "
        "list-attacks endpoint excludes some variants; tracking upstream divergence at #206)"
    )


def render_attack_list(attacks: list[AttackListItem], footnote: str | None = None) -> None:
    """Print the attacks a static scan ran, worst outcome spelled out per row."""
    if not attacks:
        ui.empty_list("attacks")
        if footnote:
            ui.dim(escape(footnote))
        return

    ui.section("Attacks:")
    for attack in attacks:
        line = Text("    ")
        if attack.severity:
            line.append(
                attack.severity.ljust(_SEVERITY_COLUMN), style=_severity_style(attack.severity)
            )
        else:
            line.append("N/A".ljust(_SEVERITY_COLUMN), style="dim")
        line.append(" ")
        if attack.threat:
            line.append("BYPASSED", style="red")
        else:
            line.append("BLOCKED", style="green")
        line.append(f"  {attack.sub_category_display_name or attack.sub_category or '—'}")
        if attack.category:
            line.append(f" [{attack.category}]", style="dim")
        _line(line)
    if footnote:
        ui.dim(escape(footnote))
    _blank()


def render_custom_attack_list(attacks: list[Any]) -> None:
    """Print prompt-level results from a custom attack run.

    Rows arrive untyped: their shape follows whichever filters the caller applied.
    """
    if not attacks:
        ui.empty_list("custom attacks")
        return

    ui.section("Custom Attacks:")
    for attack in attacks:
        row = attack if isinstance(attack, dict) else {}
        line = Text("    ")
        if row.get("threat"):
            line.append("THREAT", style="red")
        else:
            line.append("SAFE", style="green")
        asr = row.get("asr")
        if asr is not None:
            line.append(f" ASR: {asr:.1f}%", style="dim")
        line.append(f"  {_elide(str(row.get('prompt_text', '')))}")
        _line(line)
        goal = row.get("goal")
        if goal:
            _line(Text(f"      {goal}", style="dim"))
    _blank()


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------


def render_categories(categories: list[CategoryModel]) -> None:
    """Print the attack category tree."""
    if not categories:
        ui.empty_list("categories")
        return

    ui.section("Attack Categories:")
    for category in categories:
        line = Text("  ")
        line.append(category.display_name, style="bold")
        line.append(f" ({category.id})", style="cyan")
        if category.description:
            line.append(f" — {category.description}", style="dim")
        _line(line)
        for sub in category.sub_categories:
            sub_line = Text("    ")
            sub_line.append("•", style="dim")
            sub_line.append(f" {sub.display_name}")
            sub_line.append(f" ({sub.id})", style="cyan")
            if sub.description:
                sub_line.append(f" — {sub.description}", style="dim")
            _line(sub_line)
        _blank()


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


def render_target_list(
    targets: list[TargetListItem], fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print the configured red team targets."""
    if not targets:
        ui.empty_list("targets")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": target.uuid,
                "name": target.name,
                "status": "active" if target.active else "inactive",
                "type": target.target_type or "",
            }
            for target in targets
        ]
        _write(format_output(rows, TARGET_COLUMNS, fmt))
        return

    ui.section("Targets:")
    for target in targets:
        ui.dim(target.uuid)
        line = Text("    ")
        line.append(target.name)
        line.append("  ")
        line.append(
            "active" if target.active else "inactive",
            style="green" if target.active else "red",
        )
        if target.target_type:
            line.append(f"  type: {target.target_type}")
        _line(line)
    _blank()


def render_target_detail(target: TargetResponse, fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Print one target, including the connection block a ``--config`` file would carry."""
    if fmt is not OutputFormat.PRETTY:
        _dump(_payload(target), fmt)
        return

    ui.section("Target Detail:")
    pairs: list[tuple[str, Any]] = [
        ("UUID", target.uuid),
        ("Name", escape(target.name)),
        ("Status", _active_state(target.active)),
    ]
    if target.target_type:
        pairs.append(("Type", escape(str(target.target_type))))
    ui.key_value(pairs)

    connection = _extra(target, "connection_params")
    if connection:
        ui.section("Connection:")
        _key_value_object(connection)
    if target.target_background:
        ui.section("Background:")
        _key_value_object(target.target_background, skip_nullish=True)
    metadata = sanitize_target_metadata(target.target_metadata)
    if metadata:
        ui.section("Metadata:")
        _key_value_object(metadata, skip_nullish=True)
    _blank()


def render_target_templates(templates: dict[str, Any]) -> None:
    """Print the provider-specific connection templates, keyed by provider."""
    ui.section("Target Templates:")
    for provider, config in templates.items():
        ui.section(provider)
        ui.dim(escape(json.dumps(config, indent=2, default=str).replace("\n", "\n  ")))
        _blank()


def render_auth_validation(result: TargetAuthValidationResponse) -> None:
    """Print the outcome of a target auth check."""
    ui.section("Auth Validation:")
    pairs: list[tuple[str, Any]] = [("Validated", _yes_no(result.validated))]
    if result.token_preview:
        pairs.append(("Token", escape(result.token_preview)))
    if result.expires_in is not None:
        pairs.append(("Expires In", f"{result.expires_in}s"))
    ui.key_value(pairs)
    _blank()


def render_error_logs(logs: list[ErrorLog], fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Print target-profile error logs."""
    if not logs:
        ui.empty_list("error logs")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "createdAt": log.created_at,
                "errorType": log.error_type or "",
                "errorSource": log.error_source or "",
                "jobId": log.job_id or "",
                "message": log.error_message or "",
            }
            for log in logs
        ]
        _write(format_output(rows, ERROR_LOG_COLUMNS, fmt))
        return

    ui.section("Target-Profile Error Logs:")
    for log in logs:
        line = Text("    ")
        line.append(log.created_at, style="dim")
        line.append("  ")
        line.append(log.error_type or "error", style="red" if log.error_type else "dim")
        if log.error_source:
            line.append(f"  ({log.error_source})")
        _line(line)
        if log.error_message:
            _line(Text(f"      {log.error_message}"))
        if log.job_id:
            _line(Text(f"      job: {log.job_id}", style="dim"))
        _blank()


# ---------------------------------------------------------------------------
# Prompt sets and prompts
# ---------------------------------------------------------------------------


def render_prompt_set_list(
    prompt_sets: list[CustomPromptSetListItem], fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print the custom prompt sets."""
    if not prompt_sets:
        ui.empty_list("prompt sets")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": ps.uuid,
                "name": ps.name,
                "status": "active" if ps.active else "inactive",
            }
            for ps in prompt_sets
        ]
        _write(format_output(rows, PROMPT_SET_COLUMNS, fmt))
        return

    ui.section("Prompt Sets:")
    for ps in prompt_sets:
        ui.dim(ps.uuid)
        line = Text("    ")
        line.append(ps.name)
        line.append("  ")
        line.append("active" if ps.active else "inactive", style="green" if ps.active else "red")
        _line(line)
    _blank()


def render_prompt_set_detail(
    prompt_set: CustomPromptSetResponse,
    fmt: OutputFormat = OutputFormat.PRETTY,
    version_info: CustomPromptSetVersionInfo | None = None,
) -> None:
    """Print one prompt set, folding version info into the machine-readable formats."""
    if fmt is not OutputFormat.PRETTY:
        payload = _payload(prompt_set)
        if version_info is not None:
            payload["versionInfo"] = _payload(version_info)
        _dump(payload, fmt)
        return

    ui.section("Prompt Set Detail:")
    pairs: list[tuple[str, Any]] = [
        ("UUID", prompt_set.uuid),
        ("Name", escape(prompt_set.name)),
        ("Status", _active_state(prompt_set.active)),
        ("Archived", "yes" if prompt_set.archive else "no"),
    ]
    if prompt_set.description:
        pairs.append(("Description", escape(str(prompt_set.description))))
    if prompt_set.created_at:
        pairs.append(("Created", prompt_set.created_at))
    if prompt_set.updated_at:
        pairs.append(("Updated", prompt_set.updated_at))
    ui.key_value(pairs)
    _blank()


def render_version_info(info: CustomPromptSetVersionInfo) -> None:
    """Print a prompt set's version and prompt counts."""
    ui.section("Version Info:")
    stats = info.stats
    ui.key_value(
        [
            ("Version", info.version),
            ("Total", stats.total_prompts if stats else 0),
            ("Active", stats.active_prompts if stats else 0),
            ("Inactive", stats.inactive_prompts if stats else 0),
        ]
    )
    _blank()


def render_version_info_unavailable() -> None:
    """Say that version info could not be read, rather than showing zeroes."""
    ui.section("Version Info:")
    ui.dim("unavailable (version-info endpoint returned an error)")
    _blank()


def render_prompt_list(
    prompts: list[CustomPromptListItem], fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print the prompts in a prompt set."""
    if fmt is not OutputFormat.PRETTY:
        _dump([_payload(prompt) for prompt in prompts], fmt)
        return
    if not prompts:
        ui.empty_list("prompts")
        return

    ui.section("Prompts:")
    for prompt in prompts:
        header = Text("  ")
        header.append(prompt.uuid, style="dim")
        header.append("  ")
        header.append(
            "active" if prompt.active else "inactive", style="green" if prompt.active else "dim"
        )
        _line(header)
        _line(Text(f"    {_elide(prompt.prompt)}"))
        if prompt.goal:
            _line(Text(f"    Goal: {prompt.goal}", style="dim"))
    _blank()


def render_prompt_detail(
    prompt: CustomPromptResponse, fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print one prompt."""
    if fmt is not OutputFormat.PRETTY:
        _dump(_payload(prompt), fmt)
        return

    ui.section("Prompt Detail:")
    pairs: list[tuple[str, Any]] = [
        ("UUID", prompt.uuid),
        ("Set UUID", prompt.prompt_set_id),
        ("Status", "[green]active[/]" if prompt.active else "[dim]inactive[/]"),
        ("Prompt", escape(prompt.prompt)),
    ]
    if prompt.goal:
        pairs.append(("Goal", escape(str(prompt.goal))))
    ui.key_value(pairs)
    _blank()


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


def render_property_names(names: list[str], fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Print the declared property names."""
    if fmt is OutputFormat.JSON or fmt is OutputFormat.YAML:
        _dump(names, fmt)
        return
    if fmt is not OutputFormat.PRETTY:
        _write(format_output([{"name": name} for name in names], PROPERTY_NAME_COLUMNS, fmt))
        return
    if not names:
        ui.empty_list("property names")
        return

    ui.section("Property Names:")
    for name in names:
        ui.bullet(name)
    _blank()


def render_property_values(
    payload: PropertyValuesResponse, fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print the values declared for one property name."""
    if fmt is not OutputFormat.PRETTY:
        _dump(_payload(payload), fmt)
        return
    values = payload.values or []
    if not values:
        ui.empty_list("property values")
        return

    ui.section("Property Values:")
    ui.key_value([("Property", escape(payload.name))])
    for value in values:
        ui.bullet(value)
    _blank()


# ---------------------------------------------------------------------------
# EULA, instances, registry credentials
# ---------------------------------------------------------------------------


def render_eula_status(status: EulaResponse) -> None:
    """Print the tenant's EULA acceptance state."""
    ui.section("EULA Status:")
    pairs: list[tuple[str, Any]] = [("Accepted", _yes_no(status.is_accepted))]
    if status.accepted_at:
        pairs.append(("Accepted At", status.accepted_at))
    if status.accepted_by_user_id:
        pairs.append(("Accepted By", status.accepted_by_user_id))
    ui.key_value(pairs)
    _blank()


def render_eula_content(content: EulaContentResponse) -> None:
    """Print the EULA text.

    The agreement is a document, so it goes to stdout unstyled -- it is meant to be read,
    piped to a pager, or diffed against a previously accepted revision.
    """
    ui.section("EULA Content:")
    _write(f"  {content.content}\n")


def render_instance_response(response: InstanceResponse) -> None:
    """Print an instance provisioning acknowledgement."""
    ui.section("Instance:")
    pairs: list[tuple[str, Any]] = [("TSG ID", response.tsg_id)]
    if response.tenant_id:
        pairs.append(("Tenant ID", response.tenant_id))
    if response.app_id:
        pairs.append(("App ID", response.app_id))
    if response.is_success is not None:
        pairs.append(("Success", _yes_no(response.is_success)))
    ui.key_value(pairs)
    _blank()


def render_instance_detail(
    instance: InstanceGetResponse, fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print one provisioned instance."""
    if fmt is not OutputFormat.PRETTY:
        _dump(_payload(instance), fmt)
        return

    ui.section("Instance Detail:")
    ui.key_value(
        [
            ("TSG ID", instance.tsg_id),
            ("Tenant ID", instance.tenant_id),
            ("App ID", instance.app_id),
            ("Region", instance.region),
        ]
    )
    _blank()


def render_registry_credentials(
    credentials: RegistryCredentials, fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print registry credentials, truncating the token in the human-readable view."""
    if fmt is not OutputFormat.PRETTY:
        _dump(_payload(credentials), fmt)
        return

    ui.section("Registry Credentials:")
    ui.key_value(
        [
            ("Token", f"{credentials.token[:_TOKEN_PREVIEW_CHARS]}..."),
            ("Expiry", credentials.expiry),
        ]
    )
    _blank()


# ---------------------------------------------------------------------------
# Network broker
# ---------------------------------------------------------------------------


def render_channel_list(channels: list[Channel], fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Print the network broker channels."""
    if not channels:
        ui.empty_list("channels")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": channel.uuid or "",
                "name": channel.name or "",
                "status": channel.status or "",
                "clients": ""
                if channel.connected_clients_count is None
                else channel.connected_clients_count,
                "lastOnline": channel.last_online_at or "",
            }
            for channel in channels
        ]
        _write(format_output(rows, CHANNEL_COLUMNS, fmt))
        return

    ui.section("Network Broker Channels:")
    for channel in channels:
        if channel.uuid:
            ui.dim(channel.uuid)
        line = Text("    ")
        line.append(channel.name or "(unnamed)")
        line.append("  ")
        if channel.status:
            line.append(
                channel.status, style=_CHANNEL_STATUS_STYLES.get(channel.status.upper(), "white")
            )
        else:
            line.append("unknown", style="dim")
        if channel.connected_clients_count is not None:
            line.append(f"  clients: {channel.connected_clients_count}")
        _line(line)
        _blank()


def render_channel_detail(channel: Channel, fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Print one network broker channel."""
    if fmt is not OutputFormat.PRETTY:
        _dump(_payload(channel), fmt)
        return

    ui.section("Channel Detail:")
    pairs: list[tuple[str, Any]] = [("UUID", channel.uuid)]
    if channel.name is not None:
        pairs.append(("Name", escape(channel.name)))
    if channel.description is not None:
        pairs.append(("Description", escape(channel.description)))
    if channel.status is not None:
        pairs.append(("Status", _channel_status_markup(channel.status)))
    if channel.connected_clients_count is not None:
        pairs.append(("Connected Clients", channel.connected_clients_count))
    if channel.outdated_clients_count is not None:
        pairs.append(("Outdated Clients", channel.outdated_clients_count))
    if channel.last_online_at is not None:
        pairs.append(("Last Online", channel.last_online_at))
    if channel.added_by is not None:
        pairs.append(("Added By", escape(channel.added_by)))
    if channel.created_at is not None:
        pairs.append(("Created", channel.created_at))
    if channel.updated_at is not None:
        pairs.append(("Updated", channel.updated_at))
    ui.key_value(pairs)

    if channel.features:
        ui.section("Features:")
        ui.key_value([(key, value) for key, value in channel.features.items()])
    _blank()


def render_channel_stats(stats: ChannelStats, fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Print broker infrastructure details and channel counts."""
    if fmt is not OutputFormat.PRETTY:
        _dump(_payload(stats), fmt)
        return

    ui.section("Network Broker Stats:")
    candidates: list[tuple[str, Any]] = [
        ("Online Channels", stats.online_channels),
        ("Total Channels", stats.total_channels),
        ("Server Domain", stats.network_channels_server_domain),
        ("Docker Registry", stats.docker_registry),
        ("Docker Image", stats.docker_image),
        ("Helm Chart", stats.helm_chart),
        ("Client Version", stats.client_version),
    ]
    ui.key_value([(label, value) for label, value in candidates if value is not None])
    _blank()


# ---------------------------------------------------------------------------
# Languages
# ---------------------------------------------------------------------------


def render_languages(
    data: TenantLanguagesResponse, fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print the tenant's language entitlement."""
    if fmt is OutputFormat.JSON or fmt is OutputFormat.YAML:
        _dump(_payload(data), fmt)
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [{"code": lang.code, "name": lang.name} for lang in data.languages]
        _write(format_output(rows, LANGUAGE_COLUMNS, fmt))
        return

    ui.section("Tenant Languages:")
    ui.key_value(
        [
            ("Multilingual", _active_state(data.multilingual_enabled)),
            ("Supported Job Types", ", ".join(data.supported_job_types) or "(none)"),
        ]
    )
    if not data.languages:
        ui.empty_list("languages")
        return

    ui.section("Languages:")
    for language in data.languages:
        line = Text("    ")
        line.append(language.code, style="dim")
        line.append(f"  {language.name}")
        _line(line)
    _blank()


# ---------------------------------------------------------------------------
# Custom target adapters
# ---------------------------------------------------------------------------


def render_adapter_list(
    adapters: list[AdapterListItem],
    fmt: OutputFormat = OutputFormat.PRETTY,
    total_items: int | None = None,
) -> None:
    """Print the custom target adapters."""
    if not adapters:
        ui.empty_list("adapters")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "uuid": adapter.uuid,
                "name": adapter.name,
                "status": adapter.status,
                "targets": "" if adapter.target_count is None else adapter.target_count,
                "updated": adapter.updated_at or "",
            }
            for adapter in adapters
        ]
        _write(format_output(rows, ADAPTER_COLUMNS, fmt))
        return

    ui.section("Custom Target Adapters:")
    for adapter in adapters:
        ui.dim(adapter.uuid)
        line = Text("    ")
        line.append(adapter.name)
        line.append("  ")
        line.append(adapter.status, style="green" if adapter.status == "ACTIVE" else "yellow")
        if adapter.target_count is not None:
            line.append(f"  targets: {adapter.target_count}")
        _line(line)
        _blank()
    if total_items is not None:
        ui.dim(f"{total_items} total")


def render_adapter_detail(
    adapter: AdapterResponse, fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print one adapter.

    Secret values arrive masked with ``is_redacted`` set. The flag is rendered rather than
    the mask, so nobody copies ``**********`` into a config file believing it is the value.
    """
    if fmt is not OutputFormat.PRETTY:
        _dump(_payload(adapter), fmt)
        return

    ui.section("Adapter Detail:")
    status_style = "green" if adapter.status == "ACTIVE" else "yellow"
    pairs: list[tuple[str, Any]] = [
        ("UUID", adapter.uuid),
        ("Name", escape(adapter.name)),
        ("Status", f"[{status_style}]{escape(adapter.status)}[/]"),
        ("Script", f"{len(adapter.script_b64)} base64 chars"),
    ]
    if adapter.description is not None:
        pairs.append(("Description", escape(adapter.description)))
    if adapter.network_broker_channel_uuid is not None:
        pairs.append(("Broker Channel", adapter.network_broker_channel_uuid))
    if adapter.target_count is not None:
        pairs.append(("Targets", adapter.target_count))
    if adapter.created_at is not None:
        pairs.append(("Created", adapter.created_at))
    if adapter.updated_at is not None:
        pairs.append(("Updated", adapter.updated_at))
    ui.key_value(pairs)

    if adapter.variables:
        ui.section("Variables:")
        ui.key_value(
            [
                (
                    f"{variable.key} ({variable.type})",
                    "[dim](redacted)[/]" if variable.is_redacted else escape(variable.value or ""),
                )
                for variable in adapter.variables
            ]
        )
    _blank()


def render_adapter_validation(
    result: AdapterValidateResponse, fmt: OutputFormat = OutputFormat.PRETTY
) -> None:
    """Print a validation run's outcome.

    On failure the traceback is the useful part -- ``stderr`` is often empty even when the
    script raised -- so both streams are shown verbatim rather than summarised.
    """
    if fmt is not OutputFormat.PRETTY:
        _dump(_payload(result), fmt)
        return

    if result.validated:
        ui.success("Adapter script validated")
    else:
        ui.error("Adapter script validation FAILED")
    if result.stdout:
        ui.section("stdout:")
        _write(result.stdout)
    if result.stderr:
        ui.section("stderr:")
        _line(Text(result.stderr, style="red"))
    if result.traceback:
        ui.section("traceback:")
        _line(Text(result.traceback, style="red"))
    _blank()


# ---------------------------------------------------------------------------
# Backup and restore
# ---------------------------------------------------------------------------


def render_backup_summary(results: list[BackupResult], output_dir: str) -> None:
    """Print what a backup run wrote, and what it could not."""
    succeeded = [result for result in results if result.status == "ok"]
    failed = [result for result in results if result.status == "failed"]

    if succeeded:
        ui.section(f"Backed up {len(succeeded)} target(s) to {output_dir}:")
        for result in succeeded:
            ui.success(f"{result.name} → {result.filename}")
    if failed:
        ui.section(f"Failed ({len(failed)}):")
        for result in failed:
            ui.error(f"{result.name}: {result.error}")
    _blank()


def render_restore_summary(results: list[RestoreResult]) -> None:
    """Print the per-target outcome of a restore run, then the tally."""
    ui.section("Restore results:")
    for result in results:
        suffix = f": {result.error}" if result.error else ""
        message = f"{result.name} — {result.action}{suffix}"
        if result.action == "failed":
            ui.error(message)
        elif result.action == "skipped":
            ui.bullet(message, "skip")
        else:
            ui.success(message)

    tally = [
        f"{sum(1 for r in results if r.action == action)} {action}"
        for action in ("created", "updated", "skipped", "failed")
        if any(r.action == action for r in results)
    ]
    _write(f"\n  Total: {', '.join(tally)}\n")
