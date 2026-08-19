"""Terminal rendering for runtime scan verdicts."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any, Final

from rich.console import Console
from rich.table import Table
from rich.text import Text

from prisma_airs.models.scan import ScanIdResult, ScanResponse, ThreatScanReport
from prisma_airs_cli.bulk.state import BulkScanResult
from prisma_airs_cli.output import Column
from prisma_airs_cli.ui import ui

#: Verdicts are colour-coded, but every one is also spelled out, so the output survives
#: a pipe, a CI log, or a colour-blind reader.
_ACTION_STYLES = {"allow": "bold green", "block": "bold red"}


def action_text(action: str) -> Text:
    """Style a verdict action for display."""
    return Text(action.upper(), style=_ACTION_STYLES.get(action, "bold yellow"))


def triggered_detections(response: ScanResponse) -> list[str]:
    """List the detection services that fired, across prompt and response."""
    triggered: list[str] = []
    for side, detected in (
        ("prompt", response.prompt_detected),
        ("response", response.response_detected),
    ):
        if detected is None:
            continue
        for name, value in detected.model_dump(exclude_none=True).items():
            if value is True:
                triggered.append(f"{side}.{name}")
    return triggered


def render_verdict(response: ScanResponse, console: Console) -> None:
    """Render a scan verdict as a summary table."""
    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_column(style="dim")
    table.add_column()

    table.add_row("Action", action_text(response.action))
    table.add_row("Category", response.category)
    if response.profile_name:
        table.add_row("Profile", response.profile_name)
    table.add_row("Scan ID", response.scan_id)
    table.add_row("Report ID", response.report_id)

    detections = triggered_detections(response)
    table.add_row("Detections", ", ".join(detections) if detections else "[dim]none[/dim]")

    if response.timeout:
        table.add_row("Timeout", "[yellow]the scan timed out upstream[/yellow]")
    if response.error:
        detail = ", ".join(filter(None, (f"{e.feature}: {e.status}" for e in response.errors)))
        table.add_row("Errors", f"[red]{detail or 'reported by the service'}[/red]")

    console.print(table)


# ---------------------------------------------------------------------------
# Bulk scan
# ---------------------------------------------------------------------------

#: Prompt-side detector flags, in the order the reference client emits them. This is the
#: column order of the results CSV, which downstream reporting already parses, so it is a
#: compatibility contract rather than a presentation choice.
RUNTIME_DETECTION_KEYS: Final[tuple[str, ...]] = (
    "topic_violation",
    "injection",
    "toxic_content",
    "dlp",
    "url_cats",
    "malicious_code",
    "source_code",
    "agent",
)

#: Header row of the bulk-scan results CSV.
BULK_CSV_HEADER: Final[tuple[str, ...]] = (
    "prompt",
    "action",
    "category",
    "triggered",
    *RUNTIME_DETECTION_KEYS,
    "scan_id",
    "report_id",
    "error",
)


def bulk_results_csv(results: list[BulkScanResult]) -> str:
    """Render bulk-scan results as CSV text.

    Column order, quoting of every data field, and lowercase booleans match the reference
    client, because the same spreadsheets and scripts read both clients' output and an
    unquoted prompt containing a comma or a newline would silently shift every column
    after it.

    Two incidental bytes differ from the reference, both because this goes through the
    standard library rather than string concatenation, as ``docs/parity.md`` records: the
    header row is quoted too, and the file ends with a newline. Every CSV reader parses
    the two forms identically.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_ALL)
    writer.writerow(BULK_CSV_HEADER)
    for result in results:
        writer.writerow(
            [
                result.prompt,
                result.action,
                result.category,
                str(result.triggered).lower(),
                *(
                    str(result.detections.get(key) is True).lower()
                    for key in RUNTIME_DETECTION_KEYS
                ),
                result.scan_id,
                result.report_id,
                result.error or "",
            ]
        )
    return buffer.getvalue()


def render_bulk_summary(
    results: list[BulkScanResult], output_path: Path, title: str = "Bulk Scan Complete"
) -> None:
    """Summarise a finished bulk scan and say where the results landed.

    The output path is repeated here because a long run scrolls its own progress off the
    screen, and the file is the only thing worth keeping. ``title`` names the run, so a
    resumed one does not claim to have been a fresh scan.
    """
    blocked = sum(1 for result in results if result.action == "block")
    allowed = sum(1 for result in results if result.action == "allow")
    failed = sum(1 for result in results if result.action == "failed")

    ui.header(title)
    ui.key_value(
        [
            ("Total", len(results)),
            ("Blocked", f"[red]{blocked}[/red]"),
            ("Allowed", f"[green]{allowed}[/green]"),
            ("Failed", f"[red]{failed}[/red]"),
            ("Output", f"[cyan]{output_path}[/cyan]"),
        ]
    )


# ---------------------------------------------------------------------------
# Stored scan artefacts -- results by scan ID, reports by report ID
# ---------------------------------------------------------------------------

#: Columns for the machine-readable renderings of ``runtime results``.
SCAN_RESULT_COLUMNS: Final[list[Column]] = [
    Column("scan_id", "Scan ID"),
    Column("req_id", "Req ID"),
    Column("status", "Status"),
    Column("action", "Action"),
    Column("category", "Category"),
    Column("report_id", "Report ID"),
    Column("detections", "Detections"),
]

#: Columns for the machine-readable renderings of ``runtime reports``.
THREAT_REPORT_COLUMNS: Final[list[Column]] = [
    Column("report_id", "Report ID"),
    Column("scan_id", "Scan ID"),
    Column("req_id", "Req ID"),
    Column("detection_service", "Service"),
    Column("data_type", "Data Type"),
    Column("verdict", "Verdict"),
    Column("action", "Action"),
]

#: Inner table shown under each report in the pretty rendering.
DETECTION_COLUMNS: Final[list[Column]] = [
    Column("detection_service", "Service"),
    Column("data_type", "Data Type"),
    Column("verdict", "Verdict"),
    Column("action", "Action"),
]


def _request_label(req_id: float | None) -> str:
    """Render a request identifier, which arrives as a float but is always whole."""
    return "" if req_id is None else str(int(req_id))


def scan_id_result_rows(results: list[ScanIdResult]) -> list[dict[str, Any]]:
    """Flatten batch results to one row each.

    A single scan ID legitimately fans out to several rows -- one per request in the
    batch -- so the request ID travels with every row rather than being folded away.
    """
    rows: list[dict[str, Any]] = []
    for entry in results:
        verdict = entry.result
        rows.append(
            {
                "scan_id": entry.scan_id or (verdict.scan_id if verdict else ""),
                "req_id": _request_label(entry.req_id),
                "status": entry.status or "",
                "action": verdict.action if verdict else "",
                "category": verdict.category if verdict else "",
                "report_id": verdict.report_id if verdict else "",
                "detections": ", ".join(triggered_detections(verdict)) if verdict else "",
            }
        )
    return rows


def render_scan_id_results(results: list[ScanIdResult], console: Console) -> None:
    """Render batch results as one block per request.

    A row that is still running carries no verdict, so its status is shown alone rather
    than an empty verdict table that would read as "allowed".
    """
    for entry in results:
        request = _request_label(entry.req_id)
        suffix = f" -- request {request}" if request else ""
        ui.section(f"Scan {entry.scan_id or 'unknown'}{suffix}")
        ui.key_value([("Status", entry.status or "unknown")])
        if entry.result is not None:
            render_verdict(entry.result, console)


def threat_report_rows(reports: list[ThreatScanReport]) -> list[dict[str, Any]]:
    """Flatten threat reports to one row per detection service.

    A report with no detections still gets a row: "this report exists and found nothing"
    is an answer, and dropping it would make the report look like it was never returned.
    """
    rows: list[dict[str, Any]] = []
    for report in reports:
        shared = {
            "report_id": report.report_id or "",
            "scan_id": report.scan_id or "",
            "req_id": _request_label(report.req_id),
        }
        detections = report.detection_results or []
        if not detections:
            rows.append(
                {**shared, "detection_service": "", "data_type": "", "verdict": "", "action": ""}
            )
            continue
        for detection in detections:
            rows.append(
                {
                    **shared,
                    "detection_service": detection.detection_service or "",
                    "data_type": detection.data_type or "",
                    "verdict": detection.verdict or "",
                    "action": detection.action or "",
                }
            )
    return rows


def render_threat_reports(reports: list[ThreatScanReport]) -> None:
    """Render threat reports as a header block plus a table of detector findings."""
    for report in reports:
        ui.section(f"Report {report.report_id or 'unknown'}")
        pairs: list[tuple[str, Any]] = [
            (label, value)
            for label, value in (
                ("Scan ID", report.scan_id),
                ("Request", _request_label(report.req_id)),
                ("Transaction", report.transaction_id),
                ("Session", report.session_id),
            )
            if value
        ]
        if pairs:
            ui.key_value(pairs)

        detections = report.detection_results or []
        if not detections:
            ui.dim("no detection results in this report")
            continue
        ui.table(
            DETECTION_COLUMNS,
            [
                {
                    "detection_service": detection.detection_service or "",
                    "data_type": detection.data_type or "",
                    "verdict": detection.verdict or "",
                    "action": detection.action or "",
                }
                for detection in detections
            ],
        )
