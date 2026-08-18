"""Terminal rendering for runtime scan verdicts."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from prisma_airs.models.scan import ScanResponse

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
