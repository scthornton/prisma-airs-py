"""``airs runtime`` -- scanning against a security profile."""

from __future__ import annotations

import csv
import io
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Final, Literal

import typer
from rich.console import Console

from prisma_airs import Scanner
from prisma_airs.constants import MAX_NUMBER_OF_BATCH_SCAN_OBJECTS
from prisma_airs.errors import AISecSDKException, FailureKind
from prisma_airs.models.scan import (
    AiProfile,
    AsyncScanObject,
    Content,
    ScanIdResult,
    ScanRequest,
    ScanResponse,
    ThreatScanReport,
)
from prisma_airs_cli.bulk.lock import BulkScanLock, BulkScanLockError
from prisma_airs_cli.bulk.state import (
    BulkScanItemState,
    BulkScanItemStatus,
    BulkScanResult,
    BulkScanState,
    load_state,
    save_state,
)
from prisma_airs_cli.config import default_config_path, load_config, resolve
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.exit_codes import EXIT_BLOCKED, EXIT_ERROR
from prisma_airs_cli.output import OutputFormat, format_output
from prisma_airs_cli.renderers.runtime import (
    RUNTIME_DETECTION_KEYS,
    SCAN_RESULT_COLUMNS,
    THREAT_REPORT_COLUMNS,
    bulk_results_csv,
    render_bulk_summary,
    render_scan_id_results,
    render_threat_reports,
    render_verdict,
    scan_id_result_rows,
    threat_report_rows,
)
from prisma_airs_cli.ui import ui

runtime_app = typer.Typer(
    name="runtime",
    help="Scan prompts and responses against a Prisma AIRS security profile.",
    no_args_is_help=True,
)


@runtime_app.command("scan")
def scan(
    prompt_argument: Annotated[
        str | None,
        typer.Argument(
            metavar="[PROMPT]",
            help="Prompt text to scan. Equivalent to --prompt, and the form the "
            "reference client uses.",
        ),
    ] = None,
    *,
    prompt: Annotated[
        str | None, typer.Option("--prompt", "-p", help="Prompt text to scan.")
    ] = None,
    response: Annotated[
        str | None, typer.Option("--response", "-r", help="Model response text to scan.")
    ] = None,
    prompt_file: Annotated[
        Path | None,
        typer.Option("--prompt-file", help="Read the prompt from a file.", exists=True),
    ] = None,
    context: Annotated[
        str | None, typer.Option("--context", help="Conversation context for the scan.")
    ] = None,
    profile: Annotated[str | None, typer.Option("--profile", help="Security profile name.")] = None,
    profile_id: Annotated[
        str | None, typer.Option("--profile-id", help="Security profile ID.")
    ] = None,
    region: Annotated[
        str | None, typer.Option("--region", help="Scan region: us, de, in, or sg.")
    ] = None,
    tr_id: Annotated[str | None, typer.Option("--tr-id", help="Transaction ID.")] = None,
    session_id: Annotated[str | None, typer.Option("--session-id", help="Session ID.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the raw verdict as JSON.")] = False,
) -> None:
    """Scan a single prompt or response.

    The prompt may be given as the argument or as `--prompt`; the two are the same thing,
    and supplying it twice is refused rather than one silently winning.

    Exits 0 when the verdict is `allow`, 1 when it is anything else, and 2 when the scan
    could not be completed -- so this drops into a CI pipeline without extra plumbing.
    """
    console = Console()
    errors = Console(stderr=True)

    sources = [source for source in (prompt_argument, prompt, prompt_file) if source is not None]
    if len(sources) > 1:
        raise usage_error("Give the prompt once: as the argument, --prompt, or --prompt-file.")

    if prompt_file is not None:
        prompt = prompt_file.read_text(encoding="utf-8")
    elif prompt is None:
        prompt = prompt_argument

    # The SDK requires something evaluable, and `--context` alone is not: it frames a
    # prompt rather than being one. Refusing here turns what would otherwise surface as a
    # pydantic traceback into the exit code and sentence a caller can act on.
    #
    # An empty prompt counts as nothing to scan, matching the reference, which rejects it
    # with the same "at least one of..." error rather than sending {"prompt": ""}.
    if not prompt and not response:
        errors.print(
            "[red]Nothing to scan.[/red] Pass a prompt (as the argument, --prompt, or "
            "--prompt-file) or --response. --context only accompanies one."
        )
        raise typer.Exit(EXIT_ERROR)

    config = load_config()
    resolved_profile = resolve("profile", profile, config=config)
    if not resolved_profile and not profile_id:
        errors.print(
            "[red]No profile.[/red] Pass --profile, or set one with "
            "[bold]airs config set profile <name>[/bold]."
        )
        raise typer.Exit(EXIT_ERROR)

    try:
        with Scanner(region=resolve("region", region, config=config)) as scanner:
            verdict = scanner.scan(
                prompt=prompt,
                response=response,
                context=context,
                profile_name=resolved_profile,
                profile_id=profile_id,
                tr_id=tr_id,
                session_id=session_id,
            )
    except AISecSDKException as err:
        errors.print(f"[red]Scan failed:[/red] {err.raw_message}")
        raise typer.Exit(EXIT_ERROR) from err

    if as_json:
        sys.stdout.write(verdict.model_dump_json(indent=2, exclude_none=True) + "\n")
    else:
        render_verdict(verdict, console)

    if verdict.action != "allow":
        raise typer.Exit(EXIT_BLOCKED)


# ---------------------------------------------------------------------------
# runtime bulk-scan
# ---------------------------------------------------------------------------

#: Prompts the asynchronous scan API accepts per request. ``--batch-size`` is a
#: checkpointing unit and may be larger; submission is always chunked down to this.
SDK_ASYNC_BATCH_SIZE: Final = MAX_NUMBER_OF_BATCH_SCAN_OBJECTS

#: Prompts per submit/poll cycle, matching the reference client's default.
DEFAULT_BATCH_SIZE: Final = 25

#: Seconds between polls of a submitted batch. Module level rather than a flag so it
#: matches the reference client, and so tests can shorten it.
POLL_INTERVAL_SECONDS: float = 5.0

#: Consecutive polls resolving nothing before the run gives up -- ten minutes at the
#: default interval. Without a ceiling a batch the service silently dropped would poll
#: forever, holding the lock and looking like progress.
MAX_NO_PROGRESS_POLLS: int = 120

#: Result statuses that will not change again.
_TERMINAL_STATUSES: Final = frozenset({"complete", "completed", "failed"})

#: Detection-service names as threat reports spell them, mapped onto the prompt-side flag
#: names used everywhere else. The service abbreviates some services and not others.
_REPORT_DETECTION_KEYS: Final[dict[str, str]] = {
    "topic_guardrails": "topic_violation",
    "topic_violation": "topic_violation",
    "pi": "injection",
    "prompt_injection": "injection",
    "injection": "injection",
    "tc": "toxic_content",
    "toxic_content": "toxic_content",
    "dlp": "dlp",
    "uf": "url_cats",
    "url_filtering": "url_cats",
    "url_cats": "url_cats",
    "mc": "malicious_code",
    "malicious_code": "malicious_code",
    "source_code": "source_code",
    "agent": "agent",
}

#: Verdict words a detector uses to say it fired.
_FIRING_VERDICTS: Final = frozenset({"malicious", "unsafe", "violation", "detected"})

#: The 4xx range, which is the only proof a submission was rejected outright.
_CLIENT_ERROR_RANGE: Final = range(400, 500)

#: Verdict values the durable result record accepts.
_Verdict = Literal["allow", "block", "failed"]


def _timestamp() -> str:
    """Return the current time as the ISO-8601 UTC string the state file stores."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _csv_prompts(text: str) -> list[str]:
    """Extract the ``prompt`` column from CSV text.

    Raises:
        typer.Exit: If there is no ``prompt`` column. Scanning the first column instead
            would quietly submit whatever else the file happens to hold.
    """
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return []
    header = [cell.strip().lower() for cell in rows[0]]
    if "prompt" not in header:
        raise usage_error('No "prompt" column found in CSV header')
    column = header.index("prompt")
    return [row[column].strip() for row in rows[1:] if len(row) > column and row[column].strip()]


def _read_prompts(path: Path) -> list[str]:
    """Read prompts from a ``.csv`` file or a newline-delimited text file.

    Raises:
        typer.Exit: If the file yields no prompts. Submitting nothing and reporting
            success would look identical to a run whose input path was wrong.
    """
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".csv":
        prompts = _csv_prompts(text)
    else:
        prompts = [line.strip() for line in text.splitlines() if line.strip()]
    if not prompts:
        raise usage_error("No prompts found in input file")
    return prompts


def _state_directory() -> Path:
    """Return where resumable bulk-scan state lives -- beside the config, not in the cwd."""
    return default_config_path().parent / "bulk-scans"


def _state_path(created_at: str) -> Path:
    """Build a unique state file name that sorts by start time."""
    stamp = created_at.replace(":", "-").replace(".", "-")
    return _state_directory() / f"{stamp}-{uuid.uuid4()}.bulk-scan.json"


def _write_results_csv(path: Path, results: list[BulkScanResult]) -> None:
    """Write the results CSV atomically, readable only by its owner.

    The file is rewritten after every batch, which is exactly when somebody is tailing
    it, so it goes to a temporary sibling and is renamed into place -- a reader sees the
    previous complete file or the new one, never half of either.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(bulk_results_csv(results))
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _definitely_rejected(err: AISecSDKException) -> bool:
    """Report whether a submission provably never reached the scanner.

    Only a 4xx response proves the batch was rejected outright and nothing was queued.
    A timeout or a 5xx leaves the outcome unknown, and re-submitting on that guess would
    scan the same content twice.
    """
    return (
        err.failure_kind is FailureKind.HTTP
        and err.status_code is not None
        and err.status_code in _CLIENT_ERROR_RANGE
    )


def _detections(response: ScanResponse) -> dict[str, bool]:
    """Collect the prompt-side detector flags as a plain mapping."""
    detected = response.prompt_detected.model_dump() if response.prompt_detected else {}
    return {
        key: bool(detected[key])
        for key in RUNTIME_DETECTION_KEYS
        if isinstance(detected.get(key), bool)
    }


def _failure_reason(response: ScanResponse) -> str:
    """Explain why a verdict counts as a failure, preferring the service's own words."""
    detail = "; ".join(
        part
        for part in (
            ": ".join(filter(None, (err.feature, err.status, err.content_type)))
            for err in response.errors
        )
        if part
    )
    if detail:
        return detail
    return "AIRS scan timed out" if response.timeout else "AIRS scan failed"


def _result_from_response(response: ScanResponse, item: BulkScanItemState) -> BulkScanResult:
    """Turn one verdict into the durable per-prompt record.

    A timeout or a partial error is recorded as ``failed`` rather than as its nominal
    action: a scan that did not finish must never be filed away as an allow.
    """
    detections = _detections(response)
    action = response.action.lower()
    verdict: _Verdict
    if response.error or response.timeout or action not in ("allow", "block"):
        verdict = "failed"
    else:
        verdict = "block" if action == "block" else "allow"

    return BulkScanResult(
        index=item.index,
        req_id=item.req_id,
        prompt=item.prompt,
        scan_id=item.scan_id or response.scan_id,
        report_id=response.report_id,
        action=verdict,
        category="error" if verdict == "failed" else response.category,
        triggered=any(detections.values()),
        detections=detections,
        error=_failure_reason(response) if verdict == "failed" else None,
    )


def _failed_result(
    item: BulkScanItemState, error: str = "AIRS async scan failed"
) -> BulkScanResult:
    """Record a prompt the service could not scan, keeping its text and position."""
    return BulkScanResult(
        index=item.index,
        req_id=item.req_id,
        prompt=item.prompt,
        scan_id=item.scan_id or "",
        report_id="",
        action="failed",
        category="error",
        triggered=False,
        detections={},
        error=error,
    )


def _result_from_report(report: ThreatScanReport, item: BulkScanItemState) -> BulkScanResult:
    """Reconstruct a verdict from a threat report.

    The results endpoint sometimes returns a single terminal row for a whole batch with
    no request ID on it. The threat report is then the only per-request record there is,
    so the verdict is reassembled from the detectors rather than the prompt being dropped.
    """
    detections: dict[str, bool] = {}
    saw_block = False
    unexpected: str | None = None

    for detection in report.detection_results or []:
        service = (detection.detection_service or "").lower()
        action = (detection.action or "").lower()
        fired = action == "block" or (detection.verdict or "").lower() in _FIRING_VERDICTS
        key = _REPORT_DETECTION_KEYS.get(service, service) or ("unknown" if fired else "")
        if key:
            detections[key] = detections.get(key, False) or fired
        if action == "block":
            saw_block = True
        elif action and action != "allow":
            unexpected = action

    verdict: _Verdict = "block" if saw_block else ("failed" if unexpected else "allow")
    triggered = any(detections.values())
    return BulkScanResult(
        index=item.index,
        req_id=item.req_id,
        prompt=item.prompt,
        scan_id=item.scan_id or "",
        report_id=report.report_id or "",
        action=verdict,
        category="error" if verdict == "failed" else ("malicious" if triggered else "benign"),
        triggered=triggered,
        detections=detections,
        error=(
            f"Unknown AIRS action in threat report: {unexpected}" if verdict == "failed" else None
        ),
    )


def _submitted_groups(items: list[BulkScanItemState]) -> list[list[BulkScanItemState]]:
    """Group submitted items by the scan ID their receipt carried.

    One receipt covers up to twenty prompts, and results are correlated on
    ``(scan_id, req_id)``, so the group is the unit that gets polled.
    """
    grouped: dict[str, list[BulkScanItemState]] = {}
    for item in items:
        if item.status is BulkScanItemStatus.SUBMITTED and item.scan_id:
            grouped.setdefault(item.scan_id, []).append(item)
    return list(grouped.values())


class _BulkScanJob:
    """One bulk-scan run: submit in chunks, poll for verdicts, checkpoint throughout.

    Every state transition is written to disk before and after the call that causes it,
    so an interruption leaves a state file that says exactly what was in flight.
    """

    def __init__(
        self,
        scanner: Scanner,
        state: BulkScanState,
        state_path: Path,
        output_path: Path,
    ) -> None:
        self._scanner = scanner
        self._state = state
        self._state_path = state_path
        self._output_path = output_path

    def run(self) -> None:
        """Submit and poll every prompt, one ``--batch-size`` batch at a time."""
        items = self._state.items
        size = self._state.batch_size
        for start in range(0, len(items), size):
            batch = items[start : start + size]
            ui.status(f"Submitting batch {start // size + 1}...")
            self._submit_all(batch)
            ui.status(f"Scan IDs saved: {self._state_path}")
            self._drain(batch)

    def resume(self) -> None:
        """Finish a run that was interrupted, one ``batch_size`` batch at a time.

        Each batch is drained before anything new goes out, so a prompt whose receipt is
        already on disk is collected rather than scanned a second time; only prompts that
        are still ``pending`` -- provably never accepted -- are submitted.
        """
        items = self._state.items
        size = self._state.batch_size
        for start in range(0, len(items), size):
            batch = items[start : start + size]
            self._drain(batch)
            unsent = [item for item in batch if item.status is BulkScanItemStatus.PENDING]
            if unsent:
                ui.status(f"Submitting {len(unsent)} unsent prompt(s)...")
                self._submit_all(unsent)
                ui.status(f"Scan IDs saved: {self._state_path}")
            self._drain(batch)

    def drain(self) -> None:
        """Collect verdicts for everything already submitted, sending nothing new."""
        self._drain(self._state.items)

    def completed(self) -> list[BulkScanResult]:
        """Return every verdict recorded so far, in input order."""
        return [item.result for item in self._state.items if item.result is not None]

    def _submit_all(self, items: list[BulkScanItemState]) -> None:
        """Submit every item, chunked down to what one API request accepts."""
        for offset in range(0, len(items), SDK_ASYNC_BATCH_SIZE):
            self._submit(items[offset : offset + SDK_ASYNC_BATCH_SIZE])

    def _drain(self, items: list[BulkScanItemState]) -> None:
        """Poll each outstanding receipt among ``items`` until its requests are terminal."""
        for group in _submitted_groups(items):
            self._poll(group)

    def _submit(self, chunk: list[BulkScanItemState]) -> None:
        """Submit one SDK-sized chunk, recording the outcome on both sides of the call."""
        for item in chunk:
            item.status = BulkScanItemStatus.SUBMITTING
        self._save()

        try:
            receipt = self._scanner.async_scan(
                [
                    AsyncScanObject(
                        req_id=item.index,
                        scan_req=ScanRequest(
                            ai_profile=AiProfile(profile_name=self._state.profile),
                            contents=[Content(prompt=item.prompt)],
                            session_id=self._state.session_id,
                        ),
                    )
                    for item in chunk
                ]
            )
        except AISecSDKException as err:
            rejected = _definitely_rejected(err)
            for item in chunk:
                item.status = (
                    BulkScanItemStatus.PENDING if rejected else BulkScanItemStatus.AMBIGUOUS
                )
                item.error = err.raw_message
            self._save()
            raise

        for item in chunk:
            item.status = BulkScanItemStatus.SUBMITTED
            item.scan_id = receipt.scan_id
            item.receipt_report_id = receipt.report_id
            item.error = None
        self._save()

    def _poll(self, group: list[BulkScanItemState]) -> None:
        """Poll one receipt until every request under it is terminal.

        Raises:
            TimeoutError: If the service stops resolving requests. Failing is better than
                holding the lock forever on a batch that will never complete.
        """
        scan_id = group[0].scan_id or ""
        pending = {item.req_id: item for item in group if item.result is None}
        no_progress = 0

        while pending:
            outstanding = len(pending)
            report_ids = self._absorb_rows(self._scanner.query_by_scan_ids([scan_id]), pending)
            if report_ids:
                self._absorb_reports(report_ids, pending)

            if len(pending) < outstanding:
                no_progress = 0
                self._checkpoint()
            else:
                no_progress += 1
                if no_progress >= MAX_NO_PROGRESS_POLLS:
                    raise TimeoutError(
                        f"Scan {scan_id} resolved nothing in {no_progress} polls; "
                        f"{len(pending)} prompt(s) are still outstanding."
                    )
            if pending:
                time.sleep(POLL_INTERVAL_SECONDS)

    def _absorb_rows(
        self, rows: list[ScanIdResult], pending: dict[int, BulkScanItemState]
    ) -> set[str]:
        """Record every terminal row, returning report IDs that still need a lookup."""
        report_ids: set[str] = set()
        for row in rows:
            status = (row.status or "").lower()
            if status not in _TERMINAL_STATUSES:
                continue
            if row.req_id is None:
                report_ids |= self._absorb_batch_row(row, pending, status)
                continue
            item = pending.get(int(row.req_id))
            if item is None:
                continue
            if status == "failed":
                self._record(item, pending, _failed_result(item))
            elif row.result is not None:
                self._record(item, pending, _result_from_response(row.result, item))
        return report_ids

    def _absorb_batch_row(
        self, row: ScanIdResult, pending: dict[int, BulkScanItemState], status: str
    ) -> set[str]:
        """Handle a terminal row that names no request, and so speaks for the whole batch.

        Raises:
            ValueError: If a completed batch row carries no report ID. There is then no
                way to correlate a verdict back to a prompt, and attaching the wrong
                verdict to the wrong text is worse than stopping.
        """
        if status == "failed":
            for item in list(pending.values()):
                self._record(item, pending, _failed_result(item))
            return set()

        report_id = (row.result.report_id if row.result else None) or next(
            (item.receipt_report_id for item in pending.values() if item.receipt_report_id),
            None,
        )
        if not report_id:
            raise ValueError(
                f"Scan {row.scan_id} returned a terminal row with neither a request nor a "
                "report ID; its verdicts cannot be correlated to prompts."
            )
        return {report_id}

    def _absorb_reports(self, report_ids: set[str], pending: dict[int, BulkScanItemState]) -> None:
        """Resolve outstanding prompts from their threat reports."""
        for report in self._scanner.query_by_report_ids(sorted(report_ids)):
            if report.req_id is None:
                continue
            item = pending.get(int(report.req_id))
            if item is not None:
                self._record(item, pending, _result_from_report(report, item))

    def _record(
        self,
        item: BulkScanItemState,
        pending: dict[int, BulkScanItemState],
        result: BulkScanResult,
    ) -> None:
        """Attach a verdict to its prompt and drop it from the outstanding set."""
        item.result = result
        item.status = (
            BulkScanItemStatus.FAILED if result.action == "failed" else BulkScanItemStatus.COMPLETE
        )
        item.error = result.error
        pending.pop(item.req_id, None)

    def _save(self) -> None:
        """Persist the state file."""
        self._state.updated_at = _timestamp()
        save_state(self._state, self._state_path)

    def _checkpoint(self) -> None:
        """Persist the state file and rewrite the results CSV."""
        self._save()
        _write_results_csv(self._output_path, self.completed())


def _announce(state: BulkScanState, state_path: Path) -> None:
    """Report what the run is about to do, on stderr so piped output stays clean."""
    batches = (len(state.items) + state.batch_size - 1) // state.batch_size
    ui.status("Prisma AIRS Bulk Scan")
    ui.status(f"Profile:  {state.profile}")
    ui.status(f"Session:  {state.session_id}")
    ui.status(f"Prompts:  {len(state.items)}")
    ui.status(f"Batches:  {batches} (size {state.batch_size})")
    ui.status(f"State:    {state_path}")


def _announce_resume(state: BulkScanState, state_path: Path) -> None:
    """Report what is left to do before a resumed run touches the network."""
    scan_ids = {item.scan_id for item in state.items if item.scan_id}
    unsent = sum(1 for item in state.items if item.status is BulkScanItemStatus.PENDING)
    ui.status("Prisma AIRS Resume Poll")
    ui.status(f"Profile:  {state.profile}")
    ui.status(f"Scan IDs: {len(scan_ids)}")
    ui.status(f"Prompts:  {len(state.items)} ({unsent} never submitted)")
    ui.status(f"State:    {state_path}")


def _finish(results: list[BulkScanResult], output_path: Path, title: str) -> None:
    """Summarise a finished run and gate on whether anything failed to scan.

    Raises:
        typer.Exit: With :data:`EXIT_BLOCKED` if any prompt failed. The results that did
            land have already been written, so the exit reports an incomplete run rather
            than discarding one.
    """
    render_bulk_summary(results, output_path, title)
    failed = sum(1 for result in results if result.action == "failed")
    if failed:
        ui.error(f"{failed} prompt(s) failed; successful results were preserved.")
        raise typer.Exit(EXIT_BLOCKED)


@runtime_app.command("bulk-scan")
def bulk_scan(
    *,
    profile: Annotated[str, typer.Option("--profile", help="Security profile name.")],
    file: Annotated[
        Path,
        typer.Option(
            "--file",
            help="Input file -- .csv (reads the prompt column) or .txt (one per line).",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    output_file: Annotated[
        Path | None, typer.Option("--output-file", help="Output CSV file path.")
    ] = None,
    session_id: Annotated[
        str | None,
        typer.Option("--session-id", help="Session ID for grouping scans in the AIRS dashboard."),
    ] = None,
    batch_size: Annotated[
        int, typer.Option("--batch-size", help="Prompts per sequential submit/poll batch.")
    ] = DEFAULT_BATCH_SIZE,
) -> None:
    """Scan many prompts at once through the asynchronous scan API.

    Progress is checkpointed to a state file and the results CSV is rewritten after every
    batch, so an interrupted run keeps everything it had already scanned.

    Exits 1 when any prompt failed to scan -- the results that did land are still written
    -- and 2 when the run could not proceed at all.
    """
    if batch_size < 1:
        raise usage_error("--batch-size must be a positive integer")

    config = load_config()
    created_at = _timestamp()
    # Whitespace in a profile name would make the default file awkward to handle in a
    # shell, so it collapses to hyphens -- the reference client does the same.
    slug = re.sub(r"\s+", "-", profile)
    output_path = (output_file or Path(f"{slug}-bulk-scan.csv")).resolve()
    results: list[BulkScanResult] = []

    try:
        prompts = _read_prompts(file)
        state = BulkScanState(
            profile=profile,
            session_id=session_id or f"prisma-airs-cli-bulk-{uuid.uuid4().hex[:12]}",
            output_file=str(output_path),
            batch_size=batch_size,
            created_at=created_at,
            updated_at=created_at,
            items=[
                BulkScanItemState(
                    index=index, req_id=index, prompt=prompt, status=BulkScanItemStatus.PENDING
                )
                for index, prompt in enumerate(prompts)
            ],
        )
        state_path = _state_path(created_at)
        save_state(state, state_path)

        # The lock is taken before the first submission and held for the whole run: two
        # processes sharing a state file would each re-submit the other's pending items.
        with BulkScanLock(state_path, now=created_at):
            _write_results_csv(output_path, results)
            _announce(state, state_path)
            with Scanner(region=resolve("region", None, config=config)) as scanner:
                job = _BulkScanJob(scanner, state, state_path, output_path)
                job.run()
                results = job.completed()
            _write_results_csv(output_path, results)
    except (AISecSDKException, BulkScanLockError, OSError, TimeoutError, ValueError) as err:
        raise fail(err) from err

    _finish(results, output_path, "Bulk Scan Complete")


@runtime_app.command("resume-poll")
def resume_poll(
    state_file: Annotated[
        Path,
        typer.Argument(
            metavar="STATE_FILE", help="State file written by an interrupted bulk scan."
        ),
    ],
    *,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", help="Output CSV file path, overriding the recorded one."),
    ] = None,
) -> None:
    """Finish a bulk scan that was interrupted, without re-scanning what it already did.

    Prompts whose receipt is on file are collected rather than submitted again, and only
    prompts the service provably never accepted are sent. If any prompt's fate is unknown
    -- the submission failed in a way that could still have been queued -- nothing is
    re-submitted at all: the verdicts that had already landed are written and the run
    stops, because a duplicate scan is not something a later run can undo.

    Exits 1 when any prompt failed to scan, and 2 when the run could not proceed.
    """
    config = load_config()
    path = state_file.resolve()
    if not path.is_file():
        raise usage_error(f"No bulk-scan state file at {path}")

    results: list[BulkScanResult] = []
    try:
        # The lock is taken before the state is read: another resume already working this
        # file would otherwise be re-submitting the very prompts we are about to read.
        with BulkScanLock(path, now=_timestamp()):
            state = load_state(path)
            if state is None:
                raise ValueError(f"Bulk-scan state {path} disappeared while it was being opened")

            unresolved = next(
                (
                    item
                    for item in state.items
                    if item.status in (BulkScanItemStatus.SUBMITTING, BulkScanItemStatus.AMBIGUOUS)
                ),
                None,
            )
            output_path = (output_file or Path(state.output_file)).resolve()
            state.output_file = str(output_path)
            state.updated_at = _timestamp()
            save_state(state, path)

            with Scanner(region=resolve("region", None, config=config)) as scanner:
                job = _BulkScanJob(scanner, state, path, output_path)
                if unresolved is not None:
                    job.drain()
                    _write_results_csv(output_path, job.completed())
                    raise ValueError(
                        f"Cannot safely resubmit prompt {unresolved.index}: its submission "
                        f"outcome is unknown. Verdicts that had already landed were kept in "
                        f"{output_path}; inspect {path} before taking manual action."
                    )
                _announce_resume(state, path)
                job.resume()
                results = job.completed()
            _write_results_csv(output_path, results)
    except (AISecSDKException, BulkScanLockError, OSError, TimeoutError, ValueError) as err:
        raise fail(err) from err

    _finish(results, output_path, "Resume Poll Complete")


# ---------------------------------------------------------------------------
# runtime results / reports -- retrieving what an asynchronous scan produced
# ---------------------------------------------------------------------------


@runtime_app.command("results")
def results(
    *,
    scan_id: Annotated[
        list[str],
        typer.Option("--scan-id", help="Scan ID to fetch. Repeat for up to five."),
    ],
    region: Annotated[
        str | None, typer.Option("--region", help="Scan region: us, de, in, or sg.")
    ] = None,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """Fetch the verdicts for scans that were submitted asynchronously.

    One scan ID covers a whole submitted batch and returns one row per request in it, so
    the request ID is shown alongside every verdict.

    Exits 1 if any completed verdict is not `allow`, so a submit-now-collect-later
    pipeline gates exactly as `runtime scan` does, and 2 if the lookup itself failed.
    """
    config = load_config()
    try:
        with Scanner(region=resolve("region", region, config=config)) as scanner:
            rows = scanner.query_by_scan_ids(scan_id)
    except AISecSDKException as err:
        raise fail(err) from err

    if not rows:
        ui.empty_list("scan results")
        return

    if output is OutputFormat.PRETTY:
        render_scan_id_results(rows, Console())
    else:
        rendered = format_output(scan_id_result_rows(rows), SCAN_RESULT_COLUMNS, output)
        sys.stdout.write(rendered + "\n")

    if any(row.result is not None and row.result.action != "allow" for row in rows):
        raise typer.Exit(EXIT_BLOCKED)


@runtime_app.command("reports")
def reports(
    *,
    report_id: Annotated[
        list[str],
        typer.Option("--report-id", help="Report ID to fetch. Repeat for up to five."),
    ],
    region: Annotated[
        str | None, typer.Option("--region", help="Scan region: us, de, in, or sg.")
    ] = None,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """Fetch the detailed threat reports behind one or more scans.

    A report exists whether or not the content was blocked -- it is the forensic detail,
    not the verdict -- so this is a lookup rather than a gate: it exits 0 on success and 2
    when the lookup failed. Use `runtime results` when a pipeline needs to gate.
    """
    config = load_config()
    try:
        with Scanner(region=resolve("region", region, config=config)) as scanner:
            fetched = scanner.query_by_report_ids(report_id)
    except AISecSDKException as err:
        raise fail(err) from err

    if not fetched:
        ui.empty_list("threat reports")
        return

    if output is OutputFormat.PRETTY:
        render_threat_reports(fetched)
    else:
        rendered = format_output(threat_report_rows(fetched), THREAT_REPORT_COLUMNS, output)
        sys.stdout.write(rendered + "\n")
