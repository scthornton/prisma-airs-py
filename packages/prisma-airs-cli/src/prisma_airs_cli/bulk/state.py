"""Durable per-item state for resumable bulk scans.

A bulk scan of a large CSV can run for a long time and will occasionally be interrupted.
Restarting from the beginning is not merely slow -- it re-submits content that was already
scanned, which distorts usage and duplicates results. So progress is tracked per item and
persisted after every batch.

The field names on disk are the ones the TypeScript CLI writes, so a run started with
either client can be resumed by the other.
"""

from __future__ import annotations

import json
import os
import tempfile
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

STATE_VERSION: Literal[2] = 2


class BulkScanItemStatus(str, Enum):
    """Where one input row has got to.

    ``AMBIGUOUS`` is the one that matters. If a submission fails after the request left
    the machine, the service may or may not have accepted it. Marking such an item
    ``PENDING`` would risk a duplicate scan and ``FAILED`` would silently drop it, so it
    gets its own state and is surfaced to the operator rather than guessed at.
    """

    PENDING = "pending"
    SUBMITTING = "submitting"
    SUBMITTED = "submitted"
    COMPLETE = "complete"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"


#: Statuses that imply the service acknowledged the submission.
_REQUIRES_SCAN_ID = frozenset(
    {BulkScanItemStatus.SUBMITTED, BulkScanItemStatus.COMPLETE, BulkScanItemStatus.FAILED}
)
#: Statuses that imply a verdict was recorded.
_REQUIRES_RESULT = frozenset({BulkScanItemStatus.COMPLETE, BulkScanItemStatus.FAILED})
#: Statuses that mean nothing has been accepted yet.
_FORBIDS_SCAN_ID = frozenset(
    {BulkScanItemStatus.PENDING, BulkScanItemStatus.SUBMITTING, BulkScanItemStatus.AMBIGUOUS}
)


class BulkScanResult(BaseModel):
    """The recorded verdict for one input row."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    index: int = Field(ge=0)
    req_id: int = Field(ge=0, alias="reqId")
    prompt: str
    scan_id: str = Field(alias="scanId")
    report_id: str = Field(alias="reportId")
    action: Literal["allow", "block", "failed"]
    category: str
    triggered: bool
    detections: dict[str, bool] = Field(default_factory=dict)
    response: str | None = None
    error: str | None = None


class BulkScanItemState(BaseModel):
    """One input row's progress through the scan."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    index: int = Field(ge=0)
    req_id: int = Field(ge=0, alias="reqId")
    prompt: str
    status: BulkScanItemStatus
    scan_id: str | None = Field(default=None, alias="scanId", min_length=1)
    receipt_report_id: str | None = Field(default=None, alias="receiptReportId")
    result: BulkScanResult | None = None
    error: str | None = None

    @model_validator(mode="after")
    def _check_invariants(self) -> BulkScanItemState:
        """Reject states that cannot have arisen from a real run.

        A state file is read back and trusted to decide what to re-submit. If it has been
        hand-edited or half-written, failing loudly beats resuming into a duplicate scan.
        """
        if self.req_id != self.index:
            raise ValueError("req_id must match the stable input index")
        if self.status in _REQUIRES_SCAN_ID and not self.scan_id:
            raise ValueError(f"{self.status.value} entries require a scan_id")
        if self.status in _REQUIRES_RESULT and self.result is None:
            raise ValueError(f"{self.status.value} entries require a result")
        if self.status not in _REQUIRES_RESULT and self.result is not None:
            raise ValueError(f"{self.status.value} entries cannot carry a result")
        if self.status in _FORBIDS_SCAN_ID and self.scan_id:
            raise ValueError(f"{self.status.value} entries cannot carry a scan_id")
        return self


class BulkScanState(BaseModel):
    """The full resumable state of one bulk scan."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    version: Literal[2] = STATE_VERSION
    profile: str
    output_file: str = Field(alias="outputFile")
    batch_size: int = Field(ge=1, alias="batchSize")
    created_at: str = Field(alias="createdAt")
    updated_at: str = Field(alias="updatedAt")
    items: list[BulkScanItemState] = Field(default_factory=list)
    session_id: str | None = Field(default=None, alias="sessionId")

    @model_validator(mode="after")
    def _check_indices_are_contiguous(self) -> BulkScanState:
        """Item order carries meaning, so a gap or reordering is corruption."""
        for position, item in enumerate(self.items):
            if item.index != position:
                raise ValueError(
                    f"item at position {position} claims index {item.index}; "
                    "state file is out of order"
                )
        return self

    def pending_items(self) -> list[BulkScanItemState]:
        """Items still needing submission, in input order."""
        return [i for i in self.items if i.status is BulkScanItemStatus.PENDING]

    def counts(self) -> dict[str, int]:
        """Tally items by status, for progress reporting."""
        tally = dict.fromkeys((s.value for s in BulkScanItemStatus), 0)
        for item in self.items:
            tally[item.status.value] += 1
        return tally

    def is_complete(self) -> bool:
        """Whether every item has reached a terminal state."""
        return not any(
            i.status in {BulkScanItemStatus.PENDING, BulkScanItemStatus.SUBMITTING}
            for i in self.items
        )


def load_state(path: Path) -> BulkScanState | None:
    """Read a state file, or return ``None`` when there is none.

    Raises:
        ValueError: If the file exists but is unusable, since resuming from a state we
            cannot interpret risks re-scanning content that already went through.
    """
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError as err:
        raise ValueError(f"Bulk-scan state {path} is not valid JSON: {err}") from err
    return BulkScanState.model_validate(payload)


def save_state(state: BulkScanState, path: Path) -> None:
    """Write the state file atomically.

    Written to a sibling temporary file and renamed, so an interruption mid-write leaves
    the previous state intact rather than a truncated file that cannot be resumed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = state.model_dump_json(by_alias=True, indent=2)

    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - closed explicitly before rename
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        handle.write(payload + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()

    temporary = Path(handle.name)
    temporary.chmod(0o600)
    temporary.replace(path)
