"""Bulk-scan state: invariants, persistence, and progress accounting."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from prisma_airs_cli.bulk.state import (
    BulkScanItemState,
    BulkScanItemStatus,
    BulkScanResult,
    BulkScanState,
    load_state,
    save_state,
)


def result(index: int = 0) -> BulkScanResult:
    return BulkScanResult(
        index=index,
        req_id=index,
        prompt="hi",
        scan_id="S1",
        report_id="R1",
        action="allow",
        category="benign",
        triggered=False,
        detections={},
    )


def item(
    index: int = 0, status: BulkScanItemStatus = BulkScanItemStatus.PENDING, **kw: Any
) -> BulkScanItemState:
    fields: dict[str, Any] = {"index": index, "req_id": index, "prompt": "hi", "status": status}
    fields.update(kw)
    return BulkScanItemState(**fields)


def state(items: list[BulkScanItemState] | None = None) -> BulkScanState:
    return BulkScanState(
        profile="prod",
        output_file="out.csv",
        batch_size=25,
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
        items=items if items is not None else [],
    )


class TestItemInvariants:
    """A state file decides what gets re-submitted, so it is validated on read."""

    def test_req_id_must_track_the_input_index(self) -> None:
        """Correlation is on req_id; letting it drift would misattribute verdicts."""
        with pytest.raises(ValidationError, match="req_id must match"):
            BulkScanItemState(index=3, req_id=4, prompt="hi", status=BulkScanItemStatus.PENDING)

    @pytest.mark.parametrize(
        "status",
        [BulkScanItemStatus.SUBMITTED, BulkScanItemStatus.COMPLETE, BulkScanItemStatus.FAILED],
    )
    def test_acknowledged_items_require_a_scan_id(self, status: BulkScanItemStatus) -> None:
        with pytest.raises(ValidationError, match="require a scan_id"):
            item(
                status=status,
                result=result() if status is not BulkScanItemStatus.SUBMITTED else None,
            )

    @pytest.mark.parametrize("status", [BulkScanItemStatus.COMPLETE, BulkScanItemStatus.FAILED])
    def test_terminal_items_require_a_result(self, status: BulkScanItemStatus) -> None:
        with pytest.raises(ValidationError, match="require a result"):
            item(status=status, scan_id="S1")

    def test_unfinished_items_cannot_carry_a_result(self) -> None:
        with pytest.raises(ValidationError, match="cannot carry a result"):
            item(status=BulkScanItemStatus.SUBMITTED, scan_id="S1", result=result())

    @pytest.mark.parametrize(
        "status",
        [BulkScanItemStatus.PENDING, BulkScanItemStatus.SUBMITTING, BulkScanItemStatus.AMBIGUOUS],
    )
    def test_unaccepted_items_cannot_carry_a_scan_id(self, status: BulkScanItemStatus) -> None:
        """A scan ID means the service accepted it, which contradicts these states."""
        with pytest.raises(ValidationError, match="cannot carry a scan_id"):
            item(status=status, scan_id="S1")

    def test_a_well_formed_complete_item_is_accepted(self) -> None:
        assert item(status=BulkScanItemStatus.COMPLETE, scan_id="S1", result=result()) is not None

    def test_ambiguous_is_a_valid_resting_state(self) -> None:
        """Submitted-but-unconfirmed is real and must be representable, not guessed at."""
        assert item(status=BulkScanItemStatus.AMBIGUOUS, error="connection reset") is not None


class TestStateInvariants:
    def test_rejects_out_of_order_items(self) -> None:
        with pytest.raises(ValidationError, match="out of order"):
            state([item(1), item(0)])

    def test_rejects_a_gap_in_indices(self) -> None:
        with pytest.raises(ValidationError, match="out of order"):
            state([item(0), item(2)])

    def test_rejects_a_zero_batch_size(self) -> None:
        with pytest.raises(ValidationError):
            BulkScanState(
                profile="p",
                output_file="o.csv",
                batch_size=0,
                created_at="t",
                updated_at="t",
            )


class TestProgress:
    def test_pending_items_are_returned_in_input_order(self) -> None:
        subject = state(
            [
                item(0, BulkScanItemStatus.COMPLETE, scan_id="S", result=result(0)),
                item(1),
                item(2),
            ]
        )

        assert [i.index for i in subject.pending_items()] == [1, 2]

    def test_counts_tally_every_status(self) -> None:
        subject = state([item(0), item(1, BulkScanItemStatus.AMBIGUOUS)])

        counts = subject.counts()
        assert counts["pending"] == 1
        assert counts["ambiguous"] == 1
        assert counts["complete"] == 0

    def test_is_complete_when_nothing_is_outstanding(self) -> None:
        subject = state([item(0, BulkScanItemStatus.COMPLETE, scan_id="S", result=result(0))])

        assert subject.is_complete()

    def test_ambiguous_does_not_block_completion(self) -> None:
        """It needs an operator's attention, but nothing further will happen on its own."""
        assert state([item(0, BulkScanItemStatus.AMBIGUOUS)]).is_complete()

    def test_pending_work_blocks_completion(self) -> None:
        assert not state([item(0)]).is_complete()


class TestPersistence:
    def test_a_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert load_state(tmp_path / "absent.json") is None

    def test_round_trips(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        original = state([item(0), item(1)])

        save_state(original, path)

        assert load_state(path) == original

    def test_writes_the_typescript_field_names(self, tmp_path: Path) -> None:
        """So a run can be resumed by either client."""
        path = tmp_path / "state.json"

        save_state(state([item(0)]), path)

        payload = json.loads(path.read_text())
        assert "batchSize" in payload
        assert "reqId" in payload["items"][0]

    def test_reads_the_typescript_field_names(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text(
            json.dumps(
                {
                    "version": 2,
                    "profile": "prod",
                    "outputFile": "out.csv",
                    "batchSize": 25,
                    "createdAt": "t",
                    "updatedAt": "t",
                    "items": [{"index": 0, "reqId": 0, "prompt": "hi", "status": "pending"}],
                }
            )
        )

        loaded = load_state(path)

        assert loaded is not None
        assert loaded.items[0].req_id == 0

    def test_restricts_permissions(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"

        save_state(state(), path)

        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_rejects_malformed_json(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text("{not json")

        with pytest.raises(ValueError, match="not valid JSON"):
            load_state(path)

    def test_rejects_a_state_that_violates_its_invariants(self, tmp_path: Path) -> None:
        """A hand-edited file must not resume into a duplicate scan."""
        path = tmp_path / "state.json"
        path.write_text(
            json.dumps(
                {
                    "version": 2,
                    "profile": "p",
                    "outputFile": "o.csv",
                    "batchSize": 1,
                    "createdAt": "t",
                    "updatedAt": "t",
                    "items": [{"index": 0, "reqId": 0, "prompt": "hi", "status": "complete"}],
                }
            )
        )

        with pytest.raises(ValidationError):
            load_state(path)

    def test_leaves_no_temporary_files_behind(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"

        save_state(state(), path)

        assert [p.name for p in tmp_path.iterdir()] == ["state.json"]

    def test_overwrites_a_previous_state(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        save_state(state([item(0)]), path)

        save_state(state([item(0), item(1)]), path)

        loaded = load_state(path)
        assert loaded is not None
        assert len(loaded.items) == 2
