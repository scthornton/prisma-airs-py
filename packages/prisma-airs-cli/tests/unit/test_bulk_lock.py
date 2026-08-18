"""Bulk-scan lock: exclusion, stale takeover, and safe release."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from prisma_airs_cli.bulk.lock import (
    BulkScanLock,
    BulkScanLockError,
    LockRecord,
    parse_lock,
    process_is_alive,
)

NOW = "2026-01-01T00:00:00Z"

#: Above the usual pid_max, so no live process can hold it.
DEAD_PID = 4_194_303


@pytest.fixture
def state_path(tmp_path: Path) -> Path:
    return tmp_path / "state.json"


def write_lock(path: Path, *, pid: int, token: str = "other-token") -> None:
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.write_text(json.dumps({"version": 1, "pid": pid, "createdAt": NOW, "token": token}))


class TestProcessLiveness:
    def test_recognises_this_process(self) -> None:
        assert process_is_alive(os.getpid())

    def test_recognises_an_absent_process(self) -> None:
        if process_is_alive(DEAD_PID):
            pytest.skip("chosen sentinel pid is in use on this host")
        assert not process_is_alive(DEAD_PID)

    def test_treats_pid_one_as_alive(self) -> None:
        """Owned by another user, so signalling raises PermissionError -- still alive."""
        assert process_is_alive(1)


class TestParseLock:
    def test_reads_a_well_formed_record(self, tmp_path: Path) -> None:
        raw = json.dumps({"version": 1, "pid": 42, "createdAt": NOW, "token": "t"})

        assert parse_lock(raw, tmp_path / "l").pid == 42

    def test_rejects_malformed_json(self, tmp_path: Path) -> None:
        with pytest.raises(BulkScanLockError, match="malformed"):
            parse_lock("{nope", tmp_path / "l")

    @pytest.mark.parametrize(
        "payload",
        [
            {"version": 2, "pid": 1, "createdAt": NOW, "token": "t"},
            {"version": 1, "pid": 0, "createdAt": NOW, "token": "t"},
            {"version": 1, "pid": -1, "createdAt": NOW, "token": "t"},
            {"version": 1, "pid": True, "createdAt": NOW, "token": "t"},
            {"version": 1, "pid": 1, "createdAt": NOW, "token": ""},
            {"version": 1, "pid": 1, "createdAt": 5, "token": "t"},
            {"version": 1, "pid": 1, "createdAt": NOW},
        ],
    )
    def test_rejects_invalid_ownership_data(
        self, payload: dict[str, object], tmp_path: Path
    ) -> None:
        """We refuse to reason about ownership we cannot read, rather than assume stale."""
        with pytest.raises(BulkScanLockError, match="invalid ownership"):
            parse_lock(json.dumps(payload), tmp_path / "l")

    def test_the_error_says_how_to_recover(self, tmp_path: Path) -> None:
        with pytest.raises(BulkScanLockError, match="remove"):
            parse_lock("{nope", tmp_path / "l")


class TestAcquire:
    def test_creates_the_lock_file(self, state_path: Path) -> None:
        with BulkScanLock(state_path, now=NOW) as lock:
            assert lock.path.is_file()

    def test_records_this_process(self, state_path: Path) -> None:
        with BulkScanLock(state_path, now=NOW) as lock:
            assert json.loads(lock.path.read_text())["pid"] == os.getpid()

    def test_releases_on_exit(self, state_path: Path) -> None:
        with BulkScanLock(state_path, now=NOW) as lock:
            path = lock.path
        assert not path.exists()

    def test_releases_when_the_body_raises(self, state_path: Path) -> None:
        """An error mid-scan must not strand the lock and block every later run."""
        lock = BulkScanLock(state_path, now=NOW)
        with pytest.raises(RuntimeError), lock:
            raise RuntimeError("scan blew up")

        assert not lock.path.exists()

    def test_refuses_when_a_live_process_holds_it(self, state_path: Path) -> None:
        """Two resumers would each re-submit the same pending items."""
        write_lock(state_path, pid=os.getpid())

        with pytest.raises(BulkScanLockError, match="Another bulk scan"):
            BulkScanLock(state_path, now=NOW).acquire()

    def test_names_the_holding_process(self, state_path: Path) -> None:
        write_lock(state_path, pid=os.getpid())

        with pytest.raises(BulkScanLockError, match=str(os.getpid())):
            BulkScanLock(state_path, now=NOW).acquire()

    def test_takes_over_a_lock_whose_owner_died(self, state_path: Path) -> None:
        if process_is_alive(DEAD_PID):
            pytest.skip("chosen sentinel pid is in use on this host")
        write_lock(state_path, pid=DEAD_PID)

        with BulkScanLock(state_path, now=NOW) as lock:
            assert json.loads(lock.path.read_text())["pid"] == os.getpid()

    def test_refuses_a_lock_it_cannot_parse(self, state_path: Path) -> None:
        """Unreadable is not the same as stale, and must not be treated as such."""
        lock_path = state_path.with_suffix(state_path.suffix + ".lock")
        lock_path.write_text("garbage")

        with pytest.raises(BulkScanLockError, match="malformed"):
            BulkScanLock(state_path, now=NOW).acquire()


class TestRelease:
    def test_does_not_remove_a_lock_taken_over_by_someone_else(self, state_path: Path) -> None:
        """If our lock was judged stale and replaced, deleting it would strand them."""
        lock = BulkScanLock(state_path, now=NOW).acquire()
        write_lock(state_path, pid=os.getpid(), token="someone-elses-token")

        lock.release()

        assert lock.path.exists()

    def test_is_a_no_op_when_never_acquired(self, state_path: Path) -> None:
        BulkScanLock(state_path, now=NOW).release()

    def test_is_idempotent(self, state_path: Path) -> None:
        lock = BulkScanLock(state_path, now=NOW).acquire()

        lock.release()
        lock.release()

        assert not lock.path.exists()


class TestLockRecord:
    def test_serialises_the_typescript_field_names(self) -> None:
        payload = json.loads(LockRecord(version=1, pid=7, created_at=NOW, token="t").to_json())

        assert payload["createdAt"] == NOW
