"""Advisory lock preventing two bulk scans from sharing one state file.

Two processes resuming the same run would each read the same pending items and submit
them twice. The lock records the owning PID so a lock left behind by a crashed process
can be distinguished from one held by a process that is genuinely still working -- the
first is safe to break, the second very much is not.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Literal

LOCK_VERSION: Literal[1] = 1


class BulkScanLockError(RuntimeError):
    """The lock could not be acquired, or is unreadable."""


@dataclass(frozen=True)
class LockRecord:
    """Ownership details written into the lock file."""

    version: int
    pid: int
    created_at: str
    token: str

    def to_json(self) -> str:
        """Serialise for writing."""
        return json.dumps(
            {
                "version": self.version,
                "pid": self.pid,
                "createdAt": self.created_at,
                "token": self.token,
            }
        )


def parse_lock(raw: str, lock_path: Path) -> LockRecord:
    """Parse a lock file.

    Raises:
        BulkScanLockError: If the content is not a well-formed lock record. We refuse to
            reason about ownership we cannot read, rather than assuming it is stale.
    """
    advice = f"If no bulk-scan process is running, remove {lock_path} manually."
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as err:
        raise BulkScanLockError(f"Bulk-scan lock {lock_path} is malformed. {advice}") from err

    if not isinstance(value, dict):
        raise BulkScanLockError(f"Bulk-scan lock {lock_path} is malformed. {advice}")

    pid = value.get("pid")
    created_at = value.get("createdAt")
    token = value.get("token")
    if (
        value.get("version") != LOCK_VERSION
        or not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 0
        or not isinstance(created_at, str)
        or not isinstance(token, str)
        or not token
    ):
        raise BulkScanLockError(f"Bulk-scan lock {lock_path} has invalid ownership data. {advice}")

    return LockRecord(version=LOCK_VERSION, pid=pid, created_at=created_at, token=token)


def process_is_alive(pid: int) -> bool:
    """Report whether a process exists.

    Signal 0 performs the permission and existence checks without delivering anything.
    A ``PermissionError`` means the process exists but belongs to another user, which
    still counts as alive -- treating it as dead would break a lock someone is using.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class BulkScanLock:
    """Context manager holding the bulk-scan lock for a state file."""

    def __init__(self, state_path: Path, *, now: str) -> None:
        self.path = state_path.with_suffix(state_path.suffix + ".lock")
        self._token = uuid.uuid4().hex
        self._now = now
        self._held = False

    def acquire(self) -> BulkScanLock:
        """Take the lock, breaking it only if its owner is demonstrably gone.

        Raises:
            BulkScanLockError: If another live process holds it.
        """
        record = LockRecord(
            version=LOCK_VERSION, pid=os.getpid(), created_at=self._now, token=self._token
        )

        try:
            self._write_exclusive(record)
        except FileExistsError:
            existing = parse_lock(self.path.read_text(), self.path)
            if process_is_alive(existing.pid):
                raise BulkScanLockError(
                    f"Another bulk scan (pid {existing.pid}) is using this state file. "
                    f"Wait for it to finish, or remove {self.path} if that process is gone."
                ) from None
            # The owner died without cleaning up. Safe to take over.
            self.path.unlink(missing_ok=True)
            try:
                self._write_exclusive(record)
            except FileExistsError:
                raise BulkScanLockError(
                    f"Lost a race for {self.path}; another process took the lock first."
                ) from None

        self._held = True
        return self

    def release(self) -> None:
        """Release the lock, but only if we still own it.

        The token guards against releasing a lock that another process took over after
        deciding ours was stale.
        """
        if not self._held:
            return
        try:
            existing = parse_lock(self.path.read_text(), self.path)
        except (OSError, BulkScanLockError):
            self._held = False
            return
        if existing.token == self._token:
            self.path.unlink(missing_ok=True)
        self._held = False

    def _write_exclusive(self, record: LockRecord) -> None:
        """Create the lock file, failing if it already exists."""
        descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(record.to_json())

    def __enter__(self) -> BulkScanLock:
        """Acquire on entry."""
        return self.acquire()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Release on exit, including when the body raised."""
        self.release()
