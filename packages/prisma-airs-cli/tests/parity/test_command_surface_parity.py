"""The command tree must match the reference, path for path.

Every individual command can work while the CLI as a whole is still wrong, because what a
user types is a *path*: `airs runtime topics list`. A group mounted in the wrong place, or
not mounted at all, breaks every documented invocation without failing a single unit test.

Both trees are read from `--help` output rather than from source, so this compares what the
two programs actually expose.
"""

from __future__ import annotations

import re
import subprocess
from typing import Any

import pytest

pytestmark = pytest.mark.parity

#: Commands this port exposes that the reference does not. Each is a deliberate addition,
#: and listing it here is what keeps "deliberate" honest -- an accidental extra command
#: fails this test rather than quietly becoming surface we have to support.
DOCUMENTED_ADDITIONS: dict[str, set[str]] = {
    "": {
        # The reference's source defines these but its program.ts never registers them.
        "backup",
        "restore",
    },
    "runtime": {
        # Retrieval for asynchronously submitted scans. The SDK exposes the endpoints;
        # the reference has no command for them.
        "results",
        "reports",
    },
}

#: Command paths to compare. Each is walked in both clients.
PATHS = ["", "runtime", "runtime profiles", "runtime topics", "runtime api-keys", "config"]

_REFERENCE_COMMAND = re.compile(r"^ {2}([a-z][a-z0-9-]*)")
_PORT_COMMAND = re.compile(r"^\s*│\s+([a-z][a-z0-9-]*)")

#: Emitted by commander itself, not part of the surface under comparison.
_REFERENCE_NOISE = {"help"}


def _reference_commands(output: str) -> set[str]:
    """Parse the command names out of commander's --help output."""
    body = output.partition("Commands:")[2]
    return {m.group(1) for line in body.splitlines() if (m := _REFERENCE_COMMAND.match(line))} - (
        _REFERENCE_NOISE
    )


def _port_commands(output: str) -> set[str]:
    """Parse the command names out of Typer's boxed --help output."""
    body = output.partition("Commands")[2]
    return {m.group(1) for line in body.splitlines() if (m := _PORT_COMMAND.match(line))}


@pytest.mark.parametrize("path", PATHS)
class TestCommandTree:
    @staticmethod
    def _both(reference_cli: list[str], run_port: Any, path: str) -> tuple[set[str], set[str]]:
        args = [*path.split(), "--help"] if path else ["--help"]
        reference = subprocess.run(  # noqa: S603
            [*reference_cli, *args], capture_output=True, text=True, timeout=120, check=False
        )
        assert reference.returncode == 0, f"reference could not show help for {path!r}"
        ported = run_port(args)
        return _reference_commands(reference.stdout), _port_commands(ported.stdout)

    def test_no_reference_command_is_missing(
        self, reference_cli: list[str], run_port: Any, path: str
    ) -> None:
        """A missing command means a documented invocation does not work."""
        reference, ported = self._both(reference_cli, run_port, path)

        assert reference, f"parsed no commands from the reference at {path!r}"
        assert reference - ported == set()

    def test_no_undocumented_command_is_added(
        self, reference_cli: list[str], run_port: Any, path: str
    ) -> None:
        """Extra surface is a decision, so it has to be written down to pass."""
        reference, ported = self._both(reference_cli, run_port, path)

        assert ported - reference - DOCUMENTED_ADDITIONS.get(path, set()) == set()


def test_the_parsers_are_not_silently_returning_nothing(
    reference_cli: list[str], run_port: Any
) -> None:
    """Both parsers must actually find commands, or every comparison above is vacuous."""
    reference = subprocess.run(  # noqa: S603
        [*reference_cli, "--help"], capture_output=True, text=True, timeout=120, check=False
    )

    assert len(_reference_commands(reference.stdout)) >= 5
    assert len(_port_commands(run_port(["--help"]).stdout)) >= 5
