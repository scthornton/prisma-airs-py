"""Shared fixtures for the CLI test suite.

Terminal width is pinned here. Typer renders usage and error text through Rich, which wraps
to the width it believes the terminal has. Click's ``CliRunner`` isolates the environment
and forces 80 columns, so a message that reads fine on a developer's wide terminal arrives
in CI wrapped mid-phrase -- and a test asserting that a flag name or a sentence appears in
the output fails for a reason unrelated to the code under test.

Setting the width on the shared consoles is what actually takes effect, because that is
where this CLI's output is rendered; the environment variables are belt and braces for any
console constructed later.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from prisma_airs_cli.ui import ui

#: Wide enough that no message this CLI emits wraps.
TEST_TERMINAL_WIDTH = 200


@pytest.fixture(autouse=True)
def _deterministic_terminal(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Render CLI output at a fixed, generous width regardless of the host terminal."""
    monkeypatch.setenv("COLUMNS", str(TEST_TERMINAL_WIDTH))
    monkeypatch.setenv("LINES", "50")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("TERM", "dumb")

    original = (ui.out.width, ui.err.width)
    ui.out.width = TEST_TERMINAL_WIDTH
    ui.err.width = TEST_TERMINAL_WIDTH
    try:
        yield
    finally:
        ui.out.width, ui.err.width = original
