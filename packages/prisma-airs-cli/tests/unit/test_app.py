"""Smoke tests for the root Typer application."""

from __future__ import annotations

from typer.testing import CliRunner

import prisma_airs_cli
from prisma_airs_cli.app import app

runner = CliRunner()


def test_version_flag_reports_the_package_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert prisma_airs_cli.__version__ in result.output


def test_bare_invocation_shows_help_rather_than_erroring() -> None:
    """A bare `airs` should orient the user, not dump a traceback."""
    result = runner.invoke(app, [])

    assert "Usage" in result.output


def test_short_help_flag_is_accepted() -> None:
    result = runner.invoke(app, ["-h"])

    assert result.exit_code == 0
    assert "Usage" in result.output
