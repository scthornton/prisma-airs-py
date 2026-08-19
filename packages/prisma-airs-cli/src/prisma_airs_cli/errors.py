"""Turning exceptions into the exit codes a pipeline gates on."""

from __future__ import annotations

import typer

from prisma_airs.errors import AISecSDKException
from prisma_airs_cli.exit_codes import EXIT_ERROR
from prisma_airs_cli.ui import ui


def usage_error(message: str) -> typer.Exit:
    """Report a bad invocation and build the exit to raise.

    Returns the exception rather than raising it, so call sites read ``raise
    usage_error(...)`` and static analysis can see the function never falls through.
    """
    ui.error(message)
    return typer.Exit(EXIT_ERROR)


def fail(err: Exception) -> typer.Exit:
    """Report an operation that could not complete and build the exit to raise.

    An SDK error carries a status code and a message the service supplied; both are shown,
    because "403" alone sends people to the wrong problem. Anything else is reported as-is
    rather than reformatted, since an unexpected exception type usually means a bug and the
    original text is the useful part.
    """
    if isinstance(err, AISecSDKException):
        ui.error(err.raw_message)
        if err.status_code is not None:
            ui.error(f"  HTTP {err.status_code}")
            ui.dim("  Re-run with --debug to capture the full API exchange.")
    else:
        ui.error(str(err))
    return typer.Exit(EXIT_ERROR)
