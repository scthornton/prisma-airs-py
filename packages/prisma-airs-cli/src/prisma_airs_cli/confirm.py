"""Confirmation prompts for destructive commands."""

from __future__ import annotations

import sys
from collections.abc import Callable

import typer

from prisma_airs_cli.errors import usage_error
from prisma_airs_cli.exit_codes import EXIT_OK
from prisma_airs_cli.ui import ui


def confirm_or_abort(
    message: str,
    *,
    force: bool,
    action: str = "proceed",
    prompt: Callable[[str], bool] | None = None,
    is_tty: bool | None = None,
) -> None:
    """Ask before doing something destructive, or refuse to guess.

    Without a TTY there is nobody to ask, so this refuses rather than assuming yes. A CI
    job that meant to pass ``--force`` gets an error it can fix, instead of silently
    deleting something on the next run.

    Args:
        message: The question to put to the user.
        force: Skip the prompt entirely.
        action: Verb used in the non-interactive refusal message.
        prompt: Confirmation function, injectable for testing.
        is_tty: Override TTY detection, for testing.

    Raises:
        typer.Exit: With ``EXIT_ERROR`` when non-interactive and not forced, or with
            ``EXIT_OK`` when the user declines -- declining is a valid outcome, not a
            failure.
    """
    if force:
        return

    interactive = sys.stdin.isatty() if is_tty is None else is_tty
    if not interactive:
        raise usage_error(f"refusing to {action} without --force in non-interactive mode")

    ask = prompt if prompt is not None else (lambda text: typer.confirm(text, default=False))
    if not ask(message):
        ui.info("Aborted")
        raise typer.Exit(EXIT_OK)
