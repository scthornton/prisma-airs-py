"""Top-level Typer application.

Command groups are registered here as they are implemented. Keeping the root
application in its own module means subcommands can import it without dragging in
the console-script shim.
"""

from __future__ import annotations

from typing import Annotated

import typer

from prisma_airs_cli import __version__
from prisma_airs_cli.commands.config import config_app
from prisma_airs_cli.commands.runtime import runtime_app

app = typer.Typer(
    name="airs",
    help="Command-line interface for Palo Alto Networks Prisma AIRS.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

app.add_typer(runtime_app)
app.add_typer(config_app)


def _version_callback(value: bool) -> None:
    """Print the version and exit, when ``--version`` is supplied."""
    if value:
        typer.echo(f"airs {__version__}")
        raise typer.Exit


@app.callback()
def root(
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show the installed version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Secure AI applications with Prisma AIRS."""
