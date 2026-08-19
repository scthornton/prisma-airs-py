"""Top-level Typer application.

Command placement follows the reference client exactly, which is not the same as following
each module's own structure. ``topics`` and ``dlp`` are implemented in their own modules
because they are large, but the reference nests them under ``runtime``, so that is where
they mount. Getting this wrong produces a CLI where every individual command works and no
documented invocation does.
"""

from __future__ import annotations

from typing import Annotated

import typer

from prisma_airs_cli import __version__
from prisma_airs_cli.commands.aigateway import aigateway_app
from prisma_airs_cli.commands.apikeys import apikeys_app, deployment_profiles_app
from prisma_airs_cli.commands.config import config_app
from prisma_airs_cli.commands.customerapps import customerapps_app, scanlogs_app
from prisma_airs_cli.commands.dlp import dlp_app
from prisma_airs_cli.commands.modelsecurity import modelsecurity_app
from prisma_airs_cli.commands.ops import backup, completion, doctor, restore
from prisma_airs_cli.commands.profiles import profiles_app
from prisma_airs_cli.commands.redteam import redteam_app
from prisma_airs_cli.commands.runtime import runtime_app
from prisma_airs_cli.commands.topics import topics_app

app = typer.Typer(
    name="airs",
    help="Command-line interface for Palo Alto Networks Prisma AIRS.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

# Everything the reference registers under `runtime`. These live in their own modules only
# because of their size; the command path is what has to match.
runtime_app.add_typer(apikeys_app)
runtime_app.add_typer(customerapps_app)
runtime_app.add_typer(deployment_profiles_app)
runtime_app.add_typer(profiles_app)
runtime_app.add_typer(scanlogs_app)
runtime_app.add_typer(topics_app)
runtime_app.add_typer(dlp_app)

app.add_typer(runtime_app)
app.add_typer(redteam_app)
app.add_typer(modelsecurity_app)
app.add_typer(aigateway_app)
app.add_typer(config_app)

# Registered individually rather than by merging the whole ops group, because that group
# also holds `profiles-cleanup`, which belongs under `runtime profiles`.
app.command("doctor")(doctor)
app.command("completion")(completion)

# Not in the reference's command surface -- its source defines them but `program.ts` never
# registers them. Exposed here as a deliberate addition; see commands/ops.py.
app.command("backup")(backup)
app.command("restore")(restore)


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
