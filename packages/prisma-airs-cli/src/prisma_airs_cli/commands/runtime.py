"""``airs runtime`` -- scanning against a security profile."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from prisma_airs import Scanner
from prisma_airs.errors import AISecSDKException
from prisma_airs_cli.config import load_config, resolve
from prisma_airs_cli.renderers.runtime import render_verdict

runtime_app = typer.Typer(
    name="runtime",
    help="Scan prompts and responses against a Prisma AIRS security profile.",
    no_args_is_help=True,
)

#: Returned when a scan resolves to anything other than `allow`, so the command composes
#: into a pipeline: a blocked prompt should fail the build.
EXIT_BLOCKED = 1
#: Returned when the scan could not be completed at all.
EXIT_ERROR = 2


@runtime_app.command("scan")
def scan(
    *,
    prompt: Annotated[
        str | None, typer.Option("--prompt", "-p", help="Prompt text to scan.")
    ] = None,
    response: Annotated[
        str | None, typer.Option("--response", "-r", help="Model response text to scan.")
    ] = None,
    prompt_file: Annotated[
        Path | None,
        typer.Option("--prompt-file", help="Read the prompt from a file.", exists=True),
    ] = None,
    context: Annotated[
        str | None, typer.Option("--context", help="Conversation context for the scan.")
    ] = None,
    profile: Annotated[str | None, typer.Option("--profile", help="Security profile name.")] = None,
    profile_id: Annotated[
        str | None, typer.Option("--profile-id", help="Security profile ID.")
    ] = None,
    region: Annotated[
        str | None, typer.Option("--region", help="Scan region: us, de, in, or sg.")
    ] = None,
    tr_id: Annotated[str | None, typer.Option("--tr-id", help="Transaction ID.")] = None,
    session_id: Annotated[str | None, typer.Option("--session-id", help="Session ID.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit the raw verdict as JSON.")] = False,
) -> None:
    """Scan a single prompt or response.

    Exits 0 when the verdict is `allow`, 1 when it is anything else, and 2 when the scan
    could not be completed -- so this drops into a CI pipeline without extra plumbing.
    """
    console = Console()
    errors = Console(stderr=True)

    if prompt_file is not None:
        prompt = prompt_file.read_text()

    if not any((prompt, response, context)):
        errors.print("[red]Nothing to scan.[/red] Pass --prompt, --response, or --prompt-file.")
        raise typer.Exit(EXIT_ERROR)

    config = load_config()
    resolved_profile = resolve("profile", profile, config=config)
    if not resolved_profile and not profile_id:
        errors.print(
            "[red]No profile.[/red] Pass --profile, or set one with "
            "[bold]airs config set profile <name>[/bold]."
        )
        raise typer.Exit(EXIT_ERROR)

    try:
        with Scanner(region=resolve("region", region, config=config)) as scanner:
            verdict = scanner.scan(
                prompt=prompt,
                response=response,
                context=context,
                profile_name=resolved_profile,
                profile_id=profile_id,
                tr_id=tr_id,
                session_id=session_id,
            )
    except AISecSDKException as err:
        errors.print(f"[red]Scan failed:[/red] {err.raw_message}")
        raise typer.Exit(EXIT_ERROR) from err

    if as_json:
        sys.stdout.write(verdict.model_dump_json(indent=2, exclude_none=True) + "\n")
    else:
        render_verdict(verdict, console)

    if verdict.action != "allow":
        raise typer.Exit(EXIT_BLOCKED)
