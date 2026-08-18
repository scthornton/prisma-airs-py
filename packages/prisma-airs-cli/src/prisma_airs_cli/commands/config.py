"""``airs config`` -- inspect and edit the persisted CLI settings."""

from __future__ import annotations

import os
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from prisma_airs_cli.config import (
    ENV_OVERRIDES,
    KNOWN_KEYS,
    default_config_path,
    load_config,
    save_config,
)

config_app = typer.Typer(
    name="config",
    help="Read and edit the settings stored in ~/.prisma-airs/config.json.",
    no_args_is_help=True,
)

EXIT_ERROR = 2

#: Keys whose stored value is not a string. Everything else round-trips as text.
_COERCIONS: dict[str, type] = {"num_retries": int}


def _fail(message: str) -> typer.Exit:
    """Print to stderr and build the exit to raise."""
    Console(stderr=True).print(f"[red]{message}[/red]")
    return typer.Exit(EXIT_ERROR)


def _check_key(key: str) -> None:
    """Reject an unknown key rather than writing a setting nothing will read."""
    if key not in KNOWN_KEYS:
        raise _fail(f"Unknown key {key!r}. Valid keys: {', '.join(KNOWN_KEYS)}")


def _coerce(key: str, value: str) -> Any:
    """Convert a command-line string to the type the setting is stored as."""
    converter = _COERCIONS.get(key)
    if converter is None:
        return value
    try:
        return converter(value)
    except ValueError:
        raise _fail(f"{key} must be {converter.__name__}, got {value!r}") from None


@config_app.command("path")
def path() -> None:
    """Print the config file location."""
    Console().print(str(default_config_path()))


@config_app.command("list")
def list_settings() -> None:
    """Show every configured setting and where its value comes from.

    Environment variables silently override the file, so showing the origin turns a
    confusing "I set that already" into an obvious one.
    """
    console = Console()
    stored = load_config()

    table = Table("Key", "Value", "Source")
    for key in KNOWN_KEYS:
        # Uses the same mapping resolve() consults, so this view cannot drift from the
        # precedence actually applied at call time.
        env_name = ENV_OVERRIDES.get(key)
        env_value = os.environ.get(env_name) if env_name else None
        if env_value:
            table.add_row(key, env_value, f"env: {env_name}")
        elif stored.get(key) is not None:
            table.add_row(key, str(stored[key]), "config file")
        else:
            table.add_row(key, "[dim]-[/dim]", "[dim]unset[/dim]")

    console.print(table)


@config_app.command("get")
def get(key: Annotated[str, typer.Argument(help="Setting name.")]) -> None:
    """Print one stored setting.

    Reads the file only, not the environment, so it answers "what is persisted" rather
    than "what would apply right now". Use `list` for the effective view.
    """
    _check_key(key)
    value = load_config().get(key)
    if value is None:
        raise _fail(f"{key} is not set")
    Console().print(str(value))


@config_app.command("set")
def set_value(
    key: Annotated[str, typer.Argument(help="Setting name.")],
    value: Annotated[str, typer.Argument(help="New value.")],
) -> None:
    """Store a setting."""
    _check_key(key)
    stored = load_config()
    stored[key] = _coerce(key, value)
    written = save_config(stored)
    Console().print(f"Set [bold]{key}[/bold] in {written}")


@config_app.command("unset")
def unset(key: Annotated[str, typer.Argument(help="Setting name.")]) -> None:
    """Remove a setting, restoring the default."""
    _check_key(key)
    stored = load_config()
    if key not in stored:
        raise _fail(f"{key} is not set")
    del stored[key]
    written = save_config(stored)
    Console().print(f"Unset [bold]{key}[/bold] in {written}")
