"""Console output primitives shared by every command group.

Two rules hold everywhere here. Anything a machine might consume goes to stdout; progress,
status, and diagnostics go to stderr, so ``airs ... --json | jq`` never swallows a spinner.
And every glyph is paired with a word, so output stays readable through a pipe, in a CI
log, or to someone who cannot distinguish the colours.
"""

from __future__ import annotations

from typing import Any, Final

from rich.console import Console
from rich.text import Text

from prisma_airs_cli.output import Column, OutputFormat, format_output

_INDENT: Final = "  "

#: Glyph and style per message kind. Ported from the reference so output stays recognisable
#: to anyone moving between the two clients.
_STYLES: Final[dict[str, tuple[str, str]]] = {
    "neutral": ("•", "dim"),
    "success": ("✓", "green"),
    "error": ("✗", "red"),
    "warn": ("⚠", "yellow"),
    "skip": ("○", "yellow"),
    "flag": ("●", "yellow"),
    "info": ("ℹ", "cyan"),  # noqa: RUF001 - matches the reference glyph set
}


class Ui:
    """Console writer with a quiet mode.

    Quiet suppresses commentary -- headers, info, progress -- but never results, warnings,
    or errors. A caller who passes ``--quiet`` wants less noise, not less signal.
    """

    def __init__(self) -> None:
        self.out = Console()
        self.err = Console(stderr=True)
        self._quiet = False

    @property
    def quiet(self) -> bool:
        """Whether commentary is suppressed."""
        return self._quiet

    def set_quiet(self, quiet: bool) -> None:
        """Turn quiet mode on or off."""
        self._quiet = quiet

    def header(self, title: str, subtitle: str | None = None) -> None:
        """Print a command heading. Suppressed when quiet."""
        if self._quiet:
            return
        self.out.print()
        self.out.print(f"{_INDENT}[bold]{title}[/bold]")
        if subtitle:
            self.out.print(f"{_INDENT}[dim]{subtitle}[/dim]")
        self.out.print()

    def section(self, label: str) -> None:
        """Print a section heading. Suppressed when quiet."""
        if self._quiet:
            return
        self.out.print(f"\n{_INDENT}[bold]{label}[/bold]\n")

    def key_value(self, pairs: list[tuple[str, Any]]) -> None:
        """Print aligned key/value lines."""
        if not pairs:
            return
        width = max(len(key) for key, _ in pairs)
        for key, value in pairs:
            rendered = "" if value is None else str(value)
            self.out.print(f"{_INDENT}[dim]{key.ljust(width)}[/dim]{_INDENT}{rendered}")

    def table(self, columns: list[Column], rows: list[dict[str, Any]]) -> None:
        """Print rows as an indented table."""
        rendered = format_output(rows, columns, OutputFormat.TABLE)
        if rendered:
            self.out.print("\n".join(f"{_INDENT}{line}" for line in rendered.splitlines()))

    def bullet(self, message: str, kind: str = "neutral") -> None:
        """Print a glyph-prefixed line in the style for ``kind``."""
        glyph, style = _STYLES.get(kind, _STYLES["neutral"])
        self.out.print(Text(f"{_INDENT}{glyph} {message}", style=style))

    def success(self, message: str) -> None:
        """Report something that worked. Shown even when quiet."""
        self.bullet(message, "success")

    def warn(self, message: str) -> None:
        """Report something the user should notice. Shown even when quiet."""
        self.bullet(message, "warn")

    def info(self, message: str) -> None:
        """Report commentary. Suppressed when quiet."""
        if self._quiet:
            return
        self.bullet(message, "info")

    def error(self, message: str) -> None:
        """Report a failure, on stderr so it survives redirection of stdout."""
        glyph, style = _STYLES["error"]
        self.err.print(Text(f"{_INDENT}{glyph} {message}", style=style))

    def dim(self, message: str) -> None:
        """Print de-emphasised commentary. Suppressed when quiet."""
        if self._quiet:
            return
        self.out.print(f"{_INDENT}[dim]{message}[/dim]")

    def status(self, message: str) -> None:
        """Print progress to stderr, so it never lands in piped output."""
        if self._quiet:
            return
        self.err.print(f"{_INDENT}[dim]{message}[/dim]")

    def empty_list(self, resource: str) -> None:
        """Report an empty result set in a way a human reads as success, not failure."""
        self.out.print(f"{_INDENT}[dim]No {resource} found[/dim]")


#: Shared instance. Commands import this rather than constructing their own, so ``--quiet``
#: set once on the root callback applies everywhere.
ui: Final = Ui()
