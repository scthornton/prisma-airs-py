"""Output formatting shared by every command group.

Five formats, matching the reference: ``pretty`` for humans, ``table`` for a quick scan,
and ``json``, ``csv``, and ``yaml`` for pipelines. A command renders the same rows through
whichever the caller asked for, so adding a format never means touching a command.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from enum import Enum
from typing import Any

import yaml

from prisma_airs.serialization import dumps_indented, to_javascript_numbers


class OutputFormat(str, Enum):
    """How to render a result set."""

    PRETTY = "pretty"
    TABLE = "table"
    CSV = "csv"
    JSON = "json"
    YAML = "yaml"


@dataclass(frozen=True)
class Column:
    """One column of a rendered result set.

    Attributes:
        key: Field name on the row mapping.
        label: Heading shown to a human. Ignored by ``json``, which keeps ``key``.
    """

    key: str
    label: str


def _cell(row: dict[str, Any], key: str) -> str:
    """Render one cell, treating a missing value as empty rather than ``None``."""
    value = row.get(key)
    return "" if value is None else str(value)


def format_output(
    rows: list[dict[str, Any]],
    columns: list[Column],
    fmt: OutputFormat,
) -> str:
    """Render rows in the requested format.

    An empty result set renders as an empty string in every format. Callers print a
    "nothing found" line instead, so a pipeline sees no output rather than a bare header
    it would have to special-case.

    Args:
        rows: Result rows, keyed by column key.
        columns: Columns to emit, in order. Fields outside this list are dropped.
        fmt: Target format.

    Returns:
        The rendered text, without a trailing newline.
    """
    if not rows:
        return ""

    if fmt is OutputFormat.JSON:
        # Keys, not labels: JSON output is consumed by machines. Numbers render the way the
        # reference renders them, so a script parsing either client sees one document.
        return dumps_indented([{c.key: row.get(c.key) for c in columns} for row in rows])

    if fmt is OutputFormat.CSV:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([c.label for c in columns])
        writer.writerows([[_cell(row, c.key) for c in columns] for row in rows])
        return buffer.getvalue().rstrip("\n")

    if fmt is OutputFormat.YAML:
        documents = [
            to_javascript_numbers({c.key: row.get(c.key) for c in columns}) for row in rows
        ]
        dumped: str = yaml.safe_dump_all(documents, sort_keys=False, default_flow_style=False)
        return dumped.rstrip("\n")

    if fmt is OutputFormat.TABLE:
        widths = [max(len(c.label), *(len(_cell(row, c.key)) for row in rows)) for c in columns]
        header = "│".join(f" {c.label.ljust(w)} " for c, w in zip(columns, widths, strict=True))
        rule = "┼".join("─" * (w + 2) for w in widths)
        body = [
            "│".join(
                f" {_cell(row, c.key).ljust(w)} " for c, w in zip(columns, widths, strict=True)
            )
            for row in rows
        ]
        return "\n".join([header, rule, *body])

    # PRETTY is rendered by each command's own renderer, which knows the shape of its data.
    return ""
