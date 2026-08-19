"""Translating ``--limit`` and ``--offset`` into whatever each API actually wants.

The CLI presents one pagination vocabulary -- limit and offset -- because that is what
people expect and what composes with shell arithmetic. The APIs underneath disagree: some
take an offset, some take a page number counted from zero, and some count from one.
Converting here means a command never open-codes the arithmetic, and a caller never has to
know which flavour they are talking to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from prisma_airs_cli.errors import usage_error

#: Used when a caller gives an offset but no limit, so a page number can still be derived.
DEFAULT_PAGE_SIZE: Final = 50


@dataclass(frozen=True)
class PageParams:
    """Resolved pagination, in the terms the target API uses."""

    page: int | None = None
    size: int | None = None


def resolve_page_params(
    limit: int | None,
    offset: int | None,
    *,
    index_base: Literal[0, 1] = 0,
    fallback_size: int = DEFAULT_PAGE_SIZE,
) -> PageParams:
    """Convert limit and offset into a page number and size.

    Args:
        limit: Rows per page.
        offset: Rows to skip. Converted to a page number using ``limit``, or
            :data:`DEFAULT_PAGE_SIZE` when no limit was given.
        index_base: Whether the target API numbers its first page ``0`` or ``1``.
        fallback_size: Page size assumed when converting an offset without a limit.

    Returns:
        The page and size to send. Either may be ``None``, meaning "let the API decide".

    Raises:
        typer.Exit: If a negative value is supplied. An offset of ``-10`` is a mistake
            somewhere upstream, and silently clamping it to zero hides that.
    """
    if limit is not None and limit < 0:
        raise usage_error(f"--limit must not be negative, got {limit}")
    if offset is not None and offset < 0:
        raise usage_error(f"--offset must not be negative, got {offset}")

    if offset is None:
        return PageParams(page=None, size=limit)

    page_size = limit if limit else fallback_size
    return PageParams(page=offset // page_size + index_base, size=limit)
