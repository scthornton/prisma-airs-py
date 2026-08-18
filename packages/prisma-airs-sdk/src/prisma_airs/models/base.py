"""Shared bases for every API model and enum."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class AirsModel(BaseModel):
    """Base model for Prisma AIRS request and response payloads.

    Unknown fields are preserved rather than rejected. The services add response fields
    without a version bump, and a client that raises on an unrecognised key turns a
    harmless server-side addition into an outage. Anything extra is still reachable
    through ``model_extra``.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class WireEnum(str, Enum):
    """A string enum whose text form is always the value the API expects.

    Python 3.11 changed ``Enum.__format__`` for mixin enums. On 3.10, ``f"{Verdict.BENIGN}"``
    renders ``benign``; from 3.11 the same expression renders ``Verdict.BENIGN``. These
    values go into URLs, query strings, and log lines, so that difference is a portability
    trap: code developed on one interpreter silently sends something else on another, and
    the resulting 404 gives no hint why.

    Pinning ``__str__`` and ``__format__`` to :class:`str` gives one behaviour on every
    supported version -- the same semantics :class:`enum.StrEnum` provides from 3.11, which
    is unavailable while 3.10 is supported.
    """

    __str__ = str.__str__
    __format__ = str.__format__  # type: ignore[assignment]
