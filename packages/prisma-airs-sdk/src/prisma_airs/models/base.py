"""Shared base for every API model."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class AirsModel(BaseModel):
    """Base model for Prisma AIRS request and response payloads.

    Unknown fields are preserved rather than rejected. The services add response fields
    without a version bump, and a client that raises on an unrecognised key turns a
    harmless server-side addition into an outage. Anything extra is still reachable
    through ``model_extra``.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)
