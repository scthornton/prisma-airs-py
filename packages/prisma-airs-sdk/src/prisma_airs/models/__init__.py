"""Pydantic models for every Prisma AIRS API plane.

Models are namespaced by domain rather than flattened into one namespace. There are just
over five hundred of them, and while they happen not to collide today, a flat re-export
would make any future collision a silent shadowing rather than an obvious import error.

    from prisma_airs.models import scan, red_team

    verdict = scan.ScanResponse.model_validate(payload)
    job = red_team.JobType.DYNAMIC

Importing a specific model directly also works and is the more common style:

    from prisma_airs.models.scan import ScanResponse
"""

from __future__ import annotations

from prisma_airs.models import (
    ai_gateway,
    dlp,
    management,
    model_security,
    red_team,
    scan,
    shared,
)
from prisma_airs.models.base import AirsModel

__all__ = [
    "AirsModel",
    "ai_gateway",
    "dlp",
    "management",
    "model_security",
    "red_team",
    "scan",
    "shared",
]
