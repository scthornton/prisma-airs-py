"""Guards on packaging metadata that is easy to break and annoying to notice."""

from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path

import prisma_airs

SEMVER = re.compile(r"^\d+\.\d+\.\d+")


def test_exports_a_semver_version() -> None:
    assert SEMVER.match(prisma_airs.__version__)


def test_installed_metadata_matches_module_version() -> None:
    """The dist version and the module attribute must not drift apart."""
    assert importlib.metadata.version("prisma-airs-sdk") == prisma_airs.__version__


def test_ships_a_pep561_typing_marker() -> None:
    """Without py.typed, downstream mypy silently ignores our annotations."""
    marker = Path(prisma_airs.__file__).parent / "py.typed"
    assert marker.is_file()
