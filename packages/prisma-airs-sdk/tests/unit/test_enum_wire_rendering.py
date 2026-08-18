"""Every enum in the package must render as the value the API expects.

Python 3.11 changed ``Enum.__format__`` for mixin enums: a plain ``(str, Enum)`` renders
as its value on 3.10 and as ``Class.MEMBER`` from 3.11. Enum values here end up in URLs,
query strings, and log lines, so an enum that opts out of ``WireEnum`` would send
different text depending on which interpreter happened to run it -- and the resulting 404
would give no hint why.

These run across every domain rather than per-enum, so an enum added later is covered
without anyone remembering to add a test.
"""

from __future__ import annotations

import json
from enum import Enum

import pytest

from prisma_airs.models import ai_gateway, dlp, management, model_security, red_team, scan, shared
from prisma_airs.models.base import WireEnum

_DOMAINS = (ai_gateway, dlp, management, model_security, red_team, scan, shared)


def _all_enums() -> list[type[Enum]]:
    """Every enum class defined across the model domains."""
    found: dict[str, type[Enum]] = {}
    for module in _DOMAINS:
        for name in dir(module):
            candidate = getattr(module, name)
            if (
                isinstance(candidate, type)
                and issubclass(candidate, Enum)
                and candidate not in (Enum, WireEnum)
                and candidate.__module__.startswith("prisma_airs.models")
            ):
                found[f"{candidate.__module__}.{candidate.__name__}"] = candidate
    return list(found.values())


ENUMS = _all_enums()


def test_the_package_actually_defines_enums() -> None:
    """Without this, every parametrised test below would vacuously pass on an empty list."""
    assert len(ENUMS) > 50


@pytest.mark.parametrize(
    "enum_class", ENUMS, ids=lambda e: f"{e.__module__.split('.')[-1]}.{e.__name__}"
)
class TestWireRendering:
    def test_derives_from_wire_enum(self, enum_class: type[Enum]) -> None:
        assert issubclass(enum_class, WireEnum)

    def test_every_member_renders_as_its_value(self, enum_class: type[Enum]) -> None:
        for member in enum_class:
            assert f"{member}" == member.value
            assert str(member) == member.value

    def test_every_member_serialises_as_its_value(self, enum_class: type[Enum]) -> None:
        for member in enum_class:
            assert json.loads(json.dumps({"k": member}))["k"] == member.value

    def test_every_member_compares_equal_to_its_raw_string(self, enum_class: type[Enum]) -> None:
        """Response models type these fields as plain str, so comparison has to work."""
        for member in enum_class:
            assert member == member.value

    def test_member_values_are_unique(self, enum_class: type[Enum]) -> None:
        """A duplicate value makes one member an alias, silently collapsing the vocabulary."""
        values = [member.value for member in enum_class]
        assert len(values) == len(set(values))
