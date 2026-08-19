"""Process exit codes, defined once so every command agrees on them.

These are a contract. A pipeline gates on them, so they are documented in the README and
changing one is a breaking change.

The reference client returns ``1`` both for a blocked verdict and for an outright failure.
This port separates them: an expired API key must not look like a clean policy block, or a
broken pipeline reads as a passing one. ``2`` therefore means "the operation did not
complete" -- bad invocation or an API failure -- and ``1`` is reserved for a real verdict
that was not ``allow``.
"""

from __future__ import annotations

from typing import Final

#: The command completed and the outcome was acceptable.
EXIT_OK: Final = 0

#: A scan produced a verdict other than ``allow``. The command worked; the content did not.
EXIT_BLOCKED: Final = 1

#: The command could not complete: bad arguments, missing configuration, or an API failure.
EXIT_ERROR: Final = 2
