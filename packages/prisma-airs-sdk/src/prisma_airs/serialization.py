"""JSON rendering that matches JavaScript, for both requests and machine-readable output.

Two consumers need this and for different reasons. Request bodies must match byte for byte,
because the scan service authenticates them with an HMAC over the exact bytes -- a
mismatch is rejected as though the API key were wrong. Machine-readable CLI output should
match because a script that parses `--output json` from either client should see the same
document.

The differences are all in how Python renders numbers. JavaScript has one number type, so
``JSON.stringify`` writes ``30`` where Python writes ``30.0``, ``0`` for ``-0.0``, and
``null`` for a non-finite value where Python writes the invalid literals ``NaN`` and
``Infinity``.
"""

from __future__ import annotations

import json
import math
from typing import Any, Final

#: Integers above 2**53 are not exactly representable as a float, so ``int(value)`` yields
#: the binary expansion while JavaScript prints the shortest decimal that round-trips --
#: 123456789012345683968 against 123456789012345680000. Below this bound the two agree
#: exactly. No Prisma AIRS payload carries a number close to it; the bound sits here because
#: this is the point where the equivalence provably stops holding.
EXACT_INTEGER_LIMIT: Final = 2**53


def to_javascript_numbers(value: Any) -> Any:
    """Rewrite floats in a decoded JSON tree the way JavaScript would render them.

    Recurses through mappings and sequences. Booleans are left alone -- ``bool`` subclasses
    ``int`` in Python, and treating one as a number would emit ``1`` for ``True``.

    Args:
        value: A JSON-compatible value.

    Returns:
        The same structure with floats normalised.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        exact_integer = value.is_integer() and abs(value) < EXACT_INTEGER_LIMIT
        return int(value) if exact_integer else value
    if isinstance(value, dict):
        return {key: to_javascript_numbers(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_javascript_numbers(item) for item in value]
    return value


def dumps_compact(value: Any) -> str:
    """Serialise exactly as ``JSON.stringify`` does, with no whitespace.

    Used for request bodies, where the bytes are hashed.

    Two ranges still render differently and are deliberately left alone: integral values
    above 2**53, where the float is no longer exact, and magnitudes below 1e-6, where Python
    zero-pads the exponent (``1e-07`` against ``1e-7``). Neither occurs in a Prisma AIRS
    payload, and both are pinned by tests so the limit stays a documented boundary rather
    than an unexamined one.
    """
    return json.dumps(to_javascript_numbers(value), separators=(",", ":"), ensure_ascii=False)


def dumps_indented(value: Any, indent: int = 2) -> str:
    """Serialise for human-readable machine output, with JavaScript number rendering."""
    return json.dumps(to_javascript_numbers(value), indent=indent, ensure_ascii=False)
