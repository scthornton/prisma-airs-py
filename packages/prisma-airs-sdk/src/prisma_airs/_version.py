"""Single source of the package version.

Kept in its own module so ``constants`` can build the user agent without importing the
package root, which would be circular once the root re-exports the clients.
"""

from __future__ import annotations

__version__ = "0.1.0"
