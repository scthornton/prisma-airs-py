"""Console entry point for the ``airs`` command."""

from __future__ import annotations

import sys

from prisma_airs_cli.app import app


def main() -> int:
    """Run the CLI and return a process exit code."""
    return int(app() or 0)


if __name__ == "__main__":
    sys.exit(main())
