"""Terminal rendering for the operational commands.

Doctor, backup, restore, and profile cleanup all report a list of per-item outcomes and
then a one-line summary, so the shapes those outcomes take live here together with the
code that prints them. Commands stay free of formatting decisions, and the structures
below are what the tests assert against.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

from prisma_airs_cli.output import Column, OutputFormat, format_output
from prisma_airs_cli.ui import ui

# ---------------------------------------------------------------------------
# Result shapes
# ---------------------------------------------------------------------------

#: A check either passed, passed with a caveat, or failed. Only ``fail`` is fatal:
#: a warning covers the things a working install is allowed not to have, such as an
#: AI Gateway grant on a tenant that does not use the gateway.
DoctorStatus = Literal["pass", "warn", "fail"]

#: What happened to one target during a restore.
RestoreAction = Literal["created", "updated", "skipped", "failed"]

#: Whether one write succeeded.
WriteStatus = Literal["ok", "failed"]


@dataclass(frozen=True)
class DoctorCheck:
    """One preflight check and its outcome.

    Attributes:
        name: Short label, e.g. ``Scanner API``.
        status: Outcome; see :data:`DoctorStatus`.
        detail: What was found. Never contains a credential -- values are digested
            before they reach this field.
        hint: The next thing to try, when there is an obvious one.
    """

    name: str
    status: DoctorStatus
    detail: str
    hint: str | None = None


@dataclass(frozen=True)
class BackupResult:
    """The outcome of backing up one target."""

    name: str
    filename: str
    status: WriteStatus
    error: str | None = None


@dataclass(frozen=True)
class RestoreResult:
    """The outcome of restoring one target."""

    name: str
    action: RestoreAction
    error: str | None = None


@dataclass(frozen=True)
class ProfileRevision:
    """One stored revision of a security profile."""

    profile_id: str
    revision: int


@dataclass(frozen=True)
class DuplicateGroup:
    """Every stored revision of a profile name, split into the keeper and the rest."""

    name: str
    keep: ProfileRevision
    remove: tuple[ProfileRevision, ...]


@dataclass(frozen=True)
class CleanupDeleteResult:
    """The outcome of deleting one superseded profile revision."""

    profile_id: str
    revision: int
    name: str
    status: WriteStatus
    error: str | None = None


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_STATUS_KIND: Final[dict[str, str]] = {"pass": "success", "warn": "warn", "fail": "error"}

_DOCTOR_COLUMNS: Final[list[Column]] = [
    Column("name", "Check"),
    Column("status", "Status"),
    Column("detail", "Detail"),
    Column("hint", "Hint"),
]


def plural(count: int, noun: str) -> str:
    """Render ``count`` with ``noun``, pluralised the naive way.

    Every noun this module pluralises is regular, so the naive rule is the whole rule.
    """
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _emit(payload: object) -> None:
    """Write a machine-readable payload to stdout.

    Bypasses the Rich console deliberately: JSON goes to a pipe, and Rich would be
    entitled to wrap it, style it, or interpret square brackets as markup.
    """
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")


# ---------------------------------------------------------------------------
# Doctor
# ---------------------------------------------------------------------------


def render_doctor(checks: list[DoctorCheck], fmt: OutputFormat) -> None:
    """Render the preflight report.

    ``pretty`` is the human view; every other format goes through the shared formatter,
    so a caller can pipe the same report into ``jq`` or a YAML reader.
    """
    if fmt is not OutputFormat.PRETTY:
        rows: list[dict[str, Any]] = [
            {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint} for c in checks
        ]
        sys.stdout.write(format_output(rows, _DOCTOR_COLUMNS, fmt) + "\n")
        return

    ui.header("Doctor", "Prisma AIRS CLI preflight checks")
    for check in checks:
        ui.bullet(f"{check.name} — {check.detail}", _STATUS_KIND[check.status])
        if check.hint:
            ui.dim(f"  {check.hint}")

    failed = sum(1 for c in checks if c.status == "fail")
    warned = sum(1 for c in checks if c.status == "warn")
    if failed:
        ui.error(f"{plural(failed, 'check')} failed")
    elif warned:
        ui.success(f"All checks passed ({plural(warned, 'warning')})")
    else:
        ui.success("All checks passed")


# ---------------------------------------------------------------------------
# Backup and restore
# ---------------------------------------------------------------------------


def render_backup_header() -> None:
    """Print the heading shared by backup and restore."""
    ui.header("Prisma AIRS — Backup & Restore")


def render_backup_summary(results: list[BackupResult], output_dir: Path) -> None:
    """Report what was written and what could not be."""
    written = [r for r in results if r.status == "ok"]
    failed = [r for r in results if r.status == "failed"]

    if written:
        ui.section(f"Backed up {plural(len(written), 'target')} to {output_dir}:")
        for result in written:
            ui.bullet(f"{result.name} → {result.filename}", "success")

    if failed:
        ui.section(f"Failed ({len(failed)}):")
        for result in failed:
            ui.bullet(f"{result.name}: {result.error}", "error")

    if not results:
        ui.empty_list("targets")


def render_restore_summary(results: list[RestoreResult]) -> None:
    """Report the disposition of every backup file that was read."""
    ui.section("Restore results:")
    for result in results:
        kind = {"failed": "error", "skipped": "skip"}.get(result.action, "success")
        suffix = f": {result.error}" if result.error else ""
        ui.bullet(f"{result.name} — {result.action}{suffix}", kind)

    counts = dict.fromkeys(("created", "updated", "skipped", "failed"), 0)
    for result in results:
        counts[result.action] += 1
    parts = [f"{n} {action}" for action, n in counts.items() if n]
    summary = f"Total: {', '.join(parts)}" if parts else "Total: nothing to restore"

    if counts["failed"]:
        ui.warn(summary)
    else:
        ui.success(summary)


# ---------------------------------------------------------------------------
# Profile cleanup
# ---------------------------------------------------------------------------


def render_cleanup_header() -> None:
    """Print the runtime-configuration heading used by the cleanup command."""
    ui.header("Prisma AIRS — Runtime Configuration", "Security profile and topic management")


def render_no_duplicates(fmt: OutputFormat) -> None:
    """Report that there is nothing to clean up.

    The JSON shape matches the one a real run emits, so a consumer never has to branch
    on "did it find anything" before parsing.
    """
    if fmt is OutputFormat.JSON:
        _emit({"duplicates": [], "summary": {"deleted": 0, "failed": 0}})
        return
    ui.success("No duplicate profiles found.")


def render_cleanup_preview(groups: list[DuplicateGroup], fmt: OutputFormat) -> None:
    """Show which revisions would be removed, before anything is deleted."""
    if fmt is OutputFormat.JSON:
        _emit(
            {
                "duplicates": [
                    {
                        "name": g.name,
                        "revisions": len(g.remove) + 1,
                        "keeping": g.keep.revision,
                        "deleting": len(g.remove),
                    }
                    for g in groups
                ],
                "total": sum(len(g.remove) for g in groups),
            }
        )
        return

    ui.section("Duplicate Profiles:")
    ui.table(
        [
            Column("profile", "Profile"),
            Column("revisions", "Revisions"),
            Column("keeping", "Keeping"),
            Column("deleting", "Deleting"),
        ],
        [
            {
                "profile": g.name,
                "revisions": len(g.remove) + 1,
                "keeping": f"rev {g.keep.revision}",
                "deleting": len(g.remove),
            }
            for g in groups
        ],
    )


def render_cleanup_result(results: list[CleanupDeleteResult], fmt: OutputFormat) -> None:
    """Report the outcome of the deletion pass."""
    deleted = sum(1 for r in results if r.status == "ok")
    failed = sum(1 for r in results if r.status == "failed")

    if fmt is OutputFormat.JSON:
        _emit(
            {
                "deleted": deleted,
                "failed": failed,
                # "id" rather than "profile_id": the field is named for the wire format
                # the reference client emits, which consumers already parse.
                "details": [
                    {
                        "id": r.profile_id,
                        "revision": r.revision,
                        "name": r.name,
                        "status": r.status,
                        "error": r.error,
                    }
                    for r in results
                ],
            }
        )
        return

    if failed:
        ui.section("Failures:")
        for result in (r for r in results if r.status == "failed"):
            ui.bullet(f"{result.name} rev {result.revision}: {result.error}", "error")

    summary = f"Cleanup complete: {deleted} deleted, {failed} failed"
    if failed:
        ui.warn(summary)
    else:
        ui.success(summary)
