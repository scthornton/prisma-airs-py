"""Terminal rendering for the DLP administration resources.

Four resources -- data filtering profiles, data patterns, data profiles, and dictionaries
-- differ only in which fields they show. Everything else is shared: a paged list, a
detail block, and a one-line acknowledgement for a write. So the primitives live here once
and each resource supplies nothing but its own field selection.

Structured formats (``json``, ``yaml``, ``csv``, ``table``) are written straight to
``sys.stdout``; pretty output goes through :data:`~prisma_airs_cli.ui.ui`. The split
matters because Rich wraps long lines and reads square brackets in a server-supplied name
as markup, either of which quietly corrupts the bytes a pipeline is parsing.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import yaml
from rich.text import Text

from prisma_airs_cli.output import Column, OutputFormat, format_output
from prisma_airs_cli.ui import ui

#: Lifecycle values worth colouring. Anything else renders dim -- and every value is
#: spelled out regardless, so the output reads the same through a pipe, in a CI log, or to
#: someone who cannot distinguish the colours.
_STATUS_STYLES: dict[str, str] = {"active": "green", "deleted": "yellow", "disabled": "yellow"}

#: Formats whose output is parsed by something other than a human.
_STRUCTURED = (OutputFormat.JSON, OutputFormat.YAML)

#: Fields lifted onto a write acknowledgement, in the order the reference emits them.
#: ``profile_status`` lands on ``status`` because a data profile spells it differently
#: from every other DLP resource, and the acknowledgement should not.
_ACK_FIELDS: tuple[tuple[str, str], ...] = (
    ("id", "id"),
    ("name", "name"),
    ("type", "type"),
    ("status", "status"),
    ("profile_status", "status"),
    ("version", "version"),
)


def _write(text: str) -> None:
    """Emit machine-consumable text verbatim on stdout."""
    sys.stdout.write(text + "\n")


def _field(item: Any, name: str) -> Any:
    """Read one field from a response model, tolerating one the model does not declare.

    The DLP responses are ``extra="allow"``, so a field the service sends but the model
    does not name is still reachable -- and a field neither declares must read as absent
    rather than raise.
    """
    return getattr(item, name, None)


def _number(value: Any) -> Any:
    """Drop the ``.0`` Python prints on an integral float.

    Version numbers arrive as JSON numbers and land in the model as floats. ``v3.0`` is
    not what the service calls that version, and not what the reference client shows.
    """
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def status_text(status: str | None) -> Text:
    """Style a lifecycle status, falling back to an em dash when there is none."""
    if not status:
        return Text("—", style="dim")
    return Text(status, style=_STATUS_STYLES.get(status, "dim"))


def iso_timestamp(value: str | float | None) -> str | None:
    """Render an audit timestamp as ISO-8601 UTC.

    The service emits both epoch milliseconds and ready-made ISO strings for the same
    field, so a string passes through untouched and a number is converted. An
    unconvertible value renders as nothing at all: a malformed timestamp is not worth
    failing a list command over.
    """
    if not value:
        return None
    if isinstance(value, str):
        return value
    try:
        moment = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def to_key(label: str) -> str:
    """Convert a display label into the snake_case key its structured form uses."""
    slug = "".join(char if char.isalnum() else "_" for char in label.lower())
    return "_".join(part for part in slug.split("_") if part)


def _plain(value: Any) -> Any:
    """Reduce a payload to plain JSON types before it is serialised.

    The SDK's wire enums subclass :class:`str`, which ``json`` happens to accept and
    ``yaml.safe_dump`` refuses outright -- so the same command would work in one machine
    format and raise in the other. Flattening here means both emit the same value.
    """
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, str):
        return str(value)
    return value


def emit_structured(payload: Any, fmt: OutputFormat) -> None:
    """Write a payload as JSON or YAML.

    Any other format reaching here is written as JSON. That is the reference's behaviour
    and it is the safer default: a caller who asked for a machine format and got a
    human-formatted table would have to discover the difference at parse time.
    """
    flattened = _plain(payload)
    if fmt is OutputFormat.YAML:
        _write(yaml.safe_dump(flattened, sort_keys=False, default_flow_style=False).rstrip("\n"))
        return
    _write(json.dumps(flattened, indent=2))


def page_meta(page: Any, returned: int) -> dict[str, Any]:
    """Summarise which slice of a collection was returned."""
    pageable = _field(page, "pageable")
    number = _field(pageable, "page_number") if pageable else None
    size = _field(pageable, "page_size") if pageable else None
    return {
        "number": _number(number) if number is not None else 0,
        "size": _number(size) if size is not None else returned,
        "total": _number(_field(page, "total_elements")),
        "returned": returned,
    }


def render_page(
    page: Any,
    fmt: OutputFormat,
    *,
    header: str,
    to_row: Callable[[Any], dict[str, Any]],
    columns: list[Column],
    pretty_line: Callable[[Any], Text],
) -> None:
    """Render one page of a DLP collection in the requested format.

    Args:
        page: The Spring ``Page`` envelope the API returned.
        fmt: Requested output format.
        header: Human-readable name of the collection, used in headings.
        to_row: Maps one item to the flat mapping the structured formats emit.
        columns: Columns for the tabular formats, in order.
        pretty_line: Maps one item to the two-line block the pretty format shows.
    """
    content: list[Any] = list(_field(page, "content") or [])
    rows = [to_row(item) for item in content]

    if fmt in _STRUCTURED:
        emit_structured({"items": rows, "page": page_meta(page, len(content))}, fmt)
        return

    if not content:
        # An empty collection is a result, not a failure, and a bare header would make a
        # pipeline special-case it. Both formats say nothing rather than nothing-shaped.
        ui.empty_list(header.lower())
        return

    if fmt is OutputFormat.PRETTY:
        ui.section(f"{header}:")
        for item in content:
            ui.out.print(pretty_line(item))
        meta = page_meta(page, len(content))
        total = meta["total"] if meta["total"] is not None else "?"
        ui.out.print()
        ui.dim(
            f"page={meta['number']} size={meta['size']} returned={meta['returned']} total={total}"
        )
        ui.out.print()
        return

    _write(format_output(rows, columns, fmt))


def render_detail(fmt: OutputFormat, fields: list[tuple[str, Any]], title: str) -> None:
    """Render one resource as a labelled detail block.

    Empty fields are dropped from the human and structured views -- a screen of ``None``
    says less than a short list of what is actually set -- but kept in the tabular views,
    where a missing column would misalign every row after it.
    """
    populated = [(label, value) for label, value in fields if value not in (None, "")]

    if fmt in _STRUCTURED:
        emit_structured({to_key(label): value for label, value in populated}, fmt)
        return

    if fmt is OutputFormat.PRETTY:
        ui.section(f"{title}:")
        ui.key_value(populated)
        ui.out.print()
        return

    row = {label: "" if value is None else value for label, value in fields}
    columns = [Column(key=label, label=label) for label, _ in fields]
    _write(format_output([row], columns, fmt))


def ack_object(verb: str, item: Any) -> dict[str, Any]:
    """Build the machine-readable acknowledgement for a completed write."""
    ack: dict[str, Any] = {"action": verb}
    for source, target in _ACK_FIELDS:
        value = _field(item, source)
        if value is not None:
            ack[target] = _number(value)
    return ack


def render_ack(verb: str, item: Any, fmt: OutputFormat) -> None:
    """Confirm a write, naming the resource it landed on."""
    if fmt is OutputFormat.PRETTY:
        version = _field(item, "version")
        suffix = f" v{_number(version)}" if version is not None else ""
        name = _field(item, "name") or ""
        ui.success(f"{verb} {_field(item, 'id') or ''}  {name}{suffix}")
        return

    row = ack_object(verb, item)
    if fmt in _STRUCTURED:
        emit_structured(row, fmt)
        return
    _write(format_output([row], [Column(key=key, label=key) for key in row], fmt))


def render_id_ack(verb: str, resource_id: str) -> None:
    """Confirm a write whose response carries no body -- a delete, or an archive."""
    ui.success(f"{verb} {resource_id}")


def _id_line(item: Any) -> Text:
    """Open a pretty list entry with the id, which is what a follow-up command needs."""
    return Text(f"  {_field(item, 'id') or ''}\n    ", style="dim")


def _suffix(label: str, value: Any) -> Text:
    """Append ``label:value`` to a pretty list entry, or nothing when unset."""
    return Text("") if value in (None, "") else Text(f" {label}{value}", style="dim")


def _entry(item: Any, *, subtype: Any, status: Any, extras: list[Text]) -> Text:
    """Assemble the two-line block one item occupies in a pretty listing."""
    line = Text.assemble(
        _id_line(item),
        Text(str(_field(item, "name") or "")),
        Text("  "),
        Text(str(subtype or ""), style="cyan"),
        Text("  "),
        status_text(None if status is None else str(status)),
    )
    for extra in extras:
        line.append_text(extra)
    return line


# ---------------------------------------------------------------------------
# Data filtering profiles
# ---------------------------------------------------------------------------

_FILTERING_COLUMNS = [
    Column(key="id", label="ID"),
    Column(key="name", label="Name"),
    Column(key="type", label="Type"),
    Column(key="direction", label="Direction"),
    Column(key="severity", label="Severity"),
    Column(key="version", label="Version"),
]


def _filtering_row(item: Any) -> dict[str, Any]:
    """Flatten a filtering profile for the tabular and structured formats."""
    return {
        "id": _field(item, "id"),
        "name": _field(item, "name"),
        "type": _field(item, "type"),
        "direction": _field(item, "direction"),
        "severity": _field(item, "log_severity"),
        "version": _number(_field(item, "version")),
    }


def _filtering_line(item: Any) -> Text:
    """Render one filtering profile as a pretty two-line entry."""
    line = Text.assemble(
        _id_line(item),
        Text(str(_field(item, "name") or "")),
        Text("  "),
        Text(str(_field(item, "type") or ""), style="cyan"),
    )
    line.append_text(_suffix("dir:", _field(item, "direction")))
    line.append_text(_suffix("sev:", _field(item, "log_severity")))
    line.append_text(_suffix("v", _number(_field(item, "version"))))
    return line


def render_filtering_profile_list(page: Any, fmt: OutputFormat) -> None:
    """Render a page of data filtering profiles."""
    render_page(
        page,
        fmt,
        header="Data Filtering Profiles",
        to_row=_filtering_row,
        columns=_FILTERING_COLUMNS,
        pretty_line=_filtering_line,
    )


def render_filtering_profile(item: Any, fmt: OutputFormat) -> None:
    """Render one data filtering profile in full."""
    audit = _field(item, "audit_metadata")
    file_types = _field(item, "file_type")
    render_detail(
        fmt,
        [
            ("ID", _field(item, "id")),
            ("Name", _field(item, "name")),
            ("Type", _field(item, "type")),
            ("Data Profile", _field(item, "data_profile_id")),
            ("Direction", _field(item, "direction")),
            ("Severity", _field(item, "log_severity")),
            ("Scan Type", _field(item, "scan_type")),
            ("File Based", "yes" if _field(item, "file_based") else "no"),
            ("Non-File Based", "yes" if _field(item, "non_file_based") else "no"),
            ("Version", _number(_field(item, "version"))),
            ("File Types", len(file_types) if file_types is not None else None),
            ("Updated", iso_timestamp(_field(audit, "updated_at") if audit else None)),
        ],
        "Data Filtering Profile",
    )


# ---------------------------------------------------------------------------
# Data patterns
# ---------------------------------------------------------------------------

_PATTERN_COLUMNS = [
    Column(key="id", label="ID"),
    Column(key="name", label="Name"),
    Column(key="type", label="Type"),
    Column(key="status", label="Status"),
    Column(key="technique", label="Technique"),
    Column(key="version", label="Version"),
]


def _pattern_row(item: Any) -> dict[str, Any]:
    """Flatten a data pattern for the tabular and structured formats."""
    config = _field(item, "detection_config")
    return {
        "id": _field(item, "id"),
        "name": _field(item, "name"),
        "type": _field(item, "type"),
        "status": _field(item, "status"),
        "technique": _field(config, "technique") if config else None,
        "version": _number(_field(item, "version")),
    }


def _pattern_line(item: Any) -> Text:
    """Render one data pattern as a pretty two-line entry."""
    config = _field(item, "detection_config")
    return _entry(
        item,
        subtype=_field(item, "type"),
        status=_field(item, "status"),
        extras=[
            _suffix("", _field(config, "technique") if config else None),
            _suffix("v", _number(_field(item, "version"))),
        ],
    )


def render_pattern_list(page: Any, fmt: OutputFormat) -> None:
    """Render a page of data patterns."""
    render_page(
        page,
        fmt,
        header="Data Patterns",
        to_row=_pattern_row,
        columns=_PATTERN_COLUMNS,
        pretty_line=_pattern_line,
    )


def render_pattern(item: Any, fmt: OutputFormat) -> None:
    """Render one data pattern in full."""
    audit = _field(item, "audit_metadata")
    config = _field(item, "detection_config")
    rules = _field(item, "matching_rules")
    levels = _field(config, "supported_confidence_levels") if config else None
    regexes = _field(rules, "regexes") if rules else None
    render_detail(
        fmt,
        [
            ("ID", _field(item, "id")),
            ("Name", _field(item, "name")),
            ("Description", _field(item, "description")),
            ("Type", _field(item, "type")),
            ("Status", _field(item, "status")),
            ("Technique", _field(config, "technique") if config else None),
            ("Confidence", ", ".join(str(level) for level in levels) if levels else None),
            ("Regexes", len(regexes) if regexes is not None else None),
            ("Version", _number(_field(item, "version"))),
            ("Updated", iso_timestamp(_field(audit, "updated_at") if audit else None)),
        ],
        "Data Pattern",
    )


# ---------------------------------------------------------------------------
# Data profiles
# ---------------------------------------------------------------------------

_PROFILE_COLUMNS = [
    Column(key="id", label="ID"),
    Column(key="name", label="Name"),
    Column(key="type", label="Type"),
    Column(key="profile_type", label="Profile Type"),
    Column(key="status", label="Status"),
    Column(key="version", label="Version"),
]


def _profile_row(item: Any) -> dict[str, Any]:
    """Flatten a data profile for the tabular and structured formats."""
    return {
        "id": _field(item, "id"),
        "name": _field(item, "name"),
        "type": _field(item, "type"),
        "profile_type": _field(item, "profile_type"),
        "status": _field(item, "profile_status"),
        "version": _number(_field(item, "version")),
    }


def _profile_line(item: Any) -> Text:
    """Render one data profile as a pretty two-line entry."""
    return _entry(
        item,
        subtype=_field(item, "type"),
        status=_field(item, "profile_status"),
        extras=[
            _suffix("", _field(item, "profile_type")),
            _suffix("v", _number(_field(item, "version"))),
        ],
    )


def render_profile_list(page: Any, fmt: OutputFormat) -> None:
    """Render a page of data profiles."""
    render_page(
        page,
        fmt,
        header="Data Profiles",
        to_row=_profile_row,
        columns=_PROFILE_COLUMNS,
        pretty_line=_profile_line,
    )


def render_profile(item: Any, fmt: OutputFormat) -> None:
    """Render one data profile in full."""
    audit = _field(item, "audit_metadata")
    render_detail(
        fmt,
        [
            ("ID", _field(item, "id")),
            ("Name", _field(item, "name")),
            ("Description", _field(item, "description")),
            ("Type", _field(item, "type")),
            ("Profile Type", _field(item, "profile_type")),
            ("Status", _field(item, "profile_status")),
            ("Version", _number(_field(item, "version"))),
            ("Updated", iso_timestamp(_field(audit, "updated_at") if audit else None)),
        ],
        "Data Profile",
    )


# ---------------------------------------------------------------------------
# Dictionaries
# ---------------------------------------------------------------------------

_DICTIONARY_COLUMNS = [
    Column(key="id", label="ID"),
    Column(key="name", label="Name"),
    Column(key="type", label="Type"),
    Column(key="status", label="Status"),
    Column(key="keywords", label="Keywords"),
    Column(key="version", label="Version"),
]


def _dictionary_row(item: Any) -> dict[str, Any]:
    """Flatten a dictionary for the tabular and structured formats."""
    keywords = _field(item, "keywords")
    return {
        "id": _field(item, "id"),
        "name": _field(item, "name"),
        "type": _field(item, "type"),
        "status": _field(item, "status"),
        "keywords": len(keywords) if keywords is not None else None,
        "version": _number(_field(item, "version")),
    }


def _dictionary_line(item: Any) -> Text:
    """Render one dictionary as a pretty two-line entry."""
    keywords = _field(item, "keywords")
    return _entry(
        item,
        subtype=_field(item, "type"),
        status=_field(item, "status"),
        extras=[
            Text("") if keywords is None else Text(f" {len(keywords)} kw", style="dim"),
            _suffix("v", _number(_field(item, "version"))),
        ],
    )


def render_dictionary_list(page: Any, fmt: OutputFormat) -> None:
    """Render a page of dictionaries."""
    render_page(
        page,
        fmt,
        header="Data Dictionaries",
        to_row=_dictionary_row,
        columns=_DICTIONARY_COLUMNS,
        pretty_line=_dictionary_line,
    )


def render_dictionary(item: Any, fmt: OutputFormat) -> None:
    """Render one dictionary in full."""
    audit = _field(item, "audit_metadata")
    keywords = _field(item, "keywords")
    render_detail(
        fmt,
        [
            ("ID", _field(item, "id")),
            ("Name", _field(item, "name")),
            ("Description", _field(item, "description")),
            ("Type", _field(item, "type")),
            ("Status", _field(item, "status")),
            ("Keywords", len(keywords) if keywords is not None else None),
            ("Version", _number(_field(item, "version"))),
            ("Updated", iso_timestamp(_field(audit, "updated_at") if audit else None)),
        ],
        "Data Dictionary",
    )


def render_dictionary_replaced_fallback(resource_id: str) -> None:
    """Confirm a replace the service answered with 204 and no resource.

    Both 200-with-body and 204-empty are normal for this endpoint, so the absence of a
    body means the replace worked -- not that anything went wrong. Saying so explicitly
    stops the empty output reading as a silent failure.
    """
    ui.success(f"replaced {resource_id} (state not echoed by region)")


# ---------------------------------------------------------------------------
# Corpus generation
# ---------------------------------------------------------------------------


def render_generate_summary(summary: dict[str, Any], fmt: OutputFormat) -> None:
    """Report what a corpus generation run wrote.

    Only ``json`` is treated as structured here: the summary is one object rather than a
    result set, so there are no rows for the tabular formats to lay out.
    """
    if fmt is OutputFormat.JSON:
        emit_structured(summary, fmt)
        return

    ui.header("DLP Test-File Generation")
    ui.key_value(
        [
            ("Output", summary.get("out")),
            ("Seed", summary.get("seed")),
            ("Clean", summary.get("clean")),
            ("Dirty", summary.get("dirty")),
            ("Manifest", summary.get("manifest_path")),
        ]
    )
    for fmt_name, counts in (summary.get("by_format") or {}).items():
        clean = counts.get("clean")
        dirty = counts.get("dirty")
        ui.dim(f"{fmt_name.ljust(5)} clean={clean} dirty={dirty}")
