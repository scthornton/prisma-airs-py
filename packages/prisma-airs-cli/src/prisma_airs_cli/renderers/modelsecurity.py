"""Terminal rendering for the ``airs model-security`` command group.

Every list renderer takes the SDK response models straight through -- there is no
intermediate normalisation layer, because the SDK already speaks the wire schema and a
second vocabulary would only be one more place for the two to drift apart.

Composed lines are assembled as Rich :class:`~rich.text.Text` rather than as markup
strings. Model names, file paths, and rule descriptions arrive from the API, and a
``[bold]`` inside one of them would otherwise be swallowed as markup instead of shown.
"""

from __future__ import annotations

from typing import Any, Final

import yaml
from rich.markup import escape
from rich.text import Text

from prisma_airs.models.base import AirsModel
from prisma_airs.models.model_security import (
    FileResponse,
    ModelResponse,
    ModelSecurityGroupResponse,
    ModelSecurityRuleInstanceResponse,
    ModelSecurityRuleResponse,
    ModelVersionResponse,
    PyPIAuthResponse,
    RuleEvaluationResponse,
    ScanBaseResponse,
    ViolationResponse,
)
from prisma_airs_cli.output import Column, OutputFormat, format_output
from prisma_airs_cli.ui import ui

#: List item bodies sit one level deeper than the identifier heading them, matching the
#: reference client's layout so output is recognisable across the two.
_ITEM_INDENT: Final = "    "

#: Style per lifecycle or verdict value. Values are a closed, server-defined set, so a
#: lookup table beats branching and keeps the vocabulary in one place.
_STATE_STYLES: Final[dict[str, str]] = {
    "ACTIVE": "green",
    "ALLOWED": "green",
    "ALLOWING": "green",
    "PASSED": "green",
    "SUCCESS": "green",
    "BLOCKED": "red",
    "BLOCKING": "red",
    "FAILED": "red",
    "DISABLED": "dim",
}

#: Anything the service invented since this build shipped renders yellow rather than
#: green: an unrecognised state should read as "look at this", never as "all clear".
_UNKNOWN_STATE_STYLE: Final = "yellow"


def state_style(state: str) -> str:
    """Return the Rich style for a lifecycle, outcome, or result value."""
    return _STATE_STYLES.get(state, _UNKNOWN_STATE_STYLE)


def _line(*segments: tuple[str, str | None], indent: str = _ITEM_INDENT) -> None:
    """Print one indented line built from ``(text, style)`` segments."""
    line = Text(indent)
    for value, style in segments:
        line.append(value, style=style)
    ui.out.print(line)


def _emit(rendered: str) -> None:
    """Write machine-readable output verbatim.

    Markup and highlighting are off and wrapping is disabled, so ``--output json`` that
    is piped into ``jq`` receives exactly the bytes that were formatted.
    """
    if rendered:
        ui.out.print(rendered, markup=False, highlight=False, soft_wrap=True)


def _emit_rows(rows: list[dict[str, Any]], columns: list[Column], fmt: OutputFormat) -> None:
    """Render a result set in the requested non-pretty format."""
    if fmt is OutputFormat.TABLE:
        ui.table(columns, rows)
    else:
        _emit(format_output(rows, columns, fmt))


def _emit_record(record: AirsModel, fmt: OutputFormat) -> bool:
    """Emit a single record as JSON or YAML.

    Returns:
        ``True`` when the format was handled. ``table`` and ``csv`` describe result sets
        rather than single records, so they report ``False`` and fall through to the
        pretty renderer -- which is what the reference client does with them too.
    """
    if fmt is OutputFormat.JSON:
        _emit(record.model_dump_json(indent=2, exclude_none=True))
        return True
    if fmt is OutputFormat.YAML:
        dumped = yaml.safe_dump(record.model_dump(mode="json", exclude_none=True), sort_keys=False)
        _emit(dumped.rstrip("\n"))
        return True
    return False


def _plain(value: Any) -> str:
    """Escape a free-text value for :meth:`Ui.key_value`, which parses markup."""
    return escape("" if value is None else str(value))


def _styled_state(value: str) -> str:
    """Render a state value as markup, for the key/value renderer."""
    return f"[{state_style(value)}]{escape(value)}[/]"


def _flatten(value: Any) -> Any:
    """Render a rule field override, joining list-valued ones onto a single line."""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return value


def _joined(values: list[str] | None) -> str:
    """Join an optional list for single-line display."""
    return ", ".join(values or [])


def render_model_security_header() -> None:
    """Print the model security banner."""
    ui.header("Prisma AIRS — Model Security", "ML model supply chain security")


# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

_GROUP_COLUMNS: Final = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("state", "State"),
    Column("sourceType", "Source Type"),
]


def render_group_list(
    groups: list[ModelSecurityGroupResponse],
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render a list of security groups."""
    if not groups:
        ui.empty_list("security groups")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {"id": g.uuid, "name": g.name, "state": g.state, "sourceType": g.source_type}
            for g in groups
        ]
        _emit_rows(rows, _GROUP_COLUMNS, fmt)
        return
    ui.section("Security Groups:")
    for group in groups:
        ui.dim(group.uuid)
        _line(
            (group.name, None),
            ("  ", None),
            (group.state, state_style(group.state)),
            ("  source: ", None),
            (group.source_type, "dim"),
        )
    ui.out.print()


def render_group_detail(
    group: ModelSecurityGroupResponse,
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render one security group."""
    if _emit_record(group, fmt):
        return
    ui.section("Security Group Detail:")
    ui.key_value(
        [
            ("UUID", group.uuid),
            ("Name", _plain(group.name)),
            ("Description", _plain(group.description) or "[dim](none)[/dim]"),
            ("Source Type", _plain(group.source_type)),
            ("State", _styled_state(group.state)),
            ("Created", group.created_at),
            ("Updated", group.updated_at),
        ]
    )
    ui.out.print()


# ---------------------------------------------------------------------------
# Security rules
# ---------------------------------------------------------------------------

_RULE_COLUMNS: Final = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("type", "Type"),
    Column("defaultState", "Default State"),
    Column("sources", "Sources"),
]


def render_rule_list(
    rules: list[ModelSecurityRuleResponse],
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render a list of security rule definitions."""
    if not rules:
        ui.empty_list("security rules")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": r.uuid,
                "name": r.name,
                "type": r.rule_type,
                "defaultState": r.default_state,
                "sources": _joined(r.compatible_sources),
            }
            for r in rules
        ]
        _emit_rows(rows, _RULE_COLUMNS, fmt)
        return
    ui.section("Security Rules:")
    for rule in rules:
        ui.dim(rule.uuid)
        _line(
            (rule.name, None),
            ("  type: ", None),
            (rule.rule_type, "dim"),
            ("  default: ", None),
            (rule.default_state, "dim"),
        )
        _line((rule.description, "dim"))
        _line(("Sources: ", None), (_joined(rule.compatible_sources), "dim"))
    ui.out.print()


def render_rule_detail(rule: ModelSecurityRuleResponse) -> None:
    """Render one security rule definition, with its remediation and editable fields."""
    ui.section("Security Rule Detail:")
    ui.key_value(
        [
            ("UUID", rule.uuid),
            ("Name", _plain(rule.name)),
            ("Description", _plain(rule.description)),
            ("Rule Type", _plain(rule.rule_type)),
            ("Default State", _plain(rule.default_state)),
            ("Sources", _plain(_joined(rule.compatible_sources))),
        ]
    )

    if rule.remediation.description:
        ui.section("Remediation:")
        _line((rule.remediation.description, None), indent="  ")
        for step in rule.remediation.steps:
            ui.bullet(step, "neutral")
        if rule.remediation.url:
            _line((rule.remediation.url, "dim"), indent="  ")

    if rule.editable_fields:
        ui.section("Editable Fields:")
        for field in rule.editable_fields:
            _line(
                (field.display_name, None),
                (" (", None),
                (field.attribute_name, "dim"),
                ("): ", None),
                (field.display_type, None),
                indent="  ",
            )
            if field.description:
                _line((field.description, "dim"))
    ui.out.print()


# ---------------------------------------------------------------------------
# Rule instances
# ---------------------------------------------------------------------------


def render_rule_instance_list(instances: list[ModelSecurityRuleInstanceResponse]) -> None:
    """Render the rule instances bound to a security group."""
    if not instances:
        ui.empty_list("rule instances")
        return
    ui.section("Rule Instances:")
    for instance in instances:
        # The catalogue rule is inlined on every instance, but fall back to the rule
        # UUID so a stripped-down response still identifies which rule this is.
        name = instance.rule.name or instance.security_rule_uuid
        ui.dim(instance.uuid)
        _line((name, None), ("  ", None), (instance.state, state_style(instance.state)))
    ui.out.print()


def render_rule_instance_detail(instance: ModelSecurityRuleInstanceResponse) -> None:
    """Render one rule instance and its field overrides."""
    ui.section("Rule Instance Detail:")
    pairs: list[tuple[str, Any]] = [
        ("UUID", instance.uuid),
        ("Group UUID", instance.security_group_uuid),
        ("Rule UUID", instance.security_rule_uuid),
        ("State", _styled_state(instance.state)),
    ]
    if instance.rule.name:
        pairs.append(("Rule Name", _plain(instance.rule.name)))
    pairs.append(("Created", instance.created_at))
    pairs.append(("Updated", instance.updated_at))
    ui.key_value(pairs)

    field_values = instance.field_values or {}
    if field_values:
        ui.section("Field Values:")
        ui.key_value([(key, _plain(_flatten(value))) for key, value in field_values.items()])
    ui.out.print()


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

_SCAN_COLUMNS: Final = [
    Column("id", "ID"),
    Column("outcome", "Outcome"),
    Column("origin", "Origin"),
    Column("modelUri", "Model URI"),
    Column("passed", "Passed"),
    Column("failed", "Failed"),
    Column("createdAt", "Created"),
]


def render_scan_list(
    scans: list[ScanBaseResponse],
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render a list of model security scans."""
    if not scans:
        ui.empty_list("scans")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": s.uuid,
                "outcome": s.eval_outcome,
                "origin": s.scan_origin,
                "modelUri": s.model_uri,
                "createdAt": s.created_at,
                "passed": s.eval_summary.rules_passed if s.eval_summary else "",
                "failed": s.eval_summary.rules_failed if s.eval_summary else "",
            }
            for s in scans
        ]
        _emit_rows(rows, _SCAN_COLUMNS, fmt)
        return
    ui.section("Model Security Scans:")
    for scan in scans:
        ui.dim(scan.uuid)
        _line(
            (scan.eval_outcome, state_style(scan.eval_outcome)),
            ("  ", None),
            (scan.scan_origin, "dim"),
            ("  ", None),
            (scan.created_at, "dim"),
        )
        if scan.model_uri:
            _line((scan.model_uri, "dim"))
        if scan.eval_summary:
            summary = scan.eval_summary
            _line(
                ("Rules: ", None),
                (f"{summary.rules_passed} passed", "green"),
                ("  ", None),
                (f"{summary.rules_failed} failed", "red"),
                (f"  / {summary.total_rules} total", None),
            )
    ui.out.print()


def render_scan_detail(scan: ScanBaseResponse) -> None:
    """Render one scan, its rule counts, and its labels."""
    ui.section("Scan Detail:")
    pairs: list[tuple[str, Any]] = [
        ("UUID", scan.uuid),
        ("Outcome", _styled_state(scan.eval_outcome)),
    ]
    if scan.model_uri:
        pairs.append(("Model URI", _plain(scan.model_uri)))
    pairs.append(("Origin", _plain(scan.scan_origin)))
    pairs.append(("Source", _plain(scan.source_type)))
    pairs.append(("Group", _plain(scan.security_group_name)))
    pairs.append(("Created", scan.created_at))
    pairs.append(("Updated", scan.updated_at))
    if scan.eval_summary:
        summary = scan.eval_summary
        pairs.append(
            (
                "Rules",
                f"[green]{summary.rules_passed} passed[/green]  "
                f"[red]{summary.rules_failed} failed[/red]  / {summary.total_rules} total",
            )
        )
    ui.key_value(pairs)

    if scan.labels:
        ui.section("Labels:")
        ui.key_value([(label.key, _plain(label.value)) for label in scan.labels])
    ui.out.print()


# ---------------------------------------------------------------------------
# Evaluations
# ---------------------------------------------------------------------------


def render_evaluation_list(evaluations: list[RuleEvaluationResponse]) -> None:
    """Render the rule evaluations recorded for a scan."""
    if not evaluations:
        ui.empty_list("evaluations")
        return
    ui.section("Rule Evaluations:")
    for evaluation in evaluations:
        ui.dim(evaluation.uuid)
        _line(
            (evaluation.rule_name, None),
            ("  ", None),
            (evaluation.result, state_style(evaluation.result)),
            ("  ", None),
            (evaluation.rule_instance_state, "dim"),
        )
    ui.out.print()


def render_evaluation_detail(evaluation: RuleEvaluationResponse) -> None:
    """Render one rule evaluation."""
    ui.section("Evaluation Detail:")
    ui.key_value(
        [
            ("UUID", evaluation.uuid),
            ("Rule", _plain(evaluation.rule_name)),
            ("Description", _plain(evaluation.rule_description)),
            ("Instance UUID", evaluation.rule_instance_uuid),
            ("Instance State", _plain(evaluation.rule_instance_state)),
            ("Result", _styled_state(evaluation.result)),
            ("Violations", evaluation.violation_count),
        ]
    )
    ui.out.print()


# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------


def render_violation_list(violations: list[ViolationResponse]) -> None:
    """Render the violations recorded for a scan."""
    if not violations:
        ui.empty_list("violations")
        return
    ui.section("Violations:")
    for violation in violations:
        ui.dim(violation.uuid)
        _line(
            (violation.rule_name, "red"),
            ("  ", None),
            (violation.file or "", "dim"),
        )
        _line((violation.description, None))
        _line(("Threat: ", None), (violation.threat or "", "dim"))
    ui.out.print()


def render_violation_detail(violation: ViolationResponse) -> None:
    """Render one violation."""
    ui.section("Violation Detail:")
    ui.key_value(
        [
            ("UUID", violation.uuid),
            ("Rule", f"[red]{_plain(violation.rule_name)}[/red]"),
            ("Description", _plain(violation.rule_description)),
            ("State", _plain(violation.rule_instance_state)),
            ("File", _plain(violation.file)),
            ("Threat", _plain(violation.threat)),
            ("Detail", _plain(violation.description)),
        ]
    )
    ui.out.print()


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

_FILE_COLUMNS: Final = [
    Column("id", "ID"),
    Column("path", "Path"),
    Column("type", "Type"),
    Column("formats", "Formats"),
    Column("result", "Result"),
]

#: SKIPPED is neither a pass nor a failure -- it means the scanner did not look -- so it
#: gets its own colour rather than being folded into either.
_FILE_RESULT_STYLES: Final[dict[str, str]] = {"SUCCESS": "green", "SKIPPED": "yellow"}


def render_file_list(files: list[FileResponse]) -> None:
    """Render scanned files as an indented pretty list."""
    if not files:
        ui.empty_list("files")
        return
    ui.section("Scanned Files:")
    for file in files:
        style = _FILE_RESULT_STYLES.get(file.result, "red")
        formats = f" [{_joined(file.formats)}]" if file.formats else ""
        _line(
            (file.result, style),
            ("  ", None),
            (file.type, None),
            ("  ", None),
            (file.path, None),
            (formats, "dim"),
        )
    ui.out.print()


def render_model_file_list(
    files: list[FileResponse],
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render model version files, honouring the machine-readable formats."""
    if not files:
        ui.empty_list("files")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": f.uuid,
                "path": f.path,
                "type": f.type,
                "formats": _joined(f.formats),
                "result": f.result,
            }
            for f in files
        ]
        _emit_rows(rows, _FILE_COLUMNS, fmt)
        return
    render_file_list(files)


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


def render_label_keys(keys: list[str]) -> None:
    """Render the label keys in use across the tenant."""
    if not keys:
        ui.empty_list("label keys")
        return
    ui.section("Label Keys:")
    for key in keys:
        _line((key, None), indent="  ")
    ui.out.print()


def render_label_values(key: str, values: list[str]) -> None:
    """Render the values recorded for one label key."""
    if not values:
        ui.empty_list(f'values for key "{escape(key)}"')
        return
    ui.section(f'Label Values for "{escape(key)}":')
    for value in values:
        _line((value, None), indent="  ")
    ui.out.print()


# ---------------------------------------------------------------------------
# Model catalogue
# ---------------------------------------------------------------------------

_MODEL_COLUMNS: Final = [
    Column("id", "ID"),
    Column("name", "Name"),
    Column("outcome", "Outcome"),
    Column("formats", "Formats"),
    Column("scanned", "Last Scan"),
]


def render_model_list(
    models: list[ModelResponse],
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render the scanned model catalogue."""
    if not models:
        ui.empty_list("models")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": m.uuid,
                "name": m.name,
                "outcome": m.latest_version_outcome or "",
                "formats": _joined(m.latest_version_formats),
                "scanned": m.latest_version_scan_time or "",
            }
            for m in models
        ]
        _emit_rows(rows, _MODEL_COLUMNS, fmt)
        return
    ui.section("Models:")
    for model in models:
        ui.dim(model.uuid)
        outcome = model.latest_version_outcome
        formats = (
            f" [{_joined(model.latest_version_formats)}]" if model.latest_version_formats else ""
        )
        _line(
            (model.name, None),
            ("  ", None),
            (outcome or "unscanned", state_style(outcome) if outcome else "dim"),
            (formats, "dim"),
        )
        ui.out.print()


def render_model_detail(
    model: ModelResponse,
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render one catalogue model."""
    if _emit_record(model, fmt):
        return
    ui.section("Model Detail:")
    pairs: list[tuple[str, Any]] = [
        ("UUID", model.uuid),
        ("Name", _plain(model.name)),
        ("Created", model.created_at),
        ("Updated", model.updated_at),
    ]
    if model.latest_version_uuid is not None:
        pairs.append(("Latest Version", model.latest_version_uuid))
    if model.latest_version_revision is not None:
        pairs.append(("Latest Revision", _plain(model.latest_version_revision)))
    if model.latest_version_outcome is not None:
        pairs.append(("Latest Outcome", _styled_state(model.latest_version_outcome)))
    if model.latest_version_formats:
        pairs.append(("Formats", _plain(_joined(model.latest_version_formats))))
    if model.latest_version_source_types:
        pairs.append(("Source Types", _plain(_joined(model.latest_version_source_types))))
    if model.latest_version_scan_time is not None:
        pairs.append(("Last Scan", model.latest_version_scan_time))
    ui.key_value(pairs)
    ui.out.print()


_VERSION_COLUMNS: Final = [
    Column("id", "ID"),
    Column("revision", "Revision"),
    Column("files", "Files"),
    Column("outcome", "Outcome"),
    Column("scanned", "Last Scan"),
]


def render_model_version_list(
    versions: list[ModelVersionResponse],
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render the versions of one model."""
    if not versions:
        ui.empty_list("versions")
        return
    if fmt is not OutputFormat.PRETTY:
        rows = [
            {
                "id": v.uuid,
                "revision": v.revision,
                "files": v.file_count if v.file_count is not None else "",
                "outcome": v.last_eval_outcome or "",
                "scanned": v.latest_scan_time or "",
            }
            for v in versions
        ]
        _emit_rows(rows, _VERSION_COLUMNS, fmt)
        return
    ui.section("Model Versions:")
    for version in versions:
        ui.dim(version.uuid)
        outcome = version.last_eval_outcome
        files = f"  files: {version.file_count}" if version.file_count is not None else ""
        _line(
            (version.revision, None),
            ("  ", None),
            (outcome or "unscanned", state_style(outcome) if outcome else "dim"),
            (files, None),
        )
        ui.out.print()


def render_model_version_detail(
    version: ModelVersionResponse,
    fmt: OutputFormat = OutputFormat.PRETTY,
) -> None:
    """Render one model version and its last evaluation summary."""
    if _emit_record(version, fmt):
        return
    ui.section("Model Version Detail:")
    pairs: list[tuple[str, Any]] = [
        ("UUID", version.uuid),
        ("Model", version.model_uuid),
        ("Revision", _plain(version.revision)),
        ("Created", version.created_at),
        ("Updated", version.updated_at),
    ]
    if version.file_count is not None:
        pairs.append(("File Count", version.file_count))
    if version.license is not None:
        pairs.append(("License", _plain(version.license)))
    if version.model_formats:
        pairs.append(("Formats", _plain(_joined(version.model_formats))))
    if version.source_types:
        pairs.append(("Source Types", _plain(_joined(version.source_types))))
    if version.hf_model_name is not None:
        pairs.append(("HF Model", _plain(version.hf_model_name)))
    if version.hf_organization is not None:
        pairs.append(("HF Organization", _plain(version.hf_organization)))
    if version.last_eval_outcome is not None:
        pairs.append(("Last Outcome", _styled_state(version.last_eval_outcome)))
    if version.latest_scan_time is not None:
        pairs.append(("Last Scan", version.latest_scan_time))
    ui.key_value(pairs)

    if version.last_eval_summary:
        summary = version.last_eval_summary
        ui.section("Last Eval Summary:")
        ui.key_value(
            [
                ("Passed", summary.rules_passed),
                ("Failed", summary.rules_failed),
                ("Total", summary.total_rules),
            ]
        )
    ui.out.print()


# ---------------------------------------------------------------------------
# Package install
# ---------------------------------------------------------------------------


def render_install_plan(commands: list[str]) -> None:
    """Print the commands ``--dry-run`` would have executed.

    Emitted as plain text rather than markup: the package specifier carries square
    brackets (``model-security-client[all]``), which Rich would otherwise swallow as a
    style tag and quietly drop from the command it is showing the user.
    """
    ui.section("Commands that would be executed")
    for command in commands:
        _line((f"$ {command}", "dim"), indent="  ")
    _line(
        ("The index token is masked above; re-run without --dry-run to install.", "dim"),
        indent="  ",
    )


def render_install_success(activate: str) -> None:
    """Confirm the install and say how to enter the environment it created."""
    ui.success("model-security-client installed successfully.")
    _line((f"Activate:  {activate}", "dim"), indent="  ")


# ---------------------------------------------------------------------------
# PyPI authentication
# ---------------------------------------------------------------------------


def render_pypi_auth(auth: PyPIAuthResponse) -> None:
    """Render the Artifact Registry index URL and its expiry."""
    ui.section("PyPI Authentication")
    ui.key_value([("URL", _plain(auth.url)), ("Expires", _plain(auth.expires_at))])
    # The URL embeds a live bearer token, so say so where the user will see it rather
    # than leaving them to paste it into a shared terminal or a ticket.
    ui.dim("The URL embeds a short-lived token — treat it as a credential.")
