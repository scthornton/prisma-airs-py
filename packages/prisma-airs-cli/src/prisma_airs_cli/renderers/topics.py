"""Result shapes and terminal rendering for ``airs runtime topics``.

Most of these commands emit one record rather than a result set, so this module owns both
halves of that record: the dataclass a command fills in, and how it reaches a terminal.
The dataclasses also define the ``--output json`` document, whose keys are a contract with
whatever script is parsing it -- they are transcribed from the reference client rather
than renamed to Python conventions, so a script survives the move between the two.

``list`` and ``get`` are the exceptions: they render the API's own ``CustomTopic`` records,
so their structured output keys on the API's field names instead of a dataclass of ours.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any, Final

import yaml
from rich.markup import escape
from rich.text import Text

from prisma_airs.models.management import CustomTopic
from prisma_airs_cli.output import Column, OutputFormat, format_output
from prisma_airs_cli.ui import ui

#: Coverage bands, ported from the reference. Coverage is the weaker of TPR and TNR, so
#: these are the numbers that decide whether a topic is fit to ship; keeping the same
#: thresholds means the same eval reads the same way in either client.
_COVERAGE_GOOD: Final = 0.9
_COVERAGE_FAIR: Final = 0.7


def normalize_revision(revision: float) -> int | float:
    """Render a revision as the whole number the API actually sent.

    Revisions arrive as JSON numbers and the SDK types them ``float``, so an unconverted
    value prints as ``1.0``. Every observed revision is integral; a fractional one is
    passed through untouched rather than rounded away.
    """
    return int(revision) if float(revision).is_integer() else revision


def render_runtime_config_header() -> None:
    """Print the runtime-configuration banner the CRUD commands open with.

    Shown by `list`, `get`, `update`, and `delete` -- the commands that read and edit the
    topic definitions themselves -- and not by the guardrail loop (`create`, `apply`,
    `eval`, `revert`, `sample`), which is where the reference draws the same line.

    Reproduced here rather than imported from another command group's renderer, following
    the convention in :mod:`prisma_airs_cli.renderers.profiles`: each group owns a copy
    named for its own commands instead of tying unrelated groups together for two lines.
    """
    ui.header("Prisma AIRS — Runtime Configuration", "Security profile and topic management")


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CreateOutput:
    """The outcome of creating or updating a custom topic."""

    topic_id: str
    topic_name: str
    revision: int | float
    #: False when an existing topic of the same name was updated instead.
    created: bool

    def as_dict(self) -> dict[str, Any]:
        """Render the JSON document, in the reference client's camelCase keys."""
        return {
            "topicId": self.topic_id,
            "topicName": self.topic_name,
            "revision": self.revision,
            "created": self.created,
        }


def render_create(result: CreateOutput) -> None:
    """Report a created or updated topic."""
    verb = "created" if result.created else "updated"
    ui.success(f"Topic {verb}: {result.topic_name}")
    ui.key_value([("ID", result.topic_id), ("Revision", result.revision)])


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApplyOutput:
    """The outcome of assigning a topic to a security profile."""

    topic_id: str
    topic_name: str
    profile_name: str
    intent: str

    def as_dict(self) -> dict[str, Any]:
        """Render the JSON document, in the reference client's camelCase keys."""
        return {
            "topicId": self.topic_id,
            "topicName": self.topic_name,
            "profileName": self.profile_name,
            "intent": self.intent,
        }


def render_apply(result: ApplyOutput) -> None:
    """Report a topic assignment."""
    ui.key_value(
        [
            ("Applied", escape(result.topic_name)),
            ("Profile", escape(result.profile_name)),
            ("Intent", result.intent),
        ]
    )


# ---------------------------------------------------------------------------
# revert
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RevertOutput:
    """The outcome of detaching a topic from a profile and deleting it."""

    profile_name: str
    #: Topic IDs that were deleted, not merely detached.
    deleted: list[str]

    def as_dict(self) -> dict[str, Any]:
        """Render the JSON document, in the reference client's camelCase keys."""
        return {"profileName": self.profile_name, "deleted": list(self.deleted)}


def render_revert(topic_name: str, result: RevertOutput) -> None:
    """Report a reverted topic.

    Takes the requested name alongside the result because the deleted topic no longer
    exists to be looked up, and an operator reads the name, not the UUID.
    """
    ui.key_value(
        [
            ("Reverted", escape(topic_name)),
            ("Profile", escape(result.profile_name)),
            ("Deleted", ", ".join(result.deleted)),
        ]
    )


# ---------------------------------------------------------------------------
# eval
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaseResult:
    """One evaluated prompt: what the prompt set expected, and what the scan did."""

    prompt: str
    expected_triggered: bool
    actual_triggered: bool


@dataclass(frozen=True)
class EvalMetrics:
    """A confusion matrix and the rates derived from it."""

    tp: int
    tn: int
    fp: int
    fn: int
    tpr: float
    tnr: float
    coverage: float
    f1: float
    total: int


@dataclass(frozen=True)
class Mismatch:
    """One prompt the topic classified the wrong way."""

    prompt: str
    expected: bool
    actual: bool


@dataclass(frozen=True)
class EvalOutput:
    """A finished evaluation: the metrics, plus every prompt that went the wrong way."""

    profile: str
    topic: str
    intent: str
    metrics: EvalMetrics
    false_positives: list[Mismatch]
    false_negatives: list[Mismatch]

    def as_dict(self) -> dict[str, Any]:
        """Render the JSON document. Its keys are already the reference client's."""
        return asdict(self)


def _rate(numerator: int, denominator: int) -> float:
    """Divide, treating "nothing to divide" as zero rather than an error.

    A prompt set with no true negatives is a real thing to hand this command, and a rate
    of zero is a truer answer for it than a crash.
    """
    return numerator / denominator if denominator else 0.0


def compute_metrics(results: Sequence[CaseResult]) -> EvalMetrics:
    """Classify results into TP/TN/FP/FN and derive the rates.

    Coverage is the weaker of TPR and TNR, not their average: a topic that catches every
    violation by flagging everything has no coverage worth shipping, and averaging would
    hide that behind a healthy-looking number.
    """
    tp = sum(1 for r in results if r.expected_triggered and r.actual_triggered)
    tn = sum(1 for r in results if not r.expected_triggered and not r.actual_triggered)
    fp = sum(1 for r in results if not r.expected_triggered and r.actual_triggered)
    fn = sum(1 for r in results if r.expected_triggered and not r.actual_triggered)

    tpr = _rate(tp, tp + fn)
    tnr = _rate(tn, tn + fp)
    precision = _rate(tp, tp + fp)
    f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0.0

    return EvalMetrics(
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        tpr=tpr,
        tnr=tnr,
        coverage=min(tpr, tnr),
        f1=f1,
        total=len(results),
    )


def build_eval_output(
    profile: str,
    topic: str,
    intent: str,
    results: Sequence[CaseResult],
) -> EvalOutput:
    """Assemble the evaluation record from the scanned cases."""
    return EvalOutput(
        profile=profile,
        topic=topic,
        intent=intent,
        metrics=compute_metrics(results),
        false_positives=[
            Mismatch(prompt=r.prompt, expected=False, actual=True)
            for r in results
            if not r.expected_triggered and r.actual_triggered
        ],
        false_negatives=[
            Mismatch(prompt=r.prompt, expected=True, actual=False)
            for r in results
            if r.expected_triggered and not r.actual_triggered
        ],
    )


def _coverage_cell(coverage: float) -> str:
    """Colour the coverage figure by band. No ui primitive covers a thresholded value."""
    if coverage >= _COVERAGE_GOOD:
        style = "green"
    elif coverage >= _COVERAGE_FAIR:
        style = "yellow"
    else:
        style = "red"
    return f"[{style}]{coverage * 100:.1f}%[/{style}]"


def render_eval(output: EvalOutput) -> None:
    """Render an evaluation as metrics followed by the prompts that went wrong.

    The mismatched prompts are listed in full rather than counted: the count says how bad
    the topic is, the prompts say what to change about it.
    """
    metrics = output.metrics

    ui.header("Eval Results")
    ui.key_value(
        [
            ("Profile", escape(output.profile)),
            ("Topic", escape(output.topic)),
            ("Intent", output.intent),
        ]
    )

    ui.section("Metrics:")
    ui.key_value(
        [
            ("Coverage", _coverage_cell(metrics.coverage)),
            ("TPR", f"{metrics.tpr * 100:.1f}%"),
            ("TNR", f"{metrics.tnr * 100:.1f}%"),
            ("F1", f"{metrics.f1:.3f}"),
        ]
    )
    ui.dim(
        f"TP: {metrics.tp}  TN: {metrics.tn}  "
        f"FP: {metrics.fp}  FN: {metrics.fn}  "
        f"Total: {metrics.total}"
    )

    if output.false_positives:
        ui.section("False Positives:")
        for case in output.false_positives:
            ui.bullet(case.prompt, "flag")

    if output.false_negatives:
        ui.section("False Negatives:")
        for case in output.false_negatives:
            ui.bullet(case.prompt, "flag")


# ---------------------------------------------------------------------------
# list and get
# ---------------------------------------------------------------------------

#: Columns of a listing, in the reference's order and under its labels.
_LIST_COLUMNS: Final = [
    Column(key="id", label="ID"),
    Column(key="name", label="Name"),
    Column(key="revision", label="Revision"),
    Column(key="description", label="Description"),
]

#: How much of a description the pretty listing shows. Cut so a topic stays one entry
#: rather than a paragraph; ``topics get`` prints the description in full.
_DESCRIPTION_PREVIEW: Final = 80


def _write(text: str) -> None:
    """Emit machine-consumable text verbatim on stdout.

    Not through :data:`~prisma_airs_cli.ui.ui`: Rich wraps long lines and reads square
    brackets in a server-supplied name as markup, either of which corrupts the bytes a
    pipeline is parsing.
    """
    sys.stdout.write(text + "\n")


def topic_row(topic: CustomTopic) -> dict[str, Any]:
    """Flatten a topic into the row the tabular and structured listings emit."""
    return {
        "id": topic.topic_id or "",
        "name": topic.topic_name,
        "revision": normalize_revision(topic.revision),
        "description": topic.description or "",
    }


def _list_entry(topic: CustomTopic) -> Text:
    """Assemble the two-line block one topic occupies in a pretty listing.

    Built as a :class:`~rich.text.Text` rather than markup because a topic name is
    server-supplied: ``Legal [advice]`` is a name, not a style tag.
    """
    entry = Text.assemble(
        Text(f"  {topic.topic_id or ''}\n    ", style="dim"),
        Text(topic.topic_name),
    )
    entry.append(f" rev:{normalize_revision(topic.revision)}", style="dim")
    if topic.description:
        entry.append(f" — {topic.description[:_DESCRIPTION_PREVIEW]}", style="dim")
    return entry


def render_topic_list(
    topics: Sequence[CustomTopic],
    fmt: OutputFormat,
    *,
    next_offset: float | None = None,
) -> None:
    """Render a page of custom topics in the requested format.

    An empty page says "nothing found" in every format rather than emitting an empty
    document: a lone ``[]`` or a bare header is something a caller has to special-case,
    and the reference reports it the same way.

    Args:
        topics: The page to render.
        fmt: Requested output format.
        next_offset: Where the API says the next page starts, if this one was cut short.
            Shown only in the pretty format, which is the only one a human is reading.
    """
    if not topics:
        ui.empty_list("topics")
        return

    if fmt is not OutputFormat.PRETTY:
        _write(format_output([topic_row(topic) for topic in topics], _LIST_COLUMNS, fmt))
        return

    ui.section("Custom Topics:")
    for topic in topics:
        ui.out.print(_list_entry(topic))
    ui.out.print()

    if next_offset is not None:
        # The reference fetches every topic and counts the remainder itself. This asks for
        # one page, so the API's own marker is what says the page was cut short -- and it
        # names where to resume rather than leaving that arithmetic to the reader.
        ui.dim(f"More topics available — re-run with --offset {int(next_offset)}")


def topic_document(topic: CustomTopic) -> dict[str, Any]:
    """Build the machine-readable document for one topic.

    Keyed by the API's own field names, and carrying any field the service added that the
    model does not declare, so a script sees the record as the service described it.
    Unset fields are dropped rather than rendered as nulls.
    """
    document: dict[str, Any] = topic.model_dump(mode="json", exclude_none=True)
    # model_dump keeps the revision a float, so an integral one would reach a script as
    # 3.0 where the API sent 3.
    document["revision"] = normalize_revision(topic.revision)
    return document


def render_topic_detail(topic: CustomTopic, fmt: OutputFormat = OutputFormat.PRETTY) -> None:
    """Render one topic as a detail block, or as a document a script can parse.

    JSON and YAML carry the same document. The reference hand-writes a curated subset of
    the fields for YAML alone; emitting one document in both formats means they cannot
    drift apart, and it survives a description containing a colon or a quote.
    """
    if fmt is OutputFormat.YAML:
        dumped = yaml.safe_dump(topic_document(topic), sort_keys=False, default_flow_style=False)
        _write(dumped.rstrip("\n"))
        return
    if fmt is OutputFormat.JSON:
        _write(json.dumps(topic_document(topic), indent=2))
        return

    ui.section("Topic Detail:")
    pairs: list[tuple[str, Any]] = [
        ("ID", topic.topic_id),
        ("Name", escape(topic.topic_name)),
        ("Revision", normalize_revision(topic.revision)),
    ]
    if topic.description:
        pairs.append(("Description", escape(topic.description)))
    ui.key_value(pairs)

    if topic.examples:
        ui.out.print("  Examples:")
        for example in topic.examples:
            ui.bullet(example, "neutral")

    # Audit fields are their own block, below the definition: they say who last touched
    # the topic, which is a different question from what the topic matches.
    meta = [
        (label, escape(value))
        for label, value in (
            ("Created", topic.created_by),
            ("Updated", topic.updated_by),
            ("Modified", topic.last_modified_ts),
        )
        if value
    ]
    if meta:
        ui.key_value(meta)
    ui.out.print()
