"""Result shapes and terminal rendering for ``airs runtime topics``.

Each command emits one record rather than a result set, so this module owns both halves
of that record: the dataclass a command fills in, and how it reaches a terminal. The
dataclasses also define the ``--output json`` document, whose keys are a contract with
whatever script is parsing it -- they are transcribed from the reference client rather
than renamed to Python conventions, so a script survives the move between the two.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any, Final

from rich.markup import escape

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
