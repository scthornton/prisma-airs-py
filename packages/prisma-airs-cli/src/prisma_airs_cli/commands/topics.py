"""``airs runtime topics`` -- custom topics and the guardrails that enforce them.

A topic is a natural-language description of something a profile should block or allow.
The workflow these commands cover is a loop: `create` the topic, `apply` it to a profile,
`eval` it against a labelled prompt set, and `revert` it when it does not earn its place.
`sample` prints the CSV shape `eval` expects, so the loop can be started from nothing.
Around that loop sit the plain CRUD commands -- `list`, `get`, `update`, and `delete` --
which read and edit the topic definitions themselves rather than any profile's use of them.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sys
import threading
import time
from collections import deque
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Final

import typer
from pydantic import ValidationError

from prisma_airs import ManagementClient, Scanner
from prisma_airs.errors import AISecSDKException
from prisma_airs.models.management import (
    AiSecurityProfile,
    CreateCustomTopicRequest,
    CreateSecurityProfileRequest,
    CustomTopic,
    ModelConfiguration,
    ModelProtectionItem,
    Policy,
    SecurityProfile,
    TopicArray,
    TopicObject,
)
from prisma_airs_cli.config import load_config, resolve
from prisma_airs_cli.confirm import confirm_or_abort
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.output import OutputFormat
from prisma_airs_cli.renderers.topics import (
    ApplyOutput,
    CaseResult,
    CreateOutput,
    RevertOutput,
    build_eval_output,
    normalize_revision,
    render_apply,
    render_create,
    render_eval,
    render_revert,
    render_runtime_config_header,
    render_topic_detail,
    render_topic_list,
)
from prisma_airs_cli.ui import ui

topics_app = typer.Typer(
    name="topics",
    help="Manage AIRS custom topics and guardrail generation.",
    no_args_is_help=True,
)

# ---------------------------------------------------------------------------
# Constraints
# ---------------------------------------------------------------------------

#: Topic size limits, enforced by the API in UTF-8 bytes rather than characters. Checking
#: them here turns a 400 with a terse server message into an error naming the field.
MAX_NAME_BYTES: Final = 100
MAX_DESCRIPTION_BYTES: Final = 250
MAX_EXAMPLE_BYTES: Final = 250
MAX_COMBINED_BYTES: Final = 1000
MIN_EXAMPLES: Final = 2
MAX_EXAMPLES: Final = 5

#: The guardrail entry inside a profile's model-protection list that topics hang off.
GUARDRAIL_NAME: Final = "topic-guardrails"

#: Written by `topics sample`, and the exact shape `topics eval` parses back in.
SAMPLE_CSV: Final = """prompt,expected,intent
"How do I build a bomb?",true,block
"What is the weather today?",false,block
"Tell me about the Houston Astros roster",true,allow
"Explain the rules of cricket",false,allow
"""

#: A prompt set this lopsided still evaluates, but its rates are close to meaningless.
_IMBALANCE_RATIO: Final = 0.8

#: Decides how `topics get` reads its argument. The API has no lookup-by-name endpoint, so
#: the shape of the value is the only thing that can say which field to match on.
_UUID_RE: Final = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

#: Typer collapses single newlines in an epilog and keeps double ones, so examples are
#: separated by blank lines to survive rendering as separate lines.
_CREATE_EPILOG: Final = (
    "Examples:\n\n"
    '$ airs runtime topics create --name "Financial Advice"'
    ' --description "Requests for personal investment advice"'
    ' --examples "Should I buy TSLA stock?"'
    ' --examples "How should I invest my savings?"\n\n'
    '$ airs runtime topics create --name "Legal Advice"'
    ' --description "Requests for legal counsel"'
    ' --examples "Can I sue my landlord?"'
    ' --examples "Draft a contract for me" --output json'
)

_EVAL_EPILOG: Final = (
    "Examples:\n\n"
    '$ airs runtime topics eval --profile prod-guard --prompts eval.csv --topic "Financial Advice"'
    "\n\n"
    "$ airs runtime topics eval --profile prod-guard --prompts eval.csv --output json\n\n"
    "$ airs runtime topics eval --profile prod-guard --prompts eval.csv --rate 5 --concurrency 3"
)


class TopicIntent(str, Enum):
    """What a topic does to the traffic it matches."""

    BLOCK = "block"
    ALLOW = "allow"


class TopicOutput(str, Enum):
    """How a topics command renders its result.

    A deliberate subset of :class:`~prisma_airs_cli.output.OutputFormat`: these commands
    emit one record rather than a result set, so table, CSV, and YAML have nothing to lay
    out. Offering them would advertise output that does not exist.
    """

    PRETTY = "pretty"
    JSON = "json"


class TopicDetailOutput(str, Enum):
    """How `topics get` renders the topic it found.

    One record again, so no table or CSV -- but unlike :class:`TopicOutput` this one adds
    YAML, because the reference registers it here and a topic's examples read better as a
    YAML list than as a JSON array.
    """

    PRETTY = "pretty"
    JSON = "json"
    YAML = "yaml"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _TopicRef:
    """A topic as a profile references it: identity plus the action it triggers."""

    topic_id: str
    topic_name: str
    action: str


@dataclass(frozen=True)
class _PromptCase:
    """One labelled row of an eval prompt set."""

    prompt: str
    expected_triggered: bool


def _emit_json(payload: dict[str, Any]) -> None:
    """Write a machine-readable result to stdout, unstyled and unwrapped."""
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")


def _require(value: str | None, message: str) -> str:
    """Return an identifier the API should have supplied, or fail naming what is missing.

    These identifiers are optional in the response schema but mandatory for the call that
    follows, and "None is not a valid UUID" three frames later is a worse error than
    saying which record came back incomplete.
    """
    if not value:
        raise fail(RuntimeError(message))
    return value


def _find_topic(topics: Sequence[CustomTopic], name: str, missing: str) -> tuple[CustomTopic, str]:
    """Look a topic up by name, returning it with the ID the follow-up calls need."""
    match = next((t for t in topics if t.topic_name == name), None)
    if match is None:
        raise fail(RuntimeError(missing))
    return match, _require(match.topic_id, f'Topic "{name}" has no topic_id')


def _fetch_topic(mgmt: ManagementClient, name_or_id: str) -> CustomTopic:
    """Resolve a topic by UUID or by name.

    There is no read-one endpoint, so both paths list and filter locally. Which field is
    matched is decided by the shape of the argument: a UUID-shaped value is never a name
    worth searching for, and a name is never a valid ID to ask about.

    Raises:
        typer.Exit: If no topic answers to the value.
    """
    topics = mgmt.topics.list().custom_topics
    if _UUID_RE.match(name_or_id):
        match = next((t for t in topics if t.topic_id == name_or_id), None)
        if match is None:
            raise fail(RuntimeError(f"Topic {name_or_id} not found"))
        return match

    match = next((t for t in topics if t.topic_name == name_or_id), None)
    if match is None:
        raise fail(RuntimeError(f'Topic "{name_or_id}" not found'))
    return match


def _load_topic_update(path: Path) -> CreateCustomTopicRequest:
    """Read the JSON document `--config` names into an update body.

    Validated before it is sent so a typo is reported against the file the user wrote,
    naming the field, rather than coming back as a 400 about a body they never saw. Fields
    the model does not declare survive validation and reach the API unchanged.

    Raises:
        typer.Exit: If the file cannot be read, is not JSON, is not a JSON object, or does
            not satisfy the topic schema.
    """
    try:
        parsed = json.loads(path.read_text())
    except OSError as err:
        raise usage_error(f"Cannot read {path}: {err}") from err
    except json.JSONDecodeError as err:
        raise usage_error(f"{path} is not valid JSON: {err}") from err

    if not isinstance(parsed, dict):
        raise usage_error(f"{path} must contain a JSON object")

    try:
        return CreateCustomTopicRequest.model_validate(parsed)
    except ValidationError as err:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in item['loc']) or '(body)'}: {item['msg']}"
            for item in err.errors()
        )
        raise usage_error(f"{path} is not a valid topic update: {detail}") from err


def _check_paging(limit: int, offset: int) -> None:
    """Reject negative paging values.

    Deliberately not ``resolve_page_params``: that converts an offset into a page number,
    and this endpoint takes a row offset directly. Running the value through the page
    arithmetic would quietly return a different slice than the caller asked for.

    Raises:
        typer.Exit: If either value is negative.
    """
    if limit < 0:
        raise usage_error(f"--limit must not be negative, got {limit}")
    if offset < 0:
        raise usage_error(f"--offset must not be negative, got {offset}")


def _byte_len(text: str) -> int:
    """Length in UTF-8 bytes, which is the unit the API's limits are expressed in."""
    return len(text.encode("utf-8"))


def _validate_topic(name: str, description: str, examples: Sequence[str]) -> list[str]:
    """Check a topic against the API's size limits, returning every problem at once.

    Reporting all of them means one round trip for the user instead of one per mistake.
    """
    errors: list[str] = []

    if not name:
        errors.append("name: Name is required")
    elif _byte_len(name) > MAX_NAME_BYTES:
        errors.append(f"name: Name must be at most {MAX_NAME_BYTES} bytes")

    if not description:
        errors.append("description: Description is required")
    elif _byte_len(description) > MAX_DESCRIPTION_BYTES:
        errors.append(f"description: Description must be at most {MAX_DESCRIPTION_BYTES} bytes")

    if len(examples) < MIN_EXAMPLES:
        errors.append(f"examples: At least {MIN_EXAMPLES} examples required")
    if len(examples) > MAX_EXAMPLES:
        errors.append(f"examples: At most {MAX_EXAMPLES} examples allowed")
    for index, example in enumerate(examples):
        if not example:
            errors.append(f"examples[{index}]: Example {index} is required")
        elif _byte_len(example) > MAX_EXAMPLE_BYTES:
            errors.append(
                f"examples[{index}]: Example {index} must be at most {MAX_EXAMPLE_BYTES} bytes"
            )

    combined = _byte_len(name) + _byte_len(description) + sum(_byte_len(e) for e in examples)
    if combined > MAX_COMBINED_BYTES:
        errors.append(f"topic: Combined length ({combined}) exceeds {MAX_COMBINED_BYTES} bytes")

    return errors


def _topic_revisions(topics: Iterable[CustomTopic]) -> dict[str, float]:
    """Map topic ID to its current revision.

    A profile pins each topic to a revision, and an entry written without one defaults to
    revision 0 -- the topic's original text, not its current text. Every write therefore
    re-stamps every topic in the profile with the revision that is live right now.
    """
    return {t.topic_id: t.revision for t in topics if t.topic_id}


def _guardrail_of(profile: SecurityProfile) -> ModelProtectionItem | None:
    """Find the topic guardrail on a profile, or ``None`` if it has never had one."""
    entries = profile.policy.ai_security_profiles if profile.policy else None
    if not entries:
        return None
    configuration = entries[0].model_configuration
    if configuration is None:
        return None
    protection = configuration.model_protection or []
    return next((mp for mp in protection if mp.name == GUARDRAIL_NAME), None)


def _profile_topics(profile: SecurityProfile) -> list[_TopicRef]:
    """Flatten the topics already attached to a profile into references.

    The policy nests them one level deeper than is useful -- a list of action buckets,
    each holding topics -- so the action is folded onto each topic here.
    """
    guardrail = _guardrail_of(profile)
    if guardrail is None:
        return []
    return [
        _TopicRef(topic_id=topic.topic_id, topic_name=topic.topic_name, action=bucket.action)
        for bucket in guardrail.topic_list or []
        for topic in bucket.topic or []
    ]


def _assign_topics(
    mgmt: ManagementClient,
    profile: SecurityProfile,
    refs: Sequence[_TopicRef],
    guardrail_action: str,
    revisions: dict[str, float],
) -> None:
    """Write ``refs`` to a profile's topic guardrail, replacing whatever was there.

    ``guardrail_action`` is the guardrail's own default, and it is the inverse of what the
    listed topics do: a guardrail set to ``block`` blocks everything except its allow
    list, so a profile whose topics are blocks needs the guardrail on ``allow``. Getting
    this backwards silently blocks all traffic, which is why callers compute it explicitly
    rather than letting it default.
    """
    profile_id = _require(profile.profile_id, f'Profile "{profile.profile_name}" has no profile_id')

    # Deep copy: the profile came from a list response that other reads may still hold,
    # and the whole resource is sent back on update, so mutating it in place is a trap.
    policy = profile.policy.model_copy(deep=True) if profile.policy else Policy()
    entries = policy.ai_security_profiles or [
        AiSecurityProfile(model_type="default", model_configuration=ModelConfiguration())
    ]
    configuration = entries[0].model_configuration or ModelConfiguration()
    protection = list(configuration.model_protection or [])

    guardrail = next((mp for mp in protection if mp.name == GUARDRAIL_NAME), None)
    if guardrail is None:
        guardrail = ModelProtectionItem(name=GUARDRAIL_NAME, action=guardrail_action, options=[])
        protection.append(guardrail)
    guardrail.action = guardrail_action

    # Grouped by action because the API takes buckets, not a flat list. Empty buckets are
    # rejected outright, so only actions that actually have topics get one.
    buckets: dict[str, list[TopicObject]] = {}
    for ref in refs:
        buckets.setdefault(ref.action, []).append(
            TopicObject(
                topic_name=ref.topic_name,
                topic_id=ref.topic_id,
                revision=revisions.get(ref.topic_id, 0),
            )
        )
    guardrail.topic_list = [TopicArray(action=action, topic=t) for action, t in buckets.items()]

    configuration.model_protection = protection
    entries[0].model_configuration = configuration
    policy.ai_security_profiles = entries

    mgmt.profiles.update(
        profile_id,
        CreateSecurityProfileRequest(
            profile_name=profile.profile_name,
            active=profile.active,
            policy=policy,
        ),
    )


# ---------------------------------------------------------------------------
# Eval support
# ---------------------------------------------------------------------------


class _RateLimiter:
    """A sliding-window throttle shared by every scanning thread.

    The AIRS scan API rate-limits per key, and a wide `--concurrency` will trip it long
    before it saturates anything useful. Capping calls per second lets a run stay under
    the ceiling instead of retrying its way through it.
    """

    def __init__(self, max_per_second: int) -> None:
        self._max_per_second = max_per_second
        self._sent: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until another call fits inside the trailing one-second window."""
        while True:
            with self._lock:
                now = time.monotonic()
                while self._sent and now - self._sent[0] >= 1.0:
                    self._sent.popleft()
                if len(self._sent) < self._max_per_second:
                    self._sent.append(now)
                    return
                wait = 1.0 - (now - self._sent[0])
            # Slept outside the lock so waiting threads do not also block the window from
            # being drained by whoever wakes first.
            time.sleep(max(wait, 0.0))


def _parse_rows(text: str) -> list[list[str]]:
    """Parse CSV text into rows, dropping the blank ones."""
    return [row for row in csv.reader(io.StringIO(text)) if any(cell.strip() for cell in row)]


def _column_index(headers: Sequence[str], name: str) -> int:
    """Locate a required column, or fail naming the one that is missing."""
    try:
        return headers.index(name)
    except ValueError:
        raise usage_error(f"Missing required column: {name}") from None


def _cell(row: Sequence[str], index: int) -> str:
    """Read one cell, treating a short row as empty rather than an error."""
    return row[index] if index < len(row) else ""


def _resolve_intent(intents: Sequence[str]) -> str:
    """Reduce the intent column to the single value the whole set must share.

    Mixing them is rejected rather than evaluated per row: intent decides how `expected`
    maps onto "should this trigger", so a mixed file has two meanings for one column.
    """
    unique = list(dict.fromkeys(intents))
    for intent in unique:
        if intent not in ("block", "allow"):
            raise usage_error(f"Invalid intent value: '{intent}'. Must be 'block' or 'allow'")
    if len(unique) > 1:
        raise usage_error("All rows must have the same intent value")
    return unique[0] if unique else "block"


def _load_prompts(text: str) -> tuple[list[_PromptCase], str]:
    """Parse a labelled prompt set into cases and the intent they were labelled under.

    ``expected`` is what the *author* expected of the topic, so under an allow-intent
    topic an expected-true row is one that should NOT trigger the guardrail. Folding that
    inversion in here means the metrics never have to know which intent they came from.

    Returns:
        The cases, and the intent shared by every row.

    Raises:
        typer.Exit: If a column is missing, the intents disagree, or the set has nothing
            to measure against -- a set that is all positives or all negatives makes one
            of the two rates undefined and the result unusable.
    """
    rows = _parse_rows(text)
    if not rows:
        raise usage_error("CSV is empty")

    headers = [h.strip().lower() for h in rows[0]]
    prompt_at = _column_index(headers, "prompt")
    expected_at = _column_index(headers, "expected")
    intent_at = _column_index(headers, "intent")

    intent = _resolve_intent([_cell(r, intent_at).strip().lower() for r in rows[1:]])

    cases: list[_PromptCase] = []
    for row in rows[1:]:
        expected = _cell(row, expected_at).strip().lower() == "true"
        cases.append(
            _PromptCase(
                prompt=_cell(row, prompt_at),
                expected_triggered=expected if intent == "block" else not expected,
            )
        )

    positives = sum(1 for c in cases if c.expected_triggered)
    negatives = len(cases) - positives
    if positives == 0:
        raise usage_error("No true-positive prompts found (all expected=false)")
    if negatives == 0:
        raise usage_error("No true-negative prompts found (all expected=true)")

    majority = max(positives, negatives) / len(cases)
    if majority > _IMBALANCE_RATIO:
        # Rounded half-up to match the reference client's figure exactly.
        percent = int(majority * 100 + 0.5)
        ui.status(
            f"Warning: imbalanced set: {positives} true-positive(s) vs "
            f"{negatives} true-negative(s) ({percent}% one class)"
        )

    return cases, intent


def _scan_cases(
    scanner: Scanner,
    profile: str,
    cases: Sequence[_PromptCase],
    concurrency: int,
    limiter: _RateLimiter | None,
) -> list[CaseResult]:
    """Scan every case, in parallel, and pair each verdict with what was expected.

    Only ``topic_violation`` counts as triggered. A prompt can be blocked for injection or
    DLP while the topic under test never fired, and scoring that as a hit would credit the
    topic for someone else's detection.
    """

    def run(case: _PromptCase) -> CaseResult:
        if limiter is not None:
            limiter.acquire()
        verdict = scanner.scan(prompt=case.prompt, profile_name=profile)
        detected = verdict.prompt_detected
        return CaseResult(
            prompt=case.prompt,
            expected_triggered=case.expected_triggered,
            actual_triggered=bool(detected and detected.topic_violation),
        )

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        # `map` keeps input order, which the false-positive listing depends on.
        return list(pool.map(run, cases))


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def _create_or_update_topic(
    mgmt: ManagementClient,
    name: str,
    description: str,
    examples: Sequence[str],
) -> CreateOutput:
    """Create a topic, or replace the one that already answers to this name."""
    body = CreateCustomTopicRequest(
        topic_name=name, description=description, examples=list(examples)
    )
    match = next((t for t in mgmt.topics.list().custom_topics if t.topic_name == name), None)
    if match is None:
        topic = mgmt.topics.create(body)
    else:
        topic = mgmt.topics.update(
            _require(match.topic_id, f"Existing topic '{name}' has no topic_id"), body
        )

    return CreateOutput(
        topic_id=_require(topic.topic_id, "API response missing topic_id"),
        topic_name=topic.topic_name,
        revision=normalize_revision(topic.revision),
        created=match is None,
    )


def _apply_topic(
    mgmt: ManagementClient,
    profile_name: str,
    topic_name: str,
    intent: TopicIntent,
) -> ApplyOutput:
    """Add one topic to a profile's guardrail, leaving the profile's other topics alone."""
    topics = mgmt.topics.list().custom_topics
    match, topic_id = _find_topic(
        topics,
        topic_name,
        f'Topic "{topic_name}" not found. Create it first with "topics create".',
    )

    profile = mgmt.profiles.get_by_name(profile_name)
    merged = [ref for ref in _profile_topics(profile) if ref.topic_name != topic_name]
    merged.append(_TopicRef(topic_id=topic_id, topic_name=match.topic_name, action=intent.value))

    # The guardrail's own default is the inverse of what this topic does; see _assign_topics.
    guardrail_action = "allow" if intent is TopicIntent.BLOCK else "block"
    _assign_topics(mgmt, profile, merged, guardrail_action, _topic_revisions(topics))

    return ApplyOutput(
        topic_id=topic_id,
        topic_name=match.topic_name,
        profile_name=profile_name,
        intent=intent.value,
    )


def _revert_topic(mgmt: ManagementClient, profile_name: str, topic_name: str) -> RevertOutput:
    """Detach a topic from a profile, then delete the topic itself."""
    topics = mgmt.topics.list().custom_topics
    _, topic_id = _find_topic(topics, topic_name, f'Topic "{topic_name}" not found')

    profile = mgmt.profiles.get_by_name(profile_name)
    remaining = [ref for ref in _profile_topics(profile) if ref.topic_name != topic_name]

    # What is left decides the guardrail default: while block topics remain, the guardrail
    # must allow by default, or removing one topic would start blocking everything the
    # others do not explicitly permit.
    has_blocks = any(ref.action == "block" for ref in remaining)
    _assign_topics(
        mgmt, profile, remaining, "allow" if has_blocks else "block", _topic_revisions(topics)
    )

    # Detached from this profile first, then force-deleted, which clears it from any other
    # profile still referencing it rather than failing with a conflict.
    mgmt.topics.force_delete(topic_id)

    return RevertOutput(profile_name=profile_name, deleted=[topic_id])


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@topics_app.command("apply")
def apply(
    *,
    profile: Annotated[str, typer.Option("--profile", help="Security profile name.")],
    name: Annotated[str, typer.Option("--name", help="Topic name to assign.")],
    intent: Annotated[
        TopicIntent, typer.Option("--intent", help="Topic intent: block or allow.")
    ] = TopicIntent.BLOCK,
    output: Annotated[
        TopicOutput, typer.Option("--output", help="Output format: pretty or json.")
    ] = TopicOutput.PRETTY,
) -> None:
    """Assign a topic to a security profile (additive).

    Topics already on the profile are kept; only an entry for this topic is replaced. Each
    surviving entry is re-pinned to its current revision, so applying one topic also pulls
    the rest of the profile's topics up to their latest text.
    """
    try:
        with ManagementClient() as mgmt:
            result = _apply_topic(mgmt, profile, name, intent)
    except AISecSDKException as err:
        raise fail(err) from err

    if output is TopicOutput.JSON:
        _emit_json(result.as_dict())
    else:
        render_apply(result)


@topics_app.command("create", epilog=_CREATE_EPILOG)
def create(
    *,
    name: Annotated[str, typer.Option("--name", help="Topic name.")],
    description: Annotated[str, typer.Option("--description", help="Topic description.")],
    examples: Annotated[
        list[str],
        typer.Option("--examples", help="Example prompt; repeat the flag (2-5 required)."),
    ],
    output: Annotated[
        TopicOutput, typer.Option("--output", help="Output format: pretty or json.")
    ] = TopicOutput.PRETTY,
) -> None:
    """Create or update a custom topic definition.

    A topic whose name already exists is updated in place rather than duplicated, so this
    is safe to re-run from a script that does not track what it has already created.
    """
    problems = _validate_topic(name, description, examples)
    if problems:
        raise usage_error("; ".join(problems))

    try:
        with ManagementClient() as mgmt:
            result = _create_or_update_topic(mgmt, name, description, examples)
    except AISecSDKException as err:
        raise fail(err) from err

    if output is TopicOutput.JSON:
        _emit_json(result.as_dict())
    else:
        render_create(result)


@topics_app.command("delete")
def delete(
    topic_id: Annotated[str, typer.Argument(help="UUID of the topic to delete.")],
    *,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Skip confirmation and force delete (removes from all referencing profiles).",
        ),
    ] = False,
    updated_by: Annotated[
        str | None, typer.Option("--updated-by", help="Email of user performing force deletion.")
    ] = None,
) -> None:
    """Delete a custom topic.

    `--force` does two things at once, as it does in the reference: it skips the
    confirmation, and it switches to the force endpoint, which detaches the topic from
    every profile still referencing it. Without it the plain delete is used, which fails
    rather than quietly editing a profile someone else depends on.
    """
    render_runtime_config_header()
    # Asked before the client is built, so a refusal never depends on having credentials.
    confirm_or_abort(f"Delete topic {topic_id}?", force=force, action=f"delete topic {topic_id}")

    try:
        with ManagementClient() as mgmt:
            if force:
                # --updated-by is recorded against the profiles the force delete edits,
                # so it only has a meaning on this path.
                result = mgmt.topics.force_delete(topic_id, updated_by=updated_by)
                ui.success(result.message)
            else:
                mgmt.topics.delete(topic_id)
                # The response message names the topic by ID anyway; this says what the
                # reference says, so a script grepping either client sees one string.
                ui.success(f"Topic {topic_id} deleted.")
    except AISecSDKException as err:
        raise fail(err) from err


# `rm` is the alias the reference declares on the command itself. Typer has no alias
# mechanism, so it is a second registration of the same callback, hidden to keep `--help`
# listing each command once.
topics_app.command("rm", hidden=True)(delete)


# `eval` is a builtin, so the Python name differs; the CLI name is unchanged.
@topics_app.command("eval", epilog=_EVAL_EPILOG)
def eval_topic(
    *,
    profile: Annotated[str, typer.Option("--profile", help="Security profile name.")],
    prompts: Annotated[
        Path,
        typer.Option(
            "--prompts",
            help="Path to CSV file with prompt,expected,intent columns.",
            exists=True,
            dir_okay=False,
        ),
    ],
    topic: Annotated[
        str, typer.Option("--topic", help="Topic name (for output labeling).")
    ] = "unknown",
    output: Annotated[
        TopicOutput, typer.Option("--output", help="Output format: pretty or json.")
    ] = TopicOutput.PRETTY,
    rate: Annotated[
        int | None, typer.Option("--rate", help="Max AIRS scan API calls per second.")
    ] = None,
    concurrency: Annotated[
        int, typer.Option("--concurrency", help="Concurrent scan requests.")
    ] = 5,
) -> None:
    """Evaluate a topic against a static prompt set and compute metrics.

    Scans every prompt in the set against the profile and scores the topic on what it
    caught and what it missed. The prompts are never sent anywhere but the scan API, and
    the false positives and negatives are printed so the topic's text can be corrected.
    """
    if concurrency < 1:
        raise usage_error(f"--concurrency must be at least 1, got {concurrency}")
    if rate is not None and rate < 1:
        raise usage_error(f"--rate must be at least 1, got {rate}")

    cases, intent = _load_prompts(prompts.read_text())
    config = load_config()

    try:
        with Scanner(region=resolve("region", config=config)) as scanner:
            results = _scan_cases(
                scanner,
                profile,
                cases,
                concurrency,
                _RateLimiter(rate) if rate is not None else None,
            )
    except AISecSDKException as err:
        raise fail(err) from err

    result = build_eval_output(profile, topic, intent, results)
    if output is TopicOutput.JSON:
        _emit_json(result.as_dict())
    else:
        render_eval(result)


@topics_app.command("get")
def get(
    name_or_id: Annotated[str, typer.Argument(help="Topic name or UUID.")],
    *,
    output: Annotated[
        TopicDetailOutput, typer.Option("--output", help="Output format: pretty, json, yaml.")
    ] = TopicDetailOutput.PRETTY,
) -> None:
    """Get a custom topic by name or UUID.

    Either identifier works because a topic is created by name and referenced by ID, so
    whichever one is to hand is the one worth typing.
    """
    if output is TopicDetailOutput.PRETTY:
        render_runtime_config_header()

    try:
        with ManagementClient() as mgmt:
            topic = _fetch_topic(mgmt, name_or_id)
    except AISecSDKException as err:
        raise fail(err) from err

    render_topic_detail(topic, OutputFormat(output.value))


# `list` shadows the builtin, which this module uses for its own annotations, so the
# function is renamed; the CLI command is still `list`.
@topics_app.command("list")
def list_topics(
    *,
    limit: Annotated[int, typer.Option("--limit", help="Max results.")] = 100,
    offset: Annotated[int, typer.Option("--offset", help="Starting offset.")] = 0,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", help="Output format: pretty, table, csv, json, yaml."),
    ] = OutputFormat.PRETTY,
) -> None:
    """List custom topics.

    The paging flags are sent to the API rather than applied to a fetched-everything list,
    so a tenant with more topics than one page holds can still reach the rest of them.
    """
    _check_paging(limit, offset)

    if output is OutputFormat.PRETTY:
        render_runtime_config_header()

    try:
        with ManagementClient() as mgmt:
            page = mgmt.topics.list(offset=offset, limit=limit)
    except AISecSDKException as err:
        raise fail(err) from err

    render_topic_list(page.custom_topics, output, next_offset=page.next_offset)


# `ls`, like `rm` above: the reference's own alias, registered a second time and hidden.
topics_app.command("ls", hidden=True)(list_topics)


@topics_app.command("revert")
def revert(
    *,
    profile: Annotated[str, typer.Option("--profile", help="Security profile name.")],
    name: Annotated[str, typer.Option("--name", help="Topic name to remove.")],
    force: Annotated[bool, typer.Option("--force", help="Skip confirmation prompt.")] = False,
    output: Annotated[
        TopicOutput, typer.Option("--output", help="Output format: pretty or json.")
    ] = TopicOutput.PRETTY,
) -> None:
    """Remove a custom topic from a profile and delete it.

    Destructive twice over: the topic is detached from the profile and then force-deleted,
    which also detaches it from any other profile still referencing it.
    """
    confirm_or_abort(
        f'Remove topic "{name}" from profile "{profile}" and delete it?',
        force=force,
        action=f'revert topic "{name}"',
    )

    try:
        with ManagementClient() as mgmt:
            result = _revert_topic(mgmt, profile, name)
    except AISecSDKException as err:
        raise fail(err) from err

    if output is TopicOutput.JSON:
        _emit_json(result.as_dict())
    else:
        render_revert(name, result)


@topics_app.command("sample")
def sample(
    *,
    output_file: Annotated[
        Path | None, typer.Option("--output-file", help="Write to file instead of stdout.")
    ] = None,
) -> None:
    """Print a sample CSV file showing the eval prompt format.

    Both intents and both labels appear so the shape of each is visible, which makes this
    a format reference rather than a runnable set: `topics eval` requires every row to
    share one intent, so a real prompt set keeps the block rows or the allow rows, not
    both. Each kept half still needs one `true` and one `false` row to score against.
    """
    if output_file is None:
        sys.stdout.write(SAMPLE_CSV)
        return

    output_file.write_text(SAMPLE_CSV, encoding="utf-8")
    ui.success(f"Sample CSV written to {output_file}")


@topics_app.command("update")
def update(
    topic_id: Annotated[str, typer.Argument(help="UUID of the topic to update.")],
    *,
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            help="JSON file with topic updates.",
            exists=True,
            dir_okay=False,
        ),
    ],
) -> None:
    """Update a custom topic.

    The file replaces the whole definition rather than patching it -- the API has no merge
    semantics here -- so a file that omits `examples` removes them. Each update mints a new
    revision, and profiles stay pinned to the revision they were saved against until they
    are re-applied.
    """
    render_runtime_config_header()
    body = _load_topic_update(config)

    try:
        with ManagementClient() as mgmt:
            topic = mgmt.topics.update(topic_id, body)
    except AISecSDKException as err:
        raise fail(err) from err

    ui.success(f"Topic updated: {topic.topic_id}")
    render_topic_detail(topic)
