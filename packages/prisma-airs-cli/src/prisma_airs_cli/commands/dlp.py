"""``airs dlp`` -- the DLP administration plane.

Four resources, each with the slice of CRUD its API actually offers: data patterns get all
of it, data profiles get everything but DELETE, dictionaries upload their keywords as
multipart, and data filtering profiles are read-and-replace only. A fifth command,
``generate``, writes a synthetic test corpus rather than talking to the API at all.

Every write takes flags for the common shape and ``--body``/``--body-file`` as the escape
hatch for anything the flags cannot express. The PATCH commands are JSON Merge Patch
(RFC 7396), where an omitted key and an explicit ``null`` mean different things -- see
:func:`_merge_patch`.
"""

from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path
from typing import Annotated, Any, Final, Protocol, TypeVar, cast

import typer
from pydantic import BaseModel, ValidationError

from prisma_airs import DlpClient
from prisma_airs.errors import AISecSDKException
from prisma_airs.models.dlp import (
    AdvancedDataProfileRequest,
    DataFilteringProfileRequest,
    DataPatternPatchRequest,
    DataPatternRequest,
    DataProfilePatchRequest,
    DictionaryPatchRequest,
    DictionaryRequest,
)
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.output import OutputFormat
from prisma_airs_cli.pagination import resolve_page_params
from prisma_airs_cli.renderers.dlp import (
    render_ack,
    render_dictionary,
    render_dictionary_list,
    render_dictionary_replaced_fallback,
    render_filtering_profile,
    render_filtering_profile_list,
    render_generate_summary,
    render_id_ack,
    render_pattern,
    render_pattern_list,
    render_profile,
    render_profile_list,
)

dlp_app = typer.Typer(
    name="dlp",
    help="DLP management (filtering-profiles, patterns, profiles, dictionaries, generate).",
    no_args_is_help=True,
)
filtering_profiles_app = typer.Typer(
    name="filtering-profiles",
    help=(
        "DLP data filtering profiles. Read + full-replace only. "
        "Create, patch, and delete are not exposed by the DLP API."
    ),
    no_args_is_help=True,
)
patterns_app = typer.Typer(
    name="patterns", help="DLP data patterns (full CRUD).", no_args_is_help=True
)
profiles_app = typer.Typer(
    name="profiles",
    help=(
        "DLP data profiles. DELETE is not exposed by the DLP API. To remove a profile, "
        'patch with profile_status: "deleted".'
    ),
    no_args_is_help=True,
)
dictionaries_app = typer.Typer(
    name="dictionaries", help="DLP dictionaries (multipart upload).", no_args_is_help=True
)

ModelT = TypeVar("ModelT", bound=BaseModel)

#: Combinators accepted by ``--combinator`` when ``--pattern-id`` builds an expression tree.
_COMBINATORS: Final = ("and", "or", "not", "and_not", "or_not")

#: A bare JSON number, the only thing ``--set`` coerces away from a string. Anything else
#: numeric-looking -- a leading ``+``, an exponent, a zip code with a leading zero --
#: stays text, because the service stores most of those as strings.
_NUMERIC: Final = re.compile(r"-?\d+(\.\d+)?")

#: Formats the corpus generator can emit.
GENERATE_FORMATS: Final = ("pdf", "png", "jpeg", "svg", "docx")

#: The corpus generator is imported by name rather than at module scope. It pulls in
#: document and image libraries that every other ``airs`` invocation would otherwise pay
#: for at startup, and an install that skipped them must still be able to run the rest.
_GENERATOR_MODULE: Final = "prisma_airs_cli.dlp"

_GENERATOR_MISSING: Final = (
    "DLP generate requires the optional corpus generator "
    f"({_GENERATOR_MODULE}), which is not installed."
)


# ---------------------------------------------------------------------------
# Shared option types
# ---------------------------------------------------------------------------

LimitOpt = Annotated[
    int | None,
    typer.Option("--limit", metavar="N", help="Max results per page (API page size)."),
]
OffsetOpt = Annotated[
    int | None,
    typer.Option(
        "--offset", metavar="N", help="Starting offset -- rounds down to a page boundary."
    ),
]
SortOpt = Annotated[
    list[str] | None,
    typer.Option("--sort", metavar="FIELD,DIR", help="Sort criteria (repeatable)."),
]
OutputOpt = Annotated[OutputFormat, typer.Option("--output", metavar="FMT", help="Output format.")]
BodyOpt = Annotated[
    str | None,
    typer.Option(
        "--body", metavar="JSON|-", help='Raw JSON body (escape hatch; or "-" for stdin).'
    ),
]
SetOpt = Annotated[
    list[str] | None,
    typer.Option("--set", metavar="K=V", help="Set scalar field (repeatable)."),
]
ClearOpt = Annotated[
    list[str] | None,
    typer.Option("--clear", metavar="KEY", help="Clear field via merge-patch null (repeatable)."),
]
PatchBodyFileOpt = Annotated[
    Path | None,
    typer.Option("--body-file", help="JSON merge-patch body file.", exists=True, dir_okay=False),
]
DescriptionOpt = Annotated[str | None, typer.Option("--description", help="Description.")]
GranularOpt = Annotated[bool | None, typer.Option("--granular", help="Granular data profile.")]


# ---------------------------------------------------------------------------
# Body construction
# ---------------------------------------------------------------------------


def _read_json_object(raw: str, source: str) -> dict[str, Any]:
    """Parse a JSON object supplied through a flag or a file.

    Args:
        raw: The text to parse.
        source: How to name the offending flag in an error message.

    Returns:
        The parsed object.

    Raises:
        typer.Exit: If the text is not valid JSON, is empty, or is not an object.
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as err:
        raise usage_error(f"invalid JSON in {source}: {err}") from err

    if parsed is None or parsed == "":
        raise usage_error(f"{source} was empty")
    if not isinstance(parsed, dict):
        raise usage_error(f"{source} must contain a JSON object")
    return cast("dict[str, Any]", parsed)


def _load_body(body: str | None, body_file: Path | None) -> dict[str, Any]:
    """Read a raw request body from ``--body``, ``--body-file``, or stdin.

    ``--body-file`` wins over ``--body``, matching the reference. A literal ``-`` reads
    stdin, so a body can be piped in without ever touching the filesystem.
    """
    if body_file is not None:
        raw = body_file.read_text()
    elif body == "-":
        raw = sys.stdin.read()
    else:
        raw = body or ""
    return _read_json_object(raw, "--body or --body-file")


def _as_csv(value: str | None) -> list[str] | None:
    """Split a comma-separated flag value, dropping blanks."""
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_tags(values: list[str] | None) -> dict[str, list[str]] | None:
    """Fold repeated ``--tag key=value`` flags into one tag mapping.

    A value may itself be a comma-separated list, and repeating a key appends to it rather
    than replacing it -- so ``--tag compliance=pci --tag compliance=hipaa`` and
    ``--tag compliance=pci,hipaa`` mean the same thing.

    Raises:
        typer.Exit: If an entry has no ``=`` or no key before it.
    """
    if not values:
        return None

    tags: dict[str, list[str]] = {}
    for entry in values:
        key, separator, raw = entry.partition("=")
        if not separator:
            raise usage_error(f"--tag must be 'key=value' (got '{entry}')")
        key = key.strip()
        if not key:
            raise usage_error(f"--tag missing key (got '{entry}')")
        tags.setdefault(key, []).extend(
            part.strip() for part in raw.strip().split(",") if part.strip()
        )
    return tags


def _parse_regexes(
    plain: list[str] | None, weighted: list[str] | None
) -> list[dict[str, Any]] | None:
    """Combine ``--regex`` and ``--weighted-regex`` into the pattern's regex list.

    ``--regex`` contributes weight 1. ``--weighted-regex`` splits on the *last* pipe, so a
    pattern containing a pipe -- an alternation, which is most of them -- survives intact.

    Raises:
        typer.Exit: If a weighted entry has no pipe or a non-numeric weight.
    """
    regexes: list[dict[str, Any]] = [{"regex": pattern, "weight": 1} for pattern in plain or []]

    for entry in weighted or []:
        pattern, separator, raw = entry.rpartition("|")
        if not separator:
            raise usage_error(f"--weighted-regex must be 'PATTERN|weight' (got '{entry}')")
        try:
            weight = float(raw)
        except ValueError as err:
            raise usage_error(f"--weighted-regex weight invalid in '{entry}'") from err
        regexes.append({"regex": pattern, "weight": weight})

    return regexes or None


def _coerce(raw: str) -> Any:
    """Turn a ``--set`` value into the JSON type the service expects.

    Booleans and bare numbers are coerced; ``{``, ``[``, and ``"`` open a JSON literal.
    Everything else stays a string. Quoting is therefore how a caller forces a string that
    would otherwise coerce: ``--set count='"5"'`` sends ``"5"``, not ``5``.
    """
    if raw == "true":
        return True
    if raw == "false":
        return False
    if _NUMERIC.fullmatch(raw):
        return float(raw) if "." in raw else int(raw)
    if raw[:1] in ("{", "[", '"'):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    return raw


def _merge_patch(set_values: list[str] | None, clear_keys: list[str] | None) -> dict[str, Any]:
    """Build a JSON Merge Patch (RFC 7396) document from ``--set`` and ``--clear``.

    The whole meaning of a merge patch lives in the difference between a key that is absent
    and one whose value is ``null``: absent leaves the server's value alone, ``null`` clears
    it. ``--set`` produces the former for every key it does not name; ``--clear`` produces
    the latter. That is why ``--set x=null`` is refused rather than quietly accepted -- it
    reads like a clear but would send the four-character string.

    Nested keys are refused too. A dotted key would have to be expanded into a nested
    object, and a merge patch on a nested object replaces only the keys it names, which is
    subtle enough that guessing on the caller's behalf is worse than pointing at
    ``--body-file``.

    Raises:
        typer.Exit: If an entry is malformed, names a nested field, or sets ``null``.
    """
    patch: dict[str, Any] = {}

    for entry in set_values or []:
        key, separator, raw = entry.partition("=")
        if not separator or not key:
            raise usage_error(f"--set expected key=value, got: {entry}")
        if "." in key:
            raise usage_error(f"--set {key}: use --body-file for nested fields")
        if raw == "null":
            raise usage_error(f"--set {key}=null: to clear a field, use --clear {key}")
        patch[key] = _coerce(raw)

    for key in clear_keys or []:
        if "." in key:
            raise usage_error(f"--clear {key}: use --body-file for nested fields")
        patch[key] = None

    return patch


def _patch_document(
    body_file: Path | None, set_values: list[str] | None, clear_keys: list[str] | None
) -> dict[str, Any]:
    """Resolve a patch body from either a file or the ``--set``/``--clear`` flags.

    Raises:
        typer.Exit: If both sources are supplied. Merging them would need a rule for which
            wins per key, and silently picking one loses an edit the caller asked for.
    """
    if body_file is not None and (set_values or clear_keys):
        raise usage_error("--body-file is mutually exclusive with --set/--clear")
    if body_file is not None:
        return _load_body(None, body_file)
    return _merge_patch(set_values, clear_keys)


def _validate(model: type[ModelT], document: dict[str, Any]) -> ModelT:
    """Validate a body against its request model before it reaches the wire.

    For the patch models this also fixes merge-patch semantics: validating from a mapping
    marks exactly the keys the caller supplied as set, so the ``merge_patch_dump()`` the
    SDK performs emits an explicit ``null`` for each ``--clear`` and omits every field
    nobody mentioned.

    Raises:
        typer.Exit: If the body does not satisfy the model.
    """
    try:
        return model.model_validate(document)
    except ValidationError as err:
        detail = "; ".join(
            f"{'.'.join(str(part) for part in item['loc']) or '(body)'}: {item['msg']}"
            for item in err.errors()
        )
        raise usage_error(f"invalid request body: {detail}") from err


def _pattern_document(
    *,
    name: str | None,
    pattern_type: str | None,
    description: str | None,
    technique: str | None,
    confidence_levels: str | None,
    regex: list[str] | None,
    weighted_regex: list[str] | None,
    delimiter: str | None,
    proximity_distance: int | None,
    proximity_keyword: list[str] | None,
    tag: list[str] | None,
) -> dict[str, Any]:
    """Assemble a data pattern body from the write flags.

    Raises:
        typer.Exit: If ``--name`` was not supplied.
    """
    if not name:
        raise usage_error("--name is required")

    detection_config: dict[str, Any] = {"technique": technique or "regex"}
    levels = _as_csv(confidence_levels)
    if levels:
        detection_config["supported_confidence_levels"] = levels

    matching_rules: dict[str, Any] = {}
    if delimiter is not None:
        matching_rules["delimiter"] = delimiter
    if proximity_distance is not None:
        matching_rules["proximity_distance"] = proximity_distance
    if proximity_keyword:
        matching_rules["proximity_keywords"] = proximity_keyword
    regexes = _parse_regexes(regex, weighted_regex)
    if regexes:
        matching_rules["regexes"] = regexes

    document: dict[str, Any] = {
        "name": name,
        "type": pattern_type or "custom",
        "detection_config": detection_config,
    }
    if description is not None:
        document["description"] = description
    if matching_rules:
        document["matching_rules"] = matching_rules
    tags = _parse_tags(tag)
    if tags:
        document["tags"] = tags
    return document


def _profile_document(
    *,
    name: str | None,
    profile_type: str | None,
    description: str | None,
    granular: bool | None,
    pattern_id: list[str] | None,
    combinator: str | None,
    confidence: str | None,
) -> dict[str, Any]:
    """Assemble a data profile body from the write flags.

    ``--pattern-id`` covers the common case: one expression tree joining named patterns
    with a single operator. Anything with real structure -- nested groups, mixed operators,
    multi-profile rules -- goes through ``--body-file`` instead, because a flag vocabulary
    for arbitrary boolean trees is harder to use than the JSON it would produce.

    Raises:
        typer.Exit: If ``--name`` is missing or ``--combinator`` is not a known operator.
    """
    if not name:
        raise usage_error("--name is required")

    document: dict[str, Any] = {"name": name, "profile_type": profile_type or "advanced"}
    if description is not None:
        document["description"] = description
    if granular is not None:
        document["is_granular_data_profile"] = bool(granular)

    if pattern_id:
        operator = (combinator or "or").lower()
        if operator not in _COMBINATORS:
            raise usage_error(
                f"--combinator must be one of {'|'.join(_COMBINATORS)} (got '{operator}')"
            )
        document["detection_rules"] = [
            {
                "rule_type": "expression_tree",
                "expression_tree": {
                    "operator_type": operator,
                    "condition_pattern": [
                        {
                            "data_pattern_id": identifier,
                            "confidence_level": confidence or "high",
                            "occurrence_operator_type": "any",
                            "occurrence_count": 1,
                        }
                        for identifier in pattern_id
                    ],
                },
            }
        ]
    return document


def _filtering_profile_document(
    *,
    file_based: bool | None,
    non_file_based: bool | None,
    description: str | None,
    direction: str | None,
    log_severity: str | None,
    scan_type: str | None,
    data_profile_id: int | None,
    euc_template_id: str | None,
    end_user_coaching: bool | None,
    granular: bool | None,
    file_type: list[str] | None,
) -> dict[str, Any]:
    """Assemble a data filtering profile body from the write flags.

    Raises:
        typer.Exit: If either scan-scope flag is missing. They are required by the API and
            defaulting them would silently change which traffic a profile inspects.
    """
    if file_based is None or non_file_based is None:
        raise usage_error("--file-based and --non-file-based are both required")

    document: dict[str, Any] = {
        "file_based": bool(file_based),
        "non_file_based": bool(non_file_based),
    }
    optional: list[tuple[str, Any]] = [
        ("description", description),
        ("direction", direction),
        ("log_severity", log_severity),
        ("scan_type", scan_type),
        ("data_profile_id", data_profile_id),
        ("euc_template_id", euc_template_id),
    ]
    document.update({key: value for key, value in optional if value is not None})
    if end_user_coaching is not None:
        document["is_end_user_coaching_enabled"] = bool(end_user_coaching)
    if granular is not None:
        document["is_granular_profile"] = bool(granular)
    if file_type:
        document["file_type"] = file_type
    return document


def _dictionary_metadata(
    *,
    name: str | None,
    category: str | None,
    region: str | None,
    description: str | None,
    classification: str | None,
    file: Path | None,
    metadata_file: Path | None,
) -> DictionaryRequest:
    """Build the ``json`` part of a dictionary upload.

    ``--metadata-file`` replaces the flags outright rather than merging with them: it is
    the escape hatch for fields the flags do not cover, and a half-merged metadata part is
    harder to reason about than one the caller wrote in full.

    Raises:
        typer.Exit: If neither a metadata file nor the full flag set was supplied.
    """
    if metadata_file is not None:
        return _validate(
            DictionaryRequest, _read_json_object(metadata_file.read_text(), "--metadata-file")
        )

    if not (name and category and region and file is not None):
        raise usage_error("--name, --category, --region, and --file are required")

    document: dict[str, Any] = {
        "name": name,
        "category": category,
        "region_name": region,
        # The keyword file's basename ties the metadata part to the bytes part.
        "original_file_name": file.name,
    }
    if description is not None:
        document["description"] = description
    if classification is not None:
        # Not a declared field on the request model. The model preserves extras, so this
        # rides through to the service unchanged rather than being silently dropped.
        document["classification"] = classification
    return _validate(DictionaryRequest, document)


def _keyword_file(file: Path | None) -> bytes:
    """Read the keyword file a dictionary upload must carry.

    Raises:
        typer.Exit: If no file was supplied. The endpoint is multipart-only.
    """
    if file is None:
        raise usage_error("--file is required (multipart upload)")
    return file.read_bytes()


# ---------------------------------------------------------------------------
# Data filtering profiles
# ---------------------------------------------------------------------------


@filtering_profiles_app.command("list")
def filtering_profiles_list(
    *,
    limit: LimitOpt = None,
    offset: OffsetOpt = None,
    sort: SortOpt = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """List filtering profiles."""
    params = resolve_page_params(limit, offset)
    try:
        with DlpClient() as dlp:
            page = dlp.data_filtering_profiles.list(page=params.page, size=params.size, sort=sort)
    except AISecSDKException as err:
        raise fail(err) from err
    render_filtering_profile_list(page, output)


@filtering_profiles_app.command("get")
def filtering_profiles_get(
    profile_id: Annotated[
        str, typer.Argument(metavar="ID", help="Server-assigned filtering profile id.")
    ],
    *,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Get a filtering profile by id."""
    try:
        with DlpClient() as dlp:
            profile = dlp.data_filtering_profiles.get(profile_id)
    except AISecSDKException as err:
        raise fail(err) from err
    render_filtering_profile(profile, output)


@filtering_profiles_app.command("replace")
def filtering_profiles_replace(
    profile_id: Annotated[str, typer.Argument(metavar="ID", help="Filtering profile to replace.")],
    *,
    file_based: Annotated[
        bool | None, typer.Option("--file-based", help="Apply to file-based scans (boolean).")
    ] = None,
    non_file_based: Annotated[
        bool | None,
        typer.Option("--non-file-based", help="Apply to non-file-based scans (boolean)."),
    ] = None,
    description: DescriptionOpt = None,
    direction: Annotated[
        str | None, typer.Option("--direction", help="Direction: BOTH|UPLOAD|DOWNLOAD.")
    ] = None,
    log_severity: Annotated[
        str | None,
        typer.Option("--log-severity", help="Severity: CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL."),
    ] = None,
    scan_type: Annotated[
        str | None, typer.Option("--scan-type", help="Scan type: include|exclude.")
    ] = None,
    data_profile_id: Annotated[
        int | None, typer.Option("--data-profile-id", metavar="N", help="Data profile ID.")
    ] = None,
    euc_template_id: Annotated[
        str | None, typer.Option("--euc-template-id", help="EUC template ID.")
    ] = None,
    end_user_coaching: Annotated[
        bool | None, typer.Option("--end-user-coaching", help="Enable end-user coaching.")
    ] = None,
    granular: Annotated[bool | None, typer.Option("--granular", help="Granular profile.")] = None,
    file_type: Annotated[
        list[str] | None, typer.Option("--file-type", help="File type (repeatable).")
    ] = None,
    body: BodyOpt = None,
    body_file: Annotated[
        Path | None,
        typer.Option(
            "--body-file", help="Raw JSON body file (escape hatch).", exists=True, dir_okay=False
        ),
    ] = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Full-replace a filtering profile (PUT).

    A PUT replaces the profile wholesale, so anything not supplied here is cleared on the
    server. There is no PATCH for this resource -- the API does not offer one.
    """
    document = (
        _load_body(body, body_file)
        if body or body_file is not None
        else _filtering_profile_document(
            file_based=file_based,
            non_file_based=non_file_based,
            description=description,
            direction=direction,
            log_severity=log_severity,
            scan_type=scan_type,
            data_profile_id=data_profile_id,
            euc_template_id=euc_template_id,
            end_user_coaching=end_user_coaching,
            granular=granular,
            file_type=file_type,
        )
    )
    request = _validate(DataFilteringProfileRequest, document)

    try:
        with DlpClient() as dlp:
            profile = dlp.data_filtering_profiles.replace(profile_id, request)
    except AISecSDKException as err:
        raise fail(err) from err
    render_ack("replaced", profile, output)


# ---------------------------------------------------------------------------
# Data patterns
# ---------------------------------------------------------------------------


@patterns_app.command("list")
def patterns_list(
    *,
    limit: LimitOpt = None,
    offset: OffsetOpt = None,
    sort: SortOpt = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """List data patterns."""
    params = resolve_page_params(limit, offset)
    try:
        with DlpClient() as dlp:
            page = dlp.data_patterns.list(page=params.page, size=params.size, sort=sort)
    except AISecSDKException as err:
        raise fail(err) from err
    render_pattern_list(page, output)


@patterns_app.command("create")
def patterns_create(
    *,
    # `type` is a builtin, so the parameter is renamed; the CLI flag stays --type.
    pattern_type: Annotated[
        str | None,
        typer.Option(
            "--type", help="Pattern type: predefined|custom|file_property (default: custom)."
        ),
    ] = None,
    name: Annotated[
        str | None, typer.Option("--name", help="Pattern name (required unless --body-file).")
    ] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="Pattern description.")
    ] = None,
    technique: Annotated[
        str | None, typer.Option("--technique", help="Detection technique (default: regex).")
    ] = None,
    confidence_levels: Annotated[
        str | None,
        typer.Option(
            "--confidence-levels", metavar="CSV", help="Confidence levels CSV: e.g. high,low."
        ),
    ] = None,
    regex: Annotated[
        list[str] | None,
        typer.Option("--regex", metavar="PATTERN", help="Regex with weight=1 (repeatable)."),
    ] = None,
    weighted_regex: Annotated[
        list[str] | None,
        typer.Option(
            "--weighted-regex",
            metavar="PATTERN|N",
            help="Regex with explicit weight (repeatable).",
        ),
    ] = None,
    delimiter: Annotated[
        str | None, typer.Option("--delimiter", help="Delimiter for proximity matching.")
    ] = None,
    proximity_distance: Annotated[
        int | None,
        typer.Option("--proximity-distance", metavar="N", help="Proximity window (2..1000)."),
    ] = None,
    proximity_keyword: Annotated[
        list[str] | None,
        typer.Option("--proximity-keyword", help="Proximity keyword (repeatable)."),
    ] = None,
    tag: Annotated[
        list[str] | None,
        typer.Option("--tag", metavar="K=V", help="Tag (repeatable, value can be CSV)."),
    ] = None,
    body: BodyOpt = None,
    body_file: Annotated[
        Path | None,
        typer.Option(
            "--body-file", help="Raw JSON body file (escape hatch).", exists=True, dir_okay=False
        ),
    ] = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Create a data pattern."""
    document = (
        _load_body(body, body_file)
        if body or body_file is not None
        else _pattern_document(
            name=name,
            pattern_type=pattern_type,
            description=description,
            technique=technique,
            confidence_levels=confidence_levels,
            regex=regex,
            weighted_regex=weighted_regex,
            delimiter=delimiter,
            proximity_distance=proximity_distance,
            proximity_keyword=proximity_keyword,
            tag=tag,
        )
    )
    request = _validate(DataPatternRequest, document)

    try:
        with DlpClient() as dlp:
            pattern = dlp.data_patterns.create(request)
    except AISecSDKException as err:
        raise fail(err) from err
    render_ack("created", pattern, output)


@patterns_app.command("get")
def patterns_get(
    pattern_id: Annotated[str, typer.Argument(metavar="ID", help="Server-assigned pattern id.")],
    *,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Get a data pattern by id."""
    try:
        with DlpClient() as dlp:
            pattern = dlp.data_patterns.get(pattern_id)
    except AISecSDKException as err:
        raise fail(err) from err
    render_pattern(pattern, output)


@patterns_app.command("replace")
def patterns_replace(
    pattern_id: Annotated[str, typer.Argument(metavar="ID", help="Pattern to replace.")],
    *,
    # `type` is a builtin, so the parameter is renamed; the CLI flag stays --type.
    pattern_type: Annotated[
        str | None,
        typer.Option(
            "--type", help="Pattern type: predefined|custom|file_property (default: custom)."
        ),
    ] = None,
    name: Annotated[
        str | None, typer.Option("--name", help="Pattern name (required unless --body-file).")
    ] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="Pattern description.")
    ] = None,
    technique: Annotated[
        str | None, typer.Option("--technique", help="Detection technique (default: regex).")
    ] = None,
    confidence_levels: Annotated[
        str | None,
        typer.Option(
            "--confidence-levels", metavar="CSV", help="Confidence levels CSV: e.g. high,low."
        ),
    ] = None,
    regex: Annotated[
        list[str] | None,
        typer.Option("--regex", metavar="PATTERN", help="Regex with weight=1 (repeatable)."),
    ] = None,
    weighted_regex: Annotated[
        list[str] | None,
        typer.Option(
            "--weighted-regex",
            metavar="PATTERN|N",
            help="Regex with explicit weight (repeatable).",
        ),
    ] = None,
    delimiter: Annotated[
        str | None, typer.Option("--delimiter", help="Delimiter for proximity matching.")
    ] = None,
    proximity_distance: Annotated[
        int | None,
        typer.Option("--proximity-distance", metavar="N", help="Proximity window (2..1000)."),
    ] = None,
    proximity_keyword: Annotated[
        list[str] | None,
        typer.Option("--proximity-keyword", help="Proximity keyword (repeatable)."),
    ] = None,
    tag: Annotated[
        list[str] | None,
        typer.Option("--tag", metavar="K=V", help="Tag (repeatable, value can be CSV)."),
    ] = None,
    body: BodyOpt = None,
    body_file: Annotated[
        Path | None,
        typer.Option(
            "--body-file", help="Raw JSON body file (escape hatch).", exists=True, dir_okay=False
        ),
    ] = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Full-replace a data pattern (PUT).

    Fields absent from the request are not preserved. Use `patch` to change one field and
    leave the rest alone.
    """
    document = (
        _load_body(body, body_file)
        if body or body_file is not None
        else _pattern_document(
            name=name,
            pattern_type=pattern_type,
            description=description,
            technique=technique,
            confidence_levels=confidence_levels,
            regex=regex,
            weighted_regex=weighted_regex,
            delimiter=delimiter,
            proximity_distance=proximity_distance,
            proximity_keyword=proximity_keyword,
            tag=tag,
        )
    )
    request = _validate(DataPatternRequest, document)

    try:
        with DlpClient() as dlp:
            pattern = dlp.data_patterns.replace(pattern_id, request)
    except AISecSDKException as err:
        raise fail(err) from err
    render_ack("replaced", pattern, output)


@patterns_app.command("patch")
def patterns_patch(
    pattern_id: Annotated[str, typer.Argument(metavar="ID", help="Pattern to update.")],
    *,
    body_file: PatchBodyFileOpt = None,
    set_values: Annotated[
        list[str] | None,
        typer.Option("--set", metavar="K=V", help="Set scalar field (repeatable)."),
    ] = None,
    clear: ClearOpt = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """JSON Merge Patch a data pattern.

    Use --body-file for nested fields. --set/--clear coerce values: numbers/booleans/JSON
    literals. To force a string, quote: --set count='"5"'.
    """
    request = _validate(DataPatternPatchRequest, _patch_document(body_file, set_values, clear))
    try:
        with DlpClient() as dlp:
            pattern = dlp.data_patterns.patch(pattern_id, request)
    except AISecSDKException as err:
        raise fail(err) from err
    render_ack("patched", pattern, output)


@patterns_app.command("delete")
def patterns_delete(
    pattern_id: Annotated[str, typer.Argument(metavar="ID", help="Pattern to archive.")],
) -> None:
    """Soft-delete (archive) a data pattern."""
    try:
        with DlpClient() as dlp:
            dlp.data_patterns.delete(pattern_id)
    except AISecSDKException as err:
        raise fail(err) from err
    render_id_ack("archived", pattern_id)


# ---------------------------------------------------------------------------
# Data profiles
# ---------------------------------------------------------------------------


@profiles_app.command("list")
def profiles_list(
    *,
    limit: LimitOpt = None,
    offset: OffsetOpt = None,
    sort: SortOpt = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """List data profiles."""
    params = resolve_page_params(limit, offset)
    try:
        with DlpClient() as dlp:
            page = dlp.data_profiles.list(page=params.page, size=params.size, sort=sort)
    except AISecSDKException as err:
        raise fail(err) from err
    render_profile_list(page, output)


@profiles_app.command("create")
def profiles_create(
    *,
    name: Annotated[
        str | None, typer.Option("--name", help="Profile name (required unless --body-file).")
    ] = None,
    profile_type: Annotated[
        str | None,
        typer.Option("--profile-type", help="Profile type: basic|advanced (default: advanced)."),
    ] = None,
    description: DescriptionOpt = None,
    granular: GranularOpt = None,
    pattern_id: Annotated[
        list[str] | None,
        typer.Option(
            "--pattern-id",
            metavar="ID",
            help="Data pattern ID to include (repeatable). Builds a simple expression_tree.",
        ),
    ] = None,
    combinator: Annotated[
        str | None,
        typer.Option(
            "--combinator",
            metavar="OP",
            help="Combinator for --pattern-id: or|and|not|and_not|or_not (default: or).",
        ),
    ] = None,
    confidence: Annotated[
        str | None,
        typer.Option(
            "--confidence",
            metavar="LEVEL",
            help="Confidence level for --pattern-id leaves (default: high).",
        ),
    ] = None,
    body: BodyOpt = None,
    body_file: Annotated[
        Path | None,
        typer.Option(
            "--body-file",
            help="Raw JSON body file (escape hatch; required for complex rule trees).",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Create a data profile."""
    document = (
        _load_body(body, body_file)
        if body or body_file is not None
        else _profile_document(
            name=name,
            profile_type=profile_type,
            description=description,
            granular=granular,
            pattern_id=pattern_id,
            combinator=combinator,
            confidence=confidence,
        )
    )
    request = _validate(AdvancedDataProfileRequest, document)

    try:
        with DlpClient() as dlp:
            profile = dlp.data_profiles.create(request)
    except AISecSDKException as err:
        raise fail(err) from err
    render_ack("created", profile, output)


@profiles_app.command("get")
def profiles_get(
    profile_id: Annotated[str, typer.Argument(metavar="ID", help="Server-assigned profile id.")],
    *,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Get a data profile by id."""
    try:
        with DlpClient() as dlp:
            profile = dlp.data_profiles.get(profile_id)
    except AISecSDKException as err:
        raise fail(err) from err
    render_profile(profile, output)


@profiles_app.command("replace")
def profiles_replace(
    profile_id: Annotated[str, typer.Argument(metavar="ID", help="Profile to replace.")],
    *,
    name: Annotated[
        str | None, typer.Option("--name", help="Profile name (required unless --body-file).")
    ] = None,
    profile_type: Annotated[
        str | None,
        typer.Option("--profile-type", help="Profile type: basic|advanced (default: advanced)."),
    ] = None,
    description: DescriptionOpt = None,
    granular: GranularOpt = None,
    pattern_id: Annotated[
        list[str] | None,
        typer.Option(
            "--pattern-id",
            metavar="ID",
            help="Data pattern ID to include (repeatable). Builds a simple expression_tree.",
        ),
    ] = None,
    combinator: Annotated[
        str | None,
        typer.Option(
            "--combinator",
            metavar="OP",
            help="Combinator for --pattern-id: or|and|not|and_not|or_not (default: or).",
        ),
    ] = None,
    confidence: Annotated[
        str | None,
        typer.Option(
            "--confidence",
            metavar="LEVEL",
            help="Confidence level for --pattern-id leaves (default: high).",
        ),
    ] = None,
    body: BodyOpt = None,
    body_file: Annotated[
        Path | None,
        typer.Option(
            "--body-file",
            help="Raw JSON body file (escape hatch; required for complex rule trees).",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Full-replace a data profile (PUT)."""
    document = (
        _load_body(body, body_file)
        if body or body_file is not None
        else _profile_document(
            name=name,
            profile_type=profile_type,
            description=description,
            granular=granular,
            pattern_id=pattern_id,
            combinator=combinator,
            confidence=confidence,
        )
    )
    request = _validate(AdvancedDataProfileRequest, document)

    try:
        with DlpClient() as dlp:
            profile = dlp.data_profiles.replace(profile_id, request)
    except AISecSDKException as err:
        raise fail(err) from err
    render_ack("replaced", profile, output)


@profiles_app.command("patch")
def profiles_patch(
    profile_id: Annotated[str, typer.Argument(metavar="ID", help="Profile to update.")],
    *,
    body_file: PatchBodyFileOpt = None,
    set_values: SetOpt = None,
    clear: ClearOpt = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """JSON Merge Patch a data profile.

    The body must include name + profile_type. Use --body-file for nested fields.
    --set/--clear coerce values: numbers/booleans/JSON literals. To force a string, quote:
    --set count='"5"'.
    """
    request = _validate(DataProfilePatchRequest, _patch_document(body_file, set_values, clear))
    try:
        with DlpClient() as dlp:
            profile = dlp.data_profiles.patch(profile_id, request)
    except AISecSDKException as err:
        raise fail(err) from err
    render_ack("patched", profile, output)


@profiles_app.command("delete")
def profiles_delete(
    ctx: typer.Context,
    profile_id: Annotated[
        str, typer.Argument(metavar="ID", help="Profile the caller meant to delete.")
    ],
) -> None:
    """Not supported -- prints the patch idiom and exits 2.

    The command exists so the failure is a pointer rather than "unknown command". The DLP
    API has no DELETE for data profiles; retiring one means patching its lifecycle state.
    """
    # The commands quoted below are meant to be pasted, so the path is taken from the
    # invocation rather than hardcoded: it stays correct wherever the parent application
    # mounts this group, and whatever the executable ends up being called.
    group = ctx.parent.command_path if ctx.parent is not None else "airs dlp profiles"
    raise usage_error(
        "This DLP API has no DELETE for data profiles.\n"
        "  To soft-delete, fetch the profile to get its name + profile_type, then patch:\n\n"
        f"    {group} get {profile_id} --output json\n"
        f"    {group} patch {profile_id} --set profile_status='\"deleted\"' \\\n"
        "      --set name='\"<existing-name>\"' --set profile_type='\"<existing-type>\"'"
    )


# ---------------------------------------------------------------------------
# Dictionaries
# ---------------------------------------------------------------------------


@dictionaries_app.command("list")
def dictionaries_list(
    *,
    limit: LimitOpt = None,
    offset: OffsetOpt = None,
    sort: SortOpt = None,
    keywords: Annotated[
        bool | None, typer.Option("--keywords", help="Include keyword list in response.")
    ] = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """List dictionaries."""
    params = resolve_page_params(limit, offset)
    try:
        with DlpClient() as dlp:
            page = dlp.dictionaries.list(
                page=params.page,
                size=params.size,
                sort=sort,
                # Absent means "do not send the parameter", which is not the same as
                # sending keywords=false: the service omits the array either way, but the
                # reference only ever sends the flag when it was asked for.
                keywords=True if keywords else None,
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_dictionary_list(page, output)


@dictionaries_app.command("create")
def dictionaries_create(
    *,
    name: Annotated[str | None, typer.Option("--name", help="Dictionary name.")] = None,
    category: Annotated[
        str | None, typer.Option("--category", help="Dictionary category, e.g. Confidential.")
    ] = None,
    region: Annotated[
        str | None, typer.Option("--region", help="Region the dictionary lives in.")
    ] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="Dictionary description.")
    ] = None,
    classification: Annotated[
        str | None,
        typer.Option("--classification", help="Classification tag, e.g. pab or endpoint."),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option("--file", help="Keyword file.", exists=True, dir_okay=False),
    ] = None,
    metadata_file: Annotated[
        Path | None,
        typer.Option(
            "--metadata-file",
            help="JSON metadata file (overrides --name/--category/...).",
            exists=True,
            dir_okay=False,
        ),
    ] = None,
    include_keywords: Annotated[
        bool | None, typer.Option("--include-keywords", help="Include keywords in response.")
    ] = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Create dictionary via multipart upload."""
    metadata = _dictionary_metadata(
        name=name,
        category=category,
        region=region,
        description=description,
        classification=classification,
        file=file,
        metadata_file=metadata_file,
    )
    payload = _keyword_file(file)

    try:
        with DlpClient() as dlp:
            dictionary = dlp.dictionaries.create(
                metadata=metadata, file=payload, include_keywords=include_keywords
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_ack("created", dictionary, output)


@dictionaries_app.command("get")
def dictionaries_get(
    dictionary_id: Annotated[
        str, typer.Argument(metavar="ID", help="Server-assigned dictionary id.")
    ],
    *,
    keywords: Annotated[
        bool | None, typer.Option("--keywords", help="Include the stored keyword list.")
    ] = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Get a dictionary by id."""
    try:
        with DlpClient() as dlp:
            dictionary = dlp.dictionaries.get(
                dictionary_id, include_keywords=True if keywords else None
            )
    except AISecSDKException as err:
        raise fail(err) from err
    render_dictionary(dictionary, output)


@dictionaries_app.command("replace")
def dictionaries_replace(
    dictionary_id: Annotated[str, typer.Argument(metavar="ID", help="Dictionary to replace.")],
    *,
    name: Annotated[str | None, typer.Option("--name", help="Dictionary name.")] = None,
    category: Annotated[
        str | None, typer.Option("--category", help="Dictionary category, e.g. Confidential.")
    ] = None,
    region: Annotated[
        str | None, typer.Option("--region", help="Region the dictionary lives in.")
    ] = None,
    description: Annotated[
        str | None, typer.Option("--description", help="Dictionary description.")
    ] = None,
    classification: Annotated[
        str | None,
        typer.Option("--classification", help="Classification tag, e.g. pab or endpoint."),
    ] = None,
    file: Annotated[
        Path | None,
        typer.Option("--file", help="Keyword file (required).", exists=True, dir_okay=False),
    ] = None,
    metadata_file: Annotated[
        Path | None,
        typer.Option("--metadata-file", help="JSON metadata file.", exists=True, dir_okay=False),
    ] = None,
    include_keywords: Annotated[
        bool | None, typer.Option("--include-keywords", help="Include keywords in response.")
    ] = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """Full-replace a dictionary via multipart upload.

    --file is required. The endpoint answers either 200 with the new state or 204 with no
    body at all; both mean the replace worked, and the 204 is reported as such rather than
    printing nothing.
    """
    metadata = _dictionary_metadata(
        name=name,
        category=category,
        region=region,
        description=description,
        classification=classification,
        file=file,
        metadata_file=metadata_file,
    )
    payload = _keyword_file(file)

    try:
        with DlpClient() as dlp:
            dictionary = dlp.dictionaries.replace(
                dictionary_id, metadata=metadata, file=payload, include_keywords=include_keywords
            )
    except AISecSDKException as err:
        raise fail(err) from err

    if dictionary is None:
        render_dictionary_replaced_fallback(dictionary_id)
        return
    render_ack("replaced", dictionary, output)


@dictionaries_app.command("patch")
def dictionaries_patch(
    dictionary_id: Annotated[str, typer.Argument(metavar="ID", help="Dictionary to update.")],
    *,
    body_file: PatchBodyFileOpt = None,
    set_values: SetOpt = None,
    clear: ClearOpt = None,
    output: OutputOpt = OutputFormat.PRETTY,
) -> None:
    """JSON Merge Patch a dictionary's metadata.

    Metadata only -- the keyword file is replaced through `replace`, which is the multipart
    route. Use --body-file for nested fields.
    """
    request = _validate(DictionaryPatchRequest, _patch_document(body_file, set_values, clear))
    try:
        with DlpClient() as dlp:
            dictionary = dlp.dictionaries.patch(dictionary_id, request)
    except AISecSDKException as err:
        raise fail(err) from err
    render_ack("patched", dictionary, output)


@dictionaries_app.command("delete")
def dictionaries_delete(
    dictionary_id: Annotated[str, typer.Argument(metavar="ID", help="Dictionary to delete.")],
) -> None:
    """Delete a dictionary."""
    try:
        with DlpClient() as dlp:
            dlp.dictionaries.delete(dictionary_id)
    except AISecSDKException as err:
        raise fail(err) from err
    render_id_ack("deleted", dictionary_id)


# ---------------------------------------------------------------------------
# Corpus generation
# ---------------------------------------------------------------------------


class CorpusGenerator(Protocol):
    """The single entry point ``dlp generate`` needs from the corpus generator."""

    def __call__(
        self,
        *,
        types: list[str],
        count: int,
        out: Path,
        techniques: list[str] | str,
        seed: int | None,
    ) -> dict[str, Any]:
        """Write a clean/dirty corpus and return a summary of what it wrote."""


def load_generate_corpus() -> CorpusGenerator:
    """Import the corpus generator on demand.

    Raises:
        typer.Exit: If the generator is not installed. Every other ``airs`` command works
            without it, so its absence is a message about one command rather than a
            broken install.
    """
    try:
        module = importlib.import_module(_GENERATOR_MODULE)
    except ImportError as err:
        raise usage_error(_GENERATOR_MISSING) from err

    generator = getattr(module, "generate_corpus", None)
    if generator is None:
        raise usage_error(_GENERATOR_MISSING)
    return cast("CorpusGenerator", generator)


def _parse_types(value: str) -> list[str]:
    """Resolve ``--types`` into the formats to generate.

    Raises:
        typer.Exit: If any named format is unknown.
    """
    if value == "all":
        return list(GENERATE_FORMATS)

    types = [item.strip().lower() for item in value.split(",")]
    invalid = [item for item in types if item not in GENERATE_FORMATS]
    if invalid:
        raise usage_error(
            f"Unknown type(s): {', '.join(invalid)}. Valid: {', '.join(GENERATE_FORMATS)}"
        )
    return types


@dlp_app.command("generate")
def generate(
    *,
    types: Annotated[
        str,
        typer.Option("--types", metavar="LIST", help="Comma list: pdf,png,jpeg,svg,docx (or all)."),
    ] = "all",
    count: Annotated[int, typer.Option("--count", metavar="N", help="Clean files per type.")] = 1,
    out: Annotated[
        Path, typer.Option("--out", metavar="DIR", help="Output base directory.")
    ] = Path("./temp"),
    techniques: Annotated[
        str,
        typer.Option("--techniques", metavar="LIST", help="all or comma list of technique ids."),
    ] = "all",
    seed: Annotated[
        int | None, typer.Option("--seed", metavar="N", help="Seed for reproducible payloads.")
    ] = None,
    output: Annotated[
        OutputFormat,
        typer.Option("--output", metavar="FORMAT", help="Summary format: pretty or json."),
    ] = OutputFormat.PRETTY,
) -> None:
    """Generate clean + dirty DLP test files across PDF/PNG/JPEG/SVG/DOCX.

    The dirty files carry synthetic sensitive data -- Luhn-valid card numbers from a test
    BIN, SSNs in the 900 area the SSA never issues -- so a DLP policy can be exercised
    end to end without anyone's real data being involved.
    """
    selected = _parse_types(types)
    if count < 1:
        raise usage_error("--count must be a positive integer")
    wanted: list[str] | str = (
        "all" if techniques == "all" else [item.strip() for item in techniques.split(",")]
    )

    generate_corpus = load_generate_corpus()
    try:
        summary = generate_corpus(
            types=selected, count=count, out=out, techniques=wanted, seed=seed
        )
    # Broad on purpose: the generator is optional code writing files, and a stack trace
    # is a worse failure mode for a CLI than one line naming what went wrong.
    except Exception as err:
        raise fail(err) from err
    render_generate_summary(summary, output)


dlp_app.add_typer(filtering_profiles_app)
dlp_app.add_typer(patterns_app)
dlp_app.add_typer(profiles_app)
dlp_app.add_typer(dictionaries_app)
