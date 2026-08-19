"""Operational commands -- doctor, completion, backup, restore, and profile cleanup.

Grouped into one module because none is big enough to earn a file and they share the same
shape: do a series of small things, report each one, then exit on whether any failed.

They do NOT all belong in the same place on the command line, and the root application
mounts them individually rather than merging this whole group:

* ``doctor`` and ``completion`` are top-level, matching the reference.
* ``profiles-cleanup`` is the reference's ``runtime profiles cleanup``.
* ``backup`` and ``restore`` exist in the reference's source but are never registered by
  its ``program.ts``, so the reference CLI has no such commands. They are ported and
  tested here, and exposed deliberately as an addition rather than by accident.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Final
from uuid import uuid4

import typer
import yaml
from pydantic import ValidationError

from prisma_airs import AIGatewayClient, ManagementClient, RedTeamClient, Scanner
from prisma_airs._http.debug import hash_token
from prisma_airs.constants import (
    ENV_AI_SEC_API_KEY,
    ENV_AI_SEC_API_TOKEN,
    ENV_PREFIX_MGMT,
)
from prisma_airs.errors import AISecSDKException
from prisma_airs.models.management import SecurityProfile
from prisma_airs.models.red_team import (
    TargetCreateRequest,
    TargetListItem,
    TargetResponse,
    TargetUpdateRequest,
)
from prisma_airs_cli.config import default_config_path, load_config
from prisma_airs_cli.confirm import confirm_or_abort
from prisma_airs_cli.errors import fail, usage_error
from prisma_airs_cli.exit_codes import EXIT_BLOCKED, EXIT_ERROR
from prisma_airs_cli.output import OutputFormat
from prisma_airs_cli.renderers.ops import (
    BackupResult,
    CleanupDeleteResult,
    DoctorCheck,
    DuplicateGroup,
    ProfileRevision,
    RestoreResult,
    plural,
    render_backup_header,
    render_backup_summary,
    render_cleanup_header,
    render_cleanup_preview,
    render_cleanup_result,
    render_doctor,
    render_no_duplicates,
    render_restore_summary,
)
from prisma_airs_cli.ui import ui

ops_app = typer.Typer(no_args_is_help=True)


# ---------------------------------------------------------------------------
# Doctor
# ---------------------------------------------------------------------------

#: Budget for each network probe. The reference races the call against a timer; here the
#: same budget is handed to the HTTP client, which is where the waiting actually happens.
DOCTOR_TIMEOUT_SECONDS: Final = 5.0

#: The floor the package declares in its metadata.
MIN_PYTHON: Final[tuple[int, int]] = (3, 10)

#: Management credentials are a group: two of the three is the same as none.
MGMT_ENV_VARS: Final[tuple[str, ...]] = tuple(
    f"{ENV_PREFIX_MGMT}_{suffix}" for suffix in ("CLIENT_ID", "CLIENT_SECRET", "TSG_ID")
)

#: The scan API reports a rejected key in the message rather than in the status, so the
#: text is the only signal available for that case.
_AUTH_REJECTED = re.compile(
    r"invalid api key|invalid.*oauth token|api key or oauth token|unauthorized|forbidden",
    re.IGNORECASE,
)
_OAUTH_FAILED = re.compile(r"oauth|invalid_client", re.IGNORECASE)

_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403


class DoctorFormat(str, Enum):
    """Formats ``doctor`` can report in."""

    PRETTY = "pretty"
    JSON = "json"
    YAML = "yaml"


def check_python_version(version: tuple[int, int] | None = None) -> DoctorCheck:
    """Check the interpreter is new enough to run this CLI."""
    running = version if version is not None else sys.version_info[:2]
    rendered = ".".join(str(part) for part in running)
    minimum = ".".join(str(part) for part in MIN_PYTHON)
    if running >= MIN_PYTHON:
        return DoctorCheck("Python version", "pass", f"{rendered} (>= {minimum} required)")
    return DoctorCheck(
        "Python version",
        "fail",
        f"{rendered} is below the required Python {minimum}",
        hint=f"Install Python {minimum}+ and reinstall the CLI into it",
    )


def check_config_file(path: Path | None = None) -> DoctorCheck:
    """Check the config file parses.

    An absent file is normal -- an environment-only install never writes one -- so it
    warns rather than fails. A file that exists but cannot be parsed is a real problem:
    every setting in it is being silently ignored.
    """
    config_path = path if path is not None else default_config_path()
    if not config_path.is_file():
        return DoctorCheck(
            "Config file",
            "warn",
            f"not found at {config_path} — using env vars and defaults",
            hint="Create one with 'airs config set <key> <value>' (optional)",
        )
    try:
        load_config(config_path)
    except ValueError as err:
        return DoctorCheck(
            "Config file",
            "fail",
            str(err),
            hint="Fix or delete the file, then re-run doctor",
        )
    return DoctorCheck("Config file", "pass", f"valid JSON at {config_path}")


def check_scanner_credentials(env: Mapping[str, str] | None = None) -> DoctorCheck:
    """Check a scan-API credential is available.

    The value is digested, never shown: this output is meant to be pasteable into a
    ticket, and a fingerprint is enough to tell two keys apart.
    """
    environ = env if env is not None else os.environ
    for name in (ENV_AI_SEC_API_KEY, ENV_AI_SEC_API_TOKEN):
        value = environ.get(name)
        if value:
            return DoctorCheck("Scanner credentials", "pass", f"{name} set ({hash_token(value)})")
    return DoctorCheck(
        "Scanner credentials",
        "fail",
        f"{ENV_AI_SEC_API_KEY} is not set",
        hint=f"Set {ENV_AI_SEC_API_KEY} (or {ENV_AI_SEC_API_TOKEN}) in the environment",
    )


def check_management_credentials(env: Mapping[str, str] | None = None) -> DoctorCheck:
    """Check the OAuth client-credentials trio is complete.

    Every value is digested, the tenant ID included: it identifies the customer even
    though it is not secret.
    """
    environ = env if env is not None else os.environ
    missing = [name for name in MGMT_ENV_VARS if not environ.get(name)]
    if not missing:
        detail = ", ".join(f"{name} ({hash_token(environ[name])})" for name in MGMT_ENV_VARS)
        return DoctorCheck("Management credentials", "pass", f"set: {detail}")
    return DoctorCheck(
        "Management credentials",
        "fail",
        f"missing: {', '.join(missing)}",
        hint=f"Set {', '.join(missing)}",
    )


def ai_gateway_grant_hint(err: AISecSDKException) -> str | None:
    """Name the SCM grant a 403 from the AI Gateway is complaining about.

    The two planes authorise against different role scopes and the bodies differ only by
    an error code, so without this the same "access denied" sends people to the wrong
    half of Access Management.
    """
    if err.status_code != _HTTP_FORBIDDEN:
        return None
    grant = (
        "the service account is missing a workspace-scope grant (data plane, /ai_gw/v2)"
        if "AB03" in err.raw_message
        else "the service account is missing a tenant-root admin grant "
        "(admin plane, /ai_gw/admin/v2)"
    )
    return (
        f"{grant}. SCM Access Management edits the existing role row by default — "
        'use "Add Role" so the account ends up with both role rows, not one row moved.'
    )


def check_scanner_api(probe: Callable[[], object], has_key: bool) -> DoctorCheck:
    """Probe the scan API for reachability and key validity.

    Any HTTP status other than 401/403 still proves the endpoint answered and the key was
    accepted -- the probe query itself being refused is not an environment problem.
    """
    name = "Scanner API"
    if not has_key:
        return DoctorCheck(
            name,
            "warn",
            "skipped — no scanner API key configured",
            hint=f"Set {ENV_AI_SEC_API_KEY} to enable this check",
        )
    try:
        probe()
    except AISecSDKException as err:
        status = err.status_code
        rejected = status in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN) or _AUTH_REJECTED.search(
            err.raw_message
        )
        if rejected:
            suffix = f" (HTTP {status})" if status is not None else ""
            return DoctorCheck(
                name,
                "fail",
                f"API key rejected{suffix}: {err.raw_message}",
                hint=f"Verify {ENV_AI_SEC_API_KEY} belongs to this tenant and is not expired",
            )
        if status is not None:
            return DoctorCheck(
                name,
                "pass",
                f"endpoint reachable, API key accepted (HTTP {status} on probe query)",
            )
        return DoctorCheck(
            name,
            "fail",
            f"network unreachable: {err.raw_message}",
            hint="Check network connectivity, proxy settings, and DNS",
        )
    return DoctorCheck(name, "pass", "endpoint reachable, API key accepted")


def check_management_auth(probe: Callable[[], int], has_creds: bool) -> DoctorCheck:
    """Probe the management plane with the smallest authenticated read there is."""
    name = "Management OAuth"
    if not has_creds:
        return DoctorCheck(
            name,
            "warn",
            "skipped — management credentials not configured",
            hint=f"Set {', '.join(MGMT_ENV_VARS)}",
        )
    try:
        count = probe()
    except AISecSDKException as err:
        message = err.raw_message
        if err.status_code is not None:
            detail = f"management API error (HTTP {err.status_code}): {message}"
        elif _AUTH_REJECTED.search(message) or _OAUTH_FAILED.search(message):
            detail = f"authentication failed: {message}"
        else:
            detail = f"network unreachable: {message}"
        return DoctorCheck(name, "fail", detail, hint=f"Verify {', '.join(MGMT_ENV_VARS)}")
    return DoctorCheck(
        name,
        "pass",
        f"OAuth token obtained, topics API answered ({plural(count, 'custom topic')})",
    )


def check_ai_gateway_api(probe: Callable[[], int], has_creds: bool) -> DoctorCheck:
    """Probe the AI Gateway data plane, which shares the management credentials.

    A 403 warns rather than fails. The endpoint answered and OAuth succeeded; the account
    simply holds no AI Gateway grant, which is a valid configuration for a tenant that
    does not use the gateway, and a preflight should not fail those.
    """
    name = "AI Gateway API"
    if not has_creds:
        return DoctorCheck(
            name,
            "warn",
            "skipped — management credentials not configured",
            hint=f"Set {', '.join(MGMT_ENV_VARS)}",
        )
    try:
        count = probe()
    except AISecSDKException as err:
        if err.status_code == _HTTP_FORBIDDEN:
            return DoctorCheck(
                name,
                "warn",
                f"endpoint reachable, but access denied (HTTP 403): {err.raw_message}",
                hint=ai_gateway_grant_hint(err),
            )
        detail = (
            f"AI Gateway API error (HTTP {err.status_code}): {err.raw_message}"
            if err.status_code is not None
            else f"network unreachable: {err.raw_message}"
        )
        return DoctorCheck(name, "fail", detail, hint="Verify credentials and the gateway endpoint")
    return DoctorCheck(name, "pass", f"endpoint reachable ({plural(count, 'workspace')} in scope)")


def _scanner_probe() -> object:
    """Read scan results for a random ID.

    The scan API's only other surfaces submit content and burn quota. This is a GET that
    authenticates the key and proves reachability without scanning anything; an empty
    result is a perfectly good answer.
    """
    with Scanner(num_retries=0, timeout=DOCTOR_TIMEOUT_SECONDS) as scanner:
        return scanner.query_by_scan_ids([str(uuid4())])


def _management_probe() -> int:
    """Count custom topics -- the cheapest authenticated management read."""
    with ManagementClient(num_retries=0, timeout=DOCTOR_TIMEOUT_SECONDS) as client:
        return len(client.topics.list().custom_topics)


def _ai_gateway_probe() -> int:
    """Count workspaces in scope -- the cheapest authenticated gateway read."""
    with AIGatewayClient(num_retries=0, timeout=DOCTOR_TIMEOUT_SECONDS) as client:
        return len(client.workspaces.list().data)


def run_doctor() -> list[DoctorCheck]:
    """Run every check in order, never raising.

    A probe is only attempted when the credentials it needs are present, so a bare
    install reports "not configured" rather than a pile of connection errors.
    """
    scanner_creds = check_scanner_credentials()
    mgmt_creds = check_management_credentials()
    return [
        check_python_version(),
        check_config_file(),
        scanner_creds,
        mgmt_creds,
        check_scanner_api(_scanner_probe, scanner_creds.status == "pass"),
        check_management_auth(_management_probe, mgmt_creds.status == "pass"),
        check_ai_gateway_api(_ai_gateway_probe, mgmt_creds.status == "pass"),
    ]


def has_failure(checks: list[DoctorCheck]) -> bool:
    """Report whether any check failed. Warnings do not count."""
    return any(check.status == "fail" for check in checks)


@ops_app.command("doctor")
def doctor(
    *,
    output: Annotated[
        DoctorFormat, typer.Option("--output", help="Output format: pretty, json, or yaml.")
    ] = DoctorFormat.PRETTY,
) -> None:
    """Check credentials, config, and API connectivity (preflight).

    Exits 1 when any check failed, so a deploy script can gate on it. That is a verdict
    about the environment, not a CLI failure: the report was produced either way.
    """
    checks = run_doctor()
    render_doctor(checks, OutputFormat(output.value))
    if has_failure(checks):
        raise typer.Exit(EXIT_BLOCKED)


# ---------------------------------------------------------------------------
# Completion
# ---------------------------------------------------------------------------


class CompletionShell(str, Enum):
    """Shells a completion script can be generated for."""

    BASH = "bash"
    ZSH = "zsh"
    FISH = "fish"


@dataclass(frozen=True)
class CompletionNode:
    """The words that may follow one command path.

    Attributes:
        path: Space-joined command path below the root; empty at the root itself.
        words: Subcommand names and visible long flags valid at that path.
    """

    path: str
    words: tuple[str, ...]


def collect_completion_nodes(command: Any, path: tuple[str, ...] = ()) -> list[CompletionNode]:
    """Walk a Click command tree, collecting one suggestion node per command path.

    Positional argument values are not completed -- their values come from the API, and a
    completion script that has to make a network call is a completion script people turn
    off. Subcommands are emitted in sorted order so the generated script is reproducible.

    Args:
        command: The Click command to walk. Typed loosely because Typer vendors its own
            copy of Click, so there is no importable ``click`` package to annotate with.
        path: Command path accumulated so far, used by the recursion.

    Returns:
        One node for this command, followed by one for each descendant.
    """
    subcommands: dict[str, Any] = getattr(command, "commands", {})
    words: list[str] = sorted(subcommands)
    for param in getattr(command, "params", []):
        if getattr(param, "hidden", False):
            continue
        # Long flags only: a completion listing "-p" alongside "--prompt" is noise.
        words.extend(opt for opt in param.opts if opt.startswith("--"))
    # Click adds --help when it builds the parser rather than storing it as a param.
    words.append("--help")

    node = CompletionNode(path=" ".join(path), words=tuple(dict.fromkeys(words)))
    children = [
        child
        for name in sorted(subcommands)
        for child in collect_completion_nodes(subcommands[name], (*path, name))
    ]
    return [node, *children]


# Placeholders are @-delimited rather than str.format fields: these scripts are dense with
# braces and dollars, and doubling every one of them to escape it invites a silent typo.
_BASH_TEMPLATE = """#!/usr/bin/env bash
# Bash completion for @NAME@ (Prisma AIRS CLI). Generated by `@NAME@ completion bash`.
#
# Install: @NAME@ completion bash > ~/.local/share/bash-completion/completions/@NAME@
#   or:    echo 'source <(@NAME@ completion bash)' >> ~/.bashrc

_@NAME@_completions() {
  local cur path i w words
  cur="${COMP_WORDS[COMP_CWORD]}"
  path=""
  for ((i = 1; i < COMP_CWORD; i++)); do
    w="${COMP_WORDS[i]}"
    [[ "$w" == -* ]] && continue
    path="${path:+$path }$w"
  done
  words=""
  case "$path" in
@CASES@
    *) words="" ;;
  esac
  COMPREPLY=( $(compgen -W "$words" -- "$cur") )
}
complete -F _@NAME@_completions @NAME@
"""

_ZSH_TEMPLATE = """#compdef @NAME@
# Zsh completion for @NAME@ (Prisma AIRS CLI). Generated by `@NAME@ completion zsh`.
#
# Install: mkdir -p ~/.zfunc && @NAME@ completion zsh > ~/.zfunc/_@NAME@
#   then in ~/.zshrc (before compinit): fpath+=(~/.zfunc)
#   and ensure: autoload -Uz compinit && compinit

_@NAME@() {
  local -a completions
  local path="" w
  for w in "${(@)words[2,CURRENT-1]}"; do
    [[ "$w" == -* ]] && continue
    path="${path:+$path }$w"
  done
  completions=()
  case "$path" in
@CASES@
  esac
  compadd -- "${completions[@]}"
}
_@NAME@ "$@"
"""

_FISH_TEMPLATE = """# Fish completion for @NAME@ (Prisma AIRS CLI). \
Generated by `@NAME@ completion fish`.
#
# Install: @NAME@ completion fish > ~/.config/fish/completions/@NAME@.fish

function __@NAME@_using
    set -l target $argv[1]
    set -l tokens (commandline -opc)
    set -l path
    for w in $tokens[2..-1]
        string match -q -- '-*' $w
        and continue
        set -a path $w
    end
    test "$path" = "$target"
end

complete -c @NAME@ -f
@CASES@
"""


def _render_template(template: str, name: str, cases: str) -> str:
    """Fill a shell-script template with the program name and its case arms."""
    return template.replace("@NAME@", name).replace("@CASES@", cases)


def generate_bash_completion(name: str, nodes: list[CompletionNode]) -> str:
    """Build a bash completion script."""
    cases = "\n".join(f"""    '{n.path}') words="{" ".join(n.words)}" ;;""" for n in nodes)
    return _render_template(_BASH_TEMPLATE, name, cases)


def generate_zsh_completion(name: str, nodes: list[CompletionNode]) -> str:
    """Build a zsh completion script."""
    cases = "\n".join(f"    '{n.path}') completions=({' '.join(n.words)}) ;;" for n in nodes)
    return _render_template(_ZSH_TEMPLATE, name, cases)


def generate_fish_completion(name: str, nodes: list[CompletionNode]) -> str:
    """Build a fish completion script."""
    cases = "\n".join(
        f"complete -c {name} -n '__{name}_using \"{n.path}\"' -a '{' '.join(n.words)}'"
        for n in nodes
    )
    return _render_template(_FISH_TEMPLATE, name, cases)


_GENERATORS: Final[dict[CompletionShell, Callable[[str, list[CompletionNode]], str]]] = {
    CompletionShell.BASH: generate_bash_completion,
    CompletionShell.ZSH: generate_zsh_completion,
    CompletionShell.FISH: generate_fish_completion,
}


@ops_app.command("completion")
def completion(
    *,
    ctx: typer.Context,
    shell: Annotated[CompletionShell, typer.Argument(help="Shell to generate a script for.")],
) -> None:
    """Generate a shell completion script (bash, zsh, fish).

    The tree is read from the running program rather than a hard-coded list, so the
    script cannot drift from the commands that actually exist.
    """
    root = ctx.find_root()
    name = root.info_name or "airs"
    nodes = collect_completion_nodes(root.command)
    # stdout only, and unstyled: the script is the payload, usually being redirected.
    sys.stdout.write(_GENERATORS[shell](name, nodes))


# ---------------------------------------------------------------------------
# Backup and restore
# ---------------------------------------------------------------------------

#: Envelope schema version. Bumped only on a breaking change to the file layout.
BACKUP_VERSION: Final = "1"

#: Discriminator, so one directory can hold backups of more than one resource kind.
BACKUP_RESOURCE_TYPE: Final = "redteam-target"

#: Targets are listed a page at a time; the service caps a page well above this.
TARGET_PAGE_SIZE: Final = 100

#: Fields the service assigns. Sending one back on create or update is at best ignored.
SERVER_DERIVED_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "uuid",
        "tsg_id",
        "status",
        "active",
        "validated",
        "version",
        "secret_version",
        "created_at",
        "updated_at",
        "created_by_user_id",
        "updated_by_user_id",
    }
)

#: What a target's create request will accept. Anything the read model returns that is
#: not in here cannot be restored, so backing it up would only produce a file that fails
#: to restore later.
_RESTORABLE_FIELDS: Final[frozenset[str]] = frozenset(TargetCreateRequest.model_fields)


class BackupFormat(str, Enum):
    """Serialisation formats a backup file can be written in."""

    JSON = "json"
    YAML = "yaml"


def sanitize_filename(name: str) -> str:
    """Reduce a target name to a safe filename stem.

    Lowercased, non-alphanumerics collapsed to single hyphens, and never empty -- a
    target named ``***`` must not produce a file called ``.json``.
    """
    sanitized = re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9-]", "-", name.lower())).strip("-")
    return sanitized or "unnamed"


def resolve_output_dir(user_dir: Path | None, default_subdir: str) -> Path:
    """Resolve where backups are written: the given directory, or ``./airs-backup/<kind>``."""
    if user_dir is not None:
        return user_dir.resolve()
    return (Path("./airs-backup") / default_subdir).resolve()


def strip_nulls(value: Any) -> Any:
    """Drop null-valued keys, recursively.

    The service is happy to return ``null`` for anything it has no value for; writing
    those into a backup makes the file harder to read and, on restore, asks the API to
    unset fields the operator never touched.
    """
    if isinstance(value, list):
        return [strip_nulls(item) for item in value]
    if isinstance(value, dict):
        return {k: strip_nulls(v) for k, v in value.items() if v is not None}
    return value


def to_backup_data(target: TargetResponse) -> dict[str, Any]:
    """Convert a target as read into the shape a create request takes.

    Credentials are never part of this: the API does not return them, so a restored
    target needs its secrets supplied again.
    """
    dumped = target.model_dump(mode="json", exclude_none=True)
    return dict(strip_nulls({k: v for k, v in dumped.items() if k in _RESTORABLE_FIELDS}))


def write_backup_file(
    directory: Path, filename: str, envelope: dict[str, Any], fmt: BackupFormat
) -> Path:
    """Serialise one envelope into ``directory``, creating it if needed.

    The file is written ``0600``. A target definition carries endpoints, headers, and
    request templates; none of that belongs to every account on the machine.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{filename}.{fmt.value}"
    if fmt is BackupFormat.YAML:
        text = yaml.safe_dump(envelope, sort_keys=False, default_flow_style=False, width=1_000_000)
    else:
        text = json.dumps(envelope, indent=2) + "\n"
    path.write_text(text)
    path.chmod(0o600)
    return path


def read_backup_file(path: Path) -> dict[str, Any]:
    """Read one backup file, choosing the parser by extension.

    Raises:
        ValueError: If the extension is unknown or the content is not an envelope.
    """
    suffix = path.suffix.lower()
    if suffix not in {".json", ".yaml", ".yml"}:
        raise ValueError(f"Unsupported file format: {suffix} (expected .json, .yaml, or .yml)")
    raw = path.read_text()
    parsed = json.loads(raw) if suffix == ".json" else yaml.safe_load(raw)
    if not isinstance(parsed, dict) or "version" not in parsed or "data" not in parsed:
        raise ValueError(f"Invalid backup file: {path} (missing version or data)")
    return parsed


def read_backup_dir(directory: Path, resource_type: str) -> list[dict[str, Any]]:
    """Read every backup of ``resource_type`` in a directory.

    Unreadable and unrelated files are skipped rather than fatal: a backup directory
    accumulates README files and half-written exports, and one of those must not stop a
    restore of the twenty files beside it.
    """
    envelopes: list[dict[str, Any]] = []
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
            continue
        try:
            envelope = read_backup_file(path)
        except (ValueError, OSError, yaml.YAMLError):
            continue
        if envelope.get("resourceType") == resource_type:
            envelopes.append(envelope)
    return envelopes


def list_all_targets(client: RedTeamClient) -> list[TargetListItem]:
    """Page through every target the credentials can see."""
    rows: list[TargetListItem] = []
    skip = 0
    while True:
        page = client.targets.list(skip=skip, limit=TARGET_PAGE_SIZE)
        data = page.data or []
        rows.extend(data)
        total = page.pagination.total_items
        if not data or len(data) < TARGET_PAGE_SIZE or (total is not None and len(rows) >= total):
            return rows
        skip += TARGET_PAGE_SIZE


def backup_targets(
    *, directory: Path, fmt: BackupFormat, name: str | None = None
) -> list[BackupResult]:
    """Write one backup file per target.

    A target that cannot be read is recorded and the run continues -- the point of a
    backup command is to save what it can.

    Raises:
        typer.Exit: If ``name`` matches no target.
    """
    with RedTeamClient() as client:
        targets = list_all_targets(client)
        if name is not None:
            targets = [t for t in targets if t.name == name]
            if not targets:
                raise usage_error(f"Target not found: {name}")

        exported_at = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")
        results: list[BackupResult] = []
        for target in targets:
            stem = sanitize_filename(target.name)
            try:
                detail = client.targets.get(target.uuid)
                envelope = {
                    # camelCase keys: the same files are read and written by the
                    # TypeScript client, so the envelope is a shared format.
                    "version": BACKUP_VERSION,
                    "resourceType": BACKUP_RESOURCE_TYPE,
                    "exportedAt": exported_at,
                    "data": to_backup_data(detail),
                }
                write_backup_file(directory, stem, envelope, fmt)
            except (AISecSDKException, OSError) as err:
                results.append(BackupResult(target.name, "", "failed", error=str(err)))
            else:
                results.append(BackupResult(target.name, f"{stem}.{fmt.value}", "ok"))
        return results


def prepare_target_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Strip server-assigned fields and rename the legacy ones.

    Older backups spell two fields ``background`` and ``metadata``; the API has since
    renamed both. Translating here means a file written by an older client still
    restores, without the read path having to know about the API at all.
    """
    clean = {k: v for k, v in data.items() if k not in SERVER_DERIVED_FIELDS}
    for legacy, current in (("background", "target_background"), ("metadata", "target_metadata")):
        if legacy in clean:
            clean.setdefault(current, clean[legacy])
            del clean[legacy]
    return clean


#: Routing defaults. The API requires the four-tuple (target type, connection type,
#: endpoint type, response mode) on every write, and a backup taken before one of them
#: existed will be missing it.
_ROUTING_DEFAULTS: Final[dict[str, str]] = {
    "connection_type": "CUSTOM",
    "api_endpoint_type": "PUBLIC",
    "response_mode": "REST",
}


def _apply_routing_defaults(payload: dict[str, Any], current: TargetResponse | None) -> None:
    """Fill in any missing routing field, preferring the stored target's own value."""
    if current is not None and not payload.get("target_type"):
        payload["target_type"] = current.target_type
    for field, default in _ROUTING_DEFAULTS.items():
        if payload.get(field):
            continue
        existing = getattr(current, field, None) if current is not None else None
        payload[field] = existing or default


def restore_targets(
    *,
    envelopes: list[dict[str, Any]],
    overwrite: bool,
    validate: bool,
) -> list[RestoreResult]:
    """Create or update one target per envelope.

    A target whose name already exists is skipped unless ``overwrite`` is set, so a
    restore into a live tenant is safe to run by mistake.
    """
    with RedTeamClient() as client:
        existing = {t.name: t.uuid for t in list_all_targets(client)}
        # Sent only when asked for: the service has its own default, and forcing
        # validate=false would suppress a check the operator may have configured on.
        validate_flag = True if validate else None
        results: list[RestoreResult] = []

        for envelope in envelopes:
            data = envelope.get("data")
            if not isinstance(data, dict) or not data.get("name"):
                results.append(
                    RestoreResult("<unnamed>", "failed", error="backup has no target name")
                )
                continue
            name = str(data["name"])
            uuid = existing.get(name)
            if uuid and not overwrite:
                results.append(RestoreResult(name, "skipped"))
                continue
            try:
                payload = prepare_target_payload(dict(data))
                if uuid:
                    _apply_routing_defaults(payload, client.targets.get(uuid))
                    body = TargetUpdateRequest.model_validate(payload)
                    client.targets.update(uuid, body, validate=validate_flag)
                    results.append(RestoreResult(name, "updated"))
                else:
                    _apply_routing_defaults(payload, None)
                    create = TargetCreateRequest.model_validate(payload)
                    client.targets.create(create, validate=validate_flag)
                    results.append(RestoreResult(name, "created"))
            except (AISecSDKException, ValidationError) as err:
                results.append(RestoreResult(name, "failed", error=str(err)))
        return results


@ops_app.command("backup")
def backup(
    *,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="Directory to write backup files into."),
    ] = None,
    output: Annotated[
        BackupFormat, typer.Option("--output", help="File format: json or yaml.")
    ] = BackupFormat.JSON,
    name: Annotated[
        str | None, typer.Option("--name", help="Back up a single target by name.")
    ] = None,
) -> None:
    """Backup red team targets to local JSON/YAML files.

    Writes one file per target into ``./airs-backup/targets`` unless told otherwise.
    Exits 2 if any target could not be written, so a backup job fails loudly rather than
    leaving a gap nobody notices until the restore.
    """
    render_backup_header()
    directory = resolve_output_dir(output_dir, "targets")
    try:
        results = backup_targets(directory=directory, fmt=output, name=name)
    except AISecSDKException as err:
        raise fail(err) from err

    render_backup_summary(results, directory)
    if any(result.status == "failed" for result in results):
        raise typer.Exit(EXIT_ERROR)


@ops_app.command("restore")
def restore(
    *,
    input_dir: Annotated[
        Path | None,
        typer.Option("--input-dir", help="Directory containing backup files."),
    ] = None,
    file: Annotated[
        Path | None, typer.Option("--file", help="Single backup file to restore.")
    ] = None,
    overwrite: Annotated[
        bool, typer.Option("--overwrite", help="Update existing targets with the same name.")
    ] = False,
    validate: Annotated[
        bool, typer.Option("--validate", help="Validate the target connection before saving.")
    ] = False,
) -> None:
    """Restore red team targets from local JSON/YAML backup files.

    Existing targets are left alone unless ``--overwrite`` is given. Exits 2 if any
    target failed to restore.
    """
    if file is None and input_dir is None:
        raise usage_error("Specify --file <path> or --input-dir <path>")

    render_backup_header()
    try:
        if file is not None:
            envelope = read_backup_file(file)
            if (
                envelope.get("version") != BACKUP_VERSION
                or envelope.get("resourceType") != BACKUP_RESOURCE_TYPE
            ):
                raise usage_error(
                    f"Invalid backup: version={envelope.get('version')}, "
                    f"resourceType={envelope.get('resourceType')}"
                )
            envelopes = [envelope]
        else:
            # input_dir is not None here: the pair is validated above.
            envelopes = read_backup_dir(Path(str(input_dir)), BACKUP_RESOURCE_TYPE)
    except (ValueError, OSError, yaml.YAMLError) as err:
        raise usage_error(str(err)) from err

    if not envelopes:
        raise usage_error("No valid backup files found")

    try:
        results = restore_targets(envelopes=envelopes, overwrite=overwrite, validate=validate)
    except AISecSDKException as err:
        raise fail(err) from err

    render_restore_summary(results)
    if any(result.action == "failed" for result in results):
        raise typer.Exit(EXIT_ERROR)


# ---------------------------------------------------------------------------
# Profile cleanup
# ---------------------------------------------------------------------------

#: Profiles are fetched a page at a time; a busy tenant has thousands of revisions.
PROFILE_PAGE_SIZE: Final = 200


class CleanupFormat(str, Enum):
    """Formats ``profiles-cleanup`` can report in."""

    PRETTY = "pretty"
    JSON = "json"


def _revision_of(profile: SecurityProfile) -> int:
    """Read a profile's revision as an integer.

    The API types the field as a number, but only ever issues whole revisions; an absent
    one sorts as zero so it is never the revision that survives a cleanup.
    """
    return int(profile.revision) if profile.revision is not None else 0


def find_duplicate_profiles(profiles: list[SecurityProfile]) -> list[DuplicateGroup]:
    """Group profiles by name, keeping the highest revision of each.

    Profiles are versioned in place, so a name legitimately resolves to several stored
    records; only the newest is reachable by name, and the rest are dead weight.
    Records without an ID are ignored -- they cannot be deleted, so they cannot be
    cleaned up.
    """
    groups: dict[str, list[ProfileRevision]] = {}
    for profile in profiles:
        if not profile.profile_id:
            continue
        entry = ProfileRevision(profile.profile_id, _revision_of(profile))
        groups.setdefault(profile.profile_name, []).append(entry)

    duplicates: list[DuplicateGroup] = []
    for name, entries in groups.items():
        if len(entries) <= 1:
            continue
        ordered = sorted(entries, key=lambda e: e.revision, reverse=True)
        duplicates.append(DuplicateGroup(name, ordered[0], tuple(ordered[1:])))
    return duplicates


def list_all_profiles(client: ManagementClient) -> list[SecurityProfile]:
    """Page through every security profile in the tenant."""
    profiles: list[SecurityProfile] = []
    offset = 0
    while True:
        page = client.profiles.list(limit=PROFILE_PAGE_SIZE, offset=offset)
        profiles.extend(page.ai_profiles)
        if page.next_offset is None:
            return profiles
        next_offset = int(page.next_offset)
        # A next offset that does not advance would loop forever. Stopping loses at most
        # the tail of a listing; not stopping hangs the command.
        if next_offset <= offset:
            return profiles
        offset = next_offset


def resolve_updated_by(flag: str | None) -> str:
    """Resolve the email recorded against each deletion.

    Falls back to the local Git identity, which is almost always the operator's own
    address and saves typing it on every invocation.

    Raises:
        typer.Exit: If no email was given and Git has none configured.
    """
    if flag:
        return flag
    try:
        # Fixed argument list, no shell, no caller-supplied input. Git is resolved from
        # PATH deliberately: hard-coding /usr/bin/git would break every other install.
        completed = subprocess.run(
            ["git", "config", "user.email"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        raise usage_error(
            "--updated-by <email> is required (could not detect git user.email)"
        ) from None
    email = completed.stdout.strip()
    if not email:
        raise usage_error("--updated-by <email> is required (git user.email is empty)")
    return email


def _delete_revisions(
    client: ManagementClient, groups: list[DuplicateGroup], updated_by: str, pretty: bool
) -> list[CleanupDeleteResult]:
    """Force-delete every superseded revision, reporting each as it goes."""
    results: list[CleanupDeleteResult] = []
    for group in groups:
        for entry in group.remove:
            try:
                client.profiles.force_delete(entry.profile_id, updated_by)
            except AISecSDKException as err:
                results.append(
                    CleanupDeleteResult(
                        entry.profile_id, entry.revision, group.name, "failed", error=str(err)
                    )
                )
                if pretty:
                    ui.bullet(f"{group.name} rev {entry.revision}: {err}", "error")
            else:
                results.append(
                    CleanupDeleteResult(entry.profile_id, entry.revision, group.name, "ok")
                )
                if pretty:
                    ui.bullet(f"{group.name} rev {entry.revision}", "success")
    return results


@ops_app.command("profiles-cleanup")
def profiles_cleanup(
    *,
    force: Annotated[
        bool, typer.Option("--force", help="Skip confirmation — proceed with deletion.")
    ] = False,
    updated_by: Annotated[
        str | None,
        typer.Option("--updated-by", help="Email for the deletion audit trail."),
    ] = None,
    output: Annotated[
        CleanupFormat, typer.Option("--output", help="Output format: pretty or json.")
    ] = CleanupFormat.PRETTY,
) -> None:
    """Delete old profile revisions, keeping only the latest per name.

    Without ``--force`` and without a terminal to ask, this prints the plan and stops:
    a scheduled job that forgot the flag reports what it would have deleted instead of
    deleting it.
    """
    fmt = OutputFormat(output.value)
    pretty = fmt is OutputFormat.PRETTY
    if pretty:
        render_cleanup_header()

    try:
        with ManagementClient() as client:
            groups = find_duplicate_profiles(list_all_profiles(client))
            if not groups:
                render_no_duplicates(fmt)
                return

            render_cleanup_preview(groups, fmt)

            if not force:
                if not sys.stdout.isatty():
                    if pretty:
                        ui.dim("Pass --force to delete these revisions.")
                    return
                total = sum(len(group.remove) for group in groups)
                confirm_or_abort(
                    f"Delete {plural(total, 'old profile revision')}?",
                    force=False,
                    action="delete profile revisions",
                )

            results = _delete_revisions(client, groups, resolve_updated_by(updated_by), pretty)
    except AISecSDKException as err:
        raise fail(err) from err

    render_cleanup_result(results, fmt)
    if any(result.status == "failed" for result in results):
        raise typer.Exit(EXIT_ERROR)
