"""Configuration file handling.

Settings resolve in the order a user expects: an explicit flag beats the environment,
which beats the config file, which beats the built-in default. The file lives beside the
credentials at ``~/.prisma-airs/config.json``, matching where the other Prisma AIRS
clients keep theirs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final

#: Keys the CLI recognises. Anything else in the file is preserved but ignored, so a
#: newer client's settings survive a round trip through an older one.
KNOWN_KEYS: Final[tuple[str, ...]] = (
    "profile",
    "region",
    "endpoint",
    "num_retries",
    "output",
)

#: Config keys that may also be supplied through the environment.
_ENV_OVERRIDES: Final[dict[str, str]] = {
    "profile": "PANW_AI_SEC_PROFILE",
    "region": "PANW_AI_SEC_REGION",
    "endpoint": "PANW_AI_SEC_API_ENDPOINT",
}


def default_config_path() -> Path:
    """Return the config file location, honouring ``PRISMA_AIRS_CONFIG``."""
    override = os.environ.get("PRISMA_AIRS_CONFIG")
    return Path(override) if override else Path.home() / ".prisma-airs" / "config.json"


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Read the config file, returning an empty mapping when there is none.

    A missing file is normal and not an error. A malformed one is an error worth
    surfacing, since silently ignoring it would apply defaults the user did not choose.

    Raises:
        ValueError: If the file exists but is not a JSON object.
    """
    config_path = path or default_config_path()
    if not config_path.is_file():
        return {}

    try:
        parsed = json.loads(config_path.read_text())
    except json.JSONDecodeError as err:
        raise ValueError(f"{config_path} is not valid JSON: {err}") from err

    if not isinstance(parsed, dict):
        raise ValueError(f"{config_path} must contain a JSON object")
    return parsed


def save_config(values: dict[str, Any], path: Path | None = None) -> Path:
    """Write the config file, creating the directory and restricting permissions.

    The file sits in the same directory as credentials, so it is created ``0600`` even
    though it holds no secrets itself.
    """
    config_path = path or default_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n")
    config_path.chmod(0o600)
    return config_path


def resolve(
    key: str,
    flag_value: Any = None,
    *,
    config: dict[str, Any] | None = None,
    default: Any = None,
) -> Any:
    """Resolve one setting across flag, environment, config file, and default.

    Args:
        key: One of :data:`KNOWN_KEYS`.
        flag_value: Value supplied on the command line, if any.
        config: Already-loaded config mapping.
        default: Fallback when nothing else supplies a value.

    Returns:
        The winning value.
    """
    if flag_value is not None:
        return flag_value

    env_name = _ENV_OVERRIDES.get(key)
    if env_name:
        env_value = os.environ.get(env_name)
        if env_value:
            return env_value

    if config and config.get(key) is not None:
        return config[key]

    return default
