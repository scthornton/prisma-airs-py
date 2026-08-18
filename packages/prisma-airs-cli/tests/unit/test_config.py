"""Config file loading and setting precedence."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from prisma_airs_cli.config import default_config_path, load_config, resolve, save_config


class TestLoadConfig:
    def test_a_missing_file_is_not_an_error(self, tmp_path: Path) -> None:
        """Most users never create one, and that is a supported state."""
        assert load_config(tmp_path / "absent.json") == {}

    def test_reads_an_object(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_text('{"profile": "prod"}')

        assert load_config(path) == {"profile": "prod"}

    def test_reports_malformed_json_rather_than_ignoring_it(self, tmp_path: Path) -> None:
        """Silently falling back would apply defaults the user did not choose."""
        path = tmp_path / "config.json"
        path.write_text("{not json")

        with pytest.raises(ValueError, match="not valid JSON"):
            load_config(path)

    def test_rejects_a_non_object_document(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_text('["a", "list"]')

        with pytest.raises(ValueError, match="must contain a JSON object"):
            load_config(path)


class TestSaveConfig:
    def test_creates_the_directory(self, tmp_path: Path) -> None:
        path = tmp_path / "nested" / "config.json"

        save_config({"profile": "prod"}, path)

        assert json.loads(path.read_text()) == {"profile": "prod"}

    def test_restricts_permissions(self, tmp_path: Path) -> None:
        """It shares a directory with credentials, so it is created owner-only."""
        path = tmp_path / "config.json"

        save_config({"profile": "prod"}, path)

        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_round_trips(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        values = {"profile": "prod", "region": "de"}

        save_config(values, path)

        assert load_config(path) == values


class TestDefaultPath:
    def test_lives_beside_the_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PRISMA_AIRS_CONFIG", raising=False)

        assert default_config_path().parent.name == ".prisma-airs"

    def test_is_overridable(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        target = tmp_path / "elsewhere.json"
        monkeypatch.setenv("PRISMA_AIRS_CONFIG", str(target))

        assert default_config_path() == target


class TestResolve:
    def test_a_flag_beats_everything(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANW_AI_SEC_PROFILE", "from-env")

        assert resolve("profile", "from-flag", config={"profile": "from-file"}) == "from-flag"

    def test_the_environment_beats_the_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANW_AI_SEC_PROFILE", "from-env")

        assert resolve("profile", None, config={"profile": "from-file"}) == "from-env"

    def test_the_file_beats_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PANW_AI_SEC_PROFILE", raising=False)

        assert resolve("profile", None, config={"profile": "from-file"}, default="d") == "from-file"

    def test_falls_back_to_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PANW_AI_SEC_PROFILE", raising=False)

        assert resolve("profile", None, config={}, default="fallback") == "fallback"

    def test_an_empty_environment_value_does_not_win(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An exported-but-blank variable should not shadow a real setting."""
        monkeypatch.setenv("PANW_AI_SEC_PROFILE", "")

        assert resolve("profile", None, config={"profile": "from-file"}) == "from-file"

    def test_a_key_with_no_environment_override_still_resolves(self) -> None:
        assert resolve("num_retries", None, config={"num_retries": 3}) == 3
