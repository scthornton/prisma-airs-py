"""``airs config`` command group."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from prisma_airs_cli.app import app

runner = CliRunner()


@pytest.fixture
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the CLI at a throwaway config and clear inherited overrides."""
    path = tmp_path / "config.json"
    monkeypatch.setenv("PRISMA_AIRS_CONFIG", str(path))
    for name in ("PANW_AI_SEC_PROFILE", "PANW_AI_SEC_REGION", "PANW_AI_SEC_API_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)
    return path


class TestSet:
    def test_writes_the_value(self, config_file: Path) -> None:
        result = runner.invoke(app, ["config", "set", "profile", "prod"])

        assert result.exit_code == 0
        assert json.loads(config_file.read_text())["profile"] == "prod"

    def test_preserves_other_settings(self, config_file: Path) -> None:
        config_file.write_text('{"region": "de"}')

        runner.invoke(app, ["config", "set", "profile", "prod"])

        assert json.loads(config_file.read_text()) == {"region": "de", "profile": "prod"}

    def test_rejects_an_unknown_key(self, config_file: Path) -> None:
        """Writing a key nothing reads would look like it worked and change nothing."""
        result = runner.invoke(app, ["config", "set", "colour", "blue"])

        assert result.exit_code == 2
        assert not config_file.exists()

    def test_lists_the_valid_keys_when_rejecting(self, config_file: Path) -> None:
        result = runner.invoke(app, ["config", "set", "colour", "blue"])

        assert "profile" in result.output

    def test_stores_numeric_settings_as_numbers(self, config_file: Path) -> None:
        runner.invoke(app, ["config", "set", "num_retries", "3"])

        assert json.loads(config_file.read_text())["num_retries"] == 3

    def test_rejects_a_non_numeric_value_for_a_numeric_key(self, config_file: Path) -> None:
        result = runner.invoke(app, ["config", "set", "num_retries", "lots"])

        assert result.exit_code == 2


class TestGet:
    def test_prints_a_stored_value(self, config_file: Path) -> None:
        config_file.write_text('{"profile": "prod"}')

        result = runner.invoke(app, ["config", "get", "profile"])

        assert result.exit_code == 0
        assert "prod" in result.output

    def test_fails_when_unset(self, config_file: Path) -> None:
        config_file.write_text("{}")

        assert runner.invoke(app, ["config", "get", "profile"]).exit_code == 2

    def test_rejects_an_unknown_key(self, config_file: Path) -> None:
        assert runner.invoke(app, ["config", "get", "colour"]).exit_code == 2


class TestUnset:
    def test_removes_the_setting(self, config_file: Path) -> None:
        config_file.write_text('{"profile": "prod", "region": "de"}')

        runner.invoke(app, ["config", "unset", "profile"])

        assert json.loads(config_file.read_text()) == {"region": "de"}

    def test_fails_when_already_unset(self, config_file: Path) -> None:
        config_file.write_text("{}")

        assert runner.invoke(app, ["config", "unset", "profile"]).exit_code == 2


class TestList:
    def test_shows_a_stored_value_and_its_origin(self, config_file: Path) -> None:
        config_file.write_text('{"profile": "prod"}')

        result = runner.invoke(app, ["config", "list"])

        assert "prod" in result.output
        assert "config file" in result.output

    def test_attributes_an_environment_override(
        self, config_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The environment silently wins, so the origin has to be visible."""
        config_file.write_text('{"profile": "from-file"}')
        monkeypatch.setenv("PANW_AI_SEC_PROFILE", "from-env")

        result = runner.invoke(app, ["config", "list"])

        assert "from-env" in result.output
        assert "PANW_AI_SEC_PROFILE" in result.output

    def test_names_the_variable_the_resolver_actually_reads(
        self, config_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """endpoint reads PANW_AI_SEC_API_ENDPOINT, not the name its key would suggest."""
        monkeypatch.setenv("PANW_AI_SEC_API_ENDPOINT", "https://custom.test")

        result = runner.invoke(app, ["config", "list"])

        assert "PANW_AI_SEC_API_ENDPOINT" in result.output

    def test_works_with_no_config_file(self, config_file: Path) -> None:
        result = runner.invoke(app, ["config", "list"])

        assert result.exit_code == 0


class TestPath:
    def test_prints_the_config_location(self, config_file: Path) -> None:
        result = runner.invoke(app, ["config", "path"])

        assert result.exit_code == 0
        assert config_file.name in result.output
