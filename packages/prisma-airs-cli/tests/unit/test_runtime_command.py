"""``airs runtime scan`` behaviour, including the exit codes CI depends on."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from prisma_airs.constants import DEFAULT_ENDPOINT
from prisma_airs_cli.app import app

runner = CliRunner()

SYNC_URL = f"{DEFAULT_ENDPOINT}/v1/scan/sync/request"

ALLOW = {
    "report_id": "R1",
    "scan_id": "S1",
    "category": "benign",
    "action": "allow",
    "timeout": False,
    "error": False,
    "errors": [],
}
BLOCK = {
    **ALLOW,
    "category": "malicious",
    "action": "block",
    "prompt_detected": {"injection": True, "dlp": False},
}


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests off the developer's real credentials and config."""
    monkeypatch.setenv("PANW_AI_SEC_API_KEY", "test-key")
    monkeypatch.setenv("PRISMA_AIRS_CONFIG", str(tmp_path / "config.json"))
    for name in ("PANW_AI_SEC_PROFILE", "PANW_AI_SEC_REGION", "PANW_AI_SEC_API_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)


class TestExitCodes:
    """The contract that lets this command gate a pipeline."""

    @respx.mock
    def test_allow_exits_zero(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        result = runner.invoke(app, ["runtime", "scan", "-p", "hi", "--profile", "prod"])

        assert result.exit_code == 0

    @respx.mock
    def test_block_exits_one(self) -> None:
        """A blocked prompt should fail the build, not pass quietly."""
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=BLOCK))

        result = runner.invoke(app, ["runtime", "scan", "-p", "bad", "--profile", "prod"])

        assert result.exit_code == 1

    @respx.mock
    def test_an_api_failure_exits_two(self) -> None:
        """Distinguishable from a block: the scan never produced a verdict."""
        respx.post(SYNC_URL).mock(
            return_value=httpx.Response(403, json={"message": "Invalid API Key"})
        )

        result = runner.invoke(app, ["runtime", "scan", "-p", "hi", "--profile", "prod"])

        assert result.exit_code == 2

    def test_missing_content_exits_two(self) -> None:
        result = runner.invoke(app, ["runtime", "scan", "--profile", "prod"])

        assert result.exit_code == 2

    def test_missing_profile_exits_two(self) -> None:
        result = runner.invoke(app, ["runtime", "scan", "-p", "hi"])

        assert result.exit_code == 2


class TestOutput:
    @respx.mock
    def test_reports_the_action_and_category(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=BLOCK))

        result = runner.invoke(app, ["runtime", "scan", "-p", "bad", "--profile", "prod"])

        assert "BLOCK" in result.output
        assert "malicious" in result.output

    @respx.mock
    def test_names_the_detections_that_fired(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=BLOCK))

        result = runner.invoke(app, ["runtime", "scan", "-p", "bad", "--profile", "prod"])

        assert "prompt.injection" in result.output

    @respx.mock
    def test_does_not_list_detections_that_did_not_fire(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=BLOCK))

        result = runner.invoke(app, ["runtime", "scan", "-p", "bad", "--profile", "prod"])

        assert "prompt.dlp" not in result.output

    @respx.mock
    def test_json_output_is_parseable(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        result = runner.invoke(app, ["runtime", "scan", "-p", "hi", "--profile", "prod", "--json"])

        assert json.loads(result.output)["action"] == "allow"

    def test_the_missing_profile_message_suggests_the_fix(self) -> None:
        result = runner.invoke(app, ["runtime", "scan", "-p", "hi"])

        assert "airs config set profile" in result.output


class TestInputSources:
    @respx.mock
    def test_reads_a_prompt_from_a_file(self, tmp_path: Path) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))
        prompt_file = tmp_path / "prompt.txt"
        prompt_file.write_text("from a file")

        runner.invoke(
            app, ["runtime", "scan", "--prompt-file", str(prompt_file), "--profile", "prod"]
        )

        body = json.loads(route.calls.last.request.content)
        assert body["contents"][0]["prompt"] == "from a file"

    def test_rejects_a_missing_prompt_file(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["runtime", "scan", "--prompt-file", str(tmp_path / "nope.txt"), "--profile", "prod"],
        )

        assert result.exit_code != 0

    @respx.mock
    def test_takes_the_profile_from_the_config_file(self, tmp_path: Path) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))
        (tmp_path / "config.json").write_text('{"profile": "from-config"}')

        runner.invoke(app, ["runtime", "scan", "-p", "hi"])

        body = json.loads(route.calls.last.request.content)
        assert body["ai_profile"]["profile_name"] == "from-config"

    @respx.mock
    def test_a_flag_overrides_the_config_file(self, tmp_path: Path) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))
        (tmp_path / "config.json").write_text('{"profile": "from-config"}')

        runner.invoke(app, ["runtime", "scan", "-p", "hi", "--profile", "from-flag"])

        body = json.loads(route.calls.last.request.content)
        assert body["ai_profile"]["profile_name"] == "from-flag"

    @respx.mock
    def test_forwards_tracing_identifiers(self) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        runner.invoke(
            app,
            [
                "runtime",
                "scan",
                "-p",
                "hi",
                "--profile",
                "p",
                "--tr-id",
                "T1",
                "--session-id",
                "S9",
            ],
        )

        body = json.loads(route.calls.last.request.content)
        assert (body["tr_id"], body["session_id"]) == ("T1", "S9")
