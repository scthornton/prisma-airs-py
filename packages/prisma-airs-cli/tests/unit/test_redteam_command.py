"""``airs redteam`` -- the request each subcommand makes, and the exit codes it returns."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner

from prisma_airs.constants import (
    DEFAULT_RED_TEAM_DATA_ENDPOINT,
    DEFAULT_RED_TEAM_MGMT_ENDPOINT,
    DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
)
from prisma_airs_cli.commands.redteam import redteam_app

# Validation-only paths never reach the network, so an unused route is not a failure.
pytestmark = pytest.mark.respx(assert_all_called=False)

runner = CliRunner()

DATA = DEFAULT_RED_TEAM_DATA_ENDPOINT
MGMT = DEFAULT_RED_TEAM_MGMT_ENDPOINT
BROKER = DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT

JOB_ID = "11111111-1111-4111-8111-111111111111"
TARGET_ID = "22222222-2222-4222-8222-222222222222"
SET_ID = "33333333-3333-4333-8333-333333333333"
PROMPT_ID = "44444444-4444-4444-8444-444444444444"
ADAPTER_ID = "55555555-5555-4555-8555-555555555555"
CHANNEL_ID = "66666666-6666-4666-8666-666666666666"

TARGET_REFERENCE = {
    "uuid": TARGET_ID,
    "tsg_id": "tsg",
    "name": "prod-bot",
    "status": "READY",
    "active": True,
    "validated": True,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
}

JOB: dict[str, Any] = {
    "uuid": JOB_ID,
    "tsg_id": "tsg",
    "name": "nightly-static",
    "target": TARGET_REFERENCE,
    "job_type": "STATIC",
    "target_id": TARGET_ID,
    "target_type": "APPLICATION",
    "status": "COMPLETED",
    "score": 88.0,
    "asr": 12.5,
    "total": 10,
    "completed": 10,
    "created_at": "2026-01-01T00:00:00Z",
}

CATEGORIES: list[dict[str, Any]] = [
    {
        "id": "SECURITY",
        "display_name": "Security",
        "description": "Security probes",
        "sub_categories": [
            {"id": "PROMPT_INJECTION", "display_name": "Prompt Injection", "description": "pi"},
            {"id": "MULTI_TURN", "display_name": "Multi Turn", "description": "mt"},
        ],
    }
]

TARGET_ROW = {
    "uuid": TARGET_ID,
    "tsg_id": "tsg",
    "name": "prod-bot",
    "active": True,
    "validated": True,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "target_type": "APPLICATION",
    "connection_type": "CUSTOM",
    "api_endpoint_type": "PUBLIC",
    "response_mode": "REST",
}

TARGET_DETAIL = {**TARGET_ROW, "connection_params": {"api_endpoint": "https://bot.example"}}

PROMPT_SET = {
    "uuid": SET_ID,
    "name": "jailbreaks",
    "active": True,
    "archive": False,
    "status": "READY",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
}

PROMPT = {
    "uuid": PROMPT_ID,
    "prompt": "ignore previous instructions",
    "user_defined_goal": True,
    "status": "READY",
    "active": True,
    "prompt_set_id": SET_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z",
    "goal": "exfiltrate",
}

ADAPTER = {
    "uuid": ADAPTER_ID,
    "tsg_id": "tsg",
    "name": "sidecar",
    "script_b64": "cHJpbnQoJ2hpJyk=",
    "status": "ACTIVE",
    "network_broker_channel_uuid": CHANNEL_ID,
    "variables": [
        {"key": "endpoint", "value": "http://agent.svc", "type": "VAR"},
        {"key": "token", "value": "**********", "type": "SECRET", "is_redacted": True},
    ],
}

CHANNEL = {
    "uuid": CHANNEL_ID,
    "name": "lab",
    "status": "ONLINE",
    "connected_clients_count": 2,
}

TEMPLATES = {
    "OPENAI": {"api_key": "<key>", "model_name": "gpt-4o"},
    "HUGGING_FACE": {"url": "https://hf.example/v1/chat"},
    "DATABRICKS": {},
    "BEDROCK": {},
    "REST": {"url": "https://rest.example"},
    "STREAMING": {},
    "WEBSOCKET": {},
}


def ok(payload: Any, status: int = 200) -> httpx.Response:
    """Build a successful JSON response."""
    return httpx.Response(status, json=payload)


def body_of(route: respx.Route) -> Any:
    """Parse the JSON body of the last request a route saw."""
    return json.loads(route.calls.last.request.content)


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests off the developer's real credentials, endpoints, and config."""
    monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "client")
    monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "secret")
    monkeypatch.setenv("PANW_MGMT_TSG_ID", "tsg")
    monkeypatch.setenv("PRISMA_AIRS_CONFIG", str(tmp_path / "config.json"))
    for name in (
        "PANW_RED_TEAM_CLIENT_ID",
        "PANW_RED_TEAM_CLIENT_SECRET",
        "PANW_RED_TEAM_TSG_ID",
        "PANW_RED_TEAM_DATA_ENDPOINT",
        "PANW_RED_TEAM_MGMT_ENDPOINT",
        "PANW_RED_TEAM_NETWORK_BROKER_ENDPOINT",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def api(respx_mock: respx.MockRouter) -> respx.MockRouter:
    """Stub the OAuth exchange every Red Team call makes before anything else."""
    respx_mock.post(DEFAULT_TOKEN_ENDPOINT).mock(
        return_value=ok({"access_token": "token", "expires_in": 900})
    )
    return respx_mock


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collapse the scan poll interval so a wait loop runs at test speed."""
    monkeypatch.setattr("prisma_airs_cli.commands.redteam.time.sleep", lambda _seconds: None)


def json_file(tmp_path: Path, name: str, payload: Any) -> str:
    """Write a JSON fixture file and return its path."""
    path = tmp_path / name
    path.write_text(json.dumps(payload))
    return str(path)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


class TestScans:
    def test_categories_reads_the_data_plane(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/categories").mock(return_value=ok(CATEGORIES))

        result = runner.invoke(redteam_app, ["categories"])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert "PROMPT_INJECTION" in result.output

    def test_abort_posts_to_the_abort_endpoint(self, api: respx.MockRouter) -> None:
        route = api.post(f"{DATA}/v1/scan/{JOB_ID}/abort").mock(
            return_value=ok({"job_id": JOB_ID, "message": "accepted"})
        )

        result = runner.invoke(redteam_app, ["abort", JOB_ID])

        assert result.exit_code == 0
        assert route.called
        assert f"Scan {JOB_ID} aborted." in result.output

    def test_abort_rejects_a_non_uuid_job_id(self, api: respx.MockRouter) -> None:
        result = runner.invoke(redteam_app, ["abort", "not-a-uuid"])

        assert result.exit_code == 2

    def test_status_reads_one_job(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok(JOB))

        result = runner.invoke(redteam_app, ["status", JOB_ID])

        assert result.exit_code == 0
        assert route.called
        assert "COMPLETED" in result.output

    def test_list_forwards_every_filter(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/scan").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [JOB]})
        )

        result = runner.invoke(
            redteam_app,
            [
                "list",
                "--status",
                "COMPLETED",
                "--type",
                "STATIC",
                "--target",
                TARGET_ID,
                "--limit",
                "5",
            ],
        )

        assert result.exit_code == 0
        params = route.calls.last.request.url.params
        assert params["status"] == "COMPLETED"
        assert params["job_type"] == "STATIC"
        assert params["target_id"] == TARGET_ID
        assert params["limit"] == "5"

    def test_list_defaults_to_ten_results(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/scan").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [JOB]})
        )

        runner.invoke(redteam_app, ["list"])

        assert route.calls.last.request.url.params["limit"] == "10"

    def test_list_json_output_is_parseable(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/scan").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [JOB]})
        )

        result = runner.invoke(redteam_app, ["list", "--output", "json"])

        assert json.loads(result.output)[0]["id"] == JOB_ID

    def test_an_api_failure_exits_two(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/categories").mock(return_value=ok({"message": "forbidden"}, status=403))

        result = runner.invoke(redteam_app, ["categories"])

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

STATIC_REPORT: dict[str, Any] = {
    "severity_report": {"stats": [{"severity": "HIGH", "successful": 2, "failed": 3}]},
    "score": 88.0,
    "asr": 40.0,
    "security_report": {
        "id": "SECURITY",
        "display_name": "Security",
        "description": "d",
        "sub_categories": [
            {
                "id": "PI",
                "display_name": "Prompt Injection",
                "description": "d",
                "successful": 2,
                "failed": 3,
                "total": 5,
            }
        ],
        "asr": 40.0,
        "total_prompts": 5,
        "total_attacks": 5,
        "successful": 2,
        "failed": 3,
    },
    "report_summary": "Target shows {{HIGH_RISK}} exposure",
}

ATTACK_ROW = {
    "uuid": "77777777-7777-4777-8777-777777777777",
    "tsg_id": "tsg",
    "job_id": JOB_ID,
    "target_id": TARGET_ID,
    "prompt": "p",
    "prompt_mapping_id": "m",
    "prompt_id": "pid",
    "category": "SECURITY",
    "sub_category": "PI",
    "category_display_name": "Security",
    "sub_category_display_name": "Prompt Injection",
    "severity": "HIGH",
    "threat": True,
}


class TestReport:
    def test_static_report_reads_the_static_endpoint(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok(JOB))
        route = api.get(f"{DATA}/v1/report/static/{JOB_ID}/report").mock(
            return_value=ok(STATIC_REPORT)
        )

        result = runner.invoke(redteam_app, ["report", JOB_ID])

        assert result.exit_code == 0
        assert route.called
        assert "Static Scan Report" in result.output

    def test_static_report_interpolates_summary_placeholders(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok(JOB))
        api.get(f"{DATA}/v1/report/static/{JOB_ID}/report").mock(return_value=ok(STATIC_REPORT))

        result = runner.invoke(redteam_app, ["report", JOB_ID])

        assert "high risk" in result.output
        assert "{{HIGH_RISK}}" not in result.output

    def test_attacks_are_only_listed_when_asked(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok(JOB))
        api.get(f"{DATA}/v1/report/static/{JOB_ID}/report").mock(return_value=ok(STATIC_REPORT))
        route = api.get(f"{DATA}/v1/report/static/{JOB_ID}/list-attacks").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [ATTACK_ROW]})
        )

        runner.invoke(redteam_app, ["report", JOB_ID])

        assert not route.called

    def test_attacks_forward_severity_and_limit(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok(JOB))
        api.get(f"{DATA}/v1/report/static/{JOB_ID}/report").mock(return_value=ok(STATIC_REPORT))
        route = api.get(f"{DATA}/v1/report/static/{JOB_ID}/list-attacks").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [ATTACK_ROW]})
        )

        result = runner.invoke(
            redteam_app, ["report", JOB_ID, "--attacks", "--severity", "HIGH", "--limit", "3"]
        )

        params = route.calls.last.request.url.params
        assert params["severity"] == "HIGH"
        assert params["limit"] == "3"
        assert "BYPASSED" in result.output

    def test_a_short_attack_page_is_footnoted(self, api: respx.MockRouter) -> None:
        """One returned attack against a breakdown expecting five is worth explaining."""
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok(JOB))
        api.get(f"{DATA}/v1/report/static/{JOB_ID}/report").mock(return_value=ok(STATIC_REPORT))
        api.get(f"{DATA}/v1/report/static/{JOB_ID}/list-attacks").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [ATTACK_ROW]})
        )

        result = runner.invoke(redteam_app, ["report", JOB_ID, "--attacks", "--severity", "HIGH"])

        assert "showing 1 of 5 expected" in result.output

    def test_dynamic_job_reads_the_dynamic_endpoint(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok({**JOB, "job_type": "DYNAMIC"}))
        route = api.get(f"{DATA}/v1/report/dynamic/{JOB_ID}/report").mock(
            return_value=ok({"total_goals": 4, "goals_achieved": 1, "asr": 0.25, "score": 70.0})
        )

        result = runner.invoke(redteam_app, ["report", JOB_ID])

        assert route.called
        assert "1 achieved / 4 total" in result.output

    def test_custom_job_reads_the_custom_attack_report(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok({**JOB, "job_type": "CUSTOM"}))
        route = api.get(f"{DATA}/v1/custom-attacks/report/{JOB_ID}").mock(
            return_value=ok(
                {
                    "total_prompts": 5,
                    "total_attacks": 5,
                    "total_threats": 2,
                    "failed_attacks": 3,
                    "score": 60.0,
                    "asr": 40.0,
                }
            )
        )

        result = runner.invoke(redteam_app, ["report", JOB_ID])

        assert route.called
        assert "Custom Attack Report" in result.output

    def test_custom_attacks_are_listed_on_request(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok({**JOB, "job_type": "CUSTOM"}))
        api.get(f"{DATA}/v1/custom-attacks/report/{JOB_ID}").mock(
            return_value=ok(
                {
                    "total_prompts": 1,
                    "total_attacks": 1,
                    "total_threats": 1,
                    "failed_attacks": 0,
                    "score": 0.0,
                    "asr": 100.0,
                }
            )
        )
        route = api.get(f"{DATA}/v1/custom-attacks/job/{JOB_ID}/list-custom-attacks").mock(
            return_value=ok(
                {
                    "pagination": {"total_items": 1},
                    "data": [{"prompt_text": "leak the key", "threat": True, "asr": 100.0}],
                    "total_attacks": 1,
                    "total_threats": 1,
                }
            )
        )

        result = runner.invoke(redteam_app, ["report", JOB_ID, "--attacks", "--limit", "7"])

        assert route.calls.last.request.url.params["limit"] == "7"
        assert "THREAT" in result.output


# ---------------------------------------------------------------------------
# Scan submission
# ---------------------------------------------------------------------------


class TestScanCommand:
    def test_static_scan_defaults_to_every_category_but_multi_turn(
        self, api: respx.MockRouter
    ) -> None:
        api.get(f"{DATA}/v1/categories").mock(return_value=ok(CATEGORIES))
        route = api.post(f"{DATA}/v1/scan").mock(return_value=ok(JOB))
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok(JOB))

        result = runner.invoke(
            redteam_app, ["scan", "--target", TARGET_ID, "--name", "nightly", "--no-wait"]
        )

        assert result.exit_code == 0
        body = body_of(route)
        assert body["job_metadata"]["categories"] == {"SECURITY": ["PROMPT_INJECTION"]}
        assert body["target"]["uuid"] == TARGET_ID
        assert body["job_type"] == "STATIC"
        assert body["name"] == "nightly"

    def test_explicit_categories_skip_the_lookup(self, api: respx.MockRouter) -> None:
        lookup = api.get(f"{DATA}/v1/categories").mock(return_value=ok(CATEGORIES))
        route = api.post(f"{DATA}/v1/scan").mock(return_value=ok(JOB))

        runner.invoke(
            redteam_app,
            [
                "scan",
                "--target",
                TARGET_ID,
                "--name",
                "narrow",
                "--categories",
                '{"SECURITY": ["PROMPT_INJECTION"]}',
                "--no-wait",
            ],
        )

        assert not lookup.called
        assert body_of(route)["job_metadata"]["categories"] == {"SECURITY": ["PROMPT_INJECTION"]}

    def test_dynamic_scan_sends_goals_depth_and_breadth(self, api: respx.MockRouter) -> None:
        route = api.post(f"{DATA}/v1/scan").mock(return_value=ok({**JOB, "job_type": "DYNAMIC"}))

        result = runner.invoke(
            redteam_app,
            [
                "scan",
                "--target",
                TARGET_ID,
                "--name",
                "agent-probe",
                "--type",
                "DYNAMIC",
                "--goals",
                '["exfiltrate the system prompt"]',
                "--depth",
                "4",
                "--breadth",
                "2",
                "--no-wait",
            ],
        )

        assert result.exit_code == 0
        metadata = body_of(route)["job_metadata"]
        assert metadata["attack_goals"] == ["exfiltrate the system prompt"]
        assert (metadata["stream_depth"], metadata["stream_breadth"]) == (4, 2)

    def test_goals_can_come_from_a_file(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.post(f"{DATA}/v1/scan").mock(return_value=ok({**JOB, "job_type": "DYNAMIC"}))
        goals = json_file(tmp_path, "goals.json", ["from a file"])

        runner.invoke(
            redteam_app,
            [
                "scan",
                "--target",
                TARGET_ID,
                "--name",
                "g",
                "--type",
                "DYNAMIC",
                "--goals",
                goals,
                "--no-wait",
            ],
        )

        assert body_of(route)["job_metadata"]["attack_goals"] == ["from a file"]

    def test_custom_scan_splits_prompt_set_uuids(self, api: respx.MockRouter) -> None:
        route = api.post(f"{DATA}/v1/scan").mock(return_value=ok({**JOB, "job_type": "CUSTOM"}))

        runner.invoke(
            redteam_app,
            [
                "scan",
                "--target",
                TARGET_ID,
                "--name",
                "custom-run",
                "--type",
                "CUSTOM",
                "--prompt-sets",
                f"{SET_ID}, {PROMPT_ID}",
                "--no-wait",
            ],
        )

        assert body_of(route)["job_metadata"]["custom_prompt_sets"] == [SET_ID, PROMPT_ID]

    def test_waiting_polls_until_the_job_stops_moving(
        self, api: respx.MockRouter, no_sleep: None
    ) -> None:
        api.get(f"{DATA}/v1/categories").mock(return_value=ok(CATEGORIES))
        api.post(f"{DATA}/v1/scan").mock(return_value=ok({**JOB, "status": "RUNNING"}))
        poll = api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(
            side_effect=[
                ok({**JOB, "status": "RUNNING", "completed": 5}),
                ok({**JOB, "status": "COMPLETED"}),
            ]
        )

        result = runner.invoke(redteam_app, ["scan", "--target", TARGET_ID, "--name", "n"])

        assert result.exit_code == 0
        assert len(poll.calls) == 2
        assert "airs redteam report" in result.output

    def test_a_failed_scan_exits_two(self, api: respx.MockRouter, no_sleep: None) -> None:
        api.get(f"{DATA}/v1/categories").mock(return_value=ok(CATEGORIES))
        api.post(f"{DATA}/v1/scan").mock(return_value=ok({**JOB, "status": "RUNNING"}))
        api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok({**JOB, "status": "FAILED"}))

        result = runner.invoke(redteam_app, ["scan", "--target", TARGET_ID, "--name", "n"])

        assert result.exit_code == 2

    def test_no_wait_skips_polling(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/categories").mock(return_value=ok(CATEGORIES))
        api.post(f"{DATA}/v1/scan").mock(return_value=ok({**JOB, "status": "QUEUED"}))
        poll = api.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=ok(JOB))

        result = runner.invoke(
            redteam_app, ["scan", "--target", TARGET_ID, "--name", "n", "--no-wait"]
        )

        assert not poll.called
        assert "airs redteam status" in result.output

    def test_a_non_positive_depth_exits_two(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            redteam_app, ["scan", "--target", TARGET_ID, "--name", "n", "--depth", "0"]
        )

        assert result.exit_code == 2

    def test_a_non_positive_breadth_exits_two(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            redteam_app, ["scan", "--target", TARGET_ID, "--name", "n", "--breadth", "-1"]
        )

        assert result.exit_code == 2

    def test_malformed_categories_json_exits_two(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            redteam_app,
            ["scan", "--target", TARGET_ID, "--name", "n", "--categories", "{not json"],
        )

        assert result.exit_code == 2

    def test_goals_that_are_not_strings_exit_two(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            redteam_app,
            [
                "scan",
                "--target",
                TARGET_ID,
                "--name",
                "n",
                "--type",
                "DYNAMIC",
                "--goals",
                "[1, 2]",
            ],
        )

        assert result.exit_code == 2

    def test_an_unknown_job_type_exits_two(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            redteam_app, ["scan", "--target", TARGET_ID, "--name", "n", "--type", "FUZZ"]
        )

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# EULA, instances, devices, licensing
# ---------------------------------------------------------------------------


class TestEula:
    def test_status_reads_the_management_plane(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/eula/status").mock(
            return_value=ok({"is_accepted": True, "accepted_at": "2026-01-01T00:00:00Z"})
        )

        result = runner.invoke(redteam_app, ["eula", "status"])

        assert result.exit_code == 0
        assert route.called
        assert "yes" in result.output

    def test_content_prints_the_agreement(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/eula/content").mock(return_value=ok({"content": "BE NICE"}))

        result = runner.invoke(redteam_app, ["eula", "content"])

        assert result.exit_code == 0
        assert route.called
        assert route.calls.last.request.method == "GET"
        assert "BE NICE" in result.output

    def test_accept_without_force_only_shows_the_agreement(self, api: respx.MockRouter) -> None:
        """Accepting a licence should not be something a mistyped command can do."""
        api.get(f"{MGMT}/v1/eula/content").mock(return_value=ok({"content": "BE NICE"}))
        route = api.post(f"{MGMT}/v1/eula/accept").mock(return_value=ok({"is_accepted": True}))

        result = runner.invoke(redteam_app, ["eula", "accept"])

        assert result.exit_code == 0
        assert not route.called
        assert "Pass --force to accept." in result.output

    def test_accept_with_force_echoes_the_agreement_text(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/eula/content").mock(return_value=ok({"content": "BE NICE"}))
        route = api.post(f"{MGMT}/v1/eula/accept").mock(return_value=ok({"is_accepted": True}))

        result = runner.invoke(redteam_app, ["eula", "accept", "--force"])

        assert result.exit_code == 0
        body = body_of(route)
        assert body["eula_content"] == "BE NICE"
        assert body["accepted_at"].endswith("+00:00")


class TestInstances:
    def test_create_sends_the_four_identifiers(self, api: respx.MockRouter) -> None:
        route = api.post(f"{MGMT}/v1/instances").mock(
            return_value=ok({"tsg_id": "tsg", "tenant_id": "t1", "is_success": True})
        )

        result = runner.invoke(
            redteam_app,
            [
                "instances",
                "create",
                "--tsg-id",
                "tsg",
                "--tenant-id",
                "t1",
                "--app-id",
                "app",
                "--region",
                "us",
            ],
        )

        assert result.exit_code == 0
        assert body_of(route) == {
            "tsg_id": "tsg",
            "tenant_id": "t1",
            "app_id": "app",
            "region": "us",
        }

    def test_create_requires_every_identifier(self, api: respx.MockRouter) -> None:
        result = runner.invoke(redteam_app, ["instances", "create", "--tsg-id", "tsg"])

        assert result.exit_code == 2

    def test_get_reads_one_tenant(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/instances/t1").mock(
            return_value=ok({"tsg_id": "tsg", "tenant_id": "t1", "app_id": "app", "region": "us"})
        )

        result = runner.invoke(redteam_app, ["instances", "get", "t1"])

        assert result.exit_code == 0
        assert route.called
        assert "us" in result.output

    def test_get_json_output_is_parseable(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/instances/t1").mock(
            return_value=ok({"tsg_id": "tsg", "tenant_id": "t1", "app_id": "app", "region": "us"})
        )

        result = runner.invoke(redteam_app, ["instances", "get", "t1", "--output", "json"])

        assert json.loads(result.output)["region"] == "us"

    def test_update_puts_the_tenant_from_the_argument(self, api: respx.MockRouter) -> None:
        route = api.put(f"{MGMT}/v1/instances/t1").mock(
            return_value=ok({"tsg_id": "tsg", "tenant_id": "t1"})
        )

        result = runner.invoke(
            redteam_app,
            [
                "instances",
                "update",
                "t1",
                "--tsg-id",
                "tsg",
                "--app-id",
                "app",
                "--region",
                "de",
            ],
        )

        assert result.exit_code == 0
        # The tenant comes from the positional argument; the rest from the flags. Every
        # field is pinned, so hardcoding any one of them upstream fails here.
        assert body_of(route) == {
            "tsg_id": "tsg",
            "tenant_id": "t1",
            "app_id": "app",
            "region": "de",
        }

    def test_delete_removes_the_instance(self, api: respx.MockRouter) -> None:
        route = api.delete(f"{MGMT}/v1/instances/t1").mock(
            return_value=ok({"tsg_id": "tsg", "tenant_id": "t1"})
        )

        result = runner.invoke(redteam_app, ["instances", "delete", "t1"])

        assert result.exit_code == 0
        assert route.called
        assert "Instance t1 deleted." in result.output


DEVICE_CONFIG = {
    "instance": {"app_id": "app", "region": "us", "tenant_id": "t1", "tsg_id": "tsg"},
    "devices": [{"serial_number": "SN1"}],
}


class TestDevices:
    def test_create_posts_the_config_file(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.post(f"{MGMT}/v1/instances/t1/devices").mock(
            return_value=ok({"status": "ok", "devices": [{"status": "ok"}]})
        )
        config = json_file(tmp_path, "devices.json", DEVICE_CONFIG)

        result = runner.invoke(redteam_app, ["devices", "create", "t1", "--config", config])

        assert result.exit_code == 0
        assert body_of(route)["devices"][0]["serial_number"] == "SN1"

    def test_update_uses_patch(self, api: respx.MockRouter, tmp_path: Path) -> None:
        """PATCH, not PUT: omitted devices are left alone rather than deregistered."""
        route = api.patch(f"{MGMT}/v1/instances/t1/devices").mock(return_value=ok({"status": "ok"}))
        config = json_file(tmp_path, "devices.json", DEVICE_CONFIG)

        result = runner.invoke(redteam_app, ["devices", "update", "t1", "--config", config])

        assert result.exit_code == 0
        assert route.called

    def test_delete_sends_serial_numbers_as_one_parameter(self, api: respx.MockRouter) -> None:
        route = api.delete(f"{MGMT}/v1/instances/t1/devices").mock(
            return_value=ok({"status": "ok"})
        )

        result = runner.invoke(
            redteam_app, ["devices", "delete", "t1", "--serial-numbers", "SN1,SN2"]
        )

        assert result.exit_code == 0
        assert route.calls.last.request.url.params["serial_numbers"] == "SN1,SN2"

    def test_a_missing_config_file_exits_two(self, api: respx.MockRouter, tmp_path: Path) -> None:
        result = runner.invoke(
            redteam_app, ["devices", "create", "t1", "--config", str(tmp_path / "nope.json")]
        )

        assert result.exit_code == 2


class TestTenantWideReads:
    def test_registry_credentials_are_minted_with_a_post(self, api: respx.MockRouter) -> None:
        """A POST despite reading like a getter -- each call mints a fresh token."""
        route = api.post(f"{MGMT}/v1/registry-credentials").mock(
            return_value=ok({"token": "a" * 40, "expiry": "2026-01-02T00:00:00Z"})
        )

        result = runner.invoke(redteam_app, ["registry-credentials"])

        assert result.exit_code == 0
        assert route.called
        assert "2026-01-02T00:00:00Z" in result.output

    def test_languages_read_the_data_plane_by_default(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/languages").mock(
            return_value=ok(
                {
                    "multilingual_enabled": True,
                    "supported_job_types": ["STATIC"],
                    "languages": [{"code": "en", "name": "English"}],
                }
            )
        )

        result = runner.invoke(redteam_app, ["languages"])

        assert result.exit_code == 0
        assert route.called
        assert "English" in result.output

    def test_management_flag_switches_planes(self, api: respx.MockRouter) -> None:
        data_route = api.get(f"{DATA}/v1/languages").mock(return_value=ok({}))
        mgmt_route = api.get(f"{MGMT}/v1/languages").mock(
            return_value=ok(
                {
                    "multilingual_enabled": False,
                    "supported_job_types": [],
                    "languages": [],
                }
            )
        )

        result = runner.invoke(redteam_app, ["languages", "--management"])

        assert result.exit_code == 0
        assert mgmt_route.called
        assert not data_route.called

    def test_languages_csv_output_lists_the_codes(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/languages").mock(
            return_value=ok(
                {
                    "multilingual_enabled": True,
                    "supported_job_types": ["STATIC"],
                    "languages": [{"code": "fr", "name": "French"}],
                }
            )
        )

        result = runner.invoke(redteam_app, ["languages", "--output", "csv"])

        assert "Code,Name" in result.output
        assert "fr,French" in result.output


# ---------------------------------------------------------------------------
# Prompt sets and prompts
# ---------------------------------------------------------------------------


class TestPromptSets:
    def test_list_reads_the_listing_path(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/custom-attack/list-custom-prompt-sets").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [PROMPT_SET]})
        )

        result = runner.invoke(redteam_app, ["prompt-sets", "list"])

        assert result.exit_code == 0
        assert route.called
        assert "jailbreaks" in result.output

    def test_list_slices_client_side(self, api: respx.MockRouter) -> None:
        """This endpoint has no paging parameters, so limit and offset are applied here."""
        second = {**PROMPT_SET, "uuid": PROMPT_ID, "name": "second-set"}
        api.get(f"{MGMT}/v1/custom-attack/list-custom-prompt-sets").mock(
            return_value=ok({"pagination": {"total_items": 2}, "data": [PROMPT_SET, second]})
        )

        result = runner.invoke(redteam_app, ["prompt-sets", "list", "--offset", "1"])

        assert "second-set" in result.output
        assert "jailbreaks" not in result.output

    def test_a_non_positive_limit_exits_two(self, api: respx.MockRouter) -> None:
        result = runner.invoke(redteam_app, ["prompt-sets", "list", "--limit", "0"])

        assert result.exit_code == 2

    def test_get_adds_version_info(self, api: respx.MockRouter) -> None:
        detail = api.get(f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}").mock(
            return_value=ok(PROMPT_SET)
        )
        version = api.get(f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}/version-info").mock(
            return_value=ok(
                {
                    "uuid": SET_ID,
                    "status": "READY",
                    "is_latest": True,
                    "version": "3",
                    "stats": {
                        "total_prompts": 9,
                        "active_prompts": 8,
                        "inactive_prompts": 1,
                    },
                }
            )
        )

        result = runner.invoke(redteam_app, ["prompt-sets", "get", SET_ID])

        assert result.exit_code == 0
        assert detail.called
        assert version.called
        assert "Version Info" in result.output
        assert "9" in result.output

    def test_get_survives_a_broken_version_info_endpoint(self, api: respx.MockRouter) -> None:
        """Upstream returns 500 here; losing the whole command over it would be worse."""
        api.get(f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}").mock(
            return_value=ok(PROMPT_SET)
        )
        api.get(f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}/version-info").mock(
            return_value=ok({"message": "boom"}, status=400)
        )

        result = runner.invoke(redteam_app, ["prompt-sets", "get", SET_ID])

        assert result.exit_code == 0
        assert "unavailable" in result.output

    def test_create_sends_name_and_description(self, api: respx.MockRouter) -> None:
        route = api.post(f"{MGMT}/v1/custom-attack/custom-prompt-set").mock(
            return_value=ok(PROMPT_SET)
        )

        result = runner.invoke(
            redteam_app,
            ["prompt-sets", "create", "--name", "jailbreaks", "--description", "d"],
        )

        assert result.exit_code == 0
        assert body_of(route) == {"name": "jailbreaks", "description": "d"}

    def test_update_omits_untouched_fields(self, api: respx.MockRouter) -> None:
        route = api.put(f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}").mock(
            return_value=ok(PROMPT_SET)
        )

        runner.invoke(redteam_app, ["prompt-sets", "update", SET_ID, "--name", "renamed"])

        assert body_of(route) == {"name": "renamed"}

    def test_archive_sets_the_flag(self, api: respx.MockRouter) -> None:
        route = api.put(f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}/archive").mock(
            return_value=ok(PROMPT_SET)
        )

        result = runner.invoke(redteam_app, ["prompt-sets", "archive", SET_ID])

        assert result.exit_code == 0
        assert body_of(route) == {"archive": True}

    def test_unarchive_clears_the_flag(self, api: respx.MockRouter) -> None:
        route = api.put(f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}/archive").mock(
            return_value=ok(PROMPT_SET)
        )

        result = runner.invoke(redteam_app, ["prompt-sets", "archive", SET_ID, "--unarchive"])

        assert body_of(route) == {"archive": False}
        assert "unarchived" in result.output

    def test_download_writes_the_template(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.get(f"{MGMT}/v1/custom-attack/download-template/{SET_ID}").mock(
            return_value=httpx.Response(200, text="prompt,goal\n")
        )
        destination = tmp_path / "template.csv"

        result = runner.invoke(
            redteam_app,
            ["prompt-sets", "download", SET_ID, "--output-file", str(destination)],
        )

        assert result.exit_code == 0
        assert route.called
        assert destination.read_text() == "prompt,goal\n"

    def test_upload_posts_the_file_as_multipart(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.post(f"{MGMT}/v1/custom-attack/upload-custom-prompts-csv").mock(
            return_value=ok({"message": "3 prompts loaded", "status": 201})
        )
        source = tmp_path / "prompts.csv"
        source.write_text("prompt,goal\nhi,x\n")

        result = runner.invoke(redteam_app, ["prompt-sets", "upload", SET_ID, str(source)])

        assert result.exit_code == 0
        assert route.calls.last.request.url.params["prompt_set_uuid"] == SET_ID
        assert b"prompts.csv" in route.calls.last.request.content
        assert "3 prompts loaded" in result.output


class TestPrompts:
    def test_list_defaults_to_fifty(self, api: respx.MockRouter) -> None:
        route = api.get(
            f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}/list-custom-prompts"
        ).mock(return_value=ok({"pagination": {"total_items": 1}, "data": [PROMPT]}))

        result = runner.invoke(redteam_app, ["prompts", "list", SET_ID])

        assert result.exit_code == 0
        assert route.calls.last.request.url.params["limit"] == "50"
        assert "ignore previous instructions" in result.output

    def test_get_reads_one_prompt(self, api: respx.MockRouter) -> None:
        route = api.get(
            f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}/custom-prompt/{PROMPT_ID}"
        ).mock(return_value=ok(PROMPT))

        result = runner.invoke(redteam_app, ["prompts", "get", SET_ID, PROMPT_ID])

        assert result.exit_code == 0
        assert route.called
        assert "exfiltrate" in result.output

    def test_add_names_the_set_in_the_body(self, api: respx.MockRouter) -> None:
        route = api.post(f"{MGMT}/v1/custom-attack/custom-prompt-set/custom-prompt").mock(
            return_value=ok(PROMPT)
        )

        result = runner.invoke(
            redteam_app, ["prompts", "add", SET_ID, "--prompt", "hello", "--goal", "g"]
        )

        assert result.exit_code == 0
        assert body_of(route) == {"prompt": "hello", "prompt_set_id": SET_ID, "goal": "g"}

    def test_update_sends_only_what_changed(self, api: respx.MockRouter) -> None:
        route = api.put(
            f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}/custom-prompt/{PROMPT_ID}"
        ).mock(return_value=ok(PROMPT))

        runner.invoke(redteam_app, ["prompts", "update", SET_ID, PROMPT_ID, "--goal", "new goal"])

        assert body_of(route) == {"goal": "new goal"}

    def test_delete_removes_the_prompt(self, api: respx.MockRouter) -> None:
        route = api.delete(
            f"{MGMT}/v1/custom-attack/custom-prompt-set/{SET_ID}/custom-prompt/{PROMPT_ID}"
        ).mock(return_value=ok({"message": "deleted", "status": 200}))

        result = runner.invoke(redteam_app, ["prompts", "delete", SET_ID, PROMPT_ID])

        assert result.exit_code == 0
        assert route.called
        assert f"Prompt {PROMPT_ID} deleted." in result.output


class TestProperties:
    def test_list_reads_the_property_names(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/custom-attack/property-names").mock(
            return_value=ok({"data": ["tactic", "persona"]})
        )

        result = runner.invoke(redteam_app, ["properties", "list"])

        assert result.exit_code == 0
        assert route.called
        assert "tactic" in result.output

    def test_list_applies_a_client_side_limit(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/custom-attack/property-names").mock(
            return_value=ok({"data": ["tactic", "persona"]})
        )

        result = runner.invoke(redteam_app, ["properties", "list", "--limit", "1"])

        assert "tactic" in result.output
        assert "persona" not in result.output

    def test_create_declares_a_name(self, api: respx.MockRouter) -> None:
        route = api.post(f"{MGMT}/v1/custom-attack/property-names").mock(
            return_value=ok({"message": "created", "status": 201})
        )

        result = runner.invoke(redteam_app, ["properties", "create", "--name", "tactic"])

        assert result.exit_code == 0
        assert body_of(route) == {"name": "tactic"}

    def test_values_percent_encodes_the_name(self, api: respx.MockRouter) -> None:
        """Property names are tenant-authored and may contain spaces or slashes."""
        route = api.get(f"{MGMT}/v1/custom-attack/property-values/attack%20tactic").mock(
            return_value=ok({"name": "attack tactic", "values": ["roleplay"]})
        )

        result = runner.invoke(redteam_app, ["properties", "values", "attack tactic"])

        assert result.exit_code == 0
        assert route.called
        assert "roleplay" in result.output

    def test_add_value_sends_name_and_value(self, api: respx.MockRouter) -> None:
        route = api.post(f"{MGMT}/v1/custom-attack/property-values").mock(
            return_value=ok({"message": "value added", "status": 201})
        )

        result = runner.invoke(
            redteam_app,
            ["properties", "add-value", "--name", "tactic", "--value", "roleplay"],
        )

        assert result.exit_code == 0
        assert body_of(route) == {"property_name": "tactic", "property_value": "roleplay"}
        assert "value added" in result.output


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------


class TestTargets:
    def test_list_walks_every_page(self, api: respx.MockRouter) -> None:
        """The listing endpoint has no "everything" mode, so a full page means more."""
        first = [{**TARGET_ROW, "name": f"t{i}"} for i in range(100)]
        route = api.get(f"{MGMT}/v1/target").mock(
            side_effect=[
                ok({"pagination": {"total_items": 101}, "data": first}),
                ok({"pagination": {"total_items": 101}, "data": [{**TARGET_ROW, "name": "t100"}]}),
            ]
        )

        result = runner.invoke(redteam_app, ["targets", "list", "--output", "csv"])

        assert result.exit_code == 0
        assert [call.request.url.params["skip"] for call in route.calls] == ["0", "100"]
        assert "t100" in result.output

    def test_list_stops_after_a_short_page(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [TARGET_ROW]})
        )

        runner.invoke(redteam_app, ["targets", "list"])

        assert len(route.calls) == 1

    def test_get_shows_the_connection_block(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/target/{TARGET_ID}").mock(return_value=ok(TARGET_DETAIL))

        result = runner.invoke(redteam_app, ["targets", "get", TARGET_ID])

        assert result.exit_code == 0
        assert route.called
        assert route.calls.last.request.method == "GET"
        assert "api_endpoint" in result.output

    def test_get_hides_the_multi_turn_error_when_multi_turn_is_off(
        self, api: respx.MockRouter
    ) -> None:
        """The message is always populated; it only means something when multi-turn is on."""
        api.get(f"{MGMT}/v1/target/{TARGET_ID}").mock(
            return_value=ok(
                {
                    **TARGET_DETAIL,
                    "target_metadata": {
                        "multi_turn": False,
                        "multi_turn_error_message": "not supported",
                    },
                }
            )
        )

        result = runner.invoke(redteam_app, ["targets", "get", TARGET_ID])

        assert "not supported" not in result.output

    def test_create_omits_validate_unless_asked(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.post(f"{MGMT}/v1/target").mock(return_value=ok(TARGET_DETAIL))
        config = json_file(tmp_path, "target.json", {"name": "prod-bot"})

        result = runner.invoke(redteam_app, ["targets", "create", "--config", config])

        assert result.exit_code == 0
        assert "validate" not in route.calls.last.request.url.params
        assert body_of(route)["name"] == "prod-bot"

    def test_create_validate_flag_is_sent(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.post(f"{MGMT}/v1/target").mock(return_value=ok(TARGET_DETAIL))
        config = json_file(tmp_path, "target.json", {"name": "prod-bot"})

        runner.invoke(redteam_app, ["targets", "create", "--config", config, "--validate"])

        assert route.calls.last.request.url.params["validate"] == "true"

    def test_update_replaces_the_target(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.put(f"{MGMT}/v1/target/{TARGET_ID}").mock(return_value=ok(TARGET_DETAIL))
        config = json_file(tmp_path, "target.json", {"name": "renamed"})

        result = runner.invoke(redteam_app, ["targets", "update", TARGET_ID, "--config", config])

        assert result.exit_code == 0
        assert body_of(route)["name"] == "renamed"

    def test_delete_refuses_without_force_when_nobody_can_be_asked(
        self, api: respx.MockRouter
    ) -> None:
        route = api.delete(f"{MGMT}/v1/target/{TARGET_ID}").mock(
            return_value=ok({"message": "deleted", "status": 200})
        )

        result = runner.invoke(redteam_app, ["targets", "delete", TARGET_ID])

        assert result.exit_code == 2
        assert not route.called

    def test_delete_with_force_removes_the_target(self, api: respx.MockRouter) -> None:
        route = api.delete(f"{MGMT}/v1/target/{TARGET_ID}").mock(
            return_value=ok({"message": "deleted", "status": 200})
        )

        result = runner.invoke(redteam_app, ["targets", "delete", TARGET_ID, "--force"])

        assert result.exit_code == 0
        assert route.called

    def test_probe_posts_the_draft_target(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.post(f"{MGMT}/v1/target/probe").mock(return_value=ok(TARGET_DETAIL))
        config = json_file(tmp_path, "probe.json", {"name": "draft-bot"})

        result = runner.invoke(redteam_app, ["targets", "probe", "--config", config])

        assert result.exit_code == 0
        assert body_of(route)["name"] == "draft-bot"

    def test_profile_reads_the_profile_endpoint(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/target/{TARGET_ID}/profile").mock(
            return_value=ok({"target_id": TARGET_ID, "target_version": 2, "status": "READY"})
        )

        result = runner.invoke(redteam_app, ["targets", "profile", TARGET_ID])

        assert result.exit_code == 0
        assert route.called
        assert '"target_version": 2' in result.output

    def test_update_profile_puts_the_context(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.put(f"{MGMT}/v1/target/{TARGET_ID}/profile").mock(
            return_value=ok(TARGET_DETAIL)
        )
        config = json_file(tmp_path, "profile.json", {"target_background": {"industry": "finance"}})

        result = runner.invoke(
            redteam_app, ["targets", "update-profile", TARGET_ID, "--config", config]
        )

        assert result.exit_code == 0
        assert body_of(route)["target_background"]["industry"] == "finance"

    def test_validate_auth_sends_type_config_and_target(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.post(f"{MGMT}/v1/target/validate-auth").mock(
            return_value=ok({"validated": True, "token_preview": "abc...", "expires_in": 3600})
        )
        config = json_file(tmp_path, "auth.json", {"auth_header": {"Authorization": "Bearer x"}})

        result = runner.invoke(
            redteam_app,
            [
                "targets",
                "validate-auth",
                "--auth-type",
                "HEADERS",
                "--config",
                config,
                "--target-id",
                TARGET_ID,
            ],
        )

        assert result.exit_code == 0
        body = body_of(route)
        assert body["auth_type"] == "HEADERS"
        assert body["target_id"] == TARGET_ID
        assert body["auth_config"]["auth_header"]["Authorization"] == "Bearer x"
        assert "3600s" in result.output

    def test_metadata_emits_bare_json(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/template/target-metadata").mock(
            return_value=ok({"fields": ["api_endpoint"]})
        )

        result = runner.invoke(redteam_app, ["targets", "metadata"])

        assert route.called
        assert json.loads(result.output) == {"fields": ["api_endpoint"]}

    def test_templates_are_keyed_by_provider(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/template/target-templates").mock(return_value=ok(TEMPLATES))

        result = runner.invoke(redteam_app, ["targets", "templates"])

        assert result.exit_code == 0
        assert route.called
        assert "OPENAI" in result.output

    def test_error_logs_translate_offset_to_skip(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/error-log/target-profile/{TARGET_ID}").mock(
            return_value=ok(
                {
                    "pagination": {"total_items": 1},
                    "data": [
                        {
                            "created_at": "2026-01-01T00:00:00Z",
                            "updated_at": "2026-01-01T00:00:00Z",
                            "error_type": "TIMEOUT",
                            "error_message": "target did not answer",
                        }
                    ],
                }
            )
        )

        result = runner.invoke(
            redteam_app,
            [
                "targets",
                "error-logs",
                TARGET_ID,
                "--limit",
                "5",
                "--offset",
                "10",
                "--search",
                "timeout",
            ],
        )

        assert result.exit_code == 0
        params = route.calls.last.request.url.params
        assert (params["skip"], params["limit"], params["search"]) == ("10", "5", "timeout")
        assert "target did not answer" in result.output


class TestTargetInit:
    def test_rest_provider_scaffold_uses_the_current_field_names(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """The template endpoint still returns a legacy `url`; the API wants api_endpoint."""
        route = api.get(f"{MGMT}/v1/template/target-templates").mock(return_value=ok(TEMPLATES))
        destination = tmp_path / "rest.json"

        result = runner.invoke(
            redteam_app, ["targets", "init", "REST", "--output-file", str(destination)]
        )

        assert result.exit_code == 0
        assert route.called
        scaffold = json.loads(destination.read_text())
        assert scaffold["connection_params"]["api_endpoint"] == "https://rest.example"
        assert "url" not in scaffold["connection_params"]

    def test_native_provider_scaffold_nests_the_template(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(f"{MGMT}/v1/template/target-templates").mock(return_value=ok(TEMPLATES))
        destination = tmp_path / "openai.json"

        runner.invoke(redteam_app, ["targets", "init", "openai", "--output-file", str(destination)])

        scaffold = json.loads(destination.read_text())
        assert scaffold["connection_type"] == "OPENAI"
        assert scaffold["connection_params"]["target_connection_config"]["model_name"] == "gpt-4o"

    def test_adapter_scaffold_uses_the_broker_shape(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(f"{MGMT}/v1/template/target-templates").mock(return_value=ok(TEMPLATES))
        destination = tmp_path / "adapter.json"

        runner.invoke(
            redteam_app,
            ["targets", "init", "CUSTOM_TARGET_ADAPTER", "--output-file", str(destination)],
        )

        scaffold = json.loads(destination.read_text())
        assert scaffold["api_endpoint_type"] == "NETWORK_BROKER"
        assert scaffold["adapter_variable_overrides"] == []

    def test_an_unknown_provider_exits_two(self, api: respx.MockRouter, tmp_path: Path) -> None:
        result = runner.invoke(
            redteam_app,
            ["targets", "init", "OLLAMA", "--output-file", str(tmp_path / "x.json")],
        )

        assert result.exit_code == 2

    def test_an_existing_file_is_never_overwritten(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        destination = tmp_path / "taken.json"
        destination.write_text("keep me")

        result = runner.invoke(
            redteam_app, ["targets", "init", "REST", "--output-file", str(destination)]
        )

        assert result.exit_code == 2
        assert destination.read_text() == "keep me"


# ---------------------------------------------------------------------------
# Target backup and restore
# ---------------------------------------------------------------------------


class TestBackupRestore:
    def test_backup_writes_one_file_per_target(self, api: respx.MockRouter, tmp_path: Path) -> None:
        listing = api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [TARGET_ROW]})
        )
        detail = api.get(f"{MGMT}/v1/target/{TARGET_ID}").mock(return_value=ok(TARGET_DETAIL))
        out = tmp_path / "backups"

        result = runner.invoke(redteam_app, ["targets", "backup", "--output-dir", str(out)])

        assert result.exit_code == 0
        # Backup walks the list, then re-reads each target for its full config.
        assert listing.called
        assert detail.called
        envelope = json.loads((out / "prod-bot.json").read_text())
        assert envelope["resourceType"] == "redteam-target"
        assert envelope["data"]["name"] == "prod-bot"
        assert "uuid" not in envelope["data"]

    def test_backup_can_emit_yaml(self, api: respx.MockRouter, tmp_path: Path) -> None:
        api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [TARGET_ROW]})
        )
        api.get(f"{MGMT}/v1/target/{TARGET_ID}").mock(return_value=ok(TARGET_DETAIL))
        out = tmp_path / "backups"

        runner.invoke(
            redteam_app, ["targets", "backup", "--output-dir", str(out), "--output", "yaml"]
        )

        assert (out / "prod-bot.yaml").exists()

    def test_backup_of_an_unknown_name_exits_two(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [TARGET_ROW]})
        )

        result = runner.invoke(
            redteam_app,
            ["targets", "backup", "--output-dir", str(tmp_path), "--name", "absent"],
        )

        assert result.exit_code == 2

    def test_a_partial_backup_exits_one(self, api: respx.MockRouter, tmp_path: Path) -> None:
        """A scheduled job must notice an incomplete backup rather than trust it."""
        api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [TARGET_ROW]})
        )
        api.get(f"{MGMT}/v1/target/{TARGET_ID}").mock(
            return_value=ok({"message": "gone"}, status=404)
        )

        result = runner.invoke(redteam_app, ["targets", "backup", "--output-dir", str(tmp_path)])

        assert result.exit_code == 1

    def test_restore_requires_a_source(self, api: respx.MockRouter) -> None:
        result = runner.invoke(redteam_app, ["targets", "restore"])

        assert result.exit_code == 2
        assert "--file" in result.output

    def test_restore_creates_a_missing_target(self, api: respx.MockRouter, tmp_path: Path) -> None:
        api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 0}, "data": []})
        )
        route = api.post(f"{MGMT}/v1/target").mock(return_value=ok(TARGET_DETAIL))
        backup = json_file(
            tmp_path,
            "prod-bot.json",
            {
                "version": "1",
                "resourceType": "redteam-target",
                "exportedAt": "2026-01-01T00:00:00Z",
                "data": {"name": "prod-bot", "uuid": "should-be-stripped"},
            },
        )

        result = runner.invoke(redteam_app, ["targets", "restore", "--file", backup])

        assert result.exit_code == 0
        body = body_of(route)
        assert body["name"] == "prod-bot"
        assert "uuid" not in body
        assert body["connection_type"] == "CUSTOM"

    def test_restore_skips_an_existing_target_without_overwrite(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [TARGET_ROW]})
        )
        created = api.post(f"{MGMT}/v1/target").mock(return_value=ok(TARGET_DETAIL))
        backup = json_file(
            tmp_path,
            "prod-bot.json",
            {
                "version": "1",
                "resourceType": "redteam-target",
                "data": {"name": "prod-bot"},
            },
        )

        result = runner.invoke(redteam_app, ["targets", "restore", "--file", backup])

        assert result.exit_code == 0
        assert not created.called
        assert "skipped" in result.output

    def test_overwrite_updates_and_fills_the_routing_tuple(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """A backup taken before those fields existed still has to produce a valid PUT."""
        api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [TARGET_ROW]})
        )
        api.get(f"{MGMT}/v1/target/{TARGET_ID}").mock(return_value=ok(TARGET_DETAIL))
        route = api.put(f"{MGMT}/v1/target/{TARGET_ID}").mock(return_value=ok(TARGET_DETAIL))
        backup = json_file(
            tmp_path,
            "prod-bot.json",
            {
                "version": "1",
                "resourceType": "redteam-target",
                "data": {"name": "prod-bot"},
            },
        )

        result = runner.invoke(redteam_app, ["targets", "restore", "--file", backup, "--overwrite"])

        assert result.exit_code == 0
        body = body_of(route)
        assert body["target_type"] == "APPLICATION"
        assert body["response_mode"] == "REST"

    def test_restore_reads_a_whole_directory(self, api: respx.MockRouter, tmp_path: Path) -> None:
        api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 0}, "data": []})
        )
        route = api.post(f"{MGMT}/v1/target").mock(return_value=ok(TARGET_DETAIL))
        source = tmp_path / "backups"
        source.mkdir()
        for name in ("one", "two"):
            (source / f"{name}.json").write_text(
                json.dumps(
                    {
                        "version": "1",
                        "resourceType": "redteam-target",
                        "data": {"name": name},
                    }
                )
            )
        (source / "unrelated.txt").write_text("ignored")

        result = runner.invoke(redteam_app, ["targets", "restore", "--input-dir", str(source)])

        assert result.exit_code == 0
        assert len(route.calls) == 2

    def test_an_empty_backup_directory_exits_two(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        source = tmp_path / "empty"
        source.mkdir()

        result = runner.invoke(redteam_app, ["targets", "restore", "--input-dir", str(source)])

        assert result.exit_code == 2

    def test_a_backup_of_the_wrong_resource_exits_two(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        backup = json_file(
            tmp_path,
            "other.json",
            {"version": "1", "resourceType": "ai-gateway-app", "data": {"name": "x"}},
        )

        result = runner.invoke(redteam_app, ["targets", "restore", "--file", backup])

        assert result.exit_code == 2

    def test_a_failed_restore_exits_one(self, api: respx.MockRouter, tmp_path: Path) -> None:
        api.get(f"{MGMT}/v1/target").mock(
            return_value=ok({"pagination": {"total_items": 0}, "data": []})
        )
        api.post(f"{MGMT}/v1/target").mock(return_value=ok({"message": "bad"}, status=400))
        backup = json_file(
            tmp_path,
            "prod-bot.json",
            {"version": "1", "resourceType": "redteam-target", "data": {"name": "prod-bot"}},
        )

        result = runner.invoke(redteam_app, ["targets", "restore", "--file", backup])

        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# Custom target adapters
# ---------------------------------------------------------------------------

SCRIPT_SOURCE = "def respond(prompt):\n    return prompt\n"
SCRIPT_B64 = "ZGVmIHJlc3BvbmQocHJvbXB0KToKICAgIHJldHVybiBwcm9tcHQK"


def script_file(tmp_path: Path) -> str:
    """Write an adapter script and return its path."""
    path = tmp_path / "adapter.py"
    path.write_text(SCRIPT_SOURCE)
    return str(path)


class TestAdapters:
    def test_list_translates_offset_to_skip(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/adapters").mock(
            return_value=ok(
                {
                    "pagination": {"total_items": 1},
                    "data": [
                        {
                            "uuid": ADAPTER_ID,
                            "name": "sidecar",
                            "status": "ACTIVE",
                            "created_at": "2026-01-01T00:00:00Z",
                            "updated_at": "2026-01-01T00:00:00Z",
                        }
                    ],
                }
            )
        )

        result = runner.invoke(
            redteam_app,
            ["adapter", "list", "--limit", "2", "--offset", "4", "--search", "side"],
        )

        assert result.exit_code == 0
        params = route.calls.last.request.url.params
        assert (params["skip"], params["limit"], params["search"]) == ("4", "2", "side")
        assert "sidecar" in result.output

    def test_get_reports_the_redaction_flag_not_the_mask(self, api: respx.MockRouter) -> None:
        """Nobody should copy `**********` into a config file believing it is the value."""
        route = api.get(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(return_value=ok(ADAPTER))

        result = runner.invoke(redteam_app, ["adapter", "get", ADAPTER_ID])

        assert result.exit_code == 0
        assert route.called
        assert route.calls.last.request.method == "GET"
        assert "(redacted)" in result.output
        assert "**********" not in result.output

    def test_create_encodes_the_script_file(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.post(f"{MGMT}/v1/adapters").mock(return_value=ok(ADAPTER))

        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "create",
                "--name",
                "sidecar",
                "--prompt",
                "Hello",
                "--script-file",
                script_file(tmp_path),
            ],
        )

        assert result.exit_code == 0
        assert body_of(route)["script_b64"] == SCRIPT_B64
        assert route.calls.last.request.url.params["validate"] == "true"

    def test_draft_creation_skips_validation(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.post(f"{MGMT}/v1/adapters").mock(
            return_value=ok({**ADAPTER, "status": "DRAFT"})
        )

        runner.invoke(
            redteam_app,
            [
                "adapter",
                "create",
                "--name",
                "sidecar",
                "--prompt",
                "Hello",
                "--script-b64",
                SCRIPT_B64,
                "--draft",
            ],
        )

        assert route.calls.last.request.url.params["validate"] == "false"

    def test_create_parses_variables(self, api: respx.MockRouter) -> None:
        route = api.post(f"{MGMT}/v1/adapters").mock(return_value=ok(ADAPTER))

        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "create",
                "--name",
                "sidecar",
                "--prompt",
                "Hello",
                "--script-b64",
                SCRIPT_B64,
                "--variables",
                '[{"key":"endpoint","value":"http://agent.svc","type":"VAR"}]',
            ],
        )

        assert result.exit_code == 0
        assert body_of(route)["variables"] == [
            {"key": "endpoint", "value": "http://agent.svc", "type": "VAR"}
        ]

    def test_both_script_flags_exit_two(self, api: respx.MockRouter, tmp_path: Path) -> None:
        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "create",
                "--name",
                "s",
                "--prompt",
                "Hello",
                "--script-file",
                script_file(tmp_path),
                "--script-b64",
                SCRIPT_B64,
            ],
        )

        assert result.exit_code == 2

    def test_no_script_flag_exits_two(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            redteam_app, ["adapter", "create", "--name", "s", "--prompt", "Hello"]
        )

        assert result.exit_code == 2

    def test_malformed_variables_exit_two(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "create",
                "--name",
                "s",
                "--prompt",
                "Hello",
                "--script-b64",
                SCRIPT_B64,
                "--variables",
                '[{"key":"endpoint","type":"NOPE"}]',
            ],
        )

        assert result.exit_code == 2

    def test_an_offline_channel_fails_before_the_write(self, api: respx.MockRouter) -> None:
        """Upstream's error for an unreachable broker sends people to look at the script."""
        api.get(f"{BROKER}/v1/channels/{CHANNEL_ID}").mock(
            return_value=ok({**CHANNEL, "status": "OFFLINE"})
        )
        route = api.post(f"{MGMT}/v1/adapters").mock(return_value=ok(ADAPTER))

        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "create",
                "--name",
                "s",
                "--prompt",
                "Hello",
                "--script-b64",
                SCRIPT_B64,
                "--channel",
                CHANNEL_ID,
            ],
        )

        assert result.exit_code == 2
        assert not route.called
        assert "OFFLINE" in result.output

    def test_an_online_channel_lets_the_write_through(self, api: respx.MockRouter) -> None:
        api.get(f"{BROKER}/v1/channels/{CHANNEL_ID}").mock(return_value=ok(CHANNEL))
        route = api.post(f"{MGMT}/v1/adapters").mock(return_value=ok(ADAPTER))

        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "create",
                "--name",
                "s",
                "--prompt",
                "Hello",
                "--script-b64",
                SCRIPT_B64,
                "--channel",
                CHANNEL_ID,
            ],
        )

        assert result.exit_code == 0
        assert body_of(route)["network_broker_channel_uuid"] == CHANNEL_ID

    def test_update_preserves_stored_variables_and_script(self, api: respx.MockRouter) -> None:
        """Update is a full-replacement PUT: an omitted key deletes the variable upstream."""
        api.get(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(return_value=ok(ADAPTER))
        route = api.put(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(return_value=ok(ADAPTER))

        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "update",
                ADAPTER_ID,
                "--prompt",
                "Hello",
                "--description",
                "new description",
            ],
        )

        assert result.exit_code == 0
        body = body_of(route)
        assert body["name"] == "sidecar"
        assert body["script_b64"] == ADAPTER["script_b64"]
        assert body["description"] == "new description"
        # A redacted secret is resent without a value, which upstream reads as "keep it".
        assert body["variables"] == [
            {"key": "endpoint", "value": "http://agent.svc", "type": "VAR"},
            {"key": "token", "type": "SECRET"},
        ]

    def test_update_replaces_variables_when_asked(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(return_value=ok(ADAPTER))
        route = api.put(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(return_value=ok(ADAPTER))

        runner.invoke(
            redteam_app,
            [
                "adapter",
                "update",
                ADAPTER_ID,
                "--prompt",
                "Hello",
                "--variables",
                '[{"key":"only","value":"1","type":"VAR"}]',
            ],
        )

        assert body_of(route)["variables"] == [{"key": "only", "value": "1", "type": "VAR"}]

    def test_update_requires_a_prompt(self, api: respx.MockRouter) -> None:
        """Upstream never stores the sample prompt, so every update has to supply one."""
        result = runner.invoke(redteam_app, ["adapter", "update", ADAPTER_ID, "--name", "x"])

        assert result.exit_code == 2

    def test_delete_refuses_without_force(self, api: respx.MockRouter) -> None:
        route = api.delete(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(
            return_value=ok({"message": "deleted", "status": 200})
        )

        result = runner.invoke(redteam_app, ["adapter", "delete", ADAPTER_ID])

        assert result.exit_code == 2
        assert not route.called

    def test_delete_with_force_removes_the_adapter(self, api: respx.MockRouter) -> None:
        route = api.delete(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(
            return_value=ok({"message": "deleted", "status": 200})
        )

        result = runner.invoke(redteam_app, ["adapter", "delete", ADAPTER_ID, "--force"])

        assert result.exit_code == 0
        assert route.called

    def test_validate_exits_zero_when_the_script_runs(self, api: respx.MockRouter) -> None:
        api.get(f"{BROKER}/v1/channels/{CHANNEL_ID}").mock(return_value=ok(CHANNEL))
        route = api.post(f"{MGMT}/v1/adapters/validate").mock(
            return_value=ok({"validated": True, "stdout": "pong"})
        )

        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "validate",
                "--channel",
                CHANNEL_ID,
                "--prompt",
                "Hello",
                "--script-b64",
                SCRIPT_B64,
            ],
        )

        assert result.exit_code == 0
        body = body_of(route)
        assert body["network_broker_channel_uuid"] == CHANNEL_ID
        assert body["prompt"] == "Hello"
        assert "pong" in result.output

    def test_validate_exits_one_when_the_script_fails(self, api: respx.MockRouter) -> None:
        """So a broken adapter fails the pipeline that was supposed to check it."""
        api.get(f"{BROKER}/v1/channels/{CHANNEL_ID}").mock(return_value=ok(CHANNEL))
        api.post(f"{MGMT}/v1/adapters/validate").mock(
            return_value=ok({"validated": False, "traceback": "KeyError: endpoint"})
        )

        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "validate",
                "--channel",
                CHANNEL_ID,
                "--prompt",
                "Hello",
                "--script-b64",
                SCRIPT_B64,
            ],
        )

        assert result.exit_code == 1
        assert "KeyError: endpoint" in result.output

    def test_validate_borrows_the_variable_set_from_an_existing_adapter(
        self, api: respx.MockRouter
    ) -> None:
        """adapter_uuid resolves redacted values but does not supply the keys."""
        api.get(f"{BROKER}/v1/channels/{CHANNEL_ID}").mock(return_value=ok(CHANNEL))
        api.get(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(return_value=ok(ADAPTER))
        route = api.post(f"{MGMT}/v1/adapters/validate").mock(return_value=ok({"validated": True}))

        result = runner.invoke(
            redteam_app,
            [
                "adapter",
                "validate",
                "--channel",
                CHANNEL_ID,
                "--prompt",
                "Hello",
                "--script-b64",
                SCRIPT_B64,
                "--adapter",
                ADAPTER_ID,
            ],
        )

        assert result.exit_code == 0
        body = body_of(route)
        assert body["adapter_uuid"] == ADAPTER_ID
        assert [variable["key"] for variable in body["variables"]] == ["endpoint", "token"]


# ---------------------------------------------------------------------------
# Network broker
# ---------------------------------------------------------------------------


class TestNetworkBroker:
    def test_channels_list_repeats_the_status_key(self, api: respx.MockRouter) -> None:
        """The endpoint reads status as a set; a comma-joined string matches nothing."""
        route = api.get(f"{BROKER}/v1/channels").mock(
            return_value=ok({"pagination": {"total_items": 1}, "data": [CHANNEL]})
        )

        result = runner.invoke(
            redteam_app,
            ["network-broker", "channels", "list", "--status", "ONLINE", "--status", "DRAFT"],
        )

        assert result.exit_code == 0
        assert route.calls.last.request.url.params.get_list("status") == ["ONLINE", "DRAFT"]
        assert "lab" in result.output

    def test_channels_list_reports_an_empty_tenant(self, api: respx.MockRouter) -> None:
        api.get(f"{BROKER}/v1/channels").mock(
            return_value=ok({"pagination": {"total_items": 0}, "data": []})
        )

        result = runner.invoke(redteam_app, ["network-broker", "channels", "list"])

        assert result.exit_code == 0
        assert "No channels found" in result.output

    def test_channels_get_reads_one_channel(self, api: respx.MockRouter) -> None:
        route = api.get(f"{BROKER}/v1/channels/{CHANNEL_ID}").mock(return_value=ok(CHANNEL))

        result = runner.invoke(redteam_app, ["network-broker", "channels", "get", CHANNEL_ID])

        assert result.exit_code == 0
        assert route.called
        assert "ONLINE" in result.output

    def test_channels_create_sends_name_and_description(self, api: respx.MockRouter) -> None:
        route = api.post(f"{BROKER}/v1/channels").mock(return_value=ok(CHANNEL))

        result = runner.invoke(
            redteam_app,
            ["network-broker", "channels", "create", "--name", "lab", "--description", "d"],
        )

        assert result.exit_code == 0
        assert body_of(route) == {"name": "lab", "description": "d"}

    def test_channels_update_uses_patch(self, api: respx.MockRouter) -> None:
        route = api.patch(f"{BROKER}/v1/channels/{CHANNEL_ID}").mock(return_value=ok(CHANNEL))

        result = runner.invoke(
            redteam_app,
            ["network-broker", "channels", "update", CHANNEL_ID, "--name", "lab-2"],
        )

        assert result.exit_code == 0
        assert body_of(route) == {"name": "lab-2"}

    def test_channels_update_without_a_field_exits_two(self, api: respx.MockRouter) -> None:
        route = api.patch(f"{BROKER}/v1/channels/{CHANNEL_ID}").mock(return_value=ok(CHANNEL))

        result = runner.invoke(redteam_app, ["network-broker", "channels", "update", CHANNEL_ID])

        assert result.exit_code == 2
        assert not route.called

    def test_stats_read_the_stats_path(self, api: respx.MockRouter) -> None:
        route = api.get(f"{BROKER}/v1/channels/stats").mock(
            return_value=ok(
                {
                    "online_channels": 1,
                    "total_channels": 3,
                    "docker_image": "panw/broker:1.4.0",
                }
            )
        )

        result = runner.invoke(redteam_app, ["network-broker", "stats"])

        assert result.exit_code == 0
        assert route.called
        assert "panw/broker:1.4.0" in result.output
