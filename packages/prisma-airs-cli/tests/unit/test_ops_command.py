"""Behaviour of the operational commands: doctor, completion, backup, restore, cleanup.

Every command is driven through the CLI with the HTTP layer intercepted, so the
assertions are about the request that actually went on the wire and the exit code the
caller receives -- the two things a pipeline depends on.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Annotated, Any

import httpx
import pytest
import respx
import typer
import yaml
from typer.testing import CliRunner

from prisma_airs._http.debug import hash_token
from prisma_airs.constants import (
    DEFAULT_AI_GW_DATA_ENDPOINT,
    DEFAULT_ENDPOINT,
    DEFAULT_MGMT_ENDPOINT,
    DEFAULT_RED_TEAM_MGMT_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
)
from prisma_airs.models.management import SecurityProfile
from prisma_airs_cli.commands.ops import (
    check_config_file,
    check_python_version,
    check_scanner_credentials,
    collect_completion_nodes,
    find_duplicate_profiles,
    ops_app,
    resolve_output_dir,
    sanitize_filename,
)

runner = CliRunner()

TSG_ID = "1852583913"
API_KEY = "scanner-key"

SCAN_RESULTS_URL = f"{DEFAULT_ENDPOINT}/v1/scan/results"
TOPICS_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/topics/tsg/{TSG_ID}"
PROFILES_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/profiles/tsg/{TSG_ID}"
PROFILE_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/profile"
WORKSPACES_URL = f"{DEFAULT_AI_GW_DATA_ENDPOINT}/workspaces"
TARGET_URL = f"{DEFAULT_RED_TEAM_MGMT_ENDPOINT}/v1/target"

UUID_A = "550e8400-e29b-41d4-a716-446655440000"
UUID_B = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

WORKSPACE = {
    "id": "ws-1",
    "slug": "main",
    "name": "main",
    "icon": None,
    "description": None,
    "created_at": "2026-01-01T00:00:00Z",
    "last_updated_at": "2026-01-01T00:00:00Z",
    "is_default": 1,
    "status": "active",
    "scope_name": f"main_airs_workspace_{TSG_ID}",
    "object": "workspace",
}

TOPIC = {
    "topic_id": UUID_A,
    "topic_name": "credit-cards",
    "revision": 1,
    "description": "Detects card numbers",
    "examples": ["4111-1111-1111-1111"],
}


def target_row(uuid: str, name: str) -> dict[str, Any]:
    """A target as it appears in a list response."""
    return {
        "uuid": uuid,
        "tsg_id": TSG_ID,
        "name": name,
        "active": True,
        "validated": True,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "status": "READY",
        "target_type": "API",
    }


def target_detail(uuid: str, name: str) -> dict[str, Any]:
    """A target as it appears when fetched by ID, with its connection settings."""
    return {
        **target_row(uuid, name),
        "connection_type": "CUSTOM",
        "api_endpoint_type": "PUBLIC",
        "response_mode": "REST",
        "description": "a target",
        "connection_params": {
            "api_endpoint": "https://target.test/v1/chat",
            "response_key": "text",
        },
    }


def profile(profile_id: str, name: str, revision: int) -> dict[str, Any]:
    """One stored revision of a security profile."""
    return {"profile_id": profile_id, "profile_name": name, "revision": revision, "active": True}


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests off the developer's real credentials, config, and terminal width."""
    monkeypatch.setenv("PANW_AI_SEC_API_KEY", API_KEY)
    monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "client-id")
    monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("PANW_MGMT_TSG_ID", TSG_ID)
    monkeypatch.setenv("PRISMA_AIRS_CONFIG", str(tmp_path / "config.json"))
    # Rich wraps at the detected width; a narrow default would split the very strings
    # these tests assert on.
    monkeypatch.setenv("COLUMNS", "300")
    for name in (
        "PANW_AI_SEC_API_TOKEN",
        "PANW_AI_SEC_API_ENDPOINT",
        "PANW_MGMT_ENDPOINT",
        "PANW_MGMT_TOKEN_ENDPOINT",
    ):
        monkeypatch.delenv(name, raising=False)
    for prefix in ("PANW_AI_GW", "PANW_RED_TEAM"):
        for suffix in (
            "CLIENT_ID",
            "CLIENT_SECRET",
            "TSG_ID",
            "DATA_ENDPOINT",
            "ADMIN_ENDPOINT",
            "MGMT_ENDPOINT",
            "TOKEN_ENDPOINT",
        ):
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)


@pytest.fixture
def cli() -> typer.Typer:
    """The root application, wired the way the real one is.

    ``ops_app`` carries no name, so Typer merges it into the parent and its commands sit
    at the top level -- ``airs doctor``, not ``airs ops doctor``.
    """
    app = typer.Typer(name="airs")
    app.add_typer(ops_app)

    scanner = typer.Typer(name="runtime")

    @scanner.command("scan")
    def scan(
        *,
        prompt: Annotated[str, typer.Option("--prompt", "-p", help="Prompt.")] = "",
    ) -> None:
        """Scan."""

    app.add_typer(scanner)
    return app


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    """Intercept HTTP with the OAuth token exchange already stubbed."""
    with respx.mock(assert_all_called=False) as router:
        router.post(DEFAULT_TOKEN_ENDPOINT, name="token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 899})
        )
        yield router


def sent(route: respx.Route) -> httpx.Request:
    """The last request a route received."""
    return route.calls.last.request


def body_of(route: respx.Route) -> Any:
    """The last request body a route received, decoded from JSON."""
    return json.loads(sent(route).content)


def json_documents(text: str) -> list[Any]:
    """Split a stdout stream of concatenated JSON documents into a list."""
    decoder = json.JSONDecoder()
    documents: list[Any] = []
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        value, index = decoder.raw_decode(text, index)
        documents.append(value)
    return documents


def healthy_doctor_routes(api: respx.MockRouter) -> dict[str, respx.Route]:
    """Stub every plane the doctor probes with a successful answer."""
    return {
        "scan": api.get(SCAN_RESULTS_URL).mock(return_value=httpx.Response(200, json=[])),
        "topics": api.get(TOPICS_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        ),
        "workspaces": api.get(WORKSPACES_URL).mock(
            return_value=httpx.Response(
                200, json={"object": "list", "total": 1, "data": [WORKSPACE]}
            )
        ),
    }


class TestDoctorProbes:
    def test_probes_every_plane(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        routes = healthy_doctor_routes(api)

        result = runner.invoke(cli, ["doctor"])

        assert result.exit_code == 0
        assert sent(routes["scan"]).method == "GET"
        assert sent(routes["scan"]).url.path == "/v1/scan/results"
        assert str(sent(routes["topics"]).url) == f"{TOPICS_URL}?offset=0&limit=100"
        assert str(sent(routes["workspaces"]).url) == WORKSPACES_URL

    def test_the_scanner_probe_queries_results_rather_than_scanning(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        """Submitting content would burn scan quota to answer "are you reachable"."""
        routes = healthy_doctor_routes(api)

        runner.invoke(cli, ["doctor"])

        scan_ids = dict(sent(routes["scan"]).url.params)["scan_ids"]
        assert len(scan_ids) == 36
        assert scan_ids.count("-") == 4

    def test_reports_the_counts_each_plane_returned(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        healthy_doctor_routes(api)

        result = runner.invoke(cli, ["doctor"])

        assert "1 custom topic" in result.output
        assert "1 workspace in scope" in result.output


class TestDoctorCredentialHandling:
    def test_never_prints_a_credential(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        healthy_doctor_routes(api)

        result = runner.invoke(cli, ["doctor"])

        assert API_KEY not in result.output
        assert "client-secret" not in result.output

    def test_prints_a_digest_instead(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        healthy_doctor_routes(api)

        result = runner.invoke(cli, ["doctor"])

        assert hash_token(API_KEY) in result.output
        assert hash_token("client-secret") in result.output

    def test_skips_probes_whose_credentials_are_absent(
        self, cli: typer.Typer, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PANW_MGMT_CLIENT_SECRET")
        routes = healthy_doctor_routes(api)

        result = runner.invoke(cli, ["doctor"])

        assert routes["topics"].call_count == 0
        assert routes["workspaces"].call_count == 0
        assert "missing: PANW_MGMT_CLIENT_SECRET" in result.output

    def test_missing_credentials_fail_the_preflight(
        self, cli: typer.Typer, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PANW_AI_SEC_API_KEY")
        healthy_doctor_routes(api)

        result = runner.invoke(cli, ["doctor"])

        assert result.exit_code == 1


class TestDoctorVerdicts:
    def test_a_rejected_key_fails(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        healthy_doctor_routes(api)
        api.get(SCAN_RESULTS_URL).mock(
            return_value=httpx.Response(401, json={"message": "Invalid API Key"})
        )

        result = runner.invoke(cli, ["doctor"])

        assert result.exit_code == 1
        assert "API key rejected" in result.output

    def test_a_refused_probe_query_still_proves_the_key_works(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        """400 means we got past auth: the endpoint answered and the key was accepted."""
        healthy_doctor_routes(api)
        api.get(SCAN_RESULTS_URL).mock(
            return_value=httpx.Response(400, json={"message": "unknown scan id"})
        )

        result = runner.invoke(cli, ["doctor"])

        assert result.exit_code == 0
        assert "API key accepted (HTTP 400 on probe query)" in result.output

    def test_a_gateway_403_warns_rather_than_fails(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        """A tenant that does not use the AI Gateway still has a healthy install."""
        healthy_doctor_routes(api)
        api.get(WORKSPACES_URL).mock(
            return_value=httpx.Response(
                403, json={"data": {"message": "denied", "errorCode": "AB03"}}
            )
        )

        result = runner.invoke(cli, ["doctor"])

        assert result.exit_code == 0
        assert "workspace-scope grant" in result.output

    def test_a_gateway_403_without_ab03_blames_the_tenant_root_grant(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        """The two planes fail identically apart from that code, and need opposite fixes."""
        healthy_doctor_routes(api)
        api.get(WORKSPACES_URL).mock(return_value=httpx.Response(403, json={"msg": "denied"}))

        result = runner.invoke(cli, ["doctor"])

        assert "tenant-root admin grant" in result.output
        assert "workspace-scope grant" not in result.output

    def test_a_management_failure_fails_the_preflight(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        healthy_doctor_routes(api)
        api.get(TOPICS_URL).mock(return_value=httpx.Response(404, json={"message": "nope"}))

        result = runner.invoke(cli, ["doctor"])

        assert result.exit_code == 1
        assert "management API error (HTTP 404)" in result.output


class TestDoctorOutputFormats:
    def test_json_is_parseable(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        healthy_doctor_routes(api)

        result = runner.invoke(cli, ["doctor", "--output", "json"])

        checks = json.loads(result.output)
        assert [c["name"] for c in checks] == [
            "Python version",
            "Config file",
            "Scanner credentials",
            "Management credentials",
            "Scanner API",
            "Management OAuth",
            "AI Gateway API",
        ]
        assert [c["status"] for c in checks if c["name"] == "Scanner API"] == ["pass"]

    def test_yaml_is_one_document_per_check(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        healthy_doctor_routes(api)

        result = runner.invoke(cli, ["doctor", "--output", "yaml"])

        documents = list(yaml.safe_load_all(result.output))
        assert len(documents) == 7
        assert documents[0]["name"] == "Python version"

    def test_rejects_an_unknown_format(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        healthy_doctor_routes(api)

        result = runner.invoke(cli, ["doctor", "--output", "xml"])

        assert result.exit_code == 2
        assert "Invalid value for '--output': 'xml' is not one of 'pretty', 'json', 'yaml'." in (
            result.output
        )


class TestDoctorChecks:
    def test_an_old_interpreter_fails(self) -> None:
        check = check_python_version((3, 9))

        assert check.status == "fail"
        assert "3.9" in check.detail

    def test_a_supported_interpreter_passes(self) -> None:
        assert check_python_version((3, 12)).status == "pass"

    def test_a_missing_config_file_only_warns(self, tmp_path: Path) -> None:
        check = check_config_file(tmp_path / "absent.json")

        assert check.status == "warn"

    def test_a_malformed_config_file_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_text("{not json")

        assert check_config_file(path).status == "fail"

    def test_a_config_file_holding_a_list_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_text("[]")

        assert check_config_file(path).status == "fail"

    def test_the_api_token_is_accepted_in_place_of_the_key(self) -> None:
        check = check_scanner_credentials({"PANW_AI_SEC_API_TOKEN": "t"})

        assert check.status == "pass"
        assert hash_token("t") in check.detail

    def test_an_empty_credential_counts_as_unset(self) -> None:
        assert check_scanner_credentials({"PANW_AI_SEC_API_KEY": ""}).status == "fail"


class TestCompletion:
    def test_bash_script_completes_the_top_level_commands(self, cli: typer.Typer) -> None:
        result = runner.invoke(cli, ["completion", "bash"])

        assert result.exit_code == 0
        assert "complete -F _airs_completions airs" in result.output
        root_case = next(line for line in result.output.splitlines() if line.startswith("    ''"))
        for command in ("doctor", "backup", "restore", "profiles-cleanup", "completion"):
            assert command in root_case

    def test_bash_script_completes_nested_paths(self, cli: typer.Typer) -> None:
        result = runner.invoke(cli, ["completion", "bash"])

        assert "'runtime') words=\"scan --help\" ;;" in result.output

    def test_long_flags_are_offered_but_short_ones_are_not(self, cli: typer.Typer) -> None:
        result = runner.invoke(cli, ["completion", "bash"])

        assert "--prompt" in result.output
        assert " -p " not in result.output

    def test_zsh_script_is_a_compdef(self, cli: typer.Typer) -> None:
        result = runner.invoke(cli, ["completion", "zsh"])

        assert result.output.startswith("#compdef airs")
        root_case = next(line for line in result.output.splitlines() if line.startswith("    ''"))
        assert root_case.startswith("    '') completions=(")
        assert "doctor" in root_case

    def test_fish_script_registers_the_program(self, cli: typer.Typer) -> None:
        result = runner.invoke(cli, ["completion", "fish"])

        assert "complete -c airs -f" in result.output
        assert "function __airs_using" in result.output

    def test_rejects_an_unsupported_shell(self, cli: typer.Typer) -> None:
        result = runner.invoke(cli, ["completion", "powershell"])

        assert result.exit_code == 2
        assert "'powershell' is not one of 'bash', 'zsh', 'fish'." in result.output

    def test_requires_a_shell(self, cli: typer.Typer) -> None:
        result = runner.invoke(cli, ["completion"])

        assert result.exit_code == 2
        assert "Missing argument 'shell'" in result.output

    def test_nodes_cover_every_command_path(self, cli: typer.Typer) -> None:
        command = typer.main.get_command(cli)
        nodes = collect_completion_nodes(command)

        assert {node.path for node in nodes} >= {"", "doctor", "runtime", "runtime scan"}

    def test_every_node_offers_help(self, cli: typer.Typer) -> None:
        nodes = collect_completion_nodes(typer.main.get_command(cli))

        assert all("--help" in node.words for node in nodes)


class TestBackup:
    def test_writes_one_file_per_target(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        listed = api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "pagination": {"total_items": 2},
                    "data": [target_row(UUID_A, "Alpha One"), target_row(UUID_B, "beta")],
                },
            )
        )
        api.get(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "Alpha One"))
        )
        api.get(f"{TARGET_URL}/{UUID_B}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_B, "beta"))
        )

        result = runner.invoke(cli, ["backup", "--output-dir", str(tmp_path)])

        assert result.exit_code == 0
        assert str(sent(listed).url) == f"{TARGET_URL}?skip=0&limit=100"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["alpha-one.json", "beta.json"]
        assert f"Backed up 2 targets to {tmp_path}" in result.output

    def test_the_envelope_carries_the_shared_schema(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )
        api.get(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )

        runner.invoke(cli, ["backup", "--output-dir", str(tmp_path)])

        envelope = json.loads((tmp_path / "alpha.json").read_text())
        assert envelope["version"] == "1"
        assert envelope["resourceType"] == "redteam-target"
        assert envelope["exportedAt"].endswith("Z")

    def test_server_assigned_fields_are_not_backed_up(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """They cannot be restored, so a file carrying them would only fail later."""
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )
        api.get(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )

        runner.invoke(cli, ["backup", "--output-dir", str(tmp_path)])

        data = json.loads((tmp_path / "alpha.json").read_text())["data"]
        assert "uuid" not in data
        assert "tsg_id" not in data
        assert "status" not in data
        assert data["connection_params"]["api_endpoint"] == "https://target.test/v1/chat"

    def test_backup_files_are_not_world_readable(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """A target definition carries endpoints and request templates."""
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )
        api.get(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )

        runner.invoke(cli, ["backup", "--output-dir", str(tmp_path)])

        assert (tmp_path / "alpha.json").stat().st_mode & 0o077 == 0

    def test_nested_nulls_are_not_written(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """A null inside connection_params would ask the API to unset it on restore."""
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )
        detail = target_detail(UUID_A, "alpha")
        detail["connection_params"] = {"api_endpoint": "https://target.test", "response_key": None}
        api.get(f"{TARGET_URL}/{UUID_A}").mock(return_value=httpx.Response(200, json=detail))

        runner.invoke(cli, ["backup", "--output-dir", str(tmp_path)])

        params = json.loads((tmp_path / "alpha.json").read_text())["data"]["connection_params"]
        assert params == {"api_endpoint": "https://target.test"}

    def test_an_empty_tenant_writes_nothing_and_succeeds(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(200, json={"pagination": {"total_items": 0}, "data": []})
        )

        result = runner.invoke(cli, ["backup", "--output-dir", str(tmp_path)])

        assert result.exit_code == 0
        assert list(tmp_path.iterdir()) == []
        assert "No targets found" in result.output

    def test_yaml_format_writes_yaml_files(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )
        api.get(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )

        runner.invoke(cli, ["backup", "--output-dir", str(tmp_path), "--output", "yaml"])

        envelope = yaml.safe_load((tmp_path / "alpha.yaml").read_text())
        assert envelope["data"]["name"] == "alpha"

    def test_a_single_target_can_be_named(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "pagination": {"total_items": 2},
                    "data": [target_row(UUID_A, "alpha"), target_row(UUID_B, "beta")],
                },
            )
        )
        detail_a = api.get(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        detail_b = api.get(f"{TARGET_URL}/{UUID_B}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_B, "beta"))
        )

        runner.invoke(cli, ["backup", "--output-dir", str(tmp_path), "--name", "alpha"])

        assert detail_a.call_count == 1
        assert detail_b.call_count == 0

    def test_an_unknown_name_is_a_usage_error(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )

        result = runner.invoke(cli, ["backup", "--output-dir", str(tmp_path), "--name", "ghost"])

        assert result.exit_code == 2
        assert "Target not found: ghost" in result.output

    def test_a_target_that_cannot_be_read_exits_two(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )
        api.get(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(403, json={"message": "forbidden"})
        )

        result = runner.invoke(cli, ["backup", "--output-dir", str(tmp_path)])

        assert result.exit_code == 2
        assert "Failed" in result.output

    def test_defaults_to_an_airs_backup_directory(
        self,
        cli: typer.Typer,
        api: respx.MockRouter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )
        api.get(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )

        runner.invoke(cli, ["backup"])

        assert (tmp_path / "airs-backup" / "targets" / "alpha.json").is_file()

    def test_the_credential_error_exits_two(
        self, cli: typer.Typer, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PANW_MGMT_CLIENT_ID")

        result = runner.invoke(cli, ["backup"])

        assert result.exit_code == 2
        assert "Missing OAuth2 credentials" in result.output


class TestBackupHelpers:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("Alpha One", "alpha-one"),
            ("a//b", "a-b"),
            ("***", "unnamed"),
            ("", "unnamed"),
            ("-lead-and-trail-", "lead-and-trail"),
        ],
    )
    def test_filenames_are_sanitized(self, name: str, expected: str) -> None:
        assert sanitize_filename(name) == expected

    def test_an_explicit_directory_wins(self, tmp_path: Path) -> None:
        assert resolve_output_dir(tmp_path, "targets") == tmp_path

    def test_the_default_directory_is_namespaced_by_kind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)

        assert resolve_output_dir(None, "targets") == tmp_path / "airs-backup" / "targets"


def write_backup(path: Path, data: dict[str, Any], resource_type: str = "redteam-target") -> Path:
    """Write a backup envelope to ``path``."""
    path.write_text(
        json.dumps(
            {
                "version": "1",
                "resourceType": resource_type,
                "exportedAt": "2026-01-01T00:00:00Z",
                "data": data,
            }
        )
    )
    return path


class TestRestore:
    def test_creates_a_target_that_does_not_exist(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(200, json={"pagination": {"total_items": 0}, "data": []})
        )
        created = api.post(TARGET_URL).mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        path = write_backup(tmp_path / "alpha.json", {"name": "alpha", "target_type": "API"})

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert result.exit_code == 0
        assert body_of(created)["name"] == "alpha"
        assert "created" in result.output

    def test_supplies_the_routing_defaults_the_api_requires(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(200, json={"pagination": {"total_items": 0}, "data": []})
        )
        created = api.post(TARGET_URL).mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        path = write_backup(tmp_path / "alpha.json", {"name": "alpha", "target_type": "API"})

        runner.invoke(cli, ["restore", "--file", str(path)])

        body = body_of(created)
        assert body["connection_type"] == "CUSTOM"
        assert body["api_endpoint_type"] == "PUBLIC"
        assert body["response_mode"] == "REST"

    def test_validate_is_only_sent_when_asked_for(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(200, json={"pagination": {"total_items": 0}, "data": []})
        )
        created = api.post(TARGET_URL).mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        path = write_backup(tmp_path / "alpha.json", {"name": "alpha", "target_type": "API"})

        runner.invoke(cli, ["restore", "--file", str(path)])
        without = str(sent(created).url)
        runner.invoke(cli, ["restore", "--file", str(path), "--validate"])
        with_flag = str(sent(created).url)

        assert without == TARGET_URL
        assert with_flag == f"{TARGET_URL}?validate=true"

    def test_an_existing_target_is_skipped_by_default(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )
        created = api.post(TARGET_URL).mock(return_value=httpx.Response(200, json={}))
        updated = api.put(f"{TARGET_URL}/{UUID_A}").mock(return_value=httpx.Response(200, json={}))
        path = write_backup(tmp_path / "alpha.json", {"name": "alpha", "target_type": "API"})

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert created.call_count == 0
        assert updated.call_count == 0
        assert "alpha — skipped" in result.output
        assert "Total: 1 skipped" in result.output

    def test_overwrite_updates_the_existing_target(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(
                200, json={"pagination": {"total_items": 1}, "data": [target_row(UUID_A, "alpha")]}
            )
        )
        api.get(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        updated = api.put(f"{TARGET_URL}/{UUID_A}").mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        path = write_backup(tmp_path / "alpha.json", {"name": "alpha"})

        result = runner.invoke(cli, ["restore", "--file", str(path), "--overwrite"])

        assert result.exit_code == 0
        assert sent(updated).method == "PUT"
        # Routing comes from the stored target, not from the defaults.
        assert body_of(updated)["target_type"] == "API"
        assert "updated" in result.output

    def test_legacy_field_names_are_translated(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(200, json={"pagination": {"total_items": 0}, "data": []})
        )
        created = api.post(TARGET_URL).mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        path = write_backup(
            tmp_path / "alpha.json",
            {
                "name": "alpha",
                "target_type": "API",
                "background": {"industry": "banking"},
                "metadata": {"multi_turn": True},
            },
        )

        runner.invoke(cli, ["restore", "--file", str(path)])

        body = body_of(created)
        assert body["target_background"] == {"industry": "banking"}
        assert body["target_metadata"]["multi_turn"] is True
        assert "background" not in body

    def test_server_assigned_fields_are_stripped_before_writing(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(200, json={"pagination": {"total_items": 0}, "data": []})
        )
        created = api.post(TARGET_URL).mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        path = write_backup(
            tmp_path / "alpha.json",
            {"name": "alpha", "target_type": "API", "uuid": UUID_A, "status": "READY"},
        )

        runner.invoke(cli, ["restore", "--file", str(path)])

        assert "uuid" not in body_of(created)
        assert "status" not in body_of(created)

    def test_a_directory_restores_every_matching_file(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(200, json={"pagination": {"total_items": 0}, "data": []})
        )
        created = api.post(TARGET_URL).mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        write_backup(tmp_path / "alpha.json", {"name": "alpha", "target_type": "API"})
        write_backup(tmp_path / "beta.json", {"name": "beta", "target_type": "API"})
        write_backup(tmp_path / "other.json", {"name": "gamma"}, resource_type="profile")
        (tmp_path / "notes.txt").write_text("not a backup")
        (tmp_path / "broken.json").write_text("{")

        result = runner.invoke(cli, ["restore", "--input-dir", str(tmp_path)])

        assert result.exit_code == 0
        assert created.call_count == 2
        assert "Total: 2 created" in result.output

    def test_pages_through_every_target(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """A tenant with more targets than one page still gets its names compared."""
        first = [target_row(f"{i:08d}-0000-0000-0000-000000000000", f"t{i}") for i in range(100)]
        listed = api.get(TARGET_URL).mock(
            side_effect=[
                httpx.Response(200, json={"pagination": {"total_items": 101}, "data": first}),
                httpx.Response(
                    200,
                    json={"pagination": {"total_items": 101}, "data": [target_row(UUID_B, "t100")]},
                ),
            ]
        )
        created = api.post(TARGET_URL).mock(
            return_value=httpx.Response(200, json=target_detail(UUID_A, "alpha"))
        )
        path = write_backup(tmp_path / "alpha.json", {"name": "alpha", "target_type": "API"})

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert result.exit_code == 0
        assert listed.call_count == 2
        assert str(listed.calls[0].request.url) == f"{TARGET_URL}?skip=0&limit=100"
        assert str(listed.calls[1].request.url) == f"{TARGET_URL}?skip=100&limit=100"
        assert created.call_count == 1

    def test_a_target_found_on_the_second_page_is_still_recognised(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """Stopping after one page would re-create a target that already exists."""
        first = [target_row(f"{i:08d}-0000-0000-0000-000000000000", f"t{i}") for i in range(100)]
        api.get(TARGET_URL).mock(
            side_effect=[
                httpx.Response(200, json={"pagination": {"total_items": 101}, "data": first}),
                httpx.Response(
                    200,
                    json={
                        "pagination": {"total_items": 101},
                        "data": [target_row(UUID_B, "alpha")],
                    },
                ),
            ]
        )
        created = api.post(TARGET_URL).mock(return_value=httpx.Response(200, json={}))
        path = write_backup(tmp_path / "alpha.json", {"name": "alpha", "target_type": "API"})

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert created.call_count == 0
        assert "skipped" in result.output

    def test_an_older_envelope_version_is_rejected(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """The envelope layout is versioned; a v0 file is not a file this can read."""
        path = tmp_path / "alpha.json"
        path.write_text(
            json.dumps(
                {
                    "version": "0",
                    "resourceType": "redteam-target",
                    "exportedAt": "2026-01-01T00:00:00Z",
                    "data": {"name": "alpha"},
                }
            )
        )

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert result.exit_code == 2
        assert "Invalid backup: version=0" in result.output

    def test_a_file_without_the_envelope_keys_is_rejected(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """Some other tool's JSON must not be read as if it were a backup."""
        path = tmp_path / "alpha.json"
        path.write_text(json.dumps({"name": "alpha", "target_type": "API"}))

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert result.exit_code == 2
        assert "missing version or data" in result.output

    def test_an_envelope_without_a_target_name_fails_that_file(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """Name is how a restore decides create-or-update, so a file without one is unusable."""
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(200, json={"pagination": {"total_items": 0}, "data": []})
        )
        created = api.post(TARGET_URL).mock(return_value=httpx.Response(200, json={}))
        path = write_backup(tmp_path / "alpha.json", {"target_type": "API"})

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert result.exit_code == 2
        assert created.call_count == 0
        assert "backup has no target name" in result.output

    def test_a_foreign_envelope_is_rejected(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        path = write_backup(tmp_path / "alpha.json", {"name": "alpha"}, resource_type="profile")

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert result.exit_code == 2
        assert "Invalid backup" in result.output

    def test_an_unreadable_file_is_a_usage_error(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        path = tmp_path / "alpha.txt"
        path.write_text("nope")

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert result.exit_code == 2
        assert "Unsupported file format" in result.output

    def test_a_missing_file_is_a_usage_error(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        result = runner.invoke(cli, ["restore", "--file", str(tmp_path / "absent.json")])

        assert result.exit_code == 2
        assert "No such file or directory" in result.output
        assert "absent.json" in result.output

    def test_an_empty_directory_is_a_usage_error(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        result = runner.invoke(cli, ["restore", "--input-dir", str(tmp_path)])

        assert result.exit_code == 2
        assert "No valid backup files found" in result.output

    def test_a_source_is_required(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["restore"])

        assert result.exit_code == 2
        assert "Specify --file <path> or --input-dir <path>" in result.output

    def test_a_rejected_target_exits_two(
        self, cli: typer.Typer, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.get(TARGET_URL).mock(
            return_value=httpx.Response(200, json={"pagination": {"total_items": 0}, "data": []})
        )
        api.post(TARGET_URL).mock(return_value=httpx.Response(400, json={"message": "bad target"}))
        path = write_backup(tmp_path / "alpha.json", {"name": "alpha", "target_type": "API"})

        result = runner.invoke(cli, ["restore", "--file", str(path)])

        assert result.exit_code == 2
        assert "alpha — failed" in result.output
        assert "Total: 1 failed" in result.output


class TestProfilesCleanup:
    def duplicates(self, api: respx.MockRouter) -> respx.Route:
        """Two revisions of one profile and a single revision of another."""
        return api.get(PROFILES_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "ai_profiles": [
                        profile(UUID_A, "prod", 1),
                        profile(UUID_B, "prod", 2),
                        profile("p3", "staging", 1),
                    ]
                },
            )
        )

    def test_previews_and_deletes_nothing_without_force(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        self.duplicates(api)
        deleted = api.delete(f"{PROFILE_URL}/{UUID_A}/force").mock(
            return_value=httpx.Response(200, json={"message": "ok"})
        )

        result = runner.invoke(cli, ["profiles-cleanup"])

        assert result.exit_code == 0
        assert deleted.call_count == 0
        assert "Pass --force to delete these revisions." in result.output

    def test_deletes_every_superseded_revision(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        self.duplicates(api)
        stale = api.delete(f"{PROFILE_URL}/{UUID_A}/force").mock(
            return_value=httpx.Response(200, json={"message": "ok"})
        )
        newest = api.delete(f"{PROFILE_URL}/{UUID_B}/force").mock(
            return_value=httpx.Response(200, json={"message": "ok"})
        )

        result = runner.invoke(
            cli, ["profiles-cleanup", "--force", "--updated-by", "ops@example.test"]
        )

        assert result.exit_code == 0
        assert newest.call_count == 0
        assert str(sent(stale).url) == f"{PROFILE_URL}/{UUID_A}/force?updated_by=ops%40example.test"

    def test_reports_nothing_to_do(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        api.get(PROFILES_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [profile(UUID_A, "prod", 1)]})
        )

        result = runner.invoke(cli, ["profiles-cleanup", "--force"])

        assert result.exit_code == 0
        assert "No duplicate profiles found." in result.output

    def test_pages_through_every_profile(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        listed = api.get(PROFILES_URL).mock(
            side_effect=[
                httpx.Response(
                    200, json={"ai_profiles": [profile(UUID_A, "prod", 1)], "next_offset": 200}
                ),
                httpx.Response(200, json={"ai_profiles": [profile(UUID_B, "prod", 2)]}),
            ]
        )
        api.delete(f"{PROFILE_URL}/{UUID_A}/force").mock(
            return_value=httpx.Response(200, json={"message": "ok"})
        )

        result = runner.invoke(cli, ["profiles-cleanup", "--force", "--updated-by", "o@e.test"])

        assert listed.call_count == 2
        assert str(listed.calls[0].request.url) == f"{PROFILES_URL}?offset=0&limit=200"
        assert str(listed.calls[1].request.url) == f"{PROFILES_URL}?offset=200&limit=200"
        assert result.exit_code == 0

    def test_json_preview_is_parseable(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        self.duplicates(api)

        result = runner.invoke(cli, ["profiles-cleanup", "--output", "json"])

        payload = json.loads(result.output)
        assert payload["total"] == 1
        assert payload["duplicates"][0] == {
            "name": "prod",
            "revisions": 2,
            "keeping": 2,
            "deleting": 1,
        }

    def test_json_result_names_every_deleted_revision(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        """The details key is "id", matching the reference client's payload."""
        self.duplicates(api)
        api.delete(f"{PROFILE_URL}/{UUID_A}/force").mock(
            return_value=httpx.Response(200, json={"message": "ok"})
        )

        result = runner.invoke(
            cli,
            ["profiles-cleanup", "--force", "--updated-by", "o@e.test", "--output", "json"],
        )

        assert json_documents(result.output)[1] == {
            "deleted": 1,
            "failed": 0,
            "details": [
                {
                    "id": UUID_A,
                    "revision": 1,
                    "name": "prod",
                    "status": "ok",
                    "error": None,
                }
            ],
        }

    def test_json_reports_a_failure_against_the_revision_that_failed(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        self.duplicates(api)
        api.delete(f"{PROFILE_URL}/{UUID_A}/force").mock(
            return_value=httpx.Response(409, json={"message": "still referenced"})
        )

        result = runner.invoke(
            cli,
            ["profiles-cleanup", "--force", "--updated-by", "o@e.test", "--output", "json"],
        )

        assert result.exit_code == 2
        payload = json_documents(result.output)[1]
        assert payload["deleted"] == 0
        assert payload["failed"] == 1
        assert payload["details"][0]["id"] == UUID_A
        assert payload["details"][0]["status"] == "failed"
        assert "still referenced" in payload["details"][0]["error"]

    def test_nothing_to_do_keeps_the_json_shape_a_real_run_emits(
        self, cli: typer.Typer, api: respx.MockRouter
    ) -> None:
        """A consumer must not have to branch on "did it find anything" before parsing."""
        api.get(PROFILES_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [profile(UUID_A, "prod", 1)]})
        )

        result = runner.invoke(cli, ["profiles-cleanup", "--force", "--output", "json"])

        assert json.loads(result.output) == {
            "duplicates": [],
            "summary": {"deleted": 0, "failed": 0},
        }

    def test_falls_back_to_the_git_identity(
        self, cli: typer.Typer, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.duplicates(api)
        stale = api.delete(f"{PROFILE_URL}/{UUID_A}/force").mock(
            return_value=httpx.Response(200, json={"message": "ok"})
        )
        monkeypatch.setattr(
            "prisma_airs_cli.commands.ops.subprocess.run",
            lambda *_args, **_kwargs: type("R", (), {"stdout": "git@example.test\n"})(),
        )

        runner.invoke(cli, ["profiles-cleanup", "--force"])

        assert dict(sent(stale).url.params)["updated_by"] == "git@example.test"

    def test_without_an_identity_it_refuses(
        self, cli: typer.Typer, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.duplicates(api)
        api.delete(f"{PROFILE_URL}/{UUID_A}/force").mock(
            return_value=httpx.Response(200, json={"message": "ok"})
        )

        def explode(*_args: object, **_kwargs: object) -> None:
            raise FileNotFoundError("git")

        monkeypatch.setattr("prisma_airs_cli.commands.ops.subprocess.run", explode)

        result = runner.invoke(cli, ["profiles-cleanup", "--force"])

        assert result.exit_code == 2
        assert "--updated-by <email> is required" in result.output

    def test_an_empty_git_identity_refuses(
        self, cli: typer.Typer, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """git exits 0 with no output when user.email is unset; that is not an address."""
        self.duplicates(api)
        deleted = api.delete(f"{PROFILE_URL}/{UUID_A}/force").mock(
            return_value=httpx.Response(200, json={"message": "ok"})
        )
        monkeypatch.setattr(
            "prisma_airs_cli.commands.ops.subprocess.run",
            lambda *_args, **_kwargs: type("R", (), {"stdout": "\n"})(),
        )

        result = runner.invoke(cli, ["profiles-cleanup", "--force"])

        assert result.exit_code == 2
        assert deleted.call_count == 0
        assert "git user.email is empty" in result.output

    def test_a_failed_delete_exits_two(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        self.duplicates(api)
        api.delete(f"{PROFILE_URL}/{UUID_A}/force").mock(
            return_value=httpx.Response(409, json={"message": "still referenced"})
        )

        result = runner.invoke(cli, ["profiles-cleanup", "--force", "--updated-by", "o@e.test"])

        assert result.exit_code == 2
        assert "1 failed" in result.output

    def test_a_listing_failure_exits_two(self, cli: typer.Typer, api: respx.MockRouter) -> None:
        api.get(PROFILES_URL).mock(return_value=httpx.Response(403, json={"message": "denied"}))

        result = runner.invoke(cli, ["profiles-cleanup", "--force"])

        assert result.exit_code == 2
        assert "HTTP 403" in result.output


class TestDuplicateDetection:
    def build(self, rows: list[tuple[str | None, str, int | None]]) -> list[SecurityProfile]:
        return [
            SecurityProfile(profile_id=pid, profile_name=name, revision=rev)
            for pid, name, rev in rows
        ]

    def test_keeps_the_highest_revision(self) -> None:
        groups = find_duplicate_profiles(self.build([("a", "prod", 1), ("b", "prod", 3)]))

        assert (groups[0].keep.profile_id, groups[0].keep.revision) == ("b", 3)
        assert [entry.profile_id for entry in groups[0].remove] == ["a"]

    def test_ignores_names_with_one_revision(self) -> None:
        assert find_duplicate_profiles(self.build([("a", "prod", 1)])) == []

    def test_a_missing_revision_sorts_last(self) -> None:
        groups = find_duplicate_profiles(self.build([("a", "prod", None), ("b", "prod", 1)]))

        assert groups[0].keep.profile_id == "b"

    def test_records_without_an_id_are_ignored(self) -> None:
        """They cannot be deleted, so proposing them would only produce a failure."""
        groups = find_duplicate_profiles(self.build([(None, "prod", 1), ("b", "prod", 2)]))

        assert groups == []
