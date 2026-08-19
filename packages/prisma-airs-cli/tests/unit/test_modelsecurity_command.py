"""``airs model-security`` behaviour: the requests it sends and the exits it returns.

Every assertion here is against the wire -- method, URL, query string, body -- rather
than against "it did not crash", because the whole point of the port is that this client
talks to the service exactly the way the reference one does.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from prisma_airs.constants import (
    DEFAULT_MODEL_SEC_DATA_ENDPOINT,
    DEFAULT_MODEL_SEC_MGMT_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
)
from prisma_airs_cli.commands.modelsecurity import modelsecurity_app

runner = CliRunner()

DATA = DEFAULT_MODEL_SEC_DATA_ENDPOINT
MGMT = DEFAULT_MODEL_SEC_MGMT_ENDPOINT

SCAN_UUID = "550e8400-e29b-41d4-a716-446655440000"
GROUP_UUID = "660e8400-e29b-41d4-a716-446655440000"
RULE_UUID = "770e8400-e29b-41d4-a716-446655440000"
INSTANCE_UUID = "880e8400-e29b-41d4-a716-446655440000"
MODEL_UUID = "990e8400-e29b-41d4-a716-446655440000"
VERSION_UUID = "aa0e8400-e29b-41d4-a716-446655440000"
EVAL_UUID = "bb0e8400-e29b-41d4-a716-446655440000"
VIOLATION_UUID = "cc0e8400-e29b-41d4-a716-446655440000"
FILE_UUID = "dd0e8400-e29b-41d4-a716-446655440000"
NOT_A_UUID = "definitely-not-a-uuid"

TSG_ID = "1234567890"

# --- canned responses -------------------------------------------------------

GROUP = {
    "uuid": GROUP_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-02T00:00:00Z",
    "name": "hf-strict",
    "description": "Hugging Face, no pickles",
    "source_type": "HUGGING_FACE",
    "state": "ACTIVE",
    "is_tombstone": False,
}
GROUP_LIST = {"pagination": {"total_items": 1}, "security_groups": [GROUP]}

RULE = {
    "uuid": RULE_UUID,
    "name": "Pickle Scan",
    "description": "Flags unsafe pickle opcodes",
    "rule_type": "ARTIFACT",
    "compatible_sources": ["HUGGING_FACE", "S3"],
    "default_state": "BLOCKING",
    "remediation": {
        "description": "Re-export the model without pickles",
        "steps": ["Convert to safetensors", "Re-scan"],
        "url": "https://example.invalid/remediation",
    },
    "editable_fields": [
        {
            "attribute_name": "approved_formats",
            "type": "array",
            "display_name": "Approved Formats",
            "display_type": "LIST",
            "description": "Formats this rule tolerates",
        }
    ],
    "constant_values": {},
    "default_values": {},
}
RULE_LIST = {"pagination": {"total_items": 1}, "rules": [RULE]}

INSTANCE = {
    "uuid": INSTANCE_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-02T00:00:00Z",
    "security_group_uuid": GROUP_UUID,
    "security_rule_uuid": RULE_UUID,
    "state": "BLOCKING",
    "rule": RULE,
    "field_values": {"approved_formats": ["safetensors", "gguf"]},
}
INSTANCE_LIST = {"pagination": {"total_items": 1}, "rule_instances": [INSTANCE]}

SCAN = {
    "uuid": SCAN_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "model_uri": "hf://acme/widget",
    "owner": "svc",
    "scan_origin": "HUGGING_FACE",
    "security_group_uuid": GROUP_UUID,
    "security_group_name": "hf-strict",
    "eval_outcome": "BLOCKED",
    "source_type": "HUGGING_FACE",
    "eval_summary": {"rules_passed": 4, "rules_failed": 1, "total_rules": 5},
    "labels": [{"key": "team", "value": "platform"}],
}
SDK_SCAN = {**SCAN, "uuid": EVAL_UUID, "scan_origin": "MODEL_SECURITY_SDK"}
SCAN_LIST = {"pagination": {"total_items": 2}, "scans": [SCAN, SDK_SCAN]}

EVALUATION = {
    "uuid": EVAL_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "result": "FAILED",
    "violation_count": 2,
    "rule_instance_uuid": INSTANCE_UUID,
    "scan_uuid": SCAN_UUID,
    "rule_name": "Pickle Scan",
    "rule_description": "Flags unsafe pickle opcodes",
    "rule_instance_state": "BLOCKING",
}
EVALUATION_LIST = {"pagination": {"total_items": 1}, "evaluations": [EVALUATION]}

VIOLATION = {
    "uuid": VIOLATION_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "description": "posix.system reachable from pickle",
    "rule_instance_uuid": INSTANCE_UUID,
    "rule_name": "Pickle Scan",
    "rule_description": "Flags unsafe pickle opcodes",
    "rule_instance_state": "BLOCKING",
    "remediation": {"steps": ["Re-export"], "url": "https://example.invalid/fix"},
    "file": "pytorch_model.bin",
    "threat": "PAIT-PKL-100",
}
VIOLATION_LIST = {"pagination": {"total_items": 1}, "violations": [VIOLATION]}

FILE = {
    "uuid": FILE_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "path": "pytorch_model.bin",
    "parent_path": "/",
    "type": "FILE",
    "result": "SUCCESS",
    "model_version_uuid": VERSION_UUID,
    "formats": ["pytorch"],
}
FILE_LIST = {"pagination": {"total_items": 1}, "files": [FILE]}

MODEL = {
    "uuid": MODEL_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-02T00:00:00Z",
    "name": "acme/widget",
    "latest_version_uuid": VERSION_UUID,
    "latest_version_revision": "main",
    "latest_version_outcome": "BLOCKED",
    "latest_version_formats": ["pytorch"],
    "latest_version_scan_time": "2026-01-02T00:00:00Z",
}
MODEL_CATALOGUE = {"pagination": {"total_items": 1}, "models": [MODEL]}

VERSION = {
    "uuid": VERSION_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-02T00:00:00Z",
    "revision": "main",
    "model_uuid": MODEL_UUID,
    "file_count": 7,
    "license": "apache-2.0",
    "model_formats": ["pytorch"],
    "last_eval_outcome": "BLOCKED",
    "last_eval_summary": {"rules_passed": 4, "rules_failed": 1, "total_rules": 5},
}
VERSION_LIST = {"pagination": {"total_items": 1}, "model_versions": [VERSION]}

LABEL_KEYS = {"pagination": {"total_items": 2}, "keys": ["team", "env"]}
LABEL_VALUES = {"pagination": {"total_items": 1}, "values": ["platform"]}

PYPI_AUTH = {
    "url": "https://_token:ya29-secret@us-python.pkg.dev/panw/airs/simple/",
    "expires_at": "2026-01-01T01:00:00Z",
}


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the tests off a developer's real tenant, and off a narrow terminal.

    Rich wraps to the terminal width, and a wrapped line breaks a substring assertion for
    reasons that have nothing to do with the command, so the width is pinned here.
    """
    for prefix in ("PANW_MODEL_SEC", "PANW_MGMT"):
        for suffix in ("CLIENT_ID", "CLIENT_SECRET", "TSG_ID", "TOKEN_ENDPOINT"):
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)
    monkeypatch.delenv("PANW_MODEL_SEC_DATA_ENDPOINT", raising=False)
    monkeypatch.delenv("PANW_MODEL_SEC_MGMT_ENDPOINT", raising=False)
    monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "cid")
    monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "csec")
    monkeypatch.setenv("PANW_MGMT_TSG_ID", TSG_ID)
    monkeypatch.setenv("PRISMA_AIRS_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("COLUMNS", "200")


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    """A mocked network with the OAuth token endpoint already answering."""
    with respx.mock(assert_all_called=False) as router:
        router.post(DEFAULT_TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )
        yield router


def query_of(route: respx.Route) -> dict[str, list[str]]:
    """Parse the query string of the last request a route served."""
    return parse_qs(urlsplit(str(route.calls.last.request.url)).query)


def body_of(route: respx.Route) -> dict[str, object]:
    """Decode the JSON body of the last request a route served."""
    decoded: dict[str, object] = json.loads(route.calls.last.request.content)
    return decoded


def write_json(path: Path, document: object) -> Path:
    """Write a JSON document to disk and return its path."""
    path.write_text(json.dumps(document))
    return path


class TestGroups:
    def test_list_sends_every_filter_it_was_given(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-groups").mock(
            return_value=httpx.Response(200, json=GROUP_LIST)
        )

        result = runner.invoke(
            modelsecurity_app,
            [
                "groups",
                "list",
                "--source-types",
                "HUGGING_FACE, S3",
                "--search",
                "strict",
                "--sort-field",
                "created_at",
                "--sort-dir",
                "desc",
                "--enabled-rules",
                f"{RULE_UUID},{GROUP_UUID}",
                "--limit",
                "5",
            ],
        )

        assert result.exit_code == 0
        assert query_of(route) == {
            "limit": ["5"],
            "sort_field": ["created_at"],
            "sort_dir": ["desc"],
            "source_types": ["HUGGING_FACE", "S3"],
            "search_query": ["strict"],
            "enabled_rules": [RULE_UUID, GROUP_UUID],
        }

    def test_list_defaults_to_twenty_results(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-groups").mock(
            return_value=httpx.Response(200, json=GROUP_LIST)
        )

        runner.invoke(modelsecurity_app, ["groups", "list"])

        assert query_of(route) == {"limit": ["20"]}

    def test_list_shows_the_group_name_and_state(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/security-groups").mock(
            return_value=httpx.Response(200, json=GROUP_LIST)
        )

        result = runner.invoke(modelsecurity_app, ["groups", "list"])

        assert "hf-strict" in result.output
        assert "ACTIVE" in result.output

    def test_list_json_output_is_parseable(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/security-groups").mock(
            return_value=httpx.Response(200, json=GROUP_LIST)
        )

        result = runner.invoke(modelsecurity_app, ["groups", "list", "--output", "json"])

        assert json.loads(result.output) == [
            {
                "id": GROUP_UUID,
                "name": "hf-strict",
                "state": "ACTIVE",
                "sourceType": "HUGGING_FACE",
            }
        ]

    def test_list_csv_output_carries_a_header(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/security-groups").mock(
            return_value=httpx.Response(200, json=GROUP_LIST)
        )

        result = runner.invoke(modelsecurity_app, ["groups", "list", "--output", "csv"])

        assert result.output.splitlines()[0] == "ID,Name,State,Source Type"

    def test_list_rejects_an_unknown_output_format(self, api: respx.MockRouter) -> None:
        result = runner.invoke(modelsecurity_app, ["groups", "list", "--output", "xml"])

        assert result.exit_code == 2

    def test_get_fetches_the_group_by_uuid(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        result = runner.invoke(modelsecurity_app, ["groups", "get", GROUP_UUID])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert "Hugging Face, no pickles" in result.output

    def test_get_json_output_uses_the_wire_field_names(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        result = runner.invoke(modelsecurity_app, ["groups", "get", GROUP_UUID, "--output", "json"])

        assert json.loads(result.output)["source_type"] == "HUGGING_FACE"

    def test_a_malformed_uuid_is_rejected_before_any_request(self, api: respx.MockRouter) -> None:
        result = runner.invoke(modelsecurity_app, ["groups", "get", NOT_A_UUID])

        assert result.exit_code == 2
        assert not api.calls

    def test_an_api_failure_exits_two(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )

        result = runner.invoke(modelsecurity_app, ["groups", "get", GROUP_UUID])

        assert result.exit_code == 2
        assert "HTTP 403" in result.output

    def test_create_posts_the_definition_from_the_file(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.post(f"{MGMT}/v1/security-groups").mock(
            return_value=httpx.Response(200, json=GROUP)
        )
        config = write_json(
            tmp_path / "group.json",
            {
                "name": "hf-strict",
                "source_type": "HUGGING_FACE",
                "description": "Hugging Face, no pickles",
                "rule_configurations": {RULE_UUID: {"state": "BLOCKING"}},
            },
        )

        result = runner.invoke(modelsecurity_app, ["groups", "create", "--config", str(config)])

        assert result.exit_code == 0
        assert body_of(route) == {
            "name": "hf-strict",
            "source_type": "HUGGING_FACE",
            "description": "Hugging Face, no pickles",
            "rule_configurations": {RULE_UUID: {"state": "BLOCKING"}},
        }
        assert f"Group created: {GROUP_UUID}" in result.output

    def test_create_rejects_a_file_that_is_not_json(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        config = tmp_path / "group.json"
        config.write_text("{not json")

        result = runner.invoke(modelsecurity_app, ["groups", "create", "--config", str(config)])

        assert result.exit_code == 2
        assert not api.calls

    def test_create_rejects_a_definition_missing_required_fields(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        config = write_json(tmp_path / "group.json", {"description": "nameless"})

        result = runner.invoke(modelsecurity_app, ["groups", "create", "--config", str(config)])

        assert result.exit_code == 2
        assert not api.calls

    def test_create_rejects_a_missing_file(self, tmp_path: Path) -> None:
        result = runner.invoke(
            modelsecurity_app, ["groups", "create", "--config", str(tmp_path / "absent.json")]
        )

        assert result.exit_code == 2

    def test_update_sends_only_the_fields_supplied(self, api: respx.MockRouter) -> None:
        route = api.put(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        result = runner.invoke(
            modelsecurity_app, ["groups", "update", GROUP_UUID, "--name", "renamed"]
        )

        assert result.exit_code == 0
        assert body_of(route) == {"name": "renamed"}
        assert f"Group updated: {GROUP_UUID}" in result.output

    def test_update_sends_the_description_too(self, api: respx.MockRouter) -> None:
        route = api.put(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        runner.invoke(
            modelsecurity_app,
            ["groups", "update", GROUP_UUID, "--name", "renamed", "--description", "why"],
        )

        assert body_of(route) == {"name": "renamed", "description": "why"}

    def test_update_with_neither_flag_sends_an_empty_body(self, api: respx.MockRouter) -> None:
        """Matching the reference: unset fields are omitted rather than sent as null."""
        route = api.put(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        result = runner.invoke(modelsecurity_app, ["groups", "update", GROUP_UUID])

        assert result.exit_code == 0
        assert body_of(route) == {}

    def test_delete_reports_success_when_the_group_stops_resolving(
        self, api: respx.MockRouter
    ) -> None:
        delete = api.delete(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(204)
        )
        api.get(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(404, json={"message": "Not found"})
        )

        result = runner.invoke(modelsecurity_app, ["groups", "delete", GROUP_UUID])

        assert result.exit_code == 0
        assert delete.called
        assert f"Group {GROUP_UUID} deleted." in result.output

    def test_delete_warns_when_the_group_still_resolves(self, api: respx.MockRouter) -> None:
        """A soft delete leaves the group readable; saying "deleted" would be a lie."""
        api.delete(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(return_value=httpx.Response(204))
        api.get(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        result = runner.invoke(modelsecurity_app, ["groups", "delete", GROUP_UUID])

        assert result.exit_code == 0
        assert "still reports state 'ACTIVE'" in result.output
        assert "deleted." not in result.output

    def test_delete_exits_two_when_the_delete_itself_fails(self, api: respx.MockRouter) -> None:
        api.delete(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(500, json={"message": "boom"})
        )

        result = runner.invoke(modelsecurity_app, ["groups", "delete", GROUP_UUID])

        assert result.exit_code == 2


class TestRules:
    def test_list_sends_the_singular_source_type_filter(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-rules").mock(
            return_value=httpx.Response(200, json=RULE_LIST)
        )

        result = runner.invoke(
            modelsecurity_app,
            ["rules", "list", "--source-type", "S3", "--search", "pickle", "--limit", "3"],
        )

        assert result.exit_code == 0
        assert query_of(route) == {
            "limit": ["3"],
            "source_type": ["S3"],
            "search_query": ["pickle"],
        }

    def test_list_table_output_names_the_columns(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/security-rules").mock(return_value=httpx.Response(200, json=RULE_LIST))

        result = runner.invoke(modelsecurity_app, ["rules", "list", "--output", "table"])

        assert "Default State" in result.output
        assert "Pickle Scan" in result.output

    def test_list_reports_an_empty_catalogue_as_such(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/security-rules").mock(
            return_value=httpx.Response(200, json={"pagination": {}, "rules": []})
        )

        result = runner.invoke(modelsecurity_app, ["rules", "list"])

        assert result.exit_code == 0
        assert "No security rules found" in result.output

    def test_get_shows_the_remediation_steps(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-rules/{RULE_UUID}").mock(
            return_value=httpx.Response(200, json=RULE)
        )

        result = runner.invoke(modelsecurity_app, ["rules", "get", RULE_UUID])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert "Convert to safetensors" in result.output
        assert "Approved Formats" in result.output


class TestRuleInstances:
    def test_list_targets_the_group_and_forwards_its_filters(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-groups/{GROUP_UUID}/rule-instances").mock(
            return_value=httpx.Response(200, json=INSTANCE_LIST)
        )

        result = runner.invoke(
            modelsecurity_app,
            [
                "rule-instances",
                "list",
                GROUP_UUID,
                "--security-rule-uuid",
                RULE_UUID,
                "--state",
                "BLOCKING",
                "--limit",
                "7",
            ],
        )

        assert result.exit_code == 0
        assert query_of(route) == {
            "limit": ["7"],
            "security_rule_uuid": [RULE_UUID],
            "state": ["BLOCKING"],
        }
        assert "Pickle Scan" in result.output

    def test_get_reads_one_instance(self, api: respx.MockRouter) -> None:
        route = api.get(
            f"{MGMT}/v1/security-groups/{GROUP_UUID}/rule-instances/{INSTANCE_UUID}"
        ).mock(return_value=httpx.Response(200, json=INSTANCE))

        result = runner.invoke(
            modelsecurity_app, ["rule-instances", "get", GROUP_UUID, INSTANCE_UUID]
        )

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert "safetensors, gguf" in result.output

    def test_update_puts_the_group_uuid_in_the_body_as_well_as_the_path(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """The service does not infer the group from the URL, so the body must carry it."""
        route = api.put(
            f"{MGMT}/v1/security-groups/{GROUP_UUID}/rule-instances/{INSTANCE_UUID}"
        ).mock(return_value=httpx.Response(200, json=INSTANCE))
        config = write_json(
            tmp_path / "instance.json",
            {"state": "ALLOWING", "field_values": {"approved_formats": ["safetensors"]}},
        )

        result = runner.invoke(
            modelsecurity_app,
            [
                "rule-instances",
                "update",
                GROUP_UUID,
                INSTANCE_UUID,
                "--config",
                str(config),
            ],
        )

        assert result.exit_code == 0
        assert body_of(route) == {
            "security_group_uuid": GROUP_UUID,
            "state": "ALLOWING",
            "field_values": {"approved_formats": ["safetensors"]},
        }
        assert f"Rule instance updated: {INSTANCE_UUID}" in result.output

    def test_update_rejects_a_json_document_that_is_not_an_object(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        config = write_json(tmp_path / "instance.json", ["ALLOWING"])

        result = runner.invoke(
            modelsecurity_app,
            ["rule-instances", "update", GROUP_UUID, INSTANCE_UUID, "--config", str(config)],
        )

        assert result.exit_code == 2
        assert not api.calls


class TestScans:
    def test_list_maps_the_singular_filters_onto_the_plural_parameters(
        self, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        result = runner.invoke(
            modelsecurity_app,
            [
                "scans",
                "list",
                "--eval-outcome",
                "BLOCKED",
                "--source-type",
                "HUGGING_FACE",
                "--search",
                "widget",
                "--limit",
                "10",
            ],
        )

        assert result.exit_code == 0
        assert query_of(route) == {
            "limit": ["10"],
            "search": ["widget"],
            "eval_outcomes": ["BLOCKED"],
            "source_types": ["HUGGING_FACE"],
        }

    def test_list_shows_the_rule_counts(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        result = runner.invoke(modelsecurity_app, ["scans", "list"])

        assert "4 passed" in result.output
        assert "1 failed" in result.output

    def test_list_json_output_uses_the_reference_row_keys(self, api: respx.MockRouter) -> None:
        """Piped output keeps the TypeScript client's camelCase keys, not the wire names."""
        api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        result = runner.invoke(modelsecurity_app, ["scans", "list", "--output", "json"])

        assert result.exit_code == 0
        assert json.loads(result.output) == [
            {
                "id": SCAN_UUID,
                "outcome": "BLOCKED",
                "origin": "HUGGING_FACE",
                "modelUri": "hf://acme/widget",
                "passed": 4,
                "failed": 1,
                "createdAt": "2026-01-01T00:00:00Z",
            },
            {
                "id": EVAL_UUID,
                "outcome": "BLOCKED",
                "origin": "MODEL_SECURITY_SDK",
                "modelUri": "hf://acme/widget",
                "passed": 4,
                "failed": 1,
                "createdAt": "2026-01-01T00:00:00Z",
            },
        ]

    def test_scan_origin_narrows_the_returned_page(self, api: respx.MockRouter) -> None:
        """No server-side filter exists for it, so the flag has to bite on the client."""
        api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        result = runner.invoke(
            modelsecurity_app, ["scans", "list", "--scan-origin", "MODEL_SECURITY_SDK"]
        )

        assert result.exit_code == 0
        assert EVAL_UUID in result.output
        assert SCAN_UUID not in result.output

    def test_scan_origin_is_not_sent_as_a_query_parameter(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        runner.invoke(modelsecurity_app, ["scans", "list", "--scan-origin", "HUGGING_FACE"])

        assert "scan_origin" not in query_of(route)

    def test_get_reads_one_scan_with_its_labels(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}").mock(
            return_value=httpx.Response(200, json=SCAN)
        )

        result = runner.invoke(modelsecurity_app, ["scans", "get", SCAN_UUID])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert "hf://acme/widget" in result.output
        assert "platform" in result.output

    def test_create_posts_the_scan_definition(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.post(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN))
        config = write_json(
            tmp_path / "scan.json",
            {
                "model_uri": "hf://acme/widget",
                "security_group_uuid": GROUP_UUID,
                "scan_origin": "HUGGING_FACE",
            },
        )

        result = runner.invoke(modelsecurity_app, ["scans", "create", "--config", str(config)])

        assert result.exit_code == 0
        assert body_of(route) == {
            "model_uri": "hf://acme/widget",
            "security_group_uuid": GROUP_UUID,
            "scan_origin": "HUGGING_FACE",
        }
        assert f"Scan created: {SCAN_UUID}" in result.output

    def test_create_rejects_a_definition_without_a_model_uri(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        config = write_json(tmp_path / "scan.json", {"security_group_uuid": GROUP_UUID})

        result = runner.invoke(modelsecurity_app, ["scans", "create", "--config", str(config)])

        assert result.exit_code == 2
        assert not api.calls

    def test_evaluations_lists_under_the_scan(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/evaluations").mock(
            return_value=httpx.Response(200, json=EVALUATION_LIST)
        )

        result = runner.invoke(
            modelsecurity_app, ["scans", "evaluations", SCAN_UUID, "--limit", "4"]
        )

        assert result.exit_code == 0
        assert query_of(route) == {"limit": ["4"]}
        assert "FAILED" in result.output

    def test_evaluation_reads_the_top_level_collection(self, api: respx.MockRouter) -> None:
        """Evaluations are fetched from /v1/evaluations, not from under their scan."""
        route = api.get(f"{DATA}/v1/evaluations/{EVAL_UUID}").mock(
            return_value=httpx.Response(200, json=EVALUATION)
        )

        result = runner.invoke(modelsecurity_app, ["scans", "evaluation", EVAL_UUID])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert "Flags unsafe pickle opcodes" in result.output

    def test_violations_use_the_rule_violations_segment(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/rule-violations").mock(
            return_value=httpx.Response(200, json=VIOLATION_LIST)
        )

        result = runner.invoke(
            modelsecurity_app, ["scans", "violations", SCAN_UUID, "--limit", "2"]
        )

        assert result.exit_code == 0
        assert query_of(route) == {"limit": ["2"]}
        assert "PAIT-PKL-100" in result.output

    def test_violation_reads_the_top_level_collection(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/violations/{VIOLATION_UUID}").mock(
            return_value=httpx.Response(200, json=VIOLATION)
        )

        result = runner.invoke(modelsecurity_app, ["scans", "violation", VIOLATION_UUID])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert "posix.system reachable from pickle" in result.output

    def test_files_sends_type_and_result_under_their_wire_names(
        self, api: respx.MockRouter
    ) -> None:
        """The parameter is `file_type` in Python but must stay `type` on the wire."""
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/files").mock(
            return_value=httpx.Response(200, json=FILE_LIST)
        )

        result = runner.invoke(
            modelsecurity_app,
            [
                "scans",
                "files",
                SCAN_UUID,
                "--type",
                "FILE",
                "--result",
                "SUCCESS",
                "--limit",
                "6",
            ],
        )

        assert result.exit_code == 0
        assert query_of(route) == {"limit": ["6"], "type": ["FILE"], "result": ["SUCCESS"]}
        assert "pytorch_model.bin" in result.output


class TestLabels:
    def test_add_posts_the_parsed_labels(self, api: respx.MockRouter) -> None:
        route = api.post(f"{DATA}/v1/scans/{SCAN_UUID}/labels").mock(
            return_value=httpx.Response(200, json={})
        )

        result = runner.invoke(
            modelsecurity_app,
            ["labels", "add", SCAN_UUID, "--labels", '[{"key":"team","value":"platform"}]'],
        )

        assert result.exit_code == 0
        assert body_of(route) == {"labels": [{"key": "team", "value": "platform"}]}
        assert "Labels added." in result.output

    def test_set_uses_put_so_it_replaces_rather_than_merges(self, api: respx.MockRouter) -> None:
        route = api.put(f"{DATA}/v1/scans/{SCAN_UUID}/labels").mock(
            return_value=httpx.Response(200, json={})
        )

        result = runner.invoke(
            modelsecurity_app,
            ["labels", "set", SCAN_UUID, "--labels", '[{"key":"env","value":"prod"}]'],
        )

        assert result.exit_code == 0
        assert route.calls.last.request.method == "PUT"
        assert body_of(route) == {"labels": [{"key": "env", "value": "prod"}]}

    def test_add_rejects_labels_that_are_not_json(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            modelsecurity_app, ["labels", "add", SCAN_UUID, "--labels", "team=platform"]
        )

        assert result.exit_code == 2
        assert not api.calls

    def test_add_rejects_labels_missing_a_value(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            modelsecurity_app, ["labels", "add", SCAN_UUID, "--labels", '[{"key":"team"}]']
        )

        assert result.exit_code == 2
        assert not api.calls

    def test_delete_sends_the_keys_as_repeated_query_parameters(
        self, api: respx.MockRouter
    ) -> None:
        """Repeated keys, not a comma-joined value: the service reads them separately."""
        route = api.delete(f"{DATA}/v1/scans/{SCAN_UUID}/labels").mock(
            return_value=httpx.Response(204)
        )

        result = runner.invoke(
            modelsecurity_app, ["labels", "delete", SCAN_UUID, "--keys", "team, env"]
        )

        assert result.exit_code == 0
        assert query_of(route) == {"keys": ["team", "env"]}
        assert "Labels deleted." in result.output

    def test_delete_rejects_an_empty_key_list(self, api: respx.MockRouter) -> None:
        result = runner.invoke(modelsecurity_app, ["labels", "delete", SCAN_UUID, "--keys", " , "])

        assert result.exit_code == 2
        assert not api.calls

    def test_keys_lists_the_tenant_wide_collection(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/scans/label-keys").mock(
            return_value=httpx.Response(200, json=LABEL_KEYS)
        )

        result = runner.invoke(modelsecurity_app, ["labels", "keys", "--limit", "9"])

        assert result.exit_code == 0
        assert query_of(route) == {"limit": ["9"]}
        assert "team" in result.output

    def test_values_sends_the_limit(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/scans/label-keys/team/values").mock(
            return_value=httpx.Response(200, json=LABEL_VALUES)
        )

        result = runner.invoke(modelsecurity_app, ["labels", "values", "team", "--limit", "4"])

        assert result.exit_code == 0
        assert query_of(route) == {"limit": ["4"]}

    def test_values_percent_encodes_the_key_into_the_path(self, api: respx.MockRouter) -> None:
        """A key containing a slash must not reshape the request path."""
        route = api.get(f"{DATA}/v1/scans/label-keys/team%2Fowner/values").mock(
            return_value=httpx.Response(200, json=LABEL_VALUES)
        )

        result = runner.invoke(modelsecurity_app, ["labels", "values", "team/owner"])

        assert result.exit_code == 0
        assert route.called
        assert "platform" in result.output


class TestModels:
    def test_list_translates_offset_into_skip(self, api: respx.MockRouter) -> None:
        """These endpoints take a row offset, so the value passes through untouched."""
        route = api.get(f"{DATA}/v1/models").mock(
            return_value=httpx.Response(200, json=MODEL_CATALOGUE)
        )

        result = runner.invoke(
            modelsecurity_app,
            [
                "models",
                "list",
                "--search",
                "widget",
                "--search-query",
                "acme",
                "--sort-field",
                "updated_at",
                "--sort-order",
                "asc",
                "--limit",
                "25",
                "--offset",
                "50",
            ],
        )

        assert result.exit_code == 0
        assert query_of(route) == {
            "skip": ["50"],
            "limit": ["25"],
            "search": ["widget"],
            "search_query": ["acme"],
            "sort_field": ["updated_at"],
            "sort_order": ["asc"],
        }

    def test_list_sends_no_paging_when_none_was_asked_for(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/models").mock(
            return_value=httpx.Response(200, json=MODEL_CATALOGUE)
        )

        runner.invoke(modelsecurity_app, ["models", "list"])

        assert query_of(route) == {}

    def test_list_yaml_output_is_parseable(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/models").mock(return_value=httpx.Response(200, json=MODEL_CATALOGUE))

        result = runner.invoke(modelsecurity_app, ["models", "list", "--output", "yaml"])

        assert next(iter(yaml.safe_load_all(result.output)))["name"] == "acme/widget"

    def test_list_marks_an_unscanned_model(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/models").mock(
            return_value=httpx.Response(
                200,
                json={
                    "pagination": {},
                    "models": [{k: v for k, v in MODEL.items() if not k.startswith("latest_")}],
                },
            )
        )

        result = runner.invoke(modelsecurity_app, ["models", "list"])

        assert "unscanned" in result.output

    def test_get_reads_one_model(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/models/{MODEL_UUID}").mock(
            return_value=httpx.Response(200, json=MODEL)
        )

        result = runner.invoke(modelsecurity_app, ["models", "get", MODEL_UUID])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert "acme/widget" in result.output

    def test_get_yaml_output_uses_the_wire_field_names(self, api: respx.MockRouter) -> None:
        """A detail view dumps the SDK record, so consumers see snake_case wire names."""
        api.get(f"{DATA}/v1/models/{MODEL_UUID}").mock(return_value=httpx.Response(200, json=MODEL))

        result = runner.invoke(modelsecurity_app, ["models", "get", MODEL_UUID, "--output", "yaml"])

        assert result.exit_code == 0
        document = yaml.safe_load(result.output)
        assert document["name"] == "acme/widget"
        assert document["latest_version_outcome"] == "BLOCKED"

    def test_versions_hangs_off_the_model(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/models/{MODEL_UUID}/model-versions").mock(
            return_value=httpx.Response(200, json=VERSION_LIST)
        )

        result = runner.invoke(
            modelsecurity_app,
            ["models", "versions", MODEL_UUID, "--sort-order", "desc", "--limit", "2"],
        )

        assert result.exit_code == 0
        assert query_of(route) == {"limit": ["2"], "sort_order": ["desc"]}
        assert "files: 7" in result.output

    def test_versions_translates_offset_into_skip(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/models/{MODEL_UUID}/model-versions").mock(
            return_value=httpx.Response(200, json=VERSION_LIST)
        )

        result = runner.invoke(
            modelsecurity_app, ["models", "versions", MODEL_UUID, "--offset", "12"]
        )

        assert result.exit_code == 0
        assert query_of(route) == {"skip": ["12"]}

    def test_versions_csv_output_carries_the_version_columns(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/models/{MODEL_UUID}/model-versions").mock(
            return_value=httpx.Response(200, json=VERSION_LIST)
        )

        result = runner.invoke(
            modelsecurity_app, ["models", "versions", MODEL_UUID, "--output", "csv"]
        )

        assert result.exit_code == 0
        assert result.output.splitlines()[0] == "ID,Revision,Files,Outcome,Last Scan"

    def test_version_reads_the_top_level_collection(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/model-versions/{VERSION_UUID}").mock(
            return_value=httpx.Response(200, json=VERSION)
        )

        result = runner.invoke(modelsecurity_app, ["models", "version", VERSION_UUID])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert "apache-2.0" in result.output

    def test_version_json_output_uses_the_wire_field_names(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/model-versions/{VERSION_UUID}").mock(
            return_value=httpx.Response(200, json=VERSION)
        )

        result = runner.invoke(
            modelsecurity_app, ["models", "version", VERSION_UUID, "--output", "json"]
        )

        assert result.exit_code == 0
        document = json.loads(result.output)
        assert document["model_uuid"] == MODEL_UUID
        assert document["last_eval_summary"]["rules_failed"] == 1

    def test_files_lists_under_the_model_version(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/model-versions/{VERSION_UUID}/files").mock(
            return_value=httpx.Response(200, json=FILE_LIST)
        )

        result = runner.invoke(
            modelsecurity_app, ["models", "files", VERSION_UUID, "--limit", "3", "--offset", "6"]
        )

        assert result.exit_code == 0
        assert query_of(route) == {"limit": ["3"], "skip": ["6"]}
        assert "pytorch_model.bin" in result.output

    def test_files_csv_output_carries_the_file_columns(self, api: respx.MockRouter) -> None:
        api.get(f"{DATA}/v1/model-versions/{VERSION_UUID}/files").mock(
            return_value=httpx.Response(200, json=FILE_LIST)
        )

        result = runner.invoke(
            modelsecurity_app, ["models", "files", VERSION_UUID, "--output", "csv"]
        )

        assert result.output.splitlines()[0] == "ID,Path,Type,Formats,Result"


class TestPyPIAuth:
    def test_pypi_auth_reads_the_management_plane(self, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )

        result = runner.invoke(modelsecurity_app, ["pypi-auth"])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert PYPI_AUTH["url"] in result.output
        assert PYPI_AUTH["expires_at"] in result.output

    def test_pypi_auth_exits_two_when_the_service_refuses(self, api: respx.MockRouter) -> None:
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(401, json={"message": "Unauthorized"})
        )

        result = runner.invoke(modelsecurity_app, ["pypi-auth"])

        assert result.exit_code == 2


class TestInstall:
    def test_dry_run_prints_the_uv_commands_without_running_them(
        self, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )
        monkeypatch.setattr(
            "prisma_airs_cli.commands.modelsecurity.shutil.which",
            lambda name: "/usr/bin/uv" if name == "uv" else None,
        )

        result = runner.invoke(
            modelsecurity_app, ["install", "--dry-run", "--extras", "aws", "--dir", "ms"]
        )

        assert result.exit_code == 0
        assert "/usr/bin/uv init ms" in result.output
        assert '"model-security-client[aws]"' in result.output

    def test_dry_run_masks_the_index_token(
        self, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The index URL carries a live token, and --dry-run output lands in shell history."""
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )
        monkeypatch.setattr(
            "prisma_airs_cli.commands.modelsecurity.shutil.which",
            lambda name: "/usr/bin/uv" if name == "uv" else None,
        )

        result = runner.invoke(modelsecurity_app, ["install", "--dry-run"])

        assert "ya29-secret" not in result.output
        assert "_token:***@us-python.pkg.dev" in result.output

    def test_dir_defaults_to_model_security(
        self, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )
        monkeypatch.setattr(
            "prisma_airs_cli.commands.modelsecurity.shutil.which",
            lambda name: "/usr/bin/uv" if name == "uv" else None,
        )

        result = runner.invoke(modelsecurity_app, ["install", "--dry-run"])

        assert result.exit_code == 0
        assert "/usr/bin/uv init model-security" in result.output

    def test_dry_run_falls_back_to_venv_and_pip_without_uv(
        self, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )
        monkeypatch.setattr(
            "prisma_airs_cli.commands.modelsecurity.shutil.which",
            lambda name: "/usr/bin/python3" if name == "python3" else None,
        )

        result = runner.invoke(modelsecurity_app, ["install", "--dry-run", "--dir", "ms"])

        assert result.exit_code == 0
        assert "/usr/bin/python3 -m venv ms/.venv" in result.output
        assert "ms/.venv/bin/pip install" in result.output

    def test_runs_each_step_and_reports_success(
        self, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )
        monkeypatch.setattr(
            "prisma_airs_cli.commands.modelsecurity.shutil.which",
            lambda name: "/usr/bin/uv" if name == "uv" else None,
        )
        commands: list[list[str]] = []

        class Completed:
            returncode = 0

        def record(command: list[str], **_kwargs: object) -> Completed:
            commands.append(command)
            return Completed()

        monkeypatch.setattr("prisma_airs_cli.commands.modelsecurity.subprocess.run", record)

        result = runner.invoke(modelsecurity_app, ["install", "--dir", "ms"])

        assert result.exit_code == 0
        assert commands == [
            ["/usr/bin/uv", "init", "ms"],
            [
                "/usr/bin/uv",
                "add",
                "--project",
                "ms",
                "model-security-client[all]",
                "--index",
                PYPI_AUTH["url"],
            ],
        ]
        assert "installed successfully" in result.output

    def test_a_failing_step_exits_two(
        self, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )
        monkeypatch.setattr(
            "prisma_airs_cli.commands.modelsecurity.shutil.which",
            lambda name: "/usr/bin/uv" if name == "uv" else None,
        )

        class Failed:
            returncode = 3

        monkeypatch.setattr(
            "prisma_airs_cli.commands.modelsecurity.subprocess.run",
            lambda *_a, **_k: Failed(),
        )

        result = runner.invoke(modelsecurity_app, ["install"])

        assert result.exit_code == 2
        assert "uv init failed with exit code 3" in result.output

    def test_rejects_an_unknown_extras_value(self, api: respx.MockRouter) -> None:
        result = runner.invoke(modelsecurity_app, ["install", "--extras", "oracle"])

        assert result.exit_code == 2
        assert not api.calls

    def test_reports_when_neither_uv_nor_python3_is_available(
        self, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "prisma_airs_cli.commands.modelsecurity.shutil.which", lambda _name: None
        )

        result = runner.invoke(modelsecurity_app, ["install"])

        assert result.exit_code == 2
        assert "Neither uv nor python3 found on PATH" in result.output
        assert not api.calls


LIMIT_COMMANDS = [
    ["groups", "list"],
    ["labels", "keys"],
    ["labels", "values", "team"],
    ["rule-instances", "list", GROUP_UUID],
    ["rules", "list"],
    ["scans", "list"],
    ["scans", "evaluations", SCAN_UUID],
    ["scans", "violations", SCAN_UUID],
    ["scans", "files", SCAN_UUID],
    ["models", "list"],
    ["models", "versions", MODEL_UUID],
    ["models", "files", VERSION_UUID],
]

OFFSET_COMMANDS = [
    ["models", "list"],
    ["models", "versions", MODEL_UUID],
    ["models", "files", VERSION_UUID],
]


class TestPagingGuard:
    """Every command that registers a paging flag refuses a negative value.

    The guard is a per-command call rather than shared middleware, so dropping it from one
    command would otherwise go unnoticed -- these cases pin it on all twelve.
    """

    @pytest.mark.parametrize(
        "argv", LIMIT_COMMANDS, ids=[" ".join(argv[:2]) for argv in LIMIT_COMMANDS]
    )
    def test_a_negative_limit_is_refused_before_any_request(
        self, api: respx.MockRouter, argv: list[str]
    ) -> None:
        result = runner.invoke(modelsecurity_app, [*argv, "--limit", "-1"])

        assert result.exit_code == 2
        assert not api.calls

    @pytest.mark.parametrize(
        "argv", OFFSET_COMMANDS, ids=[" ".join(argv[:2]) for argv in OFFSET_COMMANDS]
    )
    def test_a_negative_offset_is_refused_before_any_request(
        self, api: respx.MockRouter, argv: list[str]
    ) -> None:
        result = runner.invoke(modelsecurity_app, [*argv, "--offset", "-1"])

        assert result.exit_code == 2
        assert not api.calls
