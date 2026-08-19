"""``airs dlp`` behaviour: the request each command sends, and every way it can refuse.

Assertions are on the wire -- method, URL, query, and body -- because a command that
reaches the right endpoint with the wrong body still exits 0. The merge-patch tests are
the sharpest of these: an omitted key and an explicit ``null`` mean opposite things to the
service, so both are checked rather than "a PATCH happened".
"""

from __future__ import annotations

import json
import re
import sys
import types
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import typer
import yaml
from typer.testing import CliRunner

from prisma_airs.constants import DEFAULT_DLP_ENDPOINT, DEFAULT_TOKEN_ENDPOINT
from prisma_airs_cli.commands.dlp import dlp_app

# The parent application wires ``dlp_app`` up itself; this stands it alone so the group's
# behaviour is tested without depending on the order units land in.
cli = typer.Typer()
cli.add_typer(dlp_app)

runner = CliRunner()

PATTERNS_URL = f"{DEFAULT_DLP_ENDPOINT}/v2/api/data-patterns"
PROFILES_URL = f"{DEFAULT_DLP_ENDPOINT}/v2/api/data-profiles"
FILTERING_URL = f"{DEFAULT_DLP_ENDPOINT}/v2/api/data-filtering-profiles"
DICTIONARIES_URL = f"{DEFAULT_DLP_ENDPOINT}/v2/api/dictionaries"

MERGE_PATCH = "application/merge-patch+json"

PATTERN = {
    "id": "dp-1",
    "name": "SSN",
    "type": "custom",
    "status": "active",
    "version": 2,
    "detection_config": {"technique": "regex"},
    "audit_metadata": {"updated_at": 1700000000000},
}
PROFILE = {
    "id": "prof-1",
    "name": "Confidential",
    "type": "custom",
    "profile_type": "advanced",
    "profile_status": "active",
    "version": 3,
}
FILTERING_PROFILE = {
    "id": "dfp-1",
    "name": "Finance",
    "type": "custom",
    "direction": "BOTH",
    "log_severity": "HIGH",
    "file_based": True,
    "non_file_based": False,
    "version": 1,
}
DICTIONARY = {
    "id": "dict-1",
    "name": "PII",
    "category": "Confidential",
    "type": "custom",
    "keywords": ["alpha", "beta"],
}


def page(item: dict[str, Any]) -> dict[str, Any]:
    """One Spring ``Page`` envelope holding a single item."""
    return {
        "content": [item],
        "totalElements": 1,
        "totalPages": 1,
        "number": 0,
        "size": 20,
        "pageable": {"pageNumber": 0, "pageSize": 20},
    }


def empty_page() -> dict[str, Any]:
    """A page with nothing on it."""
    return {"content": [], "totalElements": 0, "totalPages": 0, "number": 0, "size": 20}


def multipart_parts(request: httpx.Request) -> dict[str, bytes]:
    """Split a multipart body into its parts, keyed by part name."""
    boundary = request.headers["content-type"].partition("boundary=")[2]
    parts: dict[str, bytes] = {}
    for chunk in request.content.split(f"--{boundary}".encode())[1:-1]:
        head, _, body = chunk.lstrip(b"\r\n").partition(b"\r\n\r\n")
        found = re.search(rb'name="([^"]*)"', head)
        assert found is not None
        parts[found.group(1).decode()] = body.removesuffix(b"\r\n")
    return parts


def sent_body(route: respx.Route) -> dict[str, Any]:
    """Parse the JSON body of the most recent request on a route."""
    return json.loads(route.calls.last.request.content)  # type: ignore[no-any-return]


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests off the developer's real credentials, and off a narrow terminal.

    DLP authenticates as the management service account, so ``PANW_MGMT_*`` is what has to
    be supplied. ``COLUMNS`` is pinned because Rich wraps to the terminal width, and a
    wrapped message would break a substring assertion for reasons that have nothing to do
    with the command.
    """
    monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "cid")
    monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("PANW_MGMT_TSG_ID", "1016244978")
    monkeypatch.delenv("PANW_MGMT_TOKEN_ENDPOINT", raising=False)
    monkeypatch.setenv("COLUMNS", "200")


@pytest.fixture
def api() -> Any:
    """A router with the OAuth token endpoint stubbed; every DLP call fetches one first."""
    with respx.mock(assert_all_called=False) as router:
        router.post(DEFAULT_TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 900})
        )
        yield router


# ---------------------------------------------------------------------------
# Data patterns
# ---------------------------------------------------------------------------


class TestPatterns:
    def test_list_sends_a_get_with_no_query_by_default(self, api: respx.MockRouter) -> None:
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        result = runner.invoke(cli, ["dlp", "patterns", "list"])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert dict(route.calls.last.request.url.params) == {}

    def test_list_converts_limit_and_offset_to_a_page(self, api: respx.MockRouter) -> None:
        """The API is page-based; the CLI speaks limit/offset and rounds down."""
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        runner.invoke(cli, ["dlp", "patterns", "list", "--limit", "10", "--offset", "25"])

        assert dict(route.calls.last.request.url.params) == {"page": "2", "size": "10"}

    def test_list_repeats_the_sort_key_once_per_entry(self, api: respx.MockRouter) -> None:
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        runner.invoke(cli, ["dlp", "patterns", "list", "--sort", "name,asc", "--sort", "type,desc"])

        assert route.calls.last.request.url.params.get_list("sort") == ["name,asc", "type,desc"]

    def test_a_negative_limit_is_refused(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "patterns", "list", "--limit", "-1"])

        assert result.exit_code == 2
        assert not api.calls

    def test_an_api_failure_exits_two(self, api: respx.MockRouter) -> None:
        api.get(PATTERNS_URL).mock(return_value=httpx.Response(403, json={"message": "nope"}))

        result = runner.invoke(cli, ["dlp", "patterns", "list"])

        assert result.exit_code == 2

    def test_create_builds_the_body_from_flags(self, api: respx.MockRouter) -> None:
        route = api.post(PATTERNS_URL).mock(return_value=httpx.Response(200, json=PATTERN))

        result = runner.invoke(
            cli,
            [
                "dlp",
                "patterns",
                "create",
                "--name",
                "Card",
                "--description",
                "PAN detector",
                "--technique",
                "weighted_regex",
                "--confidence-levels",
                "high, low",
                "--regex",
                r"\d{16}",
                "--delimiter",
                ";",
                "--proximity-distance",
                "40",
                "--proximity-keyword",
                "card",
                "--tag",
                "compliance=pci,hipaa",
            ],
        )

        assert result.exit_code == 0
        assert sent_body(route) == {
            "name": "Card",
            "type": "custom",
            "description": "PAN detector",
            "detection_config": {
                "technique": "weighted_regex",
                "supported_confidence_levels": ["high", "low"],
            },
            "matching_rules": {
                "delimiter": ";",
                "proximity_distance": 40,
                "proximity_keywords": ["card"],
                "regexes": [{"regex": r"\d{16}", "weight": 1.0}],
            },
            "tags": {"compliance": ["pci", "hipaa"]},
        }

    def test_create_splits_a_weighted_regex_on_its_last_pipe(self, api: respx.MockRouter) -> None:
        """An alternation contains pipes, so only the final one separates the weight."""
        route = api.post(PATTERNS_URL).mock(return_value=httpx.Response(200, json=PATTERN))

        runner.invoke(
            cli,
            ["dlp", "patterns", "create", "--name", "P", "--weighted-regex", "foo|bar|2.5"],
        )

        assert sent_body(route)["matching_rules"]["regexes"] == [
            {"regex": "foo|bar", "weight": 2.5}
        ]

    def test_create_refuses_a_weighted_regex_without_a_weight(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            cli, ["dlp", "patterns", "create", "--name", "P", "--weighted-regex", "nopipe"]
        )

        assert result.exit_code == 2
        assert "PATTERN|weight" in result.output

    def test_create_refuses_a_non_numeric_weight(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            cli, ["dlp", "patterns", "create", "--name", "P", "--weighted-regex", "a|heavy"]
        )

        assert result.exit_code == 2
        assert "weight invalid" in result.output

    def test_create_refuses_a_tag_without_an_equals(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            cli, ["dlp", "patterns", "create", "--name", "P", "--tag", "compliance"]
        )

        assert result.exit_code == 2
        assert "--tag must be 'key=value'" in result.output
        assert not api.calls

    def test_create_refuses_a_tag_with_no_key(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "patterns", "create", "--name", "P", "--tag", "=pci"])

        assert result.exit_code == 2
        assert "--tag missing key" in result.output
        assert not api.calls

    def test_create_sends_the_type_flag_verbatim(self, api: respx.MockRouter) -> None:
        """``--type`` is spelled ``pattern_type`` in Python; the flag itself must not move."""
        route = api.post(PATTERNS_URL).mock(return_value=httpx.Response(200, json=PATTERN))

        result = runner.invoke(
            cli, ["dlp", "patterns", "create", "--name", "P", "--type", "file_property"]
        )

        assert result.exit_code == 0
        assert sent_body(route) == {
            "name": "P",
            "type": "file_property",
            # Nothing named a technique, so the default rides along.
            "detection_config": {"technique": "regex"},
        }

    def test_create_requires_a_name(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "patterns", "create"])

        assert result.exit_code == 2
        assert "--name is required" in result.output
        assert not api.calls

    def test_create_takes_a_raw_body_from_a_file(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.post(PATTERNS_URL).mock(return_value=httpx.Response(200, json=PATTERN))
        body_file = tmp_path / "body.json"
        body_file.write_text(
            json.dumps(
                {"name": "FromFile", "type": "custom", "detection_config": {"technique": "ml"}}
            )
        )

        runner.invoke(cli, ["dlp", "patterns", "create", "--body-file", str(body_file)])

        assert sent_body(route)["name"] == "FromFile"

    def test_create_takes_a_raw_body_from_stdin(self, api: respx.MockRouter) -> None:
        route = api.post(PATTERNS_URL).mock(return_value=httpx.Response(200, json=PATTERN))
        body = json.dumps(
            {"name": "FromStdin", "type": "custom", "detection_config": {"technique": "regex"}}
        )

        runner.invoke(cli, ["dlp", "patterns", "create", "--body", "-"], input=body)

        assert sent_body(route)["name"] == "FromStdin"

    def test_create_refuses_a_malformed_raw_body(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "patterns", "create", "--body", "{not json"])

        assert result.exit_code == 2
        assert "invalid JSON" in result.output

    def test_create_refuses_a_body_that_fails_validation(self, api: respx.MockRouter) -> None:
        """A pattern with no detection config never reaches the wire."""
        result = runner.invoke(cli, ["dlp", "patterns", "create", "--body", '{"name": "X"}'])

        assert result.exit_code == 2
        assert not api.calls

    def test_create_refuses_an_empty_raw_body(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "patterns", "create", "--body", '""'])

        assert result.exit_code == 2
        assert "was empty" in result.output
        assert not api.calls

    def test_create_refuses_a_raw_body_that_is_not_an_object(self, api: respx.MockRouter) -> None:
        """A JSON array parses fine but cannot be a request body; say so, don't guess."""
        result = runner.invoke(cli, ["dlp", "patterns", "create", "--body", '[{"name": "X"}]'])

        assert result.exit_code == 2
        assert "must contain a JSON object" in result.output
        assert not api.calls

    def test_get_addresses_the_item_path(self, api: respx.MockRouter) -> None:
        route = api.get(f"{PATTERNS_URL}/dp-1").mock(return_value=httpx.Response(200, json=PATTERN))

        result = runner.invoke(cli, ["dlp", "patterns", "get", "dp-1"])

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "GET"
        assert str(request.url) == f"{PATTERNS_URL}/dp-1"

    def test_replace_sends_a_put_carrying_the_whole_body(self, api: respx.MockRouter) -> None:
        route = api.put(f"{PATTERNS_URL}/dp-1").mock(return_value=httpx.Response(200, json=PATTERN))

        result = runner.invoke(
            cli,
            [
                "dlp",
                "patterns",
                "replace",
                "dp-1",
                "--name",
                "New",
                "--type",
                "predefined",
                "--technique",
                "ml",
            ],
        )

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "PUT"
        assert str(request.url) == f"{PATTERNS_URL}/dp-1"
        assert sent_body(route) == {
            "name": "New",
            "type": "predefined",
            "detection_config": {"technique": "ml"},
        }

    def test_patch_sends_a_merge_patch_document(self, api: respx.MockRouter) -> None:
        """The point of RFC 7396: a cleared field is ``null``, an untouched one is absent."""
        route = api.patch(f"{PATTERNS_URL}/dp-1").mock(
            return_value=httpx.Response(200, json=PATTERN)
        )

        result = runner.invoke(
            cli,
            [
                "dlp",
                "patterns",
                "patch",
                "dp-1",
                "--set",
                "name=SSN",
                "--set",
                "type=custom",
                "--set",
                'detection_config={"technique": "regex"}',
                "--clear",
                "description",
            ],
        )

        assert result.exit_code == 0
        assert route.calls.last.request.headers["content-type"] == MERGE_PATCH
        body = sent_body(route)
        assert body["description"] is None
        assert body["detection_config"] == {"technique": "regex"}
        assert "matching_rules" not in body
        assert "tags" not in body

    def test_patch_coerces_scalars_but_leaves_quoted_values_alone(
        self, api: respx.MockRouter
    ) -> None:
        route = api.patch(f"{PATTERNS_URL}/dp-1").mock(
            return_value=httpx.Response(200, json=PATTERN)
        )

        runner.invoke(
            cli,
            [
                "dlp",
                "patterns",
                "patch",
                "dp-1",
                "--set",
                "name=SSN",
                "--set",
                "type=custom",
                "--set",
                'detection_config={"technique": "regex"}',
                "--set",
                "version=7",
                "--set",
                "enabled=true",
                "--set",
                'code="5"',
            ],
        )

        body = sent_body(route)
        assert body["version"] == 7
        assert body["enabled"] is True
        assert body["code"] == "5"

    def test_patch_reads_a_merge_patch_from_a_body_file(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.patch(f"{PATTERNS_URL}/dp-1").mock(
            return_value=httpx.Response(200, json=PATTERN)
        )
        body_file = tmp_path / "patch.json"
        body_file.write_text(
            json.dumps(
                {
                    "name": "SSN",
                    "type": "custom",
                    "detection_config": {"technique": "regex"},
                    "tags": None,
                }
            )
        )

        result = runner.invoke(
            cli, ["dlp", "patterns", "patch", "dp-1", "--body-file", str(body_file)]
        )

        assert result.exit_code == 0
        body = sent_body(route)
        assert body["tags"] is None
        assert "description" not in body

    def test_patch_refuses_a_body_file_alongside_set(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        body_file = tmp_path / "patch.json"
        body_file.write_text("{}")

        result = runner.invoke(
            cli,
            ["dlp", "patterns", "patch", "dp-1", "--body-file", str(body_file), "--set", "a=b"],
        )

        assert result.exit_code == 2
        assert "mutually exclusive" in result.output

    def test_patch_refuses_a_nested_set_key(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            cli, ["dlp", "patterns", "patch", "dp-1", "--set", "detection_config.technique=ml"]
        )

        assert result.exit_code == 2
        assert "--body-file for nested fields" in result.output

    def test_patch_refuses_a_nested_clear_key(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            cli, ["dlp", "patterns", "patch", "dp-1", "--clear", "tags.classification"]
        )

        assert result.exit_code == 2
        assert "--body-file for nested fields" in result.output
        assert not api.calls

    def test_patch_points_set_null_at_clear(self, api: respx.MockRouter) -> None:
        """``--set x=null`` looks like a clear but would send the string 'null'."""
        result = runner.invoke(
            cli, ["dlp", "patterns", "patch", "dp-1", "--set", "description=null"]
        )

        assert result.exit_code == 2
        assert "--clear description" in result.output

    def test_patch_refuses_a_set_entry_without_a_key(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "patterns", "patch", "dp-1", "--set", "=value"])

        assert result.exit_code == 2
        assert "expected key=value" in result.output

    def test_delete_archives_and_says_so(self, api: respx.MockRouter) -> None:
        route = api.delete(f"{PATTERNS_URL}/dp-1").mock(return_value=httpx.Response(204))

        result = runner.invoke(cli, ["dlp", "patterns", "delete", "dp-1"])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "DELETE"
        assert "archived dp-1" in result.output


# ---------------------------------------------------------------------------
# Data profiles
# ---------------------------------------------------------------------------


class TestProfiles:
    def test_list_sends_a_get(self, api: respx.MockRouter) -> None:
        route = api.get(PROFILES_URL).mock(return_value=httpx.Response(200, json=page(PROFILE)))

        result = runner.invoke(cli, ["dlp", "profiles", "list", "--limit", "5"])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert dict(route.calls.last.request.url.params) == {"size": "5"}

    def test_list_sends_the_page_derived_from_offset(self, api: respx.MockRouter) -> None:
        route = api.get(PROFILES_URL).mock(return_value=httpx.Response(200, json=page(PROFILE)))

        runner.invoke(cli, ["dlp", "profiles", "list", "--limit", "5", "--offset", "12"])

        # 12 // 5 == 2: the offset rounds down onto a page boundary.
        assert dict(route.calls.last.request.url.params) == {"page": "2", "size": "5"}

    def test_a_negative_offset_is_refused(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "profiles", "list", "--offset", "-5"])

        assert result.exit_code == 2
        assert not api.calls

    def test_create_turns_pattern_ids_into_an_expression_tree(self, api: respx.MockRouter) -> None:
        route = api.post(PROFILES_URL).mock(return_value=httpx.Response(200, json=PROFILE))

        result = runner.invoke(
            cli,
            [
                "dlp",
                "profiles",
                "create",
                "--name",
                "Cards",
                "--profile-type",
                "basic",
                "--pattern-id",
                "dp-1",
                "--pattern-id",
                "dp-2",
                "--combinator",
                "AND",
                "--confidence",
                "medium",
                "--granular",
            ],
        )

        assert result.exit_code == 0
        body = sent_body(route)
        assert body["name"] == "Cards"
        assert body["profile_type"] == "basic"
        assert body["is_granular_data_profile"] is True
        assert body["detection_rules"] == [
            {
                "rule_type": "expression_tree",
                "expression_tree": {
                    "operator_type": "and",
                    "condition_pattern": [
                        {
                            "data_pattern_id": "dp-1",
                            "confidence_level": "medium",
                            "occurrence_operator_type": "any",
                            "occurrence_count": 1,
                        },
                        {
                            "data_pattern_id": "dp-2",
                            "confidence_level": "medium",
                            "occurrence_operator_type": "any",
                            "occurrence_count": 1,
                        },
                    ],
                },
            }
        ]

    def test_create_defaults_the_combinator_and_the_leaf_confidence(
        self, api: respx.MockRouter
    ) -> None:
        """Without --combinator/--confidence the tree ORs its leaves at high confidence."""
        route = api.post(PROFILES_URL).mock(return_value=httpx.Response(200, json=PROFILE))

        result = runner.invoke(
            cli, ["dlp", "profiles", "create", "--name", "Cards", "--pattern-id", "dp-1"]
        )

        assert result.exit_code == 0
        body = sent_body(route)
        assert body["profile_type"] == "advanced"
        tree = body["detection_rules"][0]["expression_tree"]
        assert tree["operator_type"] == "or"
        assert tree["condition_pattern"][0]["confidence_level"] == "high"

    def test_create_refuses_an_unknown_combinator(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            cli,
            [
                "dlp",
                "profiles",
                "create",
                "--name",
                "X",
                "--pattern-id",
                "dp-1",
                "--combinator",
                "xor",
            ],
        )

        assert result.exit_code == 2
        assert "--combinator must be one of" in result.output
        assert not api.calls

    def test_create_requires_a_name(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "profiles", "create"])

        assert result.exit_code == 2
        assert "--name is required" in result.output
        assert not api.calls

    def test_create_refuses_a_profile_with_no_detection_rules(self, api: respx.MockRouter) -> None:
        """A profile that detects nothing is rejected here rather than by the service."""
        result = runner.invoke(cli, ["dlp", "profiles", "create", "--name", "Empty"])

        assert result.exit_code == 2
        assert not api.calls

    def test_get_addresses_the_item_path(self, api: respx.MockRouter) -> None:
        route = api.get(f"{PROFILES_URL}/prof-1").mock(
            return_value=httpx.Response(200, json=PROFILE)
        )

        result = runner.invoke(cli, ["dlp", "profiles", "get", "prof-1"])

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "GET"
        assert str(request.url) == f"{PROFILES_URL}/prof-1"

    def test_replace_sends_a_put_carrying_the_whole_body(self, api: respx.MockRouter) -> None:
        route = api.put(f"{PROFILES_URL}/prof-1").mock(
            return_value=httpx.Response(200, json=PROFILE)
        )

        result = runner.invoke(
            cli,
            [
                "dlp",
                "profiles",
                "replace",
                "prof-1",
                "--name",
                "N",
                "--profile-type",
                "basic",
                "--description",
                "d",
                "--pattern-id",
                "dp-1",
            ],
        )

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "PUT"
        assert str(request.url) == f"{PROFILES_URL}/prof-1"
        body = sent_body(route)
        assert body["name"] == "N"
        assert body["profile_type"] == "basic"
        assert body["description"] == "d"
        assert (
            body["detection_rules"][0]["expression_tree"]["condition_pattern"][0]["data_pattern_id"]
            == "dp-1"
        )

    def test_patch_carries_the_soft_delete_idiom(self, api: respx.MockRouter) -> None:
        """``profile_status`` is not a declared field; the model preserves it regardless."""
        route = api.patch(f"{PROFILES_URL}/prof-1").mock(
            return_value=httpx.Response(200, json=PROFILE)
        )

        result = runner.invoke(
            cli,
            [
                "dlp",
                "profiles",
                "patch",
                "prof-1",
                "--set",
                'name="Confidential"',
                "--set",
                'profile_type="advanced"',
                "--set",
                'profile_status="deleted"',
            ],
        )

        assert result.exit_code == 0
        assert route.calls.last.request.headers["content-type"] == MERGE_PATCH
        assert sent_body(route) == {
            "name": "Confidential",
            "profile_type": "advanced",
            "profile_status": "deleted",
        }

    def test_patch_requires_name_and_profile_type(self, api: respx.MockRouter) -> None:
        result = runner.invoke(
            cli, ["dlp", "profiles", "patch", "prof-1", "--set", 'profile_status="deleted"']
        )

        assert result.exit_code == 2
        assert not api.calls

    def test_delete_refuses_and_prints_the_patch_idiom(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "profiles", "delete", "prof-1"])

        assert result.exit_code == 2
        assert "no DELETE for data profiles" in result.output
        assert "profile_status" in result.output
        assert not api.calls

    def test_delete_quotes_the_path_the_caller_actually_invoked(
        self, api: respx.MockRouter
    ) -> None:
        """The quoted commands are meant to be pasted, so the group path must be real."""
        result = runner.invoke(cli, ["dlp", "profiles", "delete", "prof-1"])

        # ``root`` is what the test runner calls the program; the point is that the path is
        # read off the invocation rather than hardcoded, so it survives being remounted.
        assert "root dlp profiles get prof-1 --output json" in result.output
        assert "root dlp profiles patch prof-1 --set profile_status=" in result.output


# ---------------------------------------------------------------------------
# Data filtering profiles
# ---------------------------------------------------------------------------


class TestFilteringProfiles:
    def test_list_sends_a_get(self, api: respx.MockRouter) -> None:
        route = api.get(FILTERING_URL).mock(
            return_value=httpx.Response(200, json=page(FILTERING_PROFILE))
        )

        result = runner.invoke(cli, ["dlp", "filtering-profiles", "list", "--offset", "100"])

        assert result.exit_code == 0
        # No --limit, so the offset converts against the default page size of 50.
        assert dict(route.calls.last.request.url.params) == {"page": "2"}
        # Nothing asked for a machine format, so the default stays human-readable.
        assert "Data Filtering Profiles" in result.output
        assert not result.output.lstrip().startswith("{")

    def test_list_passes_the_limit_through_as_the_page_size(self, api: respx.MockRouter) -> None:
        route = api.get(FILTERING_URL).mock(
            return_value=httpx.Response(200, json=page(FILTERING_PROFILE))
        )

        runner.invoke(cli, ["dlp", "filtering-profiles", "list", "--limit", "7"])

        assert dict(route.calls.last.request.url.params) == {"size": "7"}

    def test_list_maps_log_severity_onto_the_severity_column(self, api: respx.MockRouter) -> None:
        """The wire field is ``log_severity``; the rendered column is ``severity``."""
        api.get(FILTERING_URL).mock(return_value=httpx.Response(200, json=page(FILTERING_PROFILE)))

        result = runner.invoke(cli, ["dlp", "filtering-profiles", "list", "--output", "json"])

        assert json.loads(result.output)["items"] == [
            {
                "id": "dfp-1",
                "name": "Finance",
                "type": "custom",
                "direction": "BOTH",
                "severity": "HIGH",
                "version": 1,
            }
        ]

    def test_get_addresses_the_item_path(self, api: respx.MockRouter) -> None:
        route = api.get(f"{FILTERING_URL}/dfp-1").mock(
            return_value=httpx.Response(200, json=FILTERING_PROFILE)
        )

        result = runner.invoke(cli, ["dlp", "filtering-profiles", "get", "dfp-1"])

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "GET"
        assert str(request.url) == f"{FILTERING_URL}/dfp-1"

    def test_get_renders_the_scan_scope_booleans_as_words(self, api: respx.MockRouter) -> None:
        api.get(f"{FILTERING_URL}/dfp-1").mock(
            return_value=httpx.Response(200, json=FILTERING_PROFILE)
        )

        result = runner.invoke(
            cli, ["dlp", "filtering-profiles", "get", "dfp-1", "--output", "json"]
        )

        detail = json.loads(result.output)
        assert detail["file_based"] == "yes"
        assert detail["non_file_based"] == "no"
        assert detail["severity"] == "HIGH"

    def test_replace_builds_the_body_from_flags(self, api: respx.MockRouter) -> None:
        route = api.put(f"{FILTERING_URL}/dfp-1").mock(
            return_value=httpx.Response(200, json=FILTERING_PROFILE)
        )

        result = runner.invoke(
            cli,
            [
                "dlp",
                "filtering-profiles",
                "replace",
                "dfp-1",
                "--file-based",
                "--non-file-based",
                "--description",
                "Finance",
                "--direction",
                "UPLOAD",
                "--log-severity",
                "HIGH",
                "--scan-type",
                "include",
                "--data-profile-id",
                "42",
                "--euc-template-id",
                "euc-9",
                "--end-user-coaching",
                "--granular",
                "--file-type",
                "pdf",
                "--file-type",
                "docx",
            ],
        )

        assert result.exit_code == 0
        assert sent_body(route) == {
            "file_based": True,
            "non_file_based": True,
            "description": "Finance",
            "direction": "UPLOAD",
            "log_severity": "HIGH",
            "scan_type": "include",
            "data_profile_id": 42,
            "euc_template_id": "euc-9",
            "is_end_user_coaching_enabled": True,
            "is_granular_profile": True,
            "file_type": ["pdf", "docx"],
        }

    def test_replace_requires_both_scan_scope_flags(self, api: respx.MockRouter) -> None:
        """Defaulting either one would silently change which traffic is inspected."""
        result = runner.invoke(
            cli, ["dlp", "filtering-profiles", "replace", "dfp-1", "--file-based"]
        )

        assert result.exit_code == 2
        assert "--file-based and --non-file-based are both required" in result.output
        assert not api.calls

    def test_replace_accepts_a_raw_body(self, api: respx.MockRouter) -> None:
        route = api.put(f"{FILTERING_URL}/dfp-1").mock(
            return_value=httpx.Response(200, json=FILTERING_PROFILE)
        )

        runner.invoke(
            cli,
            [
                "dlp",
                "filtering-profiles",
                "replace",
                "dfp-1",
                "--body",
                '{"file_based": false, "non_file_based": true, "direction": "BOTH"}',
            ],
        )

        assert sent_body(route) == {
            "file_based": False,
            "non_file_based": True,
            "direction": "BOTH",
        }


# ---------------------------------------------------------------------------
# Dictionaries
# ---------------------------------------------------------------------------


@pytest.fixture
def keyword_file(tmp_path: Path) -> Path:
    """A keyword file to upload."""
    path = tmp_path / "keywords.txt"
    path.write_text("alpha\nbeta\n")
    return path


class TestDictionaries:
    def test_list_sends_no_keywords_flag_unless_asked(self, api: respx.MockRouter) -> None:
        route = api.get(DICTIONARIES_URL).mock(
            return_value=httpx.Response(200, json=page(DICTIONARY))
        )

        result = runner.invoke(cli, ["dlp", "dictionaries", "list"])

        assert result.exit_code == 0
        assert "keywords" not in route.calls.last.request.url.params

    def test_list_asks_for_keywords_as_a_lowercase_literal(self, api: respx.MockRouter) -> None:
        route = api.get(DICTIONARIES_URL).mock(
            return_value=httpx.Response(200, json=page(DICTIONARY))
        )

        runner.invoke(cli, ["dlp", "dictionaries", "list", "--keywords"])

        assert route.calls.last.request.url.params["keywords"] == "true"

    def test_create_uploads_metadata_and_the_keyword_file(
        self, api: respx.MockRouter, keyword_file: Path
    ) -> None:
        route = api.post(DICTIONARIES_URL).mock(return_value=httpx.Response(200, json=DICTIONARY))

        result = runner.invoke(
            cli,
            [
                "dlp",
                "dictionaries",
                "create",
                "--name",
                "PII",
                "--category",
                "Confidential",
                "--region",
                "us-west-2",
                "--description",
                "personal data",
                "--classification",
                "pab",
                "--file",
                str(keyword_file),
                "--include-keywords",
            ],
        )

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "POST"
        assert str(request.url).startswith(DICTIONARIES_URL)
        assert request.url.params["keywords"] == "true"
        parts = multipart_parts(request)
        assert json.loads(parts["json"]) == {
            "category": "Confidential",
            "name": "PII",
            "original_file_name": "keywords.txt",
            "region_name": "us-west-2",
            "description": "personal data",
            "classification": "pab",
        }
        assert parts["file"] == b"alpha\nbeta\n"

    def test_create_requires_the_identifying_flags(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "dictionaries", "create", "--name", "PII"])

        assert result.exit_code == 2
        assert "--name, --category, --region, and --file are required" in result.output

    def test_create_takes_metadata_from_a_file(
        self, api: respx.MockRouter, keyword_file: Path, tmp_path: Path
    ) -> None:
        route = api.post(DICTIONARIES_URL).mock(return_value=httpx.Response(200, json=DICTIONARY))
        metadata_file = tmp_path / "metadata.json"
        metadata_file.write_text(
            json.dumps(
                {
                    "name": "FromFile",
                    "category": "Legal",
                    "region_name": "eu-west-1",
                    "original_file_name": "other.txt",
                }
            )
        )

        runner.invoke(
            cli,
            [
                "dlp",
                "dictionaries",
                "create",
                "--metadata-file",
                str(metadata_file),
                "--file",
                str(keyword_file),
            ],
        )

        assert json.loads(multipart_parts(route.calls.last.request)["json"])["name"] == "FromFile"

    def test_create_still_needs_the_keyword_file_with_a_metadata_file(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """The endpoint is multipart-only, so metadata alone cannot satisfy it."""
        metadata_file = tmp_path / "metadata.json"
        metadata_file.write_text(
            json.dumps(
                {
                    "name": "N",
                    "category": "Legal",
                    "region_name": "eu-west-1",
                    "original_file_name": "other.txt",
                }
            )
        )

        result = runner.invoke(
            cli, ["dlp", "dictionaries", "create", "--metadata-file", str(metadata_file)]
        )

        assert result.exit_code == 2
        assert "--file is required" in result.output

    def test_get_asks_for_keywords_when_requested(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DICTIONARIES_URL}/dict-1").mock(
            return_value=httpx.Response(200, json=DICTIONARY)
        )

        result = runner.invoke(cli, ["dlp", "dictionaries", "get", "dict-1", "--keywords"])

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "GET"
        assert request.url.params["keywords"] == "true"

    def test_get_sends_no_keywords_flag_unless_asked(self, api: respx.MockRouter) -> None:
        route = api.get(f"{DICTIONARIES_URL}/dict-1").mock(
            return_value=httpx.Response(200, json=DICTIONARY)
        )

        result = runner.invoke(cli, ["dlp", "dictionaries", "get", "dict-1"])

        assert result.exit_code == 0
        assert "keywords" not in route.calls.last.request.url.params

    def test_replace_sends_a_multipart_put(self, api: respx.MockRouter, keyword_file: Path) -> None:
        route = api.put(f"{DICTIONARIES_URL}/dict-1").mock(
            return_value=httpx.Response(200, json=DICTIONARY)
        )

        result = runner.invoke(
            cli,
            [
                "dlp",
                "dictionaries",
                "replace",
                "dict-1",
                "--name",
                "PII",
                "--category",
                "Confidential",
                "--region",
                "us-west-2",
                "--include-keywords",
                "--file",
                str(keyword_file),
            ],
        )

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "PUT"
        assert str(request.url).startswith(f"{DICTIONARIES_URL}/dict-1")
        assert request.url.params["keywords"] == "true"
        parts = multipart_parts(request)
        assert parts["file"] == b"alpha\nbeta\n"
        assert json.loads(parts["json"]) == {
            "name": "PII",
            "category": "Confidential",
            "region_name": "us-west-2",
            "original_file_name": "keywords.txt",
        }
        assert "replaced dict-1" in result.output

    def test_replace_reports_a_204_as_success(
        self, api: respx.MockRouter, keyword_file: Path
    ) -> None:
        """204 is a normal answer here; printing nothing would read as a silent failure."""
        api.put(f"{DICTIONARIES_URL}/dict-1").mock(return_value=httpx.Response(204))

        result = runner.invoke(
            cli,
            [
                "dlp",
                "dictionaries",
                "replace",
                "dict-1",
                "--name",
                "PII",
                "--category",
                "Confidential",
                "--region",
                "us-west-2",
                "--file",
                str(keyword_file),
            ],
        )

        assert result.exit_code == 0
        assert "state not echoed" in result.output

    def test_patch_sends_a_merge_patch(self, api: respx.MockRouter) -> None:
        route = api.patch(f"{DICTIONARIES_URL}/dict-1").mock(
            return_value=httpx.Response(200, json=DICTIONARY)
        )

        result = runner.invoke(
            cli,
            [
                "dlp",
                "dictionaries",
                "patch",
                "dict-1",
                "--set",
                "name=PII",
                "--set",
                "category=Legal",
                "--set",
                "original_file_name=keywords.txt",
                "--clear",
                "description",
            ],
        )

        assert result.exit_code == 0
        assert route.calls.last.request.headers["content-type"] == MERGE_PATCH
        body = sent_body(route)
        assert body["description"] is None
        assert "region_name" not in body

    def test_delete_sends_a_delete(self, api: respx.MockRouter) -> None:
        route = api.delete(f"{DICTIONARIES_URL}/dict-1").mock(return_value=httpx.Response(204))

        result = runner.invoke(cli, ["dlp", "dictionaries", "delete", "dict-1"])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "DELETE"
        assert "deleted dict-1" in result.output


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------


class TestOutputFormats:
    def test_pretty_list_names_the_items_and_the_page(self, api: respx.MockRouter) -> None:
        api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        result = runner.invoke(cli, ["dlp", "patterns", "list"])

        assert "Data Patterns" in result.output
        assert "SSN" in result.output
        assert "total=1" in result.output

    def test_an_empty_page_reads_as_success_not_failure(self, api: respx.MockRouter) -> None:
        api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=empty_page()))

        result = runner.invoke(cli, ["dlp", "patterns", "list"])

        assert result.exit_code == 0
        assert "No data patterns found" in result.output

    def test_json_list_output_is_parseable(self, api: respx.MockRouter) -> None:
        api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        result = runner.invoke(cli, ["dlp", "patterns", "list", "--output", "json"])

        payload = json.loads(result.output)
        assert payload["items"] == [
            {
                "id": "dp-1",
                "name": "SSN",
                "type": "custom",
                "status": "active",
                "technique": "regex",
                "version": 2,
            }
        ]
        assert payload["page"] == {"number": 0, "size": 20, "total": 1, "returned": 1}

    def test_json_list_counts_a_dictionary_s_keywords(self, api: respx.MockRouter) -> None:
        """The list column is a count, not the keyword array itself."""
        api.get(DICTIONARIES_URL).mock(return_value=httpx.Response(200, json=page(DICTIONARY)))

        result = runner.invoke(cli, ["dlp", "dictionaries", "list", "--output", "json"])

        assert json.loads(result.output)["items"] == [
            {
                "id": "dict-1",
                "name": "PII",
                "type": "custom",
                "status": None,
                "keywords": 2,
                "version": None,
            }
        ]

    def test_json_list_maps_profile_status_onto_the_status_column(
        self, api: respx.MockRouter
    ) -> None:
        api.get(PROFILES_URL).mock(return_value=httpx.Response(200, json=page(PROFILE)))

        result = runner.invoke(cli, ["dlp", "profiles", "list", "--output", "json"])

        assert json.loads(result.output)["items"] == [
            {
                "id": "prof-1",
                "name": "Confidential",
                "type": "custom",
                "profile_type": "advanced",
                "status": "active",
                "version": 3,
            }
        ]

    def test_an_integral_version_renders_without_a_decimal_point(
        self, api: respx.MockRouter
    ) -> None:
        """A data pattern's version is a float on the model; ``v3.0`` is not a version.

        The resource matters: ``DataProfileResponse.version`` is declared ``int``, so
        pydantic would flatten the float before the renderer ever saw it and the test
        would pass no matter what the renderer did.
        """
        api.get(f"{PATTERNS_URL}/dp-1").mock(
            return_value=httpx.Response(200, json={**PATTERN, "version": 3.0})
        )

        result = runner.invoke(cli, ["dlp", "patterns", "get", "dp-1", "--output", "json"])

        assert "3.0" not in result.output
        assert json.loads(result.output)["version"] == 3

    def test_an_integral_version_renders_without_a_decimal_point_in_a_list(
        self, api: respx.MockRouter
    ) -> None:
        api.get(PATTERNS_URL).mock(
            return_value=httpx.Response(200, json=page({**PATTERN, "version": 3.0}))
        )

        result = runner.invoke(cli, ["dlp", "patterns", "list", "--output", "json"])

        assert "3.0" not in result.output
        assert json.loads(result.output)["items"][0]["version"] == 3

    def test_csv_list_output_carries_a_header_row(self, api: respx.MockRouter) -> None:
        api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        result = runner.invoke(cli, ["dlp", "patterns", "list", "--output", "csv"])

        lines = result.output.strip().splitlines()
        assert lines[0] == "ID,Name,Type,Status,Technique,Version"
        assert lines[1].startswith("dp-1,SSN,custom,active,regex")

    def test_json_detail_output_uses_snake_case_keys(self, api: respx.MockRouter) -> None:
        api.get(f"{PATTERNS_URL}/dp-1").mock(return_value=httpx.Response(200, json=PATTERN))

        result = runner.invoke(cli, ["dlp", "patterns", "get", "dp-1", "--output", "json"])

        detail = json.loads(result.output)
        assert detail["id"] == "dp-1"
        assert detail["technique"] == "regex"
        assert detail["updated"].startswith("2023-11-")

    def test_json_detail_output_drops_unset_fields(self, api: respx.MockRouter) -> None:
        """A screen of nulls says less than a short list of what is actually set."""
        api.get(f"{PATTERNS_URL}/dp-1").mock(return_value=httpx.Response(200, json=PATTERN))

        result = runner.invoke(cli, ["dlp", "patterns", "get", "dp-1", "--output", "json"])

        assert "description" not in json.loads(result.output)

    def test_json_write_acknowledgement_names_the_resource(self, api: respx.MockRouter) -> None:
        api.post(PATTERNS_URL).mock(return_value=httpx.Response(200, json=PATTERN))

        result = runner.invoke(
            cli, ["dlp", "patterns", "create", "--name", "SSN", "--output", "json"]
        )

        assert json.loads(result.output) == {
            "action": "created",
            "id": "dp-1",
            "name": "SSN",
            "type": "custom",
            "status": "active",
            "version": 2,
        }

    def test_a_profile_acknowledgement_reports_profile_status_as_status(
        self, api: respx.MockRouter
    ) -> None:
        """Only data profiles spell it ``profile_status``; the acknowledgement should not."""
        api.get(PROFILES_URL).mock(return_value=httpx.Response(200, json=page(PROFILE)))
        api.put(f"{PROFILES_URL}/prof-1").mock(return_value=httpx.Response(200, json=PROFILE))

        result = runner.invoke(
            cli,
            [
                "dlp",
                "profiles",
                "replace",
                "prof-1",
                "--name",
                "N",
                "--pattern-id",
                "dp-1",
                "--output",
                "json",
            ],
        )

        assert json.loads(result.output)["status"] == "active"

    def test_yaml_output_is_parseable(self, api: respx.MockRouter) -> None:
        """Wire enums subclass str, which YAML will not serialise unless it is flattened."""
        api.get(f"{PATTERNS_URL}/dp-1").mock(return_value=httpx.Response(200, json=PATTERN))

        result = runner.invoke(cli, ["dlp", "patterns", "get", "dp-1", "--output", "yaml"])

        assert result.exit_code == 0
        detail = yaml.safe_load(result.output)
        assert detail["id"] == "dp-1"
        assert detail["type"] == "custom"

    def test_an_unknown_output_format_is_refused(self, api: respx.MockRouter) -> None:
        result = runner.invoke(cli, ["dlp", "patterns", "list", "--output", "xml"])

        assert result.exit_code == 2
        assert not api.calls


# ---------------------------------------------------------------------------
# Corpus generation
# ---------------------------------------------------------------------------

SUMMARY = {
    "out": "temp",
    "seed": 7,
    "clean": 5,
    "dirty": 12,
    "manifest_path": "temp/manifest.json",
    "by_format": {"pdf": {"clean": 1, "dirty": 3}},
}


@pytest.fixture
def stub_generator(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Install a corpus generator that records its arguments instead of writing files."""
    calls: list[dict[str, Any]] = []

    def generate_corpus(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return SUMMARY

    module = types.ModuleType("prisma_airs_cli.dlp")
    module.generate_corpus = generate_corpus  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "prisma_airs_cli.dlp", module)
    return calls


class TestGenerate:
    def test_defaults_cover_every_format(self, stub_generator: list[dict[str, Any]]) -> None:
        result = runner.invoke(cli, ["dlp", "generate"])

        assert result.exit_code == 0
        assert stub_generator[0]["types"] == ["pdf", "png", "jpeg", "svg", "docx"]
        assert stub_generator[0]["count"] == 1
        assert stub_generator[0]["techniques"] == "all"
        assert stub_generator[0]["seed"] is None
        assert stub_generator[0]["out"] == Path("./temp")

    def test_passes_the_selected_formats_through(
        self, stub_generator: list[dict[str, Any]], tmp_path: Path
    ) -> None:
        result = runner.invoke(
            cli,
            [
                "dlp",
                "generate",
                "--types",
                "PDF, svg",
                "--count",
                "3",
                "--out",
                str(tmp_path / "corpus"),
                "--techniques",
                "exif, overlay",
                "--seed",
                "99",
            ],
        )

        assert result.exit_code == 0
        assert stub_generator[0] == {
            "types": ["pdf", "svg"],
            "count": 3,
            "out": tmp_path / "corpus",
            "techniques": ["exif", "overlay"],
            "seed": 99,
        }

    def test_reports_the_summary(self, stub_generator: list[dict[str, Any]]) -> None:
        result = runner.invoke(cli, ["dlp", "generate"])

        assert result.exit_code == 0
        assert "DLP Test-File Generation" in result.output
        assert "temp/manifest.json" in result.output
        assert "pdf   clean=1 dirty=3" in result.output

    def test_json_summary_is_parseable(self, stub_generator: list[dict[str, Any]]) -> None:
        result = runner.invoke(cli, ["dlp", "generate", "--output", "json"])

        assert json.loads(result.output) == SUMMARY

    def test_refuses_an_unknown_format(self, stub_generator: list[dict[str, Any]]) -> None:
        result = runner.invoke(cli, ["dlp", "generate", "--types", "pdf,tiff"])

        assert result.exit_code == 2
        assert "Unknown type(s): tiff" in result.output
        assert not stub_generator

    def test_refuses_a_non_positive_count(self, stub_generator: list[dict[str, Any]]) -> None:
        result = runner.invoke(cli, ["dlp", "generate", "--count", "0"])

        assert result.exit_code == 2
        assert "--count must be a positive integer" in result.output
        assert not stub_generator

    def test_a_generator_failure_exits_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def explode(**_kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("disk full")

        module = types.ModuleType("prisma_airs_cli.dlp")
        module.generate_corpus = explode  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "prisma_airs_cli.dlp", module)

        result = runner.invoke(cli, ["dlp", "generate"])

        assert result.exit_code == 2
        assert "disk full" in result.output

    def test_a_missing_generator_names_the_one_command_it_breaks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delitem(sys.modules, "prisma_airs_cli.dlp", raising=False)

        result = runner.invoke(cli, ["dlp", "generate"])

        assert result.exit_code == 2
        assert "prisma_airs_cli.dlp" in result.output

    def test_a_generator_module_without_the_entry_point_is_reported(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An importable module missing ``generate_corpus`` is as unusable as none at all."""
        monkeypatch.setitem(
            sys.modules, "prisma_airs_cli.dlp", types.ModuleType("prisma_airs_cli.dlp")
        )

        result = runner.invoke(cli, ["dlp", "generate"])

        assert result.exit_code == 2
        assert "prisma_airs_cli.dlp" in result.output
