"""``airs aigateway`` behaviour: which plane each call lands on, and what it sends.

The plane is the load-bearing detail in this group. The same path answers differently on
``/ai_gw/v2`` and ``/ai_gw/admin/v2`` -- one shows the workspaces the caller is scoped to,
the other the whole tenant, and every write is admin-only -- so these tests assert the
host and path each command actually reached, not merely that it did not crash.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from prisma_airs.constants import (
    DEFAULT_AI_GW_ADMIN_ENDPOINT,
    DEFAULT_AI_GW_DATA_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
)
from prisma_airs_cli.commands.aigateway import aigateway_app

runner = CliRunner()

DATA = DEFAULT_AI_GW_DATA_ENDPOINT
ADMIN = DEFAULT_AI_GW_ADMIN_ENDPOINT
DATA_WORKSPACES = f"{DATA}/workspaces"
ADMIN_WORKSPACES = f"{ADMIN}/workspaces"
COST_URL = f"{DATA}/logs/charts/cost"

TSG_ID = "1852583913"
WORKSPACE_ID = "16f7e90d-382a-4e78-b577-1b01eb5f8297"
SLUG = "ws-main-a-349e0e"

WORKSPACE_ROW = {
    "id": WORKSPACE_ID,
    "slug": SLUG,
    "name": "Main",
    "icon": None,
    "description": None,
    "created_at": "2026-07-01T00:00:00Z",
    "last_updated_at": "2026-07-02T00:00:00Z",
    "is_default": 1,
    "status": "active",
    "scope_name": "main_airs_workspace_1852583913",
    "object": "workspace",
}
ARCHIVED_ROW = {
    **WORKSPACE_ROW,
    "id": "5a4f3e2d-1c0b-4a99-8877-665544332211",
    "slug": "ws-old-a-111111",
    "name": "Retired",
    "is_default": 0,
    "status": "archived",
}


def page(*rows: dict[str, Any]) -> dict[str, Any]:
    """Wrap rows in the list envelope the gateway returns."""
    return {"object": "list", "total": len(rows), "data": list(rows)}


WORKSPACE_DETAIL = {
    "id": WORKSPACE_ID,
    "name": "Main",
    "description": "Primary workspace",
    "created_at": "2026-07-01T00:00:00Z",
    "last_updated_at": "2026-07-02T00:00:00Z",
    "is_default": 1,
    "slug": SLUG,
    "icon": None,
    "defaults": {"metadata": {"env": "production"}},
    "usage_limits": None,
    "rate_limits": [{"type": "requests", "unit": "rpm", "value": 100}],
    "security_settings": {"membersViewLogs": True},
    "status": "active",
}

WORKSPACE_CREATED = {
    "id": WORKSPACE_ID,
    "name": "Production",
    "slug": "ws-produc-985697",
    "description": None,
    "created_at": "2026-08-01T00:00:00Z",
    "last_updated_at": "2026-08-01T00:00:00Z",
    "scope_name": "ws_production_bx7qw0",
    "object": "workspace",
}

COST_CHART = {
    "success": True,
    "data": {
        "isQuotaExceeded": False,
        "records": [{"x": "2026-08-01", "y": 250.0}, {"x": "2026-08-02", "y": 411083.0}],
        "total": 411333.0,
        "avg": 58761.86,
    },
}


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests off the developer's real tenant, credentials, and endpoint overrides."""
    monkeypatch.setenv("PANW_AI_GW_CLIENT_ID", "test-id")
    monkeypatch.setenv("PANW_AI_GW_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("PANW_AI_GW_TSG_ID", TSG_ID)
    for name in (
        "PANW_AI_GW_DATA_ENDPOINT",
        "PANW_AI_GW_ADMIN_ENDPOINT",
        "PANW_AI_GW_TOKEN_ENDPOINT",
        "PANW_MGMT_CLIENT_ID",
        "PANW_MGMT_CLIENT_SECRET",
        "PANW_MGMT_TSG_ID",
    ):
        monkeypatch.delenv(name, raising=False)


def stub_token() -> None:
    """Stub the OAuth exchange; every gateway call fetches a token first."""
    respx.post(DEFAULT_TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(200, json={"access_token": "gw-token", "expires_in": 900})
    )


def flat(text: str) -> str:
    """Collapse the wrapping Rich applies at the terminal width, so matches survive it."""
    return " ".join(text.split())


def query(route: respx.Route) -> dict[str, str]:
    """Query parameters of the most recent request on ``route``."""
    return dict(route.calls.last.request.url.params)


def sent_body(route: respx.Route) -> dict[str, Any]:
    """Decode the JSON body of the most recent request on ``route``."""
    body: dict[str, Any] = json.loads(route.calls.last.request.content)
    return body


class TestWorkspaceList:
    @respx.mock
    def test_reads_the_data_plane_unfiltered_by_default(self) -> None:
        """The default is the scoped view, and no status filter at all."""
        stub_token()
        route = respx.get(DATA_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page(WORKSPACE_ROW))
        )

        result = runner.invoke(aigateway_app, ["workspace", "list"])

        assert result.exit_code == 0
        assert route.call_count == 1
        assert route.calls.last.request.method == "GET"
        assert query(route) == {}

    @respx.mock
    def test_plane_admin_reads_the_admin_plane(self) -> None:
        stub_token()
        data = respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page()))
        admin = respx.get(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page(WORKSPACE_ROW))
        )

        result = runner.invoke(aigateway_app, ["workspace", "list", "--plane", "admin"])

        assert result.exit_code == 0
        assert admin.call_count == 1
        assert data.call_count == 0

    @respx.mock
    def test_status_becomes_a_query_filter(self) -> None:
        stub_token()
        route = respx.get(DATA_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page(ARCHIVED_ROW))
        )

        result = runner.invoke(aigateway_app, ["workspace", "list", "--status", "archived"])

        assert result.exit_code == 0
        assert query(route) == {"status": "archived"}

    @respx.mock
    def test_all_merges_both_admin_plane_reads(self) -> None:
        """No single call returns both states, so --all issues two and concatenates them."""
        stub_token()
        route = respx.get(ADMIN_WORKSPACES).mock(
            side_effect=[
                httpx.Response(200, json=page(WORKSPACE_ROW)),
                httpx.Response(200, json=page(ARCHIVED_ROW)),
            ]
        )

        result = runner.invoke(aigateway_app, ["workspace", "list", "--all", "--output", "json"])

        assert result.exit_code == 0
        assert route.call_count == 2
        assert [dict(call.request.url.params) for call in route.calls] == [
            {},
            {"status": "archived"},
        ]
        assert [row["slug"] for row in json.loads(result.stdout)] == [SLUG, "ws-old-a-111111"]

    @respx.mock
    def test_all_with_plane_is_refused(self) -> None:
        """--all already fixes both, so accepting a contradicting --plane would mislead."""
        stub_token()
        route = respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page()))

        result = runner.invoke(aigateway_app, ["workspace", "list", "--all", "--plane", "admin"])

        assert result.exit_code == 2
        assert route.call_count == 0

    @respx.mock
    def test_all_with_status_is_refused(self) -> None:
        stub_token()
        route = respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page()))

        result = runner.invoke(
            aigateway_app, ["workspace", "list", "--all", "--status", "archived"]
        )

        assert result.exit_code == 2
        assert route.call_count == 0

    # These four take no route: an unmocked request exits 1, so `exit_code == 2` here means
    # the value really was refused during parsing rather than sent to the gateway.
    @respx.mock
    def test_rejects_an_unknown_plane(self) -> None:
        result = runner.invoke(aigateway_app, ["workspace", "list", "--plane", "control"])

        assert result.exit_code == 2
        assert "data" in flat(result.output)
        assert "admin" in flat(result.output)

    @respx.mock
    def test_rejects_an_unknown_status(self) -> None:
        result = runner.invoke(aigateway_app, ["workspace", "list", "--status", "deleted"])

        assert result.exit_code == 2
        assert "active" in flat(result.output)
        assert "archived" in flat(result.output)

    @respx.mock
    def test_pretty_output_names_the_workspace_and_its_scope(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))

        result = runner.invoke(aigateway_app, ["workspace", "list"])

        rendered = flat(result.stdout)
        assert SLUG in rendered
        assert "scope: main_airs_workspace_1852583913" in rendered
        assert "active" in rendered

    @respx.mock
    def test_pretty_output_warns_that_the_data_plane_hides_rows(self) -> None:
        """The hint is progress, not data, so it must not land in a piped result."""
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))

        result = runner.invoke(aigateway_app, ["workspace", "list"])

        assert "use --plane admin or --all" in flat(result.stderr)
        assert "use --plane admin or --all" not in flat(result.stdout)

    @respx.mock
    def test_the_scope_hint_is_dropped_for_an_admin_read(self) -> None:
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))

        result = runner.invoke(aigateway_app, ["workspace", "list", "--plane", "admin"])

        assert "use --plane admin or --all" not in flat(result.stderr)

    @respx.mock
    def test_pretty_output_marks_the_default_workspace(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page({**WORKSPACE_ROW, "is_default": 1}))
        )

        result = runner.invoke(aigateway_app, ["workspace", "list"])

        assert result.exit_code == 0
        assert "default" in flat(result.stdout)

    @respx.mock
    def test_a_non_default_row_carries_no_default_marker(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page({**WORKSPACE_ROW, "is_default": 0}))
        )

        result = runner.invoke(aigateway_app, ["workspace", "list"])

        assert "default" not in flat(result.stdout)

    @respx.mock
    def test_csv_output_carries_the_column_headings(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))

        result = runner.invoke(aigateway_app, ["workspace", "list", "--output", "csv"])

        lines = result.stdout.strip().splitlines()
        assert lines[0] == "ID,Slug,Name,Status,Default,Scope"
        assert lines[1].startswith(f"{WORKSPACE_ID},{SLUG},Main,active,True,")

    @respx.mock
    def test_an_empty_tenant_reads_as_success(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page()))

        result = runner.invoke(aigateway_app, ["workspace", "list"])

        assert result.exit_code == 0
        assert "No workspaces found" in flat(result.stdout)


class TestGrantHints:
    @respx.mock
    def test_ab03_points_at_the_workspace_scope_grant(self) -> None:
        """403 alone sends people to the wrong grant; the error code says which one."""
        stub_token()
        respx.get(DATA_WORKSPACES).mock(
            return_value=httpx.Response(
                403, json={"data": {"message": "Forbidden", "errorCode": "AB03"}}
            )
        )

        result = runner.invoke(aigateway_app, ["workspace", "list"])

        assert result.exit_code == 2
        assert "missing a workspace-scope grant" in flat(result.output)

    @respx.mock
    def test_a_bare_403_points_at_the_tenant_root_grant(self) -> None:
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(403, json={"message": "access denied"})
        )

        result = runner.invoke(aigateway_app, ["workspace", "list", "--plane", "admin"])

        assert result.exit_code == 2
        assert "missing a tenant-root admin grant" in flat(result.output)

    @respx.mock
    def test_a_non_403_failure_carries_no_grant_hint(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(
            return_value=httpx.Response(400, json={"message": "bad request"})
        )

        result = runner.invoke(aigateway_app, ["workspace", "list"])

        assert result.exit_code == 2
        assert "grant" not in flat(result.output)


class TestWorkspaceGet:
    @respx.mock
    def test_gets_by_slug_on_the_data_plane(self) -> None:
        stub_token()
        route = respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", SLUG])

        assert result.exit_code == 0
        assert route.call_count == 1

    @respx.mock
    def test_plane_admin_gets_from_the_admin_plane(self) -> None:
        stub_token()
        route = respx.get(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", SLUG, "--plane", "admin"])

        assert result.exit_code == 0
        assert route.call_count == 1

    @respx.mock
    def test_a_404_is_retried_against_a_resolved_name(self) -> None:
        """A display name that happens to be slug-shaped reaches the API and 404s."""
        stub_token()
        missed = respx.get(f"{DATA_WORKSPACES}/Main").mock(
            return_value=httpx.Response(404, json={"message": "not found"})
        )
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        resolved = respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", "Main"])

        assert result.exit_code == 0
        assert missed.call_count == 1
        assert resolved.call_count == 1

    @respx.mock
    def test_a_name_the_sdk_rejects_outright_is_still_resolved(self) -> None:
        """A name with a space is neither UUID nor slug, so no request is ever sent for it."""
        stub_token()
        respx.get(DATA_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page({**WORKSPACE_ROW, "name": "Main Estate"}))
        )
        resolved = respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", "Main Estate"])

        assert result.exit_code == 0
        assert resolved.call_count == 1

    @respx.mock
    def test_an_unresolvable_ref_keeps_the_api_error(self) -> None:
        """Nothing matched, so the API's own 404 stands rather than a guess replacing it."""
        stub_token()
        respx.get(f"{DATA_WORKSPACES}/ws-gone-000000").mock(
            return_value=httpx.Response(404, json={"message": "not found"})
        )
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page()))

        result = runner.invoke(aigateway_app, ["workspace", "get", "ws-gone-000000"])

        assert result.exit_code == 2
        assert "not found" in flat(result.output)

    @respx.mock
    def test_pretty_output_shows_the_settings_blocks(self) -> None:
        stub_token()
        respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", SLUG])

        rendered = flat(result.stdout)
        assert "Rate Limits:" in rendered
        assert "Primary workspace" in rendered
        assert "membersViewLogs" in rendered

    @respx.mock
    def test_pretty_output_shows_configured_usage_limits(self) -> None:
        stub_token()
        respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(
                200,
                json={
                    **WORKSPACE_DETAIL,
                    "usage_limits": [{"credit_limit": 5000.0, "type": "cost"}],
                },
            )
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", SLUG])

        rendered = flat(result.stdout)
        assert "Usage Limits:" in rendered
        assert "credit_limit" in rendered

    @respx.mock
    def test_yaml_output_normalises_the_limit_arrays(self) -> None:
        """usage_limits is null on the wire and a list here, so consumers need no branch."""
        stub_token()
        respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", SLUG, "--output", "yaml"])

        parsed = yaml.safe_load(result.stdout)
        assert parsed["usage_limits"] == []
        assert parsed["rate_limits"] == [{"type": "requests", "unit": "rpm", "value": 100}]

    @respx.mock
    def test_a_legacy_single_limit_object_becomes_a_one_element_array(self) -> None:
        """The object form is still accepted upstream; consumers should not have to branch."""
        stub_token()
        respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(
                200, json={**WORKSPACE_DETAIL, "rate_limits": {"type": "requests", "unit": "rpm"}}
            )
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", SLUG, "--output", "json"])

        assert json.loads(result.stdout)["rate_limits"] == [{"type": "requests", "unit": "rpm"}]

    @respx.mock
    def test_a_null_status_reads_as_unknown_not_inactive(self) -> None:
        """`get` reports a null status for a workspace `list` calls active -- rendering that
        as inactive would state a lifecycle fact the API never asserted."""
        stub_token()
        respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json={**WORKSPACE_DETAIL, "status": None})
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", SLUG])

        rendered = flat(result.stdout)
        assert result.exit_code == 0
        assert "unknown" in rendered
        assert "inactive" not in rendered

    @respx.mock
    def test_detail_reports_the_scope_that_governs_visibility(self) -> None:
        """`scope_name` is outside the declared detail schema but a live tenant sends it,
        and it is the one field that explains data-plane visibility -- so it is read out of
        the preserved extras rather than dropped."""
        stub_token()
        respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(
                200, json={**WORKSPACE_DETAIL, "scope_name": "main_airs_workspace_1852583913"}
            )
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", SLUG, "--output", "json"])

        assert json.loads(result.stdout)["scope_name"] == "main_airs_workspace_1852583913"

    @respx.mock
    def test_rejects_a_tabular_format(self) -> None:
        """One record with nested settings blocks has no honest CSV form."""
        stub_token()
        route = respx.get(f"{DATA_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(aigateway_app, ["workspace", "get", SLUG, "--output", "csv"])

        assert result.exit_code == 2
        assert route.call_count == 0


class TestWorkspaceCreate:
    @respx.mock
    def test_posts_to_the_admin_plane_and_re_reads_the_record(self) -> None:
        """Create omits status, icon, and both limit arrays, so the record is re-read."""
        stub_token()
        created = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )
        refetch = respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(
            aigateway_app,
            ["workspace", "create", "--name", "Production", "--scope-name", "ws_production_bx"],
        )

        assert result.exit_code == 0
        assert sent_body(created) == {"name": "Production", "scope_name": "ws_production_bx"}
        assert refetch.call_count == 1
        assert "Workspace created" in flat(result.stdout)

    @respx.mock
    def test_every_optional_flag_reaches_the_post_body(self) -> None:
        """A flag that parses and then silently drops is worse than one that never existed,
        so each optional flag is asserted on the request rather than on the exit code."""
        stub_token()
        created = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--description",
                "Production workloads, us-east",
                "--icon",
                "rocket",
                "--defaults",
                '{"cache":true}',
                "--users",
                "alice,bob",
                "--usage-limits",
                '[{"type":"cost","credit_limit":5000}]',
                "--rate-limits",
                '[{"type":"requests","unit":"rpm","value":100}]',
            ],
        )

        assert result.exit_code == 0
        assert sent_body(created) == {
            "name": "Production",
            "scope_name": "ws_production_bx",
            "description": "Production workloads, us-east",
            "icon": "rocket",
            "defaults": {"cache": True},
            "users": ["alice", "bob"],
            "usage_limits": [{"type": "cost", "credit_limit": 5000}],
            "rate_limits": [{"type": "requests", "unit": "rpm", "value": 100}],
        }

    @respx.mock
    def test_rejects_a_tabular_format(self) -> None:
        """A created record carries the same nested blocks a get does -- no CSV form."""
        stub_token()
        route = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )

        result = runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--output",
                "csv",
            ],
        )

        assert result.exit_code == 2
        assert route.call_count == 0

    @respx.mock
    def test_metadata_is_sugar_for_defaults_metadata(self) -> None:
        stub_token()
        created = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--metadata",
                '{"env":"production"}',
            ],
        )

        assert sent_body(created)["defaults"] == {"metadata": {"env": "production"}}

    @respx.mock
    def test_metadata_wins_over_defaults_on_that_one_key(self) -> None:
        stub_token()
        created = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--defaults",
                '{"metadata":{"env":"staging"},"cache":true}',
                "--metadata",
                '{"env":"production"}',
            ],
        )

        assert sent_body(created)["defaults"] == {
            "cache": True,
            "metadata": {"env": "production"},
        }

    @respx.mock
    def test_users_are_split_and_trimmed(self) -> None:
        stub_token()
        created = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--users",
                "alice, bob ,,carol",
            ],
        )

        assert sent_body(created)["users"] == ["alice", "bob", "carol"]

    @respx.mock
    def test_rate_limits_are_forwarded_as_an_array(self) -> None:
        stub_token()
        created = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--rate-limits",
                '[{"type":"requests","unit":"rpm","value":100}]',
            ],
        )

        assert sent_body(created)["rate_limits"] == [
            {"type": "requests", "unit": "rpm", "value": 100}
        ]

    @respx.mock
    def test_a_lone_limit_object_is_refused(self) -> None:
        """The API wants an array; a bare object fails far from the flag that caused it."""
        stub_token()
        route = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )

        result = runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--rate-limits",
                '{"type":"requests"}',
            ],
        )

        assert result.exit_code == 2
        assert route.call_count == 0

    @respx.mock
    def test_malformed_json_is_refused_before_the_request(self) -> None:
        stub_token()
        route = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )

        result = runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--metadata",
                "{not json}",
            ],
        )

        assert result.exit_code == 2
        assert "--metadata must be valid JSON" in flat(result.output)
        assert route.call_count == 0

    @respx.mock
    def test_defaults_must_be_a_json_object(self) -> None:
        """A JSON scalar parses fine and then silently contributes nothing."""
        stub_token()
        route = respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=WORKSPACE_CREATED)
        )

        result = runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--defaults",
                '"production"',
            ],
        )

        assert result.exit_code == 2
        assert "--defaults must be a JSON object" in flat(result.output)
        assert route.call_count == 0

    @respx.mock
    def test_warns_when_the_scope_shares_no_token_with_the_name(self) -> None:
        """A workspace whose scope nobody holds is invisible to every data-plane list."""
        stub_token()
        respx.post(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=WORKSPACE_CREATED))
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(
            aigateway_app,
            ["workspace", "create", "--name", "Production", "--scope-name", "ws_billing_bx7qw0"],
        )

        assert result.exit_code == 0
        assert "shares no token" in flat(result.output)

    @respx.mock
    def test_stays_quiet_when_the_scope_carries_the_name(self) -> None:
        stub_token()
        respx.post(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=WORKSPACE_CREATED))
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(
            aigateway_app,
            ["workspace", "create", "--name", "Production", "--scope-name", "ws_production_bx"],
        )

        assert "shares no token" not in flat(result.output)

    @respx.mock
    def test_falls_back_to_the_create_response_when_the_re_read_is_refused(self) -> None:
        """A fresh workspace's scope may not be granted yet; a partial record beats none."""
        stub_token()
        respx.post(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=WORKSPACE_CREATED))
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(403, json={"message": "no grant"})
        )

        result = runner.invoke(
            aigateway_app,
            ["workspace", "create", "--name", "Production", "--scope-name", "ws_production_bx"],
        )

        assert result.exit_code == 0
        assert "ws-produc-985697" in flat(result.stdout)

    @respx.mock
    def test_a_rejected_create_exits_two(self) -> None:
        stub_token()
        respx.post(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(400, json={"message": "scope_name already in use"})
        )

        result = runner.invoke(
            aigateway_app,
            ["workspace", "create", "--name", "Production", "--scope-name", "ws_production_bx"],
        )

        assert result.exit_code == 2
        assert "scope_name already in use" in flat(result.output)

    @respx.mock
    def test_a_name_too_short_to_judge_is_never_flagged(self) -> None:
        """Two letters match almost any scope, so the heuristic would only cry wolf."""
        stub_token()
        respx.post(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=WORKSPACE_CREATED))
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(
            aigateway_app,
            ["workspace", "create", "--name", "AI", "--scope-name", "ws_billing_bx7qw0"],
        )

        assert result.exit_code == 0
        assert "shares no token" not in flat(result.output)

    @respx.mock
    def test_requires_a_scope_name(self) -> None:
        """It is not derived from --name, so guessing one would create an invisible row."""
        result = runner.invoke(aigateway_app, ["workspace", "create", "--name", "Production"])

        assert result.exit_code == 2
        assert "--scope-name" in flat(result.output)

    @respx.mock
    def test_requires_a_name(self) -> None:
        result = runner.invoke(
            aigateway_app, ["workspace", "create", "--scope-name", "ws_production_bx"]
        )

        assert result.exit_code == 2
        assert "--name" in flat(result.output)

    @respx.mock
    def test_json_output_keeps_the_confirmation_off_stdout(self) -> None:
        stub_token()
        respx.post(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=WORKSPACE_CREATED))
        respx.get(f"{ADMIN_WORKSPACES}/{WORKSPACE_ID}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(
            aigateway_app,
            [
                "workspace",
                "create",
                "--name",
                "Production",
                "--scope-name",
                "ws_production_bx",
                "--output",
                "json",
            ],
        )

        assert json.loads(result.stdout)["id"] == WORKSPACE_ID
        assert "Workspace created" in flat(result.stderr)


class TestWorkspaceUpdate:
    @respx.mock
    def test_patches_only_the_supplied_fields_on_the_admin_plane(self) -> None:
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        updated = respx.put(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json={})
        )
        respx.get(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(
            aigateway_app,
            ["workspace", "update", SLUG, "--description", "Production workloads, us-east"],
        )

        assert result.exit_code == 0
        assert sent_body(updated) == {"description": "Production workloads, us-east"}

    @respx.mock
    def test_every_patchable_field_reaches_the_put_body(self) -> None:
        """`--users` is absent here on purpose (the API takes no user patch); everything
        else the flag list advertises has to land in the request."""
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        updated = respx.put(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json={})
        )
        respx.get(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(
            aigateway_app,
            [
                "workspace",
                "update",
                SLUG,
                "--name",
                "Renamed",
                "--description",
                "Production workloads, us-east",
                "--icon",
                "rocket",
                "--defaults",
                '{"cache":true}',
                "--metadata",
                '{"env":"production"}',
                "--usage-limits",
                '[{"type":"cost","credit_limit":5000}]',
                "--rate-limits",
                '[{"type":"requests","unit":"rpm","value":100}]',
            ],
        )

        assert result.exit_code == 0
        assert sent_body(updated) == {
            "name": "Renamed",
            "description": "Production workloads, us-east",
            "icon": "rocket",
            "defaults": {"cache": True, "metadata": {"env": "production"}},
            "usage_limits": [{"type": "cost", "credit_limit": 5000}],
            "rate_limits": [{"type": "requests", "unit": "rpm", "value": 100}],
        }

    @respx.mock
    def test_a_display_name_is_resolved_to_a_slug_before_the_write(self) -> None:
        """Addressed by name the API answers a misleading 400 AB01, so it is resolved first."""
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        updated = respx.put(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json={})
        )
        respx.get(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(aigateway_app, ["workspace", "update", "Main", "--icon", "rocket"])

        assert result.exit_code == 0
        assert updated.call_count == 1

    @respx.mock
    def test_an_ambiguous_name_is_refused_rather_than_guessed(self) -> None:
        stub_token()
        twin = {**WORKSPACE_ROW, "id": "other", "slug": "ws-main-b-999999"}
        respx.get(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page(WORKSPACE_ROW, twin))
        )
        updated = respx.put(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json={})
        )

        result = runner.invoke(aigateway_app, ["workspace", "update", "Main", "--icon", "rocket"])

        assert result.exit_code == 2
        assert "ambiguous" in flat(result.output)
        assert updated.call_count == 0

    @respx.mock
    def test_an_empty_patch_is_refused_before_any_request(self) -> None:
        stub_token()
        route = respx.get(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page(WORKSPACE_ROW))
        )

        result = runner.invoke(aigateway_app, ["workspace", "update", SLUG])

        assert result.exit_code == 2
        assert "Specify at least one of" in flat(result.output)
        assert route.call_count == 0

    @respx.mock
    def test_usage_limits_must_be_an_array_of_policies(self) -> None:
        stub_token()
        route = respx.get(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page(WORKSPACE_ROW))
        )

        result = runner.invoke(
            aigateway_app,
            ["workspace", "update", SLUG, "--usage-limits", '{"credit_limit": 100}'],
        )

        assert result.exit_code == 2
        assert "--usage-limits must be a JSON array" in flat(result.output)
        assert route.call_count == 0

    @respx.mock
    def test_rejects_a_tabular_format(self) -> None:
        stub_token()
        route = respx.get(ADMIN_WORKSPACES).mock(
            return_value=httpx.Response(200, json=page(WORKSPACE_ROW))
        )

        result = runner.invoke(
            aigateway_app, ["workspace", "update", SLUG, "--icon", "rocket", "--output", "table"]
        )

        assert result.exit_code == 2
        assert route.call_count == 0

    @respx.mock
    def test_re_reads_the_record_because_the_write_answers_an_empty_object(self) -> None:
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        respx.put(f"{ADMIN_WORKSPACES}/{SLUG}").mock(return_value=httpx.Response(200, json={}))
        refetch = respx.get(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(200, json=WORKSPACE_DETAIL)
        )

        result = runner.invoke(aigateway_app, ["workspace", "update", SLUG, "--name", "Renamed"])

        assert refetch.call_count == 1
        assert "Primary workspace" in flat(result.stdout)

    @respx.mock
    def test_a_rejected_patch_exits_two(self) -> None:
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        respx.put(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(400, json={"data": {"errorCode": "AB01"}})
        )

        result = runner.invoke(aigateway_app, ["workspace", "update", SLUG, "--icon", "rocket"])

        assert result.exit_code == 2


class TestWorkspaceDelete:
    @respx.mock
    def test_force_archives_on_the_admin_plane(self) -> None:
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        deleted = respx.delete(f"{ADMIN_WORKSPACES}/{SLUG}").mock(return_value=httpx.Response(204))

        result = runner.invoke(aigateway_app, ["workspace", "delete", SLUG, "--force"])

        assert result.exit_code == 0
        assert deleted.call_count == 1
        assert "Workspace archived" in flat(result.stdout)

    @respx.mock
    def test_refuses_without_force_when_there_is_nobody_to_ask(self) -> None:
        stub_token()
        deleted = respx.delete(f"{ADMIN_WORKSPACES}/{SLUG}").mock(return_value=httpx.Response(204))

        result = runner.invoke(aigateway_app, ["workspace", "delete", SLUG])

        assert result.exit_code == 2
        assert deleted.call_count == 0

    @respx.mock
    def test_says_the_row_survives_as_archived(self) -> None:
        """A `get` on it now 404s, which reads as a failed delete unless this is said."""
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        respx.delete(f"{ADMIN_WORKSPACES}/{SLUG}").mock(return_value=httpx.Response(204))

        result = runner.invoke(aigateway_app, ["workspace", "delete", SLUG, "--force"])

        assert "soft delete" in flat(result.stderr)

    @respx.mock
    def test_a_display_name_is_resolved_before_the_delete(self) -> None:
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        deleted = respx.delete(f"{ADMIN_WORKSPACES}/{SLUG}").mock(return_value=httpx.Response(204))

        result = runner.invoke(aigateway_app, ["workspace", "delete", "Main", "--force"])

        assert result.exit_code == 0
        assert deleted.call_count == 1

    @respx.mock
    def test_a_rejected_archive_exits_two(self) -> None:
        stub_token()
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        respx.delete(f"{ADMIN_WORKSPACES}/{SLUG}").mock(
            return_value=httpx.Response(404, json={"message": "already archived"})
        )

        result = runner.invoke(aigateway_app, ["workspace", "delete", SLUG, "--force"])

        assert result.exit_code == 2
        assert "already archived" in flat(result.output)


class TestTelemetryCost:
    @respx.mock
    def test_queries_the_cost_chart_for_the_requested_window(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        route = respx.get(COST_URL).mock(return_value=httpx.Response(200, json=COST_CHART))

        result = runner.invoke(
            aigateway_app, ["telemetry", "cost", "--workspace", SLUG, "--days", "30"]
        )

        assert result.exit_code == 0
        params = query(route)
        assert params["organisationId"] == TSG_ID
        assert params["workspaceSlug"] == SLUG
        window = datetime.fromisoformat(params["timeOfGenerationMax"]) - datetime.fromisoformat(
            params["timeOfGenerationMin"]
        )
        assert window.days == 30

    @respx.mock
    def test_defaults_to_a_seven_day_window(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        route = respx.get(COST_URL).mock(return_value=httpx.Response(200, json=COST_CHART))

        runner.invoke(aigateway_app, ["telemetry", "cost", "--workspace", SLUG])

        params = query(route)
        window = datetime.fromisoformat(params["timeOfGenerationMax"]) - datetime.fromisoformat(
            params["timeOfGenerationMin"]
        )
        assert window.days == 7

    @respx.mock
    def test_falls_back_to_the_admin_plane_to_resolve_a_name(self) -> None:
        """A missing data-plane grant must not stop a name being turned into a slug."""
        stub_token()
        respx.get(DATA_WORKSPACES).mock(
            return_value=httpx.Response(
                403, json={"data": {"message": "Forbidden", "errorCode": "AB03"}}
            )
        )
        respx.get(ADMIN_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        route = respx.get(COST_URL).mock(return_value=httpx.Response(200, json=COST_CHART))

        result = runner.invoke(
            aigateway_app, ["telemetry", "cost", "--workspace", "Main", "--output", "json"]
        )

        assert result.exit_code == 0
        assert query(route)["workspaceSlug"] == SLUG
        # The report names the slug that was actually queried, not the name that was typed.
        assert json.loads(result.stdout)["workspace_slug"] == SLUG

    @respx.mock
    def test_pretty_output_converts_cents_to_dollars(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        respx.get(COST_URL).mock(return_value=httpx.Response(200, json=COST_CHART))

        result = runner.invoke(aigateway_app, ["telemetry", "cost", "--workspace", SLUG])

        rendered = flat(result.stdout)
        assert "$4113.33" in rendered
        assert "2026-08-02 $4110.83" in rendered

    @respx.mock
    def test_structured_output_keeps_the_raw_cents(self) -> None:
        """Handing a consumer silently scaled money is worse than handing it cents."""
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        respx.get(COST_URL).mock(return_value=httpx.Response(200, json=COST_CHART))

        result = runner.invoke(
            aigateway_app, ["telemetry", "cost", "--workspace", SLUG, "--output", "json"]
        )

        parsed = json.loads(result.stdout)
        assert parsed["total_cents"] == 411333.0
        assert parsed["days"] == 7
        assert parsed["records"][0] == {"date": "2026-08-01", "cost_cents": 250.0}

    @respx.mock
    def test_warns_when_telemetry_was_truncated(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        respx.get(COST_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "success": True,
                    "data": {**COST_CHART["data"], "isQuotaExceeded": True},  # type: ignore[dict-item]
                },
            )
        )

        result = runner.invoke(aigateway_app, ["telemetry", "cost", "--workspace", SLUG])

        assert "quota exceeded" in flat(result.stdout).lower()

    @respx.mock
    def test_a_rejected_chart_query_exits_two(self) -> None:
        stub_token()
        respx.get(DATA_WORKSPACES).mock(return_value=httpx.Response(200, json=page(WORKSPACE_ROW)))
        respx.get(COST_URL).mock(
            return_value=httpx.Response(400, json={"message": "invalid window"})
        )

        result = runner.invoke(aigateway_app, ["telemetry", "cost", "--workspace", SLUG])

        assert result.exit_code == 2
        assert "invalid window" in flat(result.output)

    @respx.mock
    def test_rejects_a_window_of_zero_days(self) -> None:
        stub_token()
        route = respx.get(COST_URL).mock(return_value=httpx.Response(200, json=COST_CHART))

        result = runner.invoke(
            aigateway_app, ["telemetry", "cost", "--workspace", SLUG, "--days", "0"]
        )

        assert result.exit_code == 2
        assert route.call_count == 0

    @respx.mock
    def test_rejects_a_negative_window(self) -> None:
        stub_token()
        route = respx.get(COST_URL).mock(return_value=httpx.Response(200, json=COST_CHART))

        result = runner.invoke(
            aigateway_app, ["telemetry", "cost", "--workspace", SLUG, "--days", "-3"]
        )

        assert result.exit_code == 2
        assert route.call_count == 0

    @respx.mock
    def test_rejects_a_non_numeric_window(self) -> None:
        result = runner.invoke(
            aigateway_app, ["telemetry", "cost", "--workspace", SLUG, "--days", "lots"]
        )

        assert result.exit_code == 2
        assert "--days" in flat(result.output)

    @respx.mock
    def test_requires_a_workspace(self) -> None:
        """Every telemetry endpoint is per-workspace; there is no tenant-wide cost read."""
        result = runner.invoke(aigateway_app, ["telemetry", "cost"])

        assert result.exit_code == 2
        assert "--workspace" in flat(result.output)

    @respx.mock
    def test_rejects_a_tabular_format(self) -> None:
        stub_token()
        route = respx.get(COST_URL).mock(return_value=httpx.Response(200, json=COST_CHART))

        result = runner.invoke(
            aigateway_app, ["telemetry", "cost", "--workspace", SLUG, "--output", "table"]
        )

        assert result.exit_code == 2
        assert route.call_count == 0
