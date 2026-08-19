"""``airs runtime customer-apps`` and ``scan-logs`` behaviour: requests sent, exits returned.

The dashboard commands are asserted against the query string rather than the rendered
output, because the two per-application endpoints need an ``appid``/``appname`` pair that
only the overview listing can supply -- a port that resolves the pair wrongly still prints
a plausible-looking report for the wrong application.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner

from prisma_airs.constants import DEFAULT_MGMT_ENDPOINT, DEFAULT_TOKEN_ENDPOINT
from prisma_airs_cli.commands.customerapps import customerapps_app, scanlogs_app

runner = CliRunner()

TSG_ID = "1234567890"
APP_ID = "550e8400-e29b-41d4-a716-446655440000"
OTHER_APP_ID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

CUSTOMER_APP_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/customerapp"
CUSTOMER_APPS_TSG_URL = f"{CUSTOMER_APP_URL}/tsg/{TSG_ID}"
SCAN_LOGS_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/scanlogs"
DASHBOARD_OVERVIEW_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/dashboard/v2/apps/applicationsoverview"
DASHBOARD_APP_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/dashboard/v2/apps/application"
DASHBOARD_BREAKDOWN_URL = (
    f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown"
)

#: A registration as the list endpoint returns it. ``description`` is not in the declared
#: schema but a live tenant sends it, so it exercises the extra-field path.
LIST_APP = {
    "customer_appId": APP_ID,
    "tsg_id": TSG_ID,
    "app_name": "chatbot",
    "cloud_provider": "aws",
    "environment": "prod",
    "description": "Support chatbot",
    "api_keys_dp_info": [{"api_key_name": "k1", "dp_name": "prod-dp", "auth_code": "ac"}],
}

#: The same registration as the read-one and update endpoints return it.
DETAIL_APP = {
    "customer_appId": APP_ID,
    "tsg_id": TSG_ID,
    "app_name": "chatbot",
    "cloud_provider": "aws",
    "environment": "prod",
    "description": "Support chatbot",
}

OVERVIEW_ITEM = {"id": APP_ID, "name": "chatbot", "cloud": "aws", "source": "api"}
OTHER_OVERVIEW_ITEM = {"id": OTHER_APP_ID, "name": "summarizer"}

APPLICATION = {
    "id": APP_ID,
    "name": "chatbot",
    "cloud": "aws",
    "source": "api",
    "created_at": "2026-01-04",
    "profiles": ["prod-guard"],
    "token_stats": {
        "average_daily_tokens": 12,
        "average_daily_tokens_scale": "K",
        "monthly_total_tokens": 4,
        "monthly_total_tokens_scale": "M",
    },
    "session_stats": {"total": 40, "violating": 3},
}

BREAKDOWN = {
    "detection_type_violation_breakdown": [
        {
            "detection_type": "pi",
            "violation_breakdown": {"critical": 1, "high": 2, "medium": 0, "low": 0, "total": 3},
        },
        {
            "detection_type": "dlp",
            "violation_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        },
    ],
    "total_violating": 3,
}

SCAN_LOG_ENTRY = {
    "csp_id": "csp",
    "tsg_id": TSG_ID,
    "scan_id": "scan-1",
    "scan_sub_req_id": 1,
    "api_key_name": "k1",
    "app_name": "chatbot",
    "tokens": 120,
    "text_records": 1,
    "received_ts": "2026-08-01T10:00:00Z",
    "action": "block",
    "verdict": "malicious",
    "profile_name": "prod-guard",
}


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests off the developer's real credentials, endpoints, and config file."""
    monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "cid")
    monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "secret")
    monkeypatch.setenv("PANW_MGMT_TSG_ID", TSG_ID)
    monkeypatch.setenv("PRISMA_AIRS_CONFIG", str(tmp_path / "config.json"))
    for name in ("PANW_MGMT_ENDPOINT", "PANW_MGMT_TOKEN_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def api() -> Iterator[respx.MockRouter]:
    """Intercept every request, with the management OAuth2 exchange already stubbed.

    Autouse so that a command which should have refused before reaching the network fails
    loudly here instead of quietly calling the real API.
    """
    with respx.mock(assert_all_called=False) as router:
        router.post(DEFAULT_TOKEN_ENDPOINT, name="token").mock(
            return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 899})
        )
        yield router


def request_of(route: respx.Route, index: int = -1) -> httpx.Request:
    """One request a route received, the last by default."""
    request: httpx.Request = route.calls[index].request
    return request


def query_of(route: respx.Route, index: int = -1) -> dict[str, str]:
    """The query string of one request a route received."""
    return dict(request_of(route, index).url.params)


def body_of(route: respx.Route, index: int = -1) -> Any:
    """The JSON body of one request a route received."""
    return json.loads(request_of(route, index).content)


def write_config(tmp_path: Path, payload: Any) -> str:
    """Write an update body and return its path."""
    path = tmp_path / "app.json"
    path.write_text(json.dumps(payload) if not isinstance(payload, str) else payload)
    return str(path)


# ---------------------------------------------------------------------------
# customer-apps list
# ---------------------------------------------------------------------------


class TestList:
    def test_lists_the_tenants_registrations(self, api: respx.MockRouter) -> None:
        route = api.get(CUSTOMER_APPS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"customer_apps": [LIST_APP]})
        )

        result = runner.invoke(customerapps_app, ["list"])

        assert result.exit_code == 0
        assert request_of(route).method == "GET"
        assert query_of(route) == {"offset": "0", "limit": "100"}
        assert "chatbot" in result.output
        assert APP_ID in result.output

    def test_limit_reaches_the_query_string(self, api: respx.MockRouter) -> None:
        route = api.get(CUSTOMER_APPS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"customer_apps": [LIST_APP]})
        )

        result = runner.invoke(customerapps_app, ["list", "--limit", "25"])

        assert result.exit_code == 0
        assert query_of(route)["limit"] == "25"

    def test_json_output_carries_the_description_the_schema_does_not_declare(
        self, api: respx.MockRouter
    ) -> None:
        """A live tenant sends `description`; dropping it would leave the column blank."""
        api.get(CUSTOMER_APPS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"customer_apps": [LIST_APP]})
        )

        result = runner.invoke(customerapps_app, ["list", "--output", "json"])

        assert json.loads(result.output) == [
            {"id": APP_ID, "name": "chatbot", "description": "Support chatbot"}
        ]

    def test_reports_an_empty_tenant_without_a_bare_header(self, api: respx.MockRouter) -> None:
        api.get(CUSTOMER_APPS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"customer_apps": []})
        )

        result = runner.invoke(customerapps_app, ["list"])

        assert result.exit_code == 0
        assert "No customer apps found" in result.output

    def test_reports_an_api_failure_as_an_error_exit(self, api: respx.MockRouter) -> None:
        api.get(CUSTOMER_APPS_TSG_URL).mock(return_value=httpx.Response(403, json={}))

        result = runner.invoke(customerapps_app, ["list"])

        assert result.exit_code == 2

    def test_ls_is_the_same_command_under_the_references_alias(self, api: respx.MockRouter) -> None:
        """The reference aliases every `list` to `ls`; the alias must send the same request."""
        route = api.get(CUSTOMER_APPS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"customer_apps": [LIST_APP]})
        )

        result = runner.invoke(customerapps_app, ["ls", "--limit", "25"])

        assert result.exit_code == 0
        assert query_of(route) == {"offset": "0", "limit": "25"}

    def test_ls_is_hidden_so_help_lists_each_command_once(self) -> None:
        result = runner.invoke(customerapps_app, ["--help"])

        assert "list" in result.output
        assert " ls " not in result.output


# ---------------------------------------------------------------------------
# customer-apps get
# ---------------------------------------------------------------------------


class TestGet:
    def test_reads_one_app_by_name_through_the_query_string(self, api: respx.MockRouter) -> None:
        """The name is a query parameter: this endpoint has no by-name path form."""
        route = api.get(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json=DETAIL_APP))

        result = runner.invoke(customerapps_app, ["get", "chatbot"])

        assert result.exit_code == 0
        assert query_of(route) == {"app_name": "chatbot"}
        assert "Support chatbot" in result.output

    def test_shows_the_underlying_record(self, api: respx.MockRouter) -> None:
        api.get(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json=DETAIL_APP))

        result = runner.invoke(customerapps_app, ["get", "chatbot"])

        assert '"cloud_provider": "aws"' in result.output

    def test_requires_a_name(self) -> None:
        result = runner.invoke(customerapps_app, ["get"])

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# customer-apps update
# ---------------------------------------------------------------------------


class TestUpdate:
    def test_sends_the_file_as_the_body_and_the_id_as_a_query_parameter(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.put(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json=DETAIL_APP))
        config = write_config(
            tmp_path,
            {
                "customer_appId": APP_ID,
                "tsg_id": TSG_ID,
                "app_name": "chatbot",
                "cloud_provider": "gcp",
                "environment": "prod",
            },
        )

        result = runner.invoke(customerapps_app, ["update", APP_ID, "--config", config])

        assert result.exit_code == 0
        assert query_of(route) == {"customer_app_id": APP_ID}
        assert body_of(route) == {
            "customer_appId": APP_ID,
            "tsg_id": TSG_ID,
            "app_name": "chatbot",
            "cloud_provider": "gcp",
            "environment": "prod",
        }
        assert "Customer app updated: chatbot" in result.output

    def test_rejects_a_file_that_is_not_json(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.put(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json=DETAIL_APP))
        config = write_config(tmp_path, "{not json")

        result = runner.invoke(customerapps_app, ["update", APP_ID, "--config", config])

        assert result.exit_code == 2
        assert not route.called

    def test_rejects_a_file_that_is_not_an_object(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.put(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json=DETAIL_APP))
        config = write_config(tmp_path, [{"app_name": "chatbot"}])

        result = runner.invoke(customerapps_app, ["update", APP_ID, "--config", config])

        assert result.exit_code == 2
        assert not route.called

    def test_rejects_a_partial_record_naming_the_missing_fields(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """The update replaces the whole record, so a patch-shaped file would erase fields."""
        route = api.put(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json=DETAIL_APP))
        config = write_config(tmp_path, {"app_name": "chatbot"})

        result = runner.invoke(customerapps_app, ["update", APP_ID, "--config", config])

        assert result.exit_code == 2
        assert not route.called
        assert "cloud_provider" in result.output

    def test_rejects_a_config_path_that_does_not_exist(self, tmp_path: Path) -> None:
        result = runner.invoke(
            customerapps_app, ["update", APP_ID, "--config", str(tmp_path / "absent.json")]
        )

        assert result.exit_code == 2

    def test_requires_the_config_flag(self, tmp_path: Path) -> None:
        result = runner.invoke(customerapps_app, ["update", APP_ID])

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# customer-apps delete
# ---------------------------------------------------------------------------


class TestDelete:
    def test_deletes_the_app_and_its_keys(self, api: respx.MockRouter) -> None:
        route = api.delete(CUSTOMER_APP_URL).mock(
            return_value=httpx.Response(200, json="successfully deleted chatbot")
        )

        result = runner.invoke(
            customerapps_app,
            ["delete", "chatbot", "--updated-by", "ops@example.com", "--force"],
        )

        assert result.exit_code == 0
        assert query_of(route) == {"app_name": "chatbot", "updated_by": "ops@example.com"}
        assert 'Customer app "chatbot" deleted.' in result.output

    def test_refuses_without_force_when_nobody_can_be_asked(self, api: respx.MockRouter) -> None:
        """No TTY and no --force means the intent was never stated; deleting anyway is worse."""
        route = api.delete(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json="gone"))

        result = runner.invoke(
            customerapps_app, ["delete", "chatbot", "--updated-by", "ops@example.com"]
        )

        assert result.exit_code == 2
        assert not route.called

    def test_requires_updated_by(self, api: respx.MockRouter) -> None:
        route = api.delete(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json="gone"))

        result = runner.invoke(customerapps_app, ["delete", "chatbot", "--force"])

        assert result.exit_code == 2
        assert not route.called

    def test_rm_is_the_same_command_under_the_references_alias(self, api: respx.MockRouter) -> None:
        """The reference aliases every `delete` to `rm`, confirmation rule included."""
        route = api.delete(CUSTOMER_APP_URL).mock(
            return_value=httpx.Response(200, json="successfully deleted chatbot")
        )

        result = runner.invoke(
            customerapps_app,
            ["rm", "chatbot", "--updated-by", "ops@example.com", "--force"],
        )

        assert result.exit_code == 0
        assert query_of(route) == {"app_name": "chatbot", "updated_by": "ops@example.com"}

    def test_rm_still_refuses_without_force(self, api: respx.MockRouter) -> None:
        route = api.delete(CUSTOMER_APP_URL).mock(return_value=httpx.Response(200, json="gone"))

        result = runner.invoke(
            customerapps_app, ["rm", "chatbot", "--updated-by", "ops@example.com"]
        )

        assert result.exit_code == 2
        assert not route.called

    def test_rm_is_hidden_so_help_lists_each_command_once(self) -> None:
        result = runner.invoke(customerapps_app, ["--help"])

        assert "delete" in result.output
        assert " rm " not in result.output


# ---------------------------------------------------------------------------
# customer-apps consumption
# ---------------------------------------------------------------------------


class TestConsumption:
    def test_resolves_the_name_to_an_id_before_reading_the_dashboard(
        self, api: respx.MockRouter
    ) -> None:
        """Both endpoints need appid AND appname, and only the overview pairs them."""
        overview = api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(200, json={"items": [OVERVIEW_ITEM, OTHER_OVERVIEW_ITEM]})
        )
        application = api.get(DASHBOARD_APP_URL).mock(
            return_value=httpx.Response(200, json=APPLICATION)
        )
        breakdown = api.get(DASHBOARD_BREAKDOWN_URL).mock(
            return_value=httpx.Response(200, json=BREAKDOWN)
        )

        result = runner.invoke(customerapps_app, ["consumption", "chatbot"])

        assert result.exit_code == 0
        assert query_of(overview) == {
            "time_interval": "30",
            "time_unit": "days",
            "limit": "100",
            "offset": "0",
        }
        expected = {
            "appid": APP_ID,
            "appname": "chatbot",
            "time_interval": "30",
            "time_unit": "days",
        }
        assert query_of(application) == expected
        assert query_of(breakdown) == expected
        assert application.call_count == 1

    def test_time_interval_reaches_both_dashboard_reads(self, api: respx.MockRouter) -> None:
        api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(200, json={"items": [OVERVIEW_ITEM]})
        )
        application = api.get(DASHBOARD_APP_URL).mock(
            return_value=httpx.Response(200, json=APPLICATION)
        )
        breakdown = api.get(DASHBOARD_BREAKDOWN_URL).mock(
            return_value=httpx.Response(200, json=BREAKDOWN)
        )

        result = runner.invoke(customerapps_app, ["consumption", "chatbot", "--time-interval", "7"])

        assert result.exit_code == 0
        assert query_of(application)["time_interval"] == "7"
        assert query_of(breakdown)["time_interval"] == "7"

    def test_rejects_a_window_the_api_does_not_accept(self, api: respx.MockRouter) -> None:
        route = api.get(DASHBOARD_OVERVIEW_URL).mock(return_value=httpx.Response(200, json={}))

        result = runner.invoke(
            customerapps_app, ["consumption", "chatbot", "--time-interval", "14"]
        )

        assert result.exit_code == 2
        assert not route.called
        assert "--time-interval must be 7, 30, or 60" in result.output

    def test_names_the_available_buckets_when_the_name_is_unknown(
        self, api: respx.MockRouter
    ) -> None:
        """The name that works is the scan payload's, so guessing costs a support ticket."""
        api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(200, json={"items": [OVERVIEW_ITEM, OTHER_OVERVIEW_ITEM]})
        )
        application = api.get(DASHBOARD_APP_URL).mock(
            return_value=httpx.Response(200, json=APPLICATION)
        )

        result = runner.invoke(customerapps_app, ["consumption", "registered-name"])

        assert result.exit_code == 2
        assert not application.called
        assert 'Dashboard application not found: "registered-name"' in result.output
        assert '"chatbot", "summarizer"' in result.output

    def test_skips_a_bucket_missing_half_its_identity_pair(self, api: respx.MockRouter) -> None:
        """An item without an id cannot be queried; sending it would 400 once per app."""
        api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(200, json={"items": [{"name": "chatbot"}]})
        )
        application = api.get(DASHBOARD_APP_URL).mock(
            return_value=httpx.Response(200, json=APPLICATION)
        )

        result = runner.invoke(customerapps_app, ["consumption", "chatbot"])

        assert result.exit_code == 2
        assert not application.called

    def test_reports_every_bucket_when_no_name_is_given(self, api: respx.MockRouter) -> None:
        api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(200, json={"items": [OVERVIEW_ITEM, OTHER_OVERVIEW_ITEM]})
        )
        application = api.get(DASHBOARD_APP_URL).mock(
            return_value=httpx.Response(200, json=APPLICATION)
        )
        api.get(DASHBOARD_BREAKDOWN_URL).mock(return_value=httpx.Response(200, json=BREAKDOWN))

        result = runner.invoke(customerapps_app, ["consumption"])

        assert result.exit_code == 0
        assert [query_of(application, i)["appname"] for i in range(2)] == ["chatbot", "summarizer"]

    def test_reports_an_empty_dashboard(self, api: respx.MockRouter) -> None:
        api.get(DASHBOARD_OVERVIEW_URL).mock(return_value=httpx.Response(200, json={"items": []}))

        result = runner.invoke(customerapps_app, ["consumption"])

        assert result.exit_code == 0
        assert "No dashboard applications found" in result.output

    def test_one_unreadable_bucket_does_not_abandon_the_rest(self, api: respx.MockRouter) -> None:
        api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(200, json={"items": [OVERVIEW_ITEM, OTHER_OVERVIEW_ITEM]})
        )
        api.get(DASHBOARD_APP_URL).mock(
            side_effect=[
                # 404, not 5xx: a retryable status would be re-sent and exhaust the stub.
                httpx.Response(404, json={"message": "no such application"}),
                httpx.Response(200, json={**APPLICATION, "name": "summarizer"}),
            ]
        )
        api.get(DASHBOARD_BREAKDOWN_URL).mock(return_value=httpx.Response(200, json=BREAKDOWN))

        result = runner.invoke(customerapps_app, ["consumption", "--output", "csv"])

        assert result.exit_code == 0
        assert "[chatbot] no such application" in result.output
        # The failing bucket contributes no rows, and the surviving one contributes all of
        # its detectors -- "summarizer appears somewhere" would also pass on a bare error.
        data_rows = [line for line in result.output.splitlines() if "," in line]
        assert [row.split(",")[0] for row in data_rows] == ["App", "summarizer", "summarizer"]

    def test_structured_output_is_one_document_covering_every_app(
        self, api: respx.MockRouter
    ) -> None:
        """Concatenating one document per app would repeat the CSV header mid-file."""
        api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(200, json={"items": [OVERVIEW_ITEM, OTHER_OVERVIEW_ITEM]})
        )
        api.get(DASHBOARD_APP_URL).mock(return_value=httpx.Response(200, json=APPLICATION))
        api.get(DASHBOARD_BREAKDOWN_URL).mock(return_value=httpx.Response(200, json=BREAKDOWN))

        result = runner.invoke(customerapps_app, ["consumption", "--output", "csv"])

        assert result.exit_code == 0
        assert result.output.count("App,AppId,MonitoringSince") == 1
        # Two apps, two detectors each: every detector gets a row, quiet ones included.
        assert len(result.output.strip().splitlines()) == 5

    def test_json_output_reports_whole_numbers_and_the_token_scale(
        self, api: respx.MockRouter
    ) -> None:
        """Counts arrive as JSON numbers; 12.0 sessions is not what the SCM panel shows."""
        api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(200, json={"items": [OVERVIEW_ITEM]})
        )
        api.get(DASHBOARD_APP_URL).mock(return_value=httpx.Response(200, json=APPLICATION))
        api.get(DASHBOARD_BREAKDOWN_URL).mock(return_value=httpx.Response(200, json=BREAKDOWN))

        result = runner.invoke(customerapps_app, ["consumption", "chatbot", "--output", "json"])

        rows = json.loads(result.output)
        assert rows[0]["daily_avg"] == "12K"
        assert rows[0]["monthly_total"] == "4M"
        assert rows[0]["sessions_total"] == 40
        assert rows[0]["detector"] == "pi"
        assert rows[0]["critical"] == 1
        assert '"sessions_total": 40,' in result.output

    def test_pretty_output_tabulates_only_the_firing_detectors(self, api: respx.MockRouter) -> None:
        api.get(DASHBOARD_OVERVIEW_URL).mock(
            return_value=httpx.Response(200, json={"items": [OVERVIEW_ITEM]})
        )
        api.get(DASHBOARD_APP_URL).mock(return_value=httpx.Response(200, json=APPLICATION))
        api.get(DASHBOARD_BREAKDOWN_URL).mock(return_value=httpx.Response(200, json=BREAKDOWN))

        result = runner.invoke(customerapps_app, ["consumption", "chatbot"])

        assert "Detectors (3 violating, 1/2 firing)" in result.output
        assert "c=1 h=2 m=0 l=0" in result.output


# ---------------------------------------------------------------------------
# scan-logs query
# ---------------------------------------------------------------------------


class TestScanLogsQuery:
    def test_queries_a_window_with_the_default_page(self, api: respx.MockRouter) -> None:
        """Mixed casing on the wire is the API's, not a typo: snake_case beside camelCase."""
        route = api.post(SCAN_LOGS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"scan_result_for_dashboard": {"scan_result_entries": [SCAN_LOG_ENTRY]}},
            )
        )

        result = runner.invoke(scanlogs_app, ["query", "--interval", "24", "--unit", "hours"])

        assert result.exit_code == 0
        assert request_of(route).method == "POST"
        assert query_of(route) == {
            "time_interval": "24",
            "time_unit": "hours",
            "pageNumber": "1",
            "pageSize": "50",
            "filter": "all",
        }
        assert "scan-1" in result.output

    def test_offset_rounds_down_to_the_page_that_contains_it(self, api: respx.MockRouter) -> None:
        route = api.post(SCAN_LOGS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"scan_result_for_dashboard": {"scan_result_entries": [SCAN_LOG_ENTRY]}},
            )
        )

        result = runner.invoke(
            scanlogs_app,
            ["query", "--interval", "24", "--unit", "hours", "--limit", "25", "--offset", "60"],
        )

        assert result.exit_code == 0
        assert query_of(route)["pageNumber"] == "3"
        assert query_of(route)["pageSize"] == "25"

    def test_filter_reaches_the_query_string_under_its_wire_name(
        self, api: respx.MockRouter
    ) -> None:
        """The parameter is renamed off the builtin; the flag and the wire key are not."""
        route = api.post(SCAN_LOGS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"scan_result_for_dashboard": {"scan_result_entries": [SCAN_LOG_ENTRY]}},
            )
        )

        result = runner.invoke(
            scanlogs_app,
            ["query", "--interval", "24", "--unit", "hours", "--filter", "threat"],
        )

        assert result.exit_code == 0
        assert query_of(route)["filter"] == "threat"

    def test_rejects_a_filter_outside_the_documented_set(self, api: respx.MockRouter) -> None:
        route = api.post(SCAN_LOGS_URL).mock(return_value=httpx.Response(200, json={}))

        result = runner.invoke(
            scanlogs_app,
            ["query", "--interval", "24", "--unit", "hours", "--filter", "malicious"],
        )

        assert result.exit_code == 2
        assert not route.called

    def test_rejects_a_negative_limit(self, api: respx.MockRouter) -> None:
        """A negative page size is a mistake upstream; clamping it hides where."""
        route = api.post(SCAN_LOGS_URL).mock(return_value=httpx.Response(200, json={}))

        result = runner.invoke(
            scanlogs_app,
            ["query", "--interval", "24", "--unit", "hours", "--limit", "-5"],
        )

        assert result.exit_code == 2
        assert not route.called

    def test_rejects_a_negative_offset(self, api: respx.MockRouter) -> None:
        route = api.post(SCAN_LOGS_URL).mock(return_value=httpx.Response(200, json={}))

        result = runner.invoke(
            scanlogs_app,
            ["query", "--interval", "24", "--unit", "hours", "--offset", "-10"],
        )

        assert result.exit_code == 2
        assert not route.called

    def test_requires_the_interval_and_unit(self, api: respx.MockRouter) -> None:
        route = api.post(SCAN_LOGS_URL).mock(return_value=httpx.Response(200, json={}))

        assert runner.invoke(scanlogs_app, ["query", "--unit", "hours"]).exit_code == 2
        assert runner.invoke(scanlogs_app, ["query", "--interval", "24"]).exit_code == 2
        assert not route.called

    def test_reports_an_empty_window(self, api: respx.MockRouter) -> None:
        """A window with no traffic answers with an empty body, not an error."""
        api.post(SCAN_LOGS_URL).mock(return_value=httpx.Response(200, json={}))

        result = runner.invoke(scanlogs_app, ["query", "--interval", "1", "--unit", "hours"])

        assert result.exit_code == 0
        assert "No scan logs found" in result.output

    def test_prints_the_continuation_token(self, api: respx.MockRouter) -> None:
        """The reported page number is a display value; the token is the way to page."""
        api.post(SCAN_LOGS_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "scan_result_for_dashboard": {"scan_result_entries": [SCAN_LOG_ENTRY]},
                    "page_token": "next-page",
                },
            )
        )

        result = runner.invoke(scanlogs_app, ["query", "--interval", "24", "--unit", "hours"])

        assert "Page token: next-page" in result.output

    def test_json_output_carries_the_five_reported_columns(self, api: respx.MockRouter) -> None:
        api.post(SCAN_LOGS_URL).mock(
            return_value=httpx.Response(
                200,
                json={"scan_result_for_dashboard": {"scan_result_entries": [SCAN_LOG_ENTRY]}},
            )
        )

        result = runner.invoke(
            scanlogs_app, ["query", "--interval", "24", "--unit", "hours", "--output", "json"]
        )

        assert json.loads(result.output) == [
            {
                "scan_id": "scan-1",
                "timestamp": "2026-08-01T10:00:00Z",
                "action": "block",
                "profile": "prod-guard",
                "app": "chatbot",
            }
        ]

    def test_falls_back_to_the_verdict_when_no_action_was_taken(
        self, api: respx.MockRouter
    ) -> None:
        """A monitored-only transaction reports a verdict and no action."""
        entry = {key: value for key, value in SCAN_LOG_ENTRY.items() if key != "action"}
        api.post(SCAN_LOGS_URL).mock(
            return_value=httpx.Response(
                200, json={"scan_result_for_dashboard": {"scan_result_entries": [entry]}}
            )
        )

        result = runner.invoke(
            scanlogs_app, ["query", "--interval", "24", "--unit", "hours", "--output", "json"]
        )

        assert json.loads(result.output)[0]["action"] == "malicious"
