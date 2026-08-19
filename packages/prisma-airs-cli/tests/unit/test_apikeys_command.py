"""``airs runtime api-keys`` and ``runtime deployment-profiles``: requests and exits.

Every command is asserted against the request it produced -- URL, method, query, body --
rather than against the response it was handed, because a port that drops ``--updated-by``
or sends the rotation unit under the wrong key still prints a perfectly happy result.

The commands are driven through a stand-in parent group rather than invoked on their own
apps. ``deployment-profiles`` has a single command, and Typer collapses a one-command app
into that command when it is the app being run -- so ``["list", ...]`` would parse as a
stray argument. Mounting both groups the way ``app.py`` does keeps the argv in these tests
identical to the argv a user types, and asserts the group names while it is there.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
import typer
from typer.testing import CliRunner

from prisma_airs.constants import DEFAULT_MGMT_ENDPOINT, DEFAULT_TOKEN_ENDPOINT
from prisma_airs_cli.commands import apikeys as apikeys_module
from prisma_airs_cli.commands.apikeys import apikeys_app, deployment_profiles_app
from prisma_airs_cli.confirm import confirm_or_abort

runner = CliRunner()

runtime = typer.Typer(name="runtime", no_args_is_help=True)
runtime.add_typer(apikeys_app)
runtime.add_typer(deployment_profiles_app)

TSG_ID = "1234567890"
API_KEY_ID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

API_KEY_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/apikey"
API_KEYS_TSG_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/apikeys/tsg/{TSG_ID}"
REGENERATE_URL = f"{API_KEY_URL}/regenerate/{API_KEY_ID}"
# The name carries a space so the percent-encoding of the path segment is asserted, not
# assumed -- an unencoded space addresses a different route.
KEY_NAME = "prod scanner"
DELETE_URL = f"{API_KEY_URL}/delete/prod%20scanner"
DEPLOYMENT_PROFILES_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/deploymentprofiles"

API_KEY = {
    "api_key_id": API_KEY_ID,
    "api_key_name": KEY_NAME,
    "api_key_last8": "ABCD1234",
    "auth_code": "AUTH-CODE-1",
    "expiration": "2027-01-01T00:00:00Z",
    "creation_ts": "2026-01-01T00:00:00Z",
    "revoked": False,
}
#: Only create and regenerate carry the secret itself.
SECRET_KEY = {**API_KEY, "api_key": "sk-live-0123456789ABCD1234"}

CREATE_CONFIG: dict[str, Any] = {
    "api_key_name": KEY_NAME,
    "auth_code": "AUTH-CODE-1",
    "cust_app": "checkout-bot",
    "created_by": "ops@example.com",
    "revoked": False,
    "rotation_time_interval": 90,
    "rotation_time_unit": "days",
}

DEPLOYMENT_PROFILE = {
    "dp_name": "prod-dp",
    "auth_code": "AUTH-CODE-1",
    "status": "active",
    "tsg_id": TSG_ID,
}
UNACTIVATED_PROFILE = {
    "dp_name": "staging-dp",
    "auth_code": "AUTH-CODE-2",
    "status": "pending",
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


def body_of(route: respx.Route) -> Any:
    """The last JSON body a route received."""
    return json.loads(route.calls.last.request.content)


def params_of(route: respx.Route) -> httpx.QueryParams:
    """The last query string a route received."""
    return route.calls.last.request.url.params


def write_config(tmp_path: Path, text: str) -> str:
    """Write an API key configuration file and return its path."""
    path = tmp_path / "apikey.json"
    path.write_text(text)
    return str(path)


@pytest.fixture
def at_a_terminal(monkeypatch: pytest.MonkeyPatch) -> Callable[[bool], None]:
    """Answer the delete confirmation as though a terminal were attached.

    ``confirm_or_abort`` refuses outright when stdin is not a TTY, which is every run
    under ``CliRunner`` -- so the prompt and the TTY check are supplied through the seams
    the helper exposes for exactly this, leaving its real accept/decline logic in play.
    """

    def attach(reply: bool) -> None:
        def patched(message: str, *, force: bool, action: str = "proceed") -> None:
            confirm_or_abort(
                message, force=force, action=action, prompt=lambda _: reply, is_tty=True
            )

        monkeypatch.setattr(apikeys_module, "confirm_or_abort", patched)

    return attach


# ---------------------------------------------------------------------------
# api-keys list
# ---------------------------------------------------------------------------


class TestList:
    def test_asks_for_a_hundred_keys_by_default(self, api: respx.MockRouter) -> None:
        route = api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": [API_KEY]})
        )

        result = runner.invoke(runtime, ["api-keys", "list"])

        assert result.exit_code == 0
        assert params_of(route)["limit"] == "100"

    def test_asks_for_the_first_page(self, api: respx.MockRouter) -> None:
        """The reference SDK sends ``offset`` alongside ``limit``, defaulted to 0."""
        route = api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": [API_KEY]})
        )

        result = runner.invoke(runtime, ["api-keys", "list"])

        assert result.exit_code == 0
        assert params_of(route)["offset"] == "0"

    def test_sends_the_requested_page_size(self, api: respx.MockRouter) -> None:
        route = api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": [API_KEY]})
        )

        result = runner.invoke(runtime, ["api-keys", "list", "--limit", "25"])

        assert result.exit_code == 0
        assert params_of(route)["limit"] == "25"

    def test_pretty_output_shows_the_banner_and_the_last_eight(self, api: respx.MockRouter) -> None:
        api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": [API_KEY]})
        )

        result = runner.invoke(runtime, ["api-keys", "list"])

        assert "Runtime Configuration" in result.output
        assert API_KEY_ID in result.output
        assert "key: …ABCD1234" in result.output

    def test_json_output_carries_the_reference_keys(self, api: respx.MockRouter) -> None:
        """The banner would land in the middle of the document a pipeline is parsing."""
        api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": [API_KEY]})
        )

        result = runner.invoke(runtime, ["api-keys", "list", "--output", "json"])

        assert result.exit_code == 0
        assert json.loads(result.output) == [
            {
                "id": API_KEY_ID,
                "name": KEY_NAME,
                "last8": "ABCD1234",
                "createdAt": "2026-01-01T00:00:00Z",
                "expiresAt": "2027-01-01T00:00:00Z",
            }
        ]

    def test_csv_output_uses_the_reference_headings(self, api: respx.MockRouter) -> None:
        api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": [API_KEY]})
        )

        result = runner.invoke(runtime, ["api-keys", "list", "--output", "csv"])

        assert result.output.splitlines()[0] == "ID,Name,Key (last 8),Created,Expires"

    def test_reports_an_empty_page_as_a_result_not_a_failure(self, api: respx.MockRouter) -> None:
        api.get(API_KEYS_TSG_URL).mock(return_value=httpx.Response(200, json={"api_keys": []}))

        result = runner.invoke(runtime, ["api-keys", "list"])

        assert result.exit_code == 0
        assert "No API keys found" in result.output

    @pytest.mark.parametrize("fmt", ["pretty", "table", "csv", "json", "yaml"])
    def test_accepts_every_documented_output_format(self, api: respx.MockRouter, fmt: str) -> None:
        """The five formats the reference advertises are the five this accepts."""
        api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": [API_KEY]})
        )

        result = runner.invoke(runtime, ["api-keys", "list", "--output", fmt])

        assert result.exit_code == 0

    def test_rejects_an_unknown_output_format(self, api: respx.MockRouter) -> None:
        """A deviation: the reference leaves this unvalidated and renders it as a table."""
        route = api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": [API_KEY]})
        )

        result = runner.invoke(runtime, ["api-keys", "list", "--output", "bogus"])

        assert result.exit_code == 2
        assert not route.called

    def test_rejects_a_limit_below_one(self, api: respx.MockRouter) -> None:
        route = api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"api_keys": []})
        )

        result = runner.invoke(runtime, ["api-keys", "list", "--limit", "0"])

        assert result.exit_code == 2
        assert not route.called
        assert "--limit must be a positive integer" in result.output

    def test_reports_what_the_service_refused(self, api: respx.MockRouter) -> None:
        api.get(API_KEYS_TSG_URL).mock(
            return_value=httpx.Response(403, json={"error": {"message": "forbidden"}})
        )

        result = runner.invoke(runtime, ["api-keys", "list"])

        assert result.exit_code == 2
        assert "HTTP 403" in result.output


# ---------------------------------------------------------------------------
# api-keys create
# ---------------------------------------------------------------------------


class TestCreate:
    def test_posts_the_configuration_file(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime,
            ["api-keys", "create", "--config", write_config(tmp_path, json.dumps(CREATE_CONFIG))],
        )

        assert result.exit_code == 0
        assert body_of(route) == CREATE_CONFIG

    def test_shows_the_secret_that_only_this_response_carries(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime,
            ["api-keys", "create", "--config", write_config(tmp_path, json.dumps(CREATE_CONFIG))],
        )

        assert f"API key created: {API_KEY_ID}" in result.output
        assert "sk-live-0123456789ABCD1234" in result.output

    def test_rejects_a_file_that_is_not_json(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime, ["api-keys", "create", "--config", write_config(tmp_path, "{nope")]
        )

        assert result.exit_code == 2
        assert not route.called
        # Naming the flag is what makes the typo findable; the parser's own complaint is
        # what distinguishes this from the file being absent or the schema being wrong.
        assert "--config" in result.output
        assert "double quotes" in result.output

    def test_names_the_field_a_configuration_is_missing(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """A local check beats the service's 400, which does not say which field it meant."""
        incomplete = {key: value for key, value in CREATE_CONFIG.items() if key != "auth_code"}
        route = api.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime,
            ["api-keys", "create", "--config", write_config(tmp_path, json.dumps(incomplete))],
        )

        assert result.exit_code == 2
        assert not route.called
        assert "auth_code" in result.output

    def test_rejects_a_configuration_path_that_does_not_exist(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime, ["api-keys", "create", "--config", str(tmp_path / "absent.json")]
        )

        assert result.exit_code == 2
        assert not route.called
        assert "does not exist" in result.output

    def test_requires_the_configuration_flag(self, api: respx.MockRouter) -> None:
        route = api.post(API_KEY_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(runtime, ["api-keys", "create"])

        assert result.exit_code == 2
        assert not route.called
        assert "Missing option '--config'." in result.output


# ---------------------------------------------------------------------------
# api-keys regenerate
# ---------------------------------------------------------------------------


class TestRegenerate:
    def test_posts_the_rotation_window_to_the_key_id(self, api: respx.MockRouter) -> None:
        route = api.post(REGENERATE_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime,
            ["api-keys", "regenerate", API_KEY_ID, "--interval", "30", "--unit", "days"],
        )

        assert result.exit_code == 0
        assert body_of(route) == {"rotation_time_interval": 30, "rotation_time_unit": "days"}

    def test_records_the_operator_when_one_is_given(self, api: respx.MockRouter) -> None:
        route = api.post(REGENERATE_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime,
            [
                "api-keys",
                "regenerate",
                API_KEY_ID,
                "--interval",
                "6",
                "--unit",
                "months",
                "--updated-by",
                "ops@example.com",
            ],
        )

        assert result.exit_code == 0
        assert body_of(route)["updated_by"] == "ops@example.com"

    def test_omits_the_operator_when_none_is_given(self, api: respx.MockRouter) -> None:
        """An explicit null is not the same as saying nothing about who rotated the key."""
        route = api.post(REGENERATE_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        runner.invoke(
            runtime,
            ["api-keys", "regenerate", API_KEY_ID, "--interval", "30", "--unit", "days"],
        )

        assert "updated_by" not in body_of(route)

    def test_sends_the_rotation_interval_as_an_integer(self, api: respx.MockRouter) -> None:
        route = api.post(REGENERATE_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        runner.invoke(
            runtime,
            ["api-keys", "regenerate", API_KEY_ID, "--interval", "30", "--unit", "days"],
        )

        assert re.search(
            rb'"rotation_time_interval":\s*30\s*[,}]', route.calls.last.request.content
        )

    def test_reports_the_rotated_key(self, api: respx.MockRouter) -> None:
        api.post(REGENERATE_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime,
            ["api-keys", "regenerate", API_KEY_ID, "--interval", "30", "--unit", "days"],
        )

        assert f"API key regenerated: {API_KEY_ID}" in result.output
        assert "sk-live-0123456789ABCD1234" in result.output

    def test_rejects_an_interval_below_one(self, api: respx.MockRouter) -> None:
        route = api.post(REGENERATE_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime,
            ["api-keys", "regenerate", API_KEY_ID, "--interval", "0", "--unit", "days"],
        )

        assert result.exit_code == 2
        assert not route.called
        assert "--interval must be a positive integer" in result.output

    def test_requires_the_rotation_unit(self, api: respx.MockRouter) -> None:
        route = api.post(REGENERATE_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(runtime, ["api-keys", "regenerate", API_KEY_ID, "--interval", "30"])

        assert result.exit_code == 2
        assert not route.called
        assert "Missing option '--unit'." in result.output

    def test_requires_the_rotation_interval(self, api: respx.MockRouter) -> None:
        route = api.post(REGENERATE_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(runtime, ["api-keys", "regenerate", API_KEY_ID, "--unit", "days"])

        assert result.exit_code == 2
        assert not route.called
        assert "Missing option '--interval'." in result.output

    def test_requires_the_key_id(self, api: respx.MockRouter) -> None:
        route = api.post(REGENERATE_URL).mock(return_value=httpx.Response(200, json=SECRET_KEY))

        result = runner.invoke(
            runtime, ["api-keys", "regenerate", "--interval", "30", "--unit", "days"]
        )

        assert result.exit_code == 2
        assert not route.called
        assert "Missing argument 'api_key_id'." in result.output


# ---------------------------------------------------------------------------
# api-keys delete
# ---------------------------------------------------------------------------


class TestDelete:
    def test_refuses_without_force_when_nobody_can_be_asked(self, api: respx.MockRouter) -> None:
        route = api.delete(DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            runtime, ["api-keys", "delete", KEY_NAME, "--updated-by", "ops@example.com"]
        )

        assert result.exit_code == 2
        assert not route.called

    def test_deletes_by_encoded_name_and_records_the_operator(self, api: respx.MockRouter) -> None:
        route = api.delete(DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            runtime,
            ["api-keys", "delete", KEY_NAME, "--updated-by", "ops@example.com", "--force"],
        )

        assert result.exit_code == 0
        assert route.calls.last.request.method == "DELETE"
        assert params_of(route)["updated_by"] == "ops@example.com"

    def test_prints_the_acknowledgement_the_service_sent(self, api: respx.MockRouter) -> None:
        api.delete(DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "successfully deleted prod scanner"})
        )

        result = runner.invoke(
            runtime,
            ["api-keys", "delete", KEY_NAME, "--updated-by", "ops@example.com", "--force"],
        )

        assert "successfully deleted prod scanner" in result.output

    def test_says_something_when_the_acknowledgement_is_bare(self, api: respx.MockRouter) -> None:
        """The delete response has been observed without a message; silence reads as a no-op."""
        api.delete(DELETE_URL).mock(return_value=httpx.Response(200, json={}))

        result = runner.invoke(
            runtime,
            ["api-keys", "delete", KEY_NAME, "--updated-by", "ops@example.com", "--force"],
        )

        assert result.exit_code == 0
        assert f"API key deleted: {KEY_NAME}" in result.output

    def test_deletes_when_the_operator_confirms(
        self, api: respx.MockRouter, at_a_terminal: Callable[[bool], None]
    ) -> None:
        at_a_terminal(True)
        route = api.delete(DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            runtime, ["api-keys", "delete", KEY_NAME, "--updated-by", "ops@example.com"]
        )

        assert result.exit_code == 0
        assert params_of(route)["updated_by"] == "ops@example.com"

    def test_sends_nothing_when_the_operator_declines(
        self, api: respx.MockRouter, at_a_terminal: Callable[[bool], None]
    ) -> None:
        """Declining is a decision, not a failure, so it leaves the exit status clean."""
        at_a_terminal(False)
        route = api.delete(DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            runtime, ["api-keys", "delete", KEY_NAME, "--updated-by", "ops@example.com"]
        )

        assert result.exit_code == 0
        assert not route.called
        assert "Aborted" in result.output

    def test_requires_the_operator_email(self, api: respx.MockRouter) -> None:
        route = api.delete(DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(runtime, ["api-keys", "delete", KEY_NAME, "--force"])

        assert result.exit_code == 2
        assert not route.called
        assert "Missing option '--updated-by'." in result.output


# ---------------------------------------------------------------------------
# deployment-profiles list
# ---------------------------------------------------------------------------


class TestDeploymentProfiles:
    def test_says_nothing_about_activation_by_default(self, api: respx.MockRouter) -> None:
        """Absent and false are different to this endpoint, so the flag is not sent as false."""
        route = api.get(DEPLOYMENT_PROFILES_URL).mock(
            return_value=httpx.Response(
                200, json={"deployment_profiles": [DEPLOYMENT_PROFILE], "status": "ok"}
            )
        )

        result = runner.invoke(runtime, ["deployment-profiles", "list"])

        assert result.exit_code == 0
        assert "unactivated" not in params_of(route)

    def test_asks_for_unactivated_profiles_when_told_to(self, api: respx.MockRouter) -> None:
        route = api.get(DEPLOYMENT_PROFILES_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "deployment_profiles": [DEPLOYMENT_PROFILE, UNACTIVATED_PROFILE],
                    "status": "ok",
                },
            )
        )

        result = runner.invoke(runtime, ["deployment-profiles", "list", "--unactivated"])

        assert result.exit_code == 0
        assert params_of(route)["unactivated"] == "true"

    def test_pretty_output_pairs_each_name_with_its_auth_code(self, api: respx.MockRouter) -> None:
        api.get(DEPLOYMENT_PROFILES_URL).mock(
            return_value=httpx.Response(
                200, json={"deployment_profiles": [DEPLOYMENT_PROFILE], "status": "ok"}
            )
        )

        result = runner.invoke(runtime, ["deployment-profiles", "list"])

        assert "Runtime Configuration" in result.output
        assert "prod-dp" in result.output
        assert "AUTH-CODE-1" in result.output

    def test_json_output_carries_the_reference_keys(self, api: respx.MockRouter) -> None:
        api.get(DEPLOYMENT_PROFILES_URL).mock(
            return_value=httpx.Response(
                200, json={"deployment_profiles": [DEPLOYMENT_PROFILE], "status": "ok"}
            )
        )

        result = runner.invoke(runtime, ["deployment-profiles", "list", "--output", "json"])

        assert json.loads(result.output) == [
            {"name": "prod-dp", "status": "active", "authCode": "AUTH-CODE-1"}
        ]

    def test_reports_an_empty_listing(self, api: respx.MockRouter) -> None:
        api.get(DEPLOYMENT_PROFILES_URL).mock(
            return_value=httpx.Response(200, json={"deployment_profiles": [], "status": "ok"})
        )

        result = runner.invoke(runtime, ["deployment-profiles", "list"])

        assert result.exit_code == 0
        assert "No deployment profiles found" in result.output

    def test_reports_what_the_service_refused(self, api: respx.MockRouter) -> None:
        route = api.get(DEPLOYMENT_PROFILES_URL).mock(
            return_value=httpx.Response(500, json={"error": {"message": "boom"}})
        )

        result = runner.invoke(runtime, ["deployment-profiles", "list"])

        assert result.exit_code == 2
        # Without these the test also passes when the command dies before it ever asks.
        assert route.called
        assert "HTTP 500" in result.output
