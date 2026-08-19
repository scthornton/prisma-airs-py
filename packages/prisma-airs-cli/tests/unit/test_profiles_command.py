"""``airs runtime profiles`` behaviour: the requests it sends and the exits it returns.

Almost every assertion here is on the request rather than the response. These commands
build a deeply nested policy document out of two dozen flat flags, and `update` sends the
*whole* profile back -- so a port that drops a section, writes it under the wrong key, or
quietly discards the topic guardrails still renders a perfectly convincing success.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
import typer
from typer.testing import CliRunner

from prisma_airs.constants import DEFAULT_MGMT_ENDPOINT, DEFAULT_TOKEN_ENDPOINT
from prisma_airs_cli import confirm as confirm_module
from prisma_airs_cli.commands.profiles import profiles_app

runner = CliRunner()

TSG_ID = "1234567890"
PROFILE_ID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
OTHER_ID = "550e8400-e29b-41d4-a716-446655440000"

PROFILE_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/profile"
PROFILE_UPDATE_URL = f"{PROFILE_URL}/uuid/{PROFILE_ID}"
PROFILE_DELETE_URL = f"{PROFILE_URL}/{PROFILE_ID}"
PROFILE_FORCE_URL = f"{PROFILE_URL}/{PROFILE_ID}/force"
PROFILES_TSG_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/profiles/tsg/{TSG_ID}"

#: A profile with no policy at all -- what the API returns for a freshly created one.
BARE_PROFILE: dict[str, Any] = {
    "profile_id": PROFILE_ID,
    "profile_name": "prod-guard",
    "revision": 2,
    "active": True,
}

#: A profile carrying policy in every section `update` merges into, including a topic
#: guardrail no flag can address. Used to prove the merge is additive rather than a
#: replacement.
FURNISHED_PROFILE: dict[str, Any] = {
    **BARE_PROFILE,
    "created_by": "author@example.test",
    "last_modified_ts": "2026-01-01T00:00:00Z",
    "policy": {
        "ai-security-profiles": [
            {
                "model-type": "default",
                "model-configuration": {
                    "model-protection": [
                        {"name": "prompt-injection", "action": "alert"},
                        {
                            "name": "topic-guardrails",
                            "action": "allow",
                            "topic-list": [
                                {
                                    "action": "block",
                                    "topic": [
                                        {
                                            "topic_name": "Financial Advice",
                                            "topic_id": OTHER_ID,
                                            "revision": 3,
                                        }
                                    ],
                                }
                            ],
                        },
                    ],
                    "app-protection": {
                        "url-detected-action": "alert",
                        "default-url-category": {"member": ["malicious"]},
                    },
                    "data-protection": {
                        "database-security": [
                            # Named by no flag any test passes, so a merge that replaces the
                            # list instead of keying into it loses this rule.
                            {"name": "database-security-create", "action": "alert"},
                            {"name": "database-security-read", "action": "alert"},
                        ]
                    },
                    "latency": {"inline-timeout-action": "allow", "max-inline-latency": 3},
                },
            }
        ]
    },
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


@pytest.fixture
def interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the confirmation prompt believe there is someone at a terminal to answer it.

    The whole ``sys`` reference inside the confirm module is replaced rather than
    ``sys.stdin`` itself, because ``CliRunner`` swaps the real ``sys.stdin`` for its own
    for the duration of the invocation.
    """
    monkeypatch.setattr(
        confirm_module, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True))
    )


def listing(api: respx.MockRouter, *profiles: dict[str, Any], **extra: Any) -> respx.Route:
    """Stub the one endpoint every lookup goes through."""
    route: respx.Route = api.get(PROFILES_TSG_URL)
    return route.mock(
        return_value=httpx.Response(200, json={"ai_profiles": list(profiles), **extra})
    )


def body_of(route: respx.Route) -> Any:
    """The last JSON body a route received."""
    return json.loads(route.calls.last.request.content)


def params_of(route: respx.Route) -> dict[str, str]:
    """The last query string a route received."""
    return dict(route.calls.last.request.url.params)


def configuration_of(route: respx.Route) -> Any:
    """The model configuration inside the last profile write a route received."""
    return body_of(route)["policy"]["ai-security-profiles"][0]["model-configuration"]


def write_json(tmp_path: Path, document: dict[str, Any]) -> str:
    """Write a legacy ``--config`` document and return its path."""
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document))
    return str(path)


# ---------------------------------------------------------------------------
# the group itself
# ---------------------------------------------------------------------------


class TestGroup:
    """The group is mounted by the parent under its own ``name``, so what it calls itself
    decides the whole command path the reference documents."""

    def test_is_named_for_the_path_the_reference_publishes(self) -> None:
        assert profiles_app.info.name == "profiles"

    def test_a_bare_group_lists_its_subcommands_instead_of_acting(self) -> None:
        result = runner.invoke(profiles_app, [])

        assert result.exit_code != 0
        for command in ("list", "get", "create", "update", "delete", "cleanup"):
            assert command in result.output


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestList:
    def test_sends_the_default_page(self, api: respx.MockRouter) -> None:
        route = listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["list"])

        assert result.exit_code == 0
        assert params_of(route) == {"offset": "0", "limit": "100"}

    def test_limit_and_offset_reach_the_query(self, api: respx.MockRouter) -> None:
        route = listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["list", "--limit", "20", "--offset", "40"])

        assert result.exit_code == 0
        assert params_of(route) == {"offset": "40", "limit": "20"}

    def test_ls_is_the_same_command(self, api: respx.MockRouter) -> None:
        """The reference registers `list|ls`; the alias must not be a different command."""
        route = listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["ls", "--limit", "5"])

        assert result.exit_code == 0
        assert params_of(route) == {"offset": "0", "limit": "5"}

    def test_pretty_output_names_each_profile_and_its_state(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE, {**BARE_PROFILE, "profile_id": OTHER_ID, "active": False})

        result = runner.invoke(profiles_app, ["list"])

        assert PROFILE_ID in result.output
        assert "prod-guard" in result.output
        assert "active" in result.output
        assert "inactive" in result.output
        # The revision is a JSON number the SDK types float; 2.0 is not what was stored.
        assert "rev:2" in result.output
        assert "rev:2.0" not in result.output

    def test_json_output_keys_on_the_column_names(self, api: respx.MockRouter) -> None:
        listing(
            api,
            BARE_PROFILE,
            {**BARE_PROFILE, "profile_id": OTHER_ID, "revision": 1, "active": False},
        )

        result = runner.invoke(profiles_app, ["list", "--output", "json"])

        # The revision stays a JSON number, as the reference emits it: a quoted "2" is a
        # different value to anything that compares or sorts the field.
        assert json.loads(result.output) == [
            {"id": PROFILE_ID, "name": "prod-guard", "status": "active", "revision": 2},
            {"id": OTHER_ID, "name": "prod-guard", "status": "inactive", "revision": 1},
        ]

    def test_a_record_with_no_revision_leaves_the_field_empty(self, api: respx.MockRouter) -> None:
        """The reference writes `revision ?? ''`; a null would break a consumer that
        formats the column, and `0` would name a revision that does not exist."""
        listing(api, BARE_PROFILE, {**BARE_PROFILE, "profile_id": OTHER_ID, "revision": None})

        result = runner.invoke(profiles_app, ["list", "--output", "json"])

        assert json.loads(result.output)[1]["revision"] == ""

    def test_a_profile_with_no_activation_state_reads_as_inactive(
        self, api: respx.MockRouter
    ) -> None:
        """`active` is optional in the response schema, and the reference's `p.active ?
        'active' : 'inactive'` reads a missing one exactly as it reads false."""
        listing(api, BARE_PROFILE, {"profile_id": OTHER_ID, "profile_name": "half-built"})

        result = runner.invoke(profiles_app, ["list", "--output", "json"])

        assert json.loads(result.output)[1]["status"] == "inactive"

    def test_yaml_is_an_accepted_list_format(self, api: respx.MockRouter) -> None:
        """`list` offers five formats where `get` offers three, and yaml is one they share.
        One document per row, `---` between them, is the shape the reference emits."""
        yaml = pytest.importorskip("yaml")
        listing(api, BARE_PROFILE, {**BARE_PROFILE, "profile_id": OTHER_ID, "revision": 1})

        result = runner.invoke(profiles_app, ["list", "--output", "yaml"])

        assert result.exit_code == 0
        assert list(yaml.safe_load_all(result.output)) == [
            {"id": PROFILE_ID, "name": "prod-guard", "status": "active", "revision": 2},
            {"id": OTHER_ID, "name": "prod-guard", "status": "active", "revision": 1},
        ]

    def test_csv_output_leads_with_the_column_headings(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["list", "--output", "csv"])

        assert result.exit_code == 0
        assert result.output.splitlines()[0] == "ID,Name,Status,Revision"
        assert result.output.splitlines()[1] == f"{PROFILE_ID},prod-guard,active,2"

    def test_pretty_output_opens_with_the_runtime_banner(self, api: respx.MockRouter) -> None:
        """The reference prints it for `pretty` only -- `test_machine_output_carries_no_
        banner` pins the other half of that rule for `get`."""
        listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["list"])

        assert "Prisma AIRS — Runtime Configuration" in result.output

    def test_help_carries_the_reference_examples(self) -> None:
        result = runner.invoke(profiles_app, ["list", "--help"])

        assert result.exit_code == 0
        assert "$ airs runtime profiles list --output json" in result.output
        assert "$ airs runtime profiles list --limit 20 --offset 20" in result.output

    def test_help_advertises_all_five_list_formats(self) -> None:
        """`list` takes five where `get` takes three, and --help is where a caller finds
        out which -- so the advertised set has to be the accepted one."""
        result = runner.invoke(profiles_app, ["list", "--help"])

        # Rich wraps the help column and boxes it, so compare on the words alone.
        described = " ".join(result.output.replace("\u2502", " ").split())
        assert "<pretty|table|csv|json|yaml>" in result.output
        assert "Output format: pretty, table, csv, json, yaml." in described

    def test_reports_where_the_next_page_starts(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE, next_offset=100)

        result = runner.invoke(profiles_app, ["list"])

        # Offsets are counts; the float the API sends is not what gets typed back in.
        assert "Next offset: 100\n" in result.output

    def test_stays_quiet_about_a_next_page_that_does_not_exist(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["list"])

        assert "Next offset" not in result.output

    def test_machine_output_carries_no_pagination_commentary(self, api: respx.MockRouter) -> None:
        """`Next offset:` in the middle of a JSON document would break every consumer."""
        listing(api, BARE_PROFILE, next_offset=100)

        result = runner.invoke(profiles_app, ["list", "--output", "json"])

        assert "Next offset" not in result.output
        assert json.loads(result.output)

    def test_reports_an_empty_tenant(self, api: respx.MockRouter) -> None:
        listing(api)

        result = runner.invoke(profiles_app, ["list"])

        assert result.exit_code == 0
        assert "No profiles found" in result.output

    def test_rejects_a_negative_limit(self, api: respx.MockRouter) -> None:
        route = listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["list", "--limit", "-1"])

        assert result.exit_code == 2
        assert not route.called

    def test_rejects_a_negative_offset(self, api: respx.MockRouter) -> None:
        route = listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["list", "--offset", "-5"])

        assert result.exit_code == 2
        assert not route.called

    def test_reports_an_api_failure(self, api: respx.MockRouter) -> None:
        api.get(PROFILES_TSG_URL).mock(return_value=httpx.Response(403, json={"message": "nope"}))

        result = runner.invoke(profiles_app, ["list"])

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


class TestGet:
    def test_resolves_a_name_to_its_live_revision(self, api: respx.MockRouter) -> None:
        """Older revisions stay listed under the same name; the newest is the live one."""
        listing(
            api,
            {**BARE_PROFILE, "profile_id": OTHER_ID, "revision": 1},
            {**BARE_PROFILE, "revision": 9},
        )

        result = runner.invoke(profiles_app, ["get", "prod-guard", "--output", "json"])

        assert result.exit_code == 0
        assert json.loads(result.output)["profile_id"] == PROFILE_ID

    def test_resolves_a_uuid_against_the_id_not_the_name(self, api: respx.MockRouter) -> None:
        listing(api, {**BARE_PROFILE, "profile_id": OTHER_ID, "profile_name": PROFILE_ID})

        result = runner.invoke(profiles_app, ["get", PROFILE_ID])

        # A name-shaped lookup would have matched the decoy's profile_name.
        assert result.exit_code == 2

    def test_pretty_output_shows_the_policy(self, api: respx.MockRouter) -> None:
        listing(api, FURNISHED_PROFILE)

        result = runner.invoke(profiles_app, ["get", "prod-guard"])

        assert result.exit_code == 0
        assert "Profile Detail" in result.output
        assert "topic-guardrails" in result.output
        assert "author@example.test" in result.output

    def test_json_output_is_the_api_wire_form(self, api: respx.MockRouter) -> None:
        """It has to be: the same document is what `create --config` reads back in."""
        listing(api, FURNISHED_PROFILE)

        result = runner.invoke(profiles_app, ["get", "prod-guard", "--output", "json"])

        document = json.loads(result.output)
        assert document["profile_name"] == "prod-guard"
        entry = document["policy"]["ai-security-profiles"][0]
        assert entry["model-configuration"]["app-protection"]["url-detected-action"] == "alert"

    def test_yaml_output_parses_as_yaml(self, api: respx.MockRouter) -> None:
        """The reference joins `key: value` strings and embeds the policy as JSON inside."""
        yaml = pytest.importorskip("yaml")
        listing(api, FURNISHED_PROFILE)

        result = runner.invoke(profiles_app, ["get", "prod-guard", "--output", "yaml"])

        document = yaml.safe_load(result.output)
        assert document["profile_id"] == PROFILE_ID
        assert document["policy"]["ai-security-profiles"][0]["model-type"] == "default"

    def test_yaml_output_keeps_the_record_order_rather_than_sorting_it(
        self, api: respx.MockRouter
    ) -> None:
        """Identity first is what makes the document readable and diffable; alphabetical
        order would open it on `active`."""
        listing(api, FURNISHED_PROFILE)

        result = runner.invoke(profiles_app, ["get", "prod-guard", "--output", "yaml"])

        assert result.output.splitlines()[0] == f"profile_id: {PROFILE_ID}"

    def test_detail_json_spells_the_revision_as_the_api_sent_it(
        self, api: respx.MockRouter
    ) -> None:
        listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["get", "prod-guard", "--output", "json"])

        # `json.loads` would compare 2.0 equal to 2, so only the raw bytes show it.
        assert re.search(r'"revision":\s*2\s*[,}]', result.output)

    def test_machine_output_carries_no_banner(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["get", "prod-guard", "--output", "json"])

        assert "Runtime Configuration" not in result.output

    def test_rejects_a_tabular_format_for_a_single_record(self, api: respx.MockRouter) -> None:
        route = listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["get", "prod-guard", "--output", "table"])

        assert result.exit_code == 2
        assert not route.called

    def test_reports_a_name_that_does_not_exist(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["get", "staging-guard"])

        assert result.exit_code == 2
        assert "staging-guard" in result.output


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


class TestCreate:
    def test_a_profile_with_no_policy_flags_is_created_bare(self, api: respx.MockRouter) -> None:
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        result = runner.invoke(profiles_app, ["create", "--name", "prod-guard"])

        assert result.exit_code == 0
        assert body_of(route) == {"profile_name": "prod-guard", "active": True}
        assert f"Profile created: {PROFILE_ID}" in result.output

    def test_no_active_creates_an_inactive_profile(self, api: respx.MockRouter) -> None:
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        result = runner.invoke(profiles_app, ["create", "--name", "prod-guard", "--no-active"])

        assert result.exit_code == 0
        assert body_of(route)["active"] is False

    def test_requires_a_name(self, api: respx.MockRouter) -> None:
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        result = runner.invoke(profiles_app, ["create"])

        assert result.exit_code == 2
        assert not route.called

    def test_every_flag_lands_in_the_policy(self, api: respx.MockRouter) -> None:
        """One assertion over the whole document: a key written under the wrong name, or
        under the right name in the wrong section, is exactly the failure that survives
        every per-section spot check."""
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        result = runner.invoke(
            profiles_app,
            [
                "create",
                "--name", "prod-guard",
                "--prompt-injection", "block",
                "--toxic-content", "high:block, moderate:alert",
                "--contextual-grounding", "alert",
                "--malicious-code", "block",
                "--url-action", "block",
                "--allow-url-categories", "business,news",
                "--block-url-categories", "malware",
                "--alert-url-categories", "unknown",
                "--agent-security", "block",
                "--dlp-action", "block",
                "--dlp-profiles", "PCI,PII",
                "--mask-data-inline",
                "--db-security-create", "block",
                "--db-security-read", "alert",
                "--db-security-update", "block",
                "--db-security-delete", "block",
                "--inline-timeout-action", "allow",
                "--max-inline-latency", "7",
                "--mask-data-in-storage",
            ],
        )  # fmt: skip

        assert result.exit_code == 0
        assert configuration_of(route) == {
            "model-protection": [
                {"name": "prompt-injection", "action": "block"},
                {"name": "toxic-content", "action": "high:block, moderate:alert"},
                {"name": "contextual-grounding", "action": "alert"},
            ],
            "app-protection": {
                "malicious-code-protection": {
                    "name": "malicious-code-detection",
                    "action": "block",
                },
                "url-detected-action": "block",
                "allow-url-category": {"member": ["business", "news"]},
                "block-url-category": {"member": ["malware"]},
                "alert-url-category": {"member": ["unknown"]},
            },
            "agent-protection": [{"name": "agent-security", "action": "block"}],
            "data-protection": {
                "data-leak-detection": {
                    "action": "block",
                    "member": [{"text": "PCI"}, {"text": "PII"}],
                    "mask-data-inline": True,
                },
                "database-security": [
                    {"name": "database-security-create", "action": "block"},
                    {"name": "database-security-read", "action": "alert"},
                    {"name": "database-security-update", "action": "block"},
                    {"name": "database-security-delete", "action": "block"},
                ],
            },
            "latency": {"inline-timeout-action": "allow", "max-inline-latency": 7.0},
            "mask-data-in-storage": True,
        }

    def test_a_bare_toxic_content_action_is_expanded_per_severity(
        self, api: respx.MockRouter
    ) -> None:
        """The console stores this per severity and cannot read a single bare action."""
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        runner.invoke(
            profiles_app,
            ["create", "--name", "prod-guard", "--toxic-content", "block"],
        )

        protection = configuration_of(route)["model-protection"]
        assert protection == [{"name": "toxic-content", "action": "high:block, moderate:block"}]

    def test_comma_lists_are_trimmed(self, api: respx.MockRouter) -> None:
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        runner.invoke(
            profiles_app,
            ["create", "--name", "prod-guard", "--block-url-categories", " malware , phishing "],
        )

        app_protection = configuration_of(route)["app-protection"]
        assert app_protection["block-url-category"] == {"member": ["malware", "phishing"]}

    def test_any_policy_flag_fills_in_the_sections_the_console_requires(
        self, api: respx.MockRouter
    ) -> None:
        """A profile missing these renders as "is not iterable" in the AIRS console."""
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        runner.invoke(
            profiles_app,
            ["create", "--name", "prod-guard", "--prompt-injection", "block"],
        )

        configuration = configuration_of(route)
        assert configuration["app-protection"] == {
            "default-url-category": {"member": ["malicious"]},
            "url-detected-action": "block",
        }
        assert configuration["data-protection"] == {
            "data-leak-detection": {"action": "", "mask-data-inline": False}
        }
        assert configuration["latency"] == {
            "inline-timeout-action": "block",
            "max-inline-latency": 5.0,
        }
        assert configuration["mask-data-in-storage"] is False

    def test_filled_in_defaults_never_overwrite_a_real_setting(self, api: respx.MockRouter) -> None:
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        runner.invoke(
            profiles_app,
            [
                "create",
                "--name", "prod-guard",
                "--url-action", "alert",
                "--inline-timeout-action", "allow",
            ],
        )  # fmt: skip

        configuration = configuration_of(route)
        assert configuration["app-protection"] == {"url-detected-action": "alert"}
        assert configuration["latency"] == {"inline-timeout-action": "allow"}

    def test_the_policy_envelope_names_the_default_model_type(self, api: respx.MockRouter) -> None:
        """Every assertion built on `configuration_of` reads straight past the envelope, so
        a wrong `model-type` -- or a second entry beside it -- survives all of them."""
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        runner.invoke(
            profiles_app, ["create", "--name", "prod-guard", "--prompt-injection", "block"]
        )

        entries = body_of(route)["policy"]["ai-security-profiles"]
        assert len(entries) == 1
        assert entries[0]["model-type"] == "default"

    def test_a_zero_latency_is_a_setting_rather_than_an_omission(
        self, api: respx.MockRouter
    ) -> None:
        """The reference tests this flag for null, not for truth, so `0` -- "never wait" --
        reaches the policy instead of falling back to the five-second default."""
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        result = runner.invoke(
            profiles_app,
            ["create", "--name", "prod-guard", "--max-inline-latency", "0"],
        )

        assert result.exit_code == 0
        assert configuration_of(route)["latency"] == {"max-inline-latency": 0.0}

    def test_an_emptied_category_list_is_written_as_an_empty_bucket(
        self, api: respx.MockRouter
    ) -> None:
        """ "This bucket has no members" is an instruction; only an absent flag is silence,
        and collapsing the two would make the list impossible to clear."""
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        result = runner.invoke(
            profiles_app,
            ["create", "--name", "prod-guard", "--allow-url-categories", ", ,"],
        )

        assert result.exit_code == 0
        assert configuration_of(route)["app-protection"]["allow-url-category"] == {"member": []}

    def test_dlp_profiles_alone_writes_no_policy(self, api: respx.MockRouter) -> None:
        """Like --mask-data-inline, it is a setting of the data-leak rule: with no
        --dlp-action there is no rule for it to hang off."""
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        runner.invoke(profiles_app, ["create", "--name", "prod-guard", "--dlp-profiles", "PCI"])

        assert body_of(route) == {"profile_name": "prod-guard", "active": True}

    def test_dlp_profiles_build_no_rule_even_once_a_policy_exists(
        self, api: respx.MockRouter
    ) -> None:
        """The previous test stops at the "any policy at all?" gate, so it never reaches the
        builder. Another flag opens that gate and leaves the same question to the builder:
        a member list with no action is not a rule, it is a rule waiting for one."""
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        runner.invoke(
            profiles_app,
            [
                "create", "--name", "prod-guard",
                "--prompt-injection", "block",
                "--dlp-profiles", "PCI",
                "--mask-data-inline",
            ],
        )  # fmt: skip

        # The console placeholder, untouched -- not a rule assembled out of the two
        # settings that cannot stand without an action.
        assert configuration_of(route)["data-protection"] == {
            "data-leak-detection": {"action": "", "mask-data-inline": False}
        }

    def test_mask_data_inline_alone_writes_no_policy(self, api: respx.MockRouter) -> None:
        """It is a setting of the data-leak rule; with no --dlp-action there is no rule."""
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        runner.invoke(profiles_app, ["create", "--name", "prod-guard", "--mask-data-inline"])

        assert body_of(route) == {"profile_name": "prod-guard", "active": True}

    def test_config_file_is_posted_as_the_whole_body(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))
        document = {"profile_name": "from-file", "active": False, "policy": {}}

        result = runner.invoke(
            profiles_app,
            ["create", "--name", "prod-guard", "--config", write_json(tmp_path, document)],
        )

        assert result.exit_code == 0
        # --name is required by the reference but unused once --config is given.
        assert body_of(route) == {"profile_name": "from-file", "active": False, "policy": {}}

    def test_rejects_a_config_file_that_is_not_a_profile(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))
        path = tmp_path / "profile.json"
        path.write_text(json.dumps({"nothing": "useful"}))

        result = runner.invoke(
            profiles_app, ["create", "--name", "prod-guard", "--config", str(path)]
        )

        assert result.exit_code == 2
        assert not route.called

    def test_rejects_a_config_file_that_does_not_exist(self, api: respx.MockRouter) -> None:
        route = api.post(PROFILE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        result = runner.invoke(
            profiles_app, ["create", "--name", "prod-guard", "--config", "/nope/absent.json"]
        )

        assert result.exit_code == 2
        assert not route.called

    def test_a_conflict_that_created_the_profile_anyway_is_a_success(
        self, api: respx.MockRouter
    ) -> None:
        """AIRS answers 409 having stored the profile, so the conflict is checked, not
        believed."""
        api.post(PROFILE_URL).mock(return_value=httpx.Response(409, json={"message": "exists"}))
        listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["create", "--name", "prod-guard"])

        assert result.exit_code == 0
        assert f"Profile created: {PROFILE_ID}" in result.output

    def test_a_conflict_over_a_profile_that_is_absent_is_a_failure(
        self, api: respx.MockRouter
    ) -> None:
        api.post(PROFILE_URL).mock(return_value=httpx.Response(409, json={"message": "exists"}))
        listing(api)

        result = runner.invoke(profiles_app, ["create", "--name", "prod-guard"])

        assert result.exit_code == 2
        assert "already exists" in result.output

    def test_an_error_that_is_not_a_conflict_is_never_second_guessed(
        self, api: respx.MockRouter
    ) -> None:
        api.post(PROFILE_URL).mock(return_value=httpx.Response(400, json={"message": "bad"}))
        lookup = listing(api, BARE_PROFILE)

        result = runner.invoke(profiles_app, ["create", "--name", "prod-guard"])

        assert result.exit_code == 2
        assert not lookup.called


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------


class TestUpdate:
    def test_writes_to_the_resolved_profile_id(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        result = runner.invoke(
            profiles_app, ["update", "prod-guard", "--prompt-injection", "block"]
        )

        assert result.exit_code == 0
        assert str(route.calls.last.request.url) == PROFILE_UPDATE_URL
        assert f"Profile updated: {PROFILE_ID}" in result.output

    def test_merges_into_the_current_policy_rather_than_replacing_it(
        self, api: respx.MockRouter
    ) -> None:
        """The API takes the whole resource back, so anything not carried across is lost --
        the topic guardrail above all, which no flag here can even name."""
        listing(api, FURNISHED_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        result = runner.invoke(
            profiles_app, ["update", "prod-guard", "--prompt-injection", "block"]
        )

        assert result.exit_code == 0
        protection = configuration_of(route)["model-protection"]
        by_name = {item["name"]: item for item in protection}
        assert by_name["prompt-injection"]["action"] == "block"
        guardrail = by_name["topic-guardrails"]
        assert guardrail["action"] == "allow"
        assert guardrail["topic-list"][0]["topic"][0]["topic_id"] == OTHER_ID

    def test_leaves_untouched_sections_exactly_as_they_were(self, api: respx.MockRouter) -> None:
        listing(api, FURNISHED_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(profiles_app, ["update", "prod-guard", "--prompt-injection", "block"])

        configuration = configuration_of(route)
        assert configuration["app-protection"] == {
            "url-detected-action": "alert",
            "default-url-category": {"member": ["malicious"]},
        }
        assert configuration["latency"] == {
            "inline-timeout-action": "allow",
            "max-inline-latency": 3.0,
        }

    def test_a_named_section_overlays_field_by_field(self, api: respx.MockRouter) -> None:
        listing(api, FURNISHED_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(profiles_app, ["update", "prod-guard", "--url-action", "block"])

        # The category list was never mentioned, so it must survive the action change.
        assert configuration_of(route)["app-protection"] == {
            "url-detected-action": "block",
            "default-url-category": {"member": ["malicious"]},
        }

    def test_database_rules_merge_by_name(self, api: respx.MockRouter) -> None:
        listing(api, FURNISHED_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(
            profiles_app,
            [
                "update", "prod-guard",
                "--db-security-read", "block",
                "--db-security-delete", "alert",
            ],
        )  # fmt: skip

        assert configuration_of(route)["data-protection"]["database-security"] == [
            {"name": "database-security-create", "action": "alert"},
            {"name": "database-security-read", "action": "block"},
            {"name": "database-security-delete", "action": "alert"},
        ]

    def test_storage_masking_is_written_alongside_the_existing_policy(
        self, api: respx.MockRouter
    ) -> None:
        """It sits at the top of the model configuration rather than in a section, which is
        the easy place for a merge to lose it."""
        listing(api, FURNISHED_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(profiles_app, ["update", "prod-guard", "--mask-data-in-storage"])

        configuration = configuration_of(route)
        assert configuration["mask-data-in-storage"] is True
        assert configuration["latency"] == {
            "inline-timeout-action": "allow",
            "max-inline-latency": 3.0,
        }

    def test_the_dlp_rule_is_replaced_whole_beside_the_rules_that_stay(
        self, api: respx.MockRouter
    ) -> None:
        """Its action and member list are one decision, so half-updating them would leave
        a rule nobody asked for -- but the database rules next to it are a separate one."""
        listing(api, FURNISHED_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(
            profiles_app,
            ["update", "prod-guard", "--dlp-action", "block", "--dlp-profiles", "PCI"],
        )

        assert configuration_of(route)["data-protection"] == {
            "data-leak-detection": {"action": "block", "member": [{"text": "PCI"}]},
            "database-security": [
                {"name": "database-security-create", "action": "alert"},
                {"name": "database-security-read", "action": "alert"},
            ],
        }

    def test_no_policy_flags_still_sends_the_policy_back_intact(
        self, api: respx.MockRouter
    ) -> None:
        """A rename must not quietly strip the policy off the profile."""
        listing(api, FURNISHED_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        result = runner.invoke(profiles_app, ["update", "prod-guard", "--name", "renamed"])

        assert result.exit_code == 0
        body = body_of(route)
        assert body["profile_name"] == "renamed"
        assert "topic-guardrails" in json.dumps(body["policy"])

    def test_keeps_the_current_name_when_none_is_given(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(profiles_app, ["update", "prod-guard"])

        assert body_of(route)["profile_name"] == "prod-guard"

    def test_no_active_deactivates_the_profile(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(profiles_app, ["update", "prod-guard", "--no-active"])

        assert body_of(route)["active"] is False

    def test_active_is_the_default(self, api: respx.MockRouter) -> None:
        listing(api, {**BARE_PROFILE, "active": False})
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(profiles_app, ["update", "prod-guard"])

        assert body_of(route)["active"] is True

    def test_a_profile_with_no_policy_gains_one(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(profiles_app, ["update", "prod-guard", "--agent-security", "block"])

        entries = body_of(route)["policy"]["ai-security-profiles"]
        # The envelope is invented here rather than carried over, so it has to be right.
        assert len(entries) == 1
        assert entries[0]["model-type"] == "default"
        assert configuration_of(route) == {
            "agent-protection": [{"name": "agent-security", "action": "block"}]
        }

    def test_config_file_replaces_the_body_outright(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        listing(api, FURNISHED_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )
        document = {"profile_name": "from-file", "active": True}

        result = runner.invoke(
            profiles_app,
            ["update", "prod-guard", "--config", write_json(tmp_path, document)],
        )

        assert result.exit_code == 0
        assert body_of(route) == {"profile_name": "from-file", "active": True}

    def test_a_profile_that_came_back_without_an_id_is_named_in_the_error(
        self, api: respx.MockRouter
    ) -> None:
        """The ID is optional in the response schema and mandatory for the write."""
        listing(api, {"profile_name": "prod-guard", "revision": 2, "active": True})
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        result = runner.invoke(profiles_app, ["update", "prod-guard"])

        assert result.exit_code == 2
        assert "prod-guard" in result.output
        assert not route.called

    def test_reports_a_profile_that_does_not_exist(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        result = runner.invoke(profiles_app, ["update", "staging-guard"])

        assert result.exit_code == 2
        assert not route.called


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


class TestDelete:
    def test_refuses_without_force_when_nobody_can_be_asked(self, api: respx.MockRouter) -> None:
        """No TTY and no --force means the intent was never stated; deleting anyway is
        worse."""
        listing(api, BARE_PROFILE)
        plain = api.delete(PROFILE_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )
        forced = api.delete(PROFILE_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(profiles_app, ["delete", "prod-guard"])

        assert result.exit_code == 2
        assert not plain.called
        assert not forced.called

    def test_a_confirmed_delete_takes_the_plain_endpoint(
        self, api: respx.MockRouter, interactive: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: True)
        listing(api, BARE_PROFILE)
        plain = api.delete(PROFILE_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )
        forced = api.delete(PROFILE_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(profiles_app, ["delete", "prod-guard"])

        assert result.exit_code == 0
        assert plain.called
        assert not forced.called
        assert f"Profile deleted: prod-guard ({PROFILE_ID})" in result.output

    def test_declining_the_prompt_deletes_nothing(
        self, api: respx.MockRouter, interactive: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: False)
        listing(api, BARE_PROFILE)
        plain = api.delete(PROFILE_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(profiles_app, ["delete", "prod-guard"])

        assert result.exit_code == 0
        assert not plain.called

    def test_force_takes_the_force_endpoint_and_records_the_operator(
        self, api: respx.MockRouter
    ) -> None:
        """A different route, not a flag: the plain delete cannot detach referencing
        policies."""
        listing(api, BARE_PROFILE)
        plain = api.delete(PROFILE_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )
        forced = api.delete(PROFILE_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            profiles_app,
            ["delete", "prod-guard", "--force", "--updated-by", "ops@example.test"],
        )

        assert result.exit_code == 0
        assert not plain.called
        assert (
            str(forced.calls.last.request.url)
            == f"{PROFILE_FORCE_URL}?updated_by=ops%40example.test"
        )

    def test_force_without_an_operator_email_is_a_usage_error(self, api: respx.MockRouter) -> None:
        """The force delete is recorded against somebody; it cannot be nobody."""
        lookup = listing(api, BARE_PROFILE)
        forced = api.delete(PROFILE_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(profiles_app, ["delete", "prod-guard", "--force"])

        assert result.exit_code == 2
        assert "--updated-by" in result.output
        assert not forced.called
        # Caught before the round trip, not after it.
        assert not lookup.called

    def test_rm_is_the_same_command(self, api: respx.MockRouter) -> None:
        """The reference registers `delete|rm`; the alias must not be a different
        command."""
        listing(api, BARE_PROFILE)
        forced = api.delete(PROFILE_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            profiles_app, ["rm", "prod-guard", "--force", "--updated-by", "ops@example.test"]
        )

        assert result.exit_code == 0
        assert forced.called

    def test_an_operator_email_alone_is_not_a_request_to_force(
        self, api: respx.MockRouter, interactive: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--updated-by is the audit trail a force delete needs, not a way to ask for one:
        the force endpoint detaches the profile from every policy referencing it."""
        monkeypatch.setattr(typer, "confirm", lambda *a, **k: True)
        listing(api, BARE_PROFILE)
        plain = api.delete(PROFILE_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )
        forced = api.delete(PROFILE_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            profiles_app, ["delete", "prod-guard", "--updated-by", "ops@example.test"]
        )

        assert result.exit_code == 0
        assert plain.called
        assert not forced.called

    def test_a_uuid_deletes_the_record_holding_that_id_not_that_name(
        self, api: respx.MockRouter
    ) -> None:
        """The decoy stores the UUID as its *name*, so a name-shaped lookup deletes the
        wrong profile rather than merely failing."""
        listing(
            api,
            {**BARE_PROFILE, "profile_id": OTHER_ID, "profile_name": PROFILE_ID},
            BARE_PROFILE,
        )
        decoy = api.delete(f"{PROFILE_URL}/{OTHER_ID}/force").mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )
        forced = api.delete(PROFILE_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            profiles_app, ["rm", PROFILE_ID, "--force", "--updated-by", "ops@example.test"]
        )

        assert result.exit_code == 0
        assert forced.called
        assert not decoy.called

    def test_reports_a_profile_that_does_not_exist(self, api: respx.MockRouter) -> None:
        listing(api, BARE_PROFILE)
        forced = api.delete(PROFILE_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            profiles_app, ["delete", "staging-guard", "--force", "--updated-by", "o@e.test"]
        )

        assert result.exit_code == 2
        assert not forced.called


# ---------------------------------------------------------------------------
# cleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    """The command itself is tested in ``test_ops_command``; what matters here is that it
    is reachable under ``runtime profiles`` at all, which is where the reference puts it."""

    def test_is_registered_on_the_group(self, api: respx.MockRouter) -> None:
        listing(
            api,
            {**BARE_PROFILE, "profile_id": OTHER_ID, "revision": 1},
            {**BARE_PROFILE, "revision": 2},
        )
        stale = api.delete(f"{PROFILE_URL}/{OTHER_ID}/force").mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )
        newest = api.delete(PROFILE_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            profiles_app, ["cleanup", "--force", "--updated-by", "ops@example.test"]
        )

        assert result.exit_code == 0
        assert stale.called
        assert not newest.called
