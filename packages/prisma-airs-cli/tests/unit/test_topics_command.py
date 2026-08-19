"""``airs runtime topics`` behaviour: the requests it sends and the exits it returns.

The guardrail writes are asserted against the request body rather than the response,
because the whole profile policy is sent back on every update -- a port that drops a field
or inverts the guardrail action still looks fine from the outside.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
import yaml
from typer.testing import CliRunner

from prisma_airs.constants import (
    DEFAULT_ENDPOINT,
    DEFAULT_MGMT_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
)
from prisma_airs_cli import confirm as confirm_module
from prisma_airs_cli.commands.topics import topics_app

runner = CliRunner()

TSG_ID = "1234567890"
TOPIC_ID = "550e8400-e29b-41d4-a716-446655440000"
OTHER_TOPIC_ID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
PROFILE_ID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"

TOPIC_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/topic"
TOPIC_UPDATE_URL = f"{TOPIC_URL}/uuid/{TOPIC_ID}"
TOPIC_FORCE_URL = f"{TOPIC_URL}/force/{TOPIC_ID}"
TOPIC_DELETE_URL = f"{TOPIC_URL}/{TOPIC_ID}"
TOPICS_TSG_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/topics/tsg/{TSG_ID}"
PROFILES_TSG_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/profiles/tsg/{TSG_ID}"
PROFILE_UPDATE_URL = f"{DEFAULT_MGMT_ENDPOINT}/v1/mgmt/profile/uuid/{PROFILE_ID}"
SCAN_URL = f"{DEFAULT_ENDPOINT}/v1/scan/sync/request"

TOPIC = {
    "topic_id": TOPIC_ID,
    "topic_name": "Financial Advice",
    "revision": 3,
    "description": "Requests for personal investment advice",
    "examples": ["Should I buy TSLA stock?", "How should I invest my savings?"],
}
OTHER_TOPIC = {
    **TOPIC,
    "topic_id": OTHER_TOPIC_ID,
    "topic_name": "Legal Advice",
    "revision": 7,
}

#: A profile that has never carried a topic guardrail.
BARE_PROFILE = {
    "profile_id": PROFILE_ID,
    "profile_name": "prod-guard",
    "revision": 2,
    "active": True,
}


def profile_with(*buckets: Any) -> dict[str, Any]:
    """A profile whose topic guardrail already holds ``buckets``."""
    return {
        **BARE_PROFILE,
        "policy": {
            "ai-security-profiles": [
                {
                    "model-type": "default",
                    "model-configuration": {
                        "model-protection": [
                            {
                                "name": "topic-guardrails",
                                "action": "allow",
                                "topic-list": list(buckets),
                            }
                        ]
                    },
                }
            ]
        },
    }


SCAN_VERDICT = {
    "report_id": "R1",
    "scan_id": "S1",
    "category": "benign",
    "action": "allow",
    "timeout": False,
    "error": False,
    "errors": [],
}


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests off the developer's real credentials, endpoints, and config file."""
    monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "cid")
    monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "secret")
    monkeypatch.setenv("PANW_MGMT_TSG_ID", TSG_ID)
    monkeypatch.setenv("PANW_AI_SEC_API_KEY", "test-key")
    monkeypatch.setenv("PRISMA_AIRS_CONFIG", str(tmp_path / "config.json"))
    for name in (
        "PANW_MGMT_ENDPOINT",
        "PANW_MGMT_TOKEN_ENDPOINT",
        "PANW_AI_SEC_API_ENDPOINT",
        "PANW_AI_SEC_REGION",
    ):
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


def guardrail_of(route: respx.Route) -> Any:
    """The topic guardrail inside the last profile update a route received."""
    entry = body_of(route)["policy"]["ai-security-profiles"][0]
    protection = entry["model-configuration"]["model-protection"]
    return next(item for item in protection if item["name"] == "topic-guardrails")


def buckets_of(route: respx.Route) -> Any:
    """That guardrail's topic buckets, keyed by the action each one carries."""
    return {bucket["action"]: bucket["topic"] for bucket in guardrail_of(route)["topic-list"]}


def url_of(route: respx.Route) -> str:
    """The full URL, query string included, the last call to a route carried."""
    return str(route.calls.last.request.url)


def write_json(tmp_path: Path, payload: Any) -> str:
    """Write a `--config` document and return its path."""
    path = tmp_path / "topic.json"
    path.write_text(json.dumps(payload) if not isinstance(payload, str) else payload)
    return str(path)


def write_csv(tmp_path: Path, text: str) -> str:
    """Write a prompt set and return its path."""
    path = tmp_path / "prompts.csv"
    path.write_text(text)
    return str(path)


#: The banner the reference opens `list`, `get`, `update`, and `delete` with -- and which
#: it deliberately withholds from the guardrail loop (`create`, `apply`, `eval`, `revert`,
#: `sample`). Matched on the first line alone so the assertion does not depend on how a
#: narrow terminal wraps the subtitle.
RUNTIME_HEADER = "Runtime Configuration"


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------


class TestCreate:
    def test_creates_a_topic_that_does_not_exist_yet(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))
        route = api.post(TOPIC_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app,
            [
                "create",
                "--name",
                "Financial Advice",
                "--description",
                "Requests for personal investment advice",
                "--examples",
                "Should I buy TSLA stock?",
                "--examples",
                "How should I invest my savings?",
            ],
        )

        assert result.exit_code == 0
        assert body_of(route) == {
            "topic_name": "Financial Advice",
            "description": "Requests for personal investment advice",
            "examples": ["Should I buy TSLA stock?", "How should I invest my savings?"],
        }

    def test_reports_a_created_topic(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))
        api.post(TOPIC_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app,
            [
                "create",
                "--name",
                "Financial Advice",
                "--description",
                "d",
                "--examples",
                "a",
                "--examples",
                "b",
            ],
        )

        assert result.exit_code == 0
        # The whole pretty block, not just the verb: the reference prints the name on the
        # success line and the ID and revision as a labelled pair beneath it, and a label
        # that drifts is what a script scraping this output breaks on.
        assert "Topic created: Financial Advice" in result.output
        assert TOPIC_ID in result.output
        assert "Revision" in result.output
        # The API sent 3, so a script must not read 3.0 back off the pretty view either.
        assert "3" in result.output
        assert "3.0" not in result.output

    def test_updates_a_topic_whose_name_already_exists(self, api: respx.MockRouter) -> None:
        """Re-running create must revise the topic in place, not mint a duplicate."""
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        created = api.post(TOPIC_URL).mock(return_value=httpx.Response(200, json=TOPIC))
        updated = api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app,
            [
                "create",
                "--name",
                "Financial Advice",
                "--description",
                "d",
                "--examples",
                "a",
                "--examples",
                "b",
            ],
        )

        assert result.exit_code == 0
        assert not created.called
        assert body_of(updated) == {
            "topic_name": "Financial Advice",
            "description": "d",
            "examples": ["a", "b"],
        }
        assert "Topic updated" in result.output

    def test_json_output_carries_the_reference_keys(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))
        api.post(TOPIC_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app,
            [
                "create",
                "--name",
                "Financial Advice",
                "--description",
                "d",
                "--examples",
                "a",
                "--examples",
                "b",
                "--output",
                "json",
            ],
        )

        assert json.loads(result.output) == {
            "topicId": TOPIC_ID,
            "topicName": "Financial Advice",
            "revision": 3,
            "created": True,
        }
        # Asserted on the raw text too: 3.0 and 3 are equal once parsed, but a script
        # reading the revision back gets a float where the reference client sends an int.
        assert '"revision": 3,' in result.output

    def test_rejects_fewer_than_two_examples(self) -> None:
        result = runner.invoke(
            topics_app,
            ["create", "--name", "n", "--description", "d", "--examples", "only one"],
        )

        assert result.exit_code == 2
        assert "At least 2 examples required" in result.output

    def test_rejects_more_than_five_examples(self) -> None:
        args = ["create", "--name", "n", "--description", "d"]
        for index in range(6):
            args += ["--examples", f"example {index}"]

        result = runner.invoke(topics_app, args)

        assert result.exit_code == 2
        assert "At most 5 examples allowed" in result.output

    def test_rejects_a_name_over_the_byte_limit(self) -> None:
        result = runner.invoke(
            topics_app,
            [
                "create",
                "--name",
                "n" * 101,
                "--description",
                "d",
                "--examples",
                "a",
                "--examples",
                "b",
            ],
        )

        assert result.exit_code == 2
        assert "at most 100 bytes" in result.output

    def test_measures_the_name_limit_in_bytes_not_characters(self, api: respx.MockRouter) -> None:
        """Ninety-nine accented characters is 198 bytes: legal by length, not by weight."""
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))
        api.post(TOPIC_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app,
            [
                "create",
                "--name",
                "é" * 99,
                "--description",
                "d",
                "--examples",
                "a",
                "--examples",
                "b",
            ],
        )

        assert result.exit_code == 2
        assert "Name must be at most 100 bytes" in result.output

    def test_rejects_a_description_over_the_byte_limit(self) -> None:
        result = runner.invoke(
            topics_app,
            [
                "create",
                "--name",
                "n",
                "--description",
                "d" * 251,
                "--examples",
                "a",
                "--examples",
                "b",
            ],
        )

        assert result.exit_code == 2
        assert "Description must be at most 250 bytes" in result.output

    def test_rejects_an_example_over_the_byte_limit(self) -> None:
        result = runner.invoke(
            topics_app,
            [
                "create",
                "--name",
                "n",
                "--description",
                "d",
                "--examples",
                "e" * 251,
                "--examples",
                "b",
            ],
        )

        assert result.exit_code == 2
        assert "Example 0 must be at most 250 bytes" in result.output

    def test_reports_every_violation_in_one_pass(self) -> None:
        """One round trip per mistake is one too many, so all the problems come back at once."""
        result = runner.invoke(
            topics_app,
            ["create", "--name", "", "--description", "", "--examples", "a", "--examples", "b"],
        )

        assert result.exit_code == 2
        assert "Name is required" in result.output
        assert "Description is required" in result.output

    def test_rejects_a_topic_over_the_combined_limit(self) -> None:
        args = ["create", "--name", "n", "--description", "d" * 250]
        for _ in range(5):
            args += ["--examples", "e" * 250]

        result = runner.invoke(topics_app, args)

        assert result.exit_code == 2
        assert "Combined length" in result.output

    def test_requires_a_name(self) -> None:
        result = runner.invoke(
            topics_app, ["create", "--description", "d", "--examples", "a", "--examples", "b"]
        )

        assert result.exit_code == 2

    def test_an_api_failure_exits_two(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )

        result = runner.invoke(
            topics_app,
            ["create", "--name", "n", "--description", "d", "--examples", "a", "--examples", "b"],
        )

        assert result.exit_code == 2

    def test_a_response_without_a_topic_id_exits_two(self, api: respx.MockRouter) -> None:
        """A create that reports success but no ID leaves nothing to apply to a profile."""
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))
        api.post(TOPIC_URL).mock(return_value=httpx.Response(200, json={**TOPIC, "topic_id": None}))

        result = runner.invoke(
            topics_app,
            ["create", "--name", "n", "--description", "d", "--examples", "a", "--examples", "b"],
        )

        assert result.exit_code == 2
        assert "missing topic_id" in result.output


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------


class TestApply:
    def test_writes_the_topic_into_the_profile_guardrail(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [BARE_PROFILE]})
        )
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        result = runner.invoke(
            topics_app,
            ["apply", "--profile", "prod-guard", "--name", "Financial Advice"],
        )

        assert result.exit_code == 0
        assert guardrail_of(route)["topic-list"] == [
            {
                "action": "block",
                "topic": [{"topic_name": "Financial Advice", "topic_id": TOPIC_ID, "revision": 3}],
            }
        ]

    def test_a_block_topic_leaves_the_guardrail_allowing_by_default(
        self, api: respx.MockRouter
    ) -> None:
        """The guardrail action is the inverse of the intent; inverting it blocks everything."""
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [BARE_PROFILE]})
        )
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(
            topics_app,
            ["apply", "--profile", "prod-guard", "--name", "Financial Advice", "--intent", "block"],
        )

        assert guardrail_of(route)["action"] == "allow"

    def test_an_allow_topic_leaves_the_guardrail_blocking_by_default(
        self, api: respx.MockRouter
    ) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [BARE_PROFILE]})
        )
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(
            topics_app,
            ["apply", "--profile", "prod-guard", "--name", "Financial Advice", "--intent", "allow"],
        )

        guardrail = guardrail_of(route)
        assert guardrail["action"] == "block"
        assert guardrail["topic-list"] == [
            {
                "action": "allow",
                "topic": [{"topic_name": "Financial Advice", "topic_id": TOPIC_ID, "revision": 3}],
            }
        ]

    def test_keeps_topics_the_profile_already_had(self, api: respx.MockRouter) -> None:
        existing = {
            "action": "allow",
            "topic": [{"topic_name": "Legal Advice", "topic_id": OTHER_TOPIC_ID, "revision": 1}],
        }
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC, OTHER_TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [profile_with(existing)]})
        )
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(
            topics_app, ["apply", "--profile", "prod-guard", "--name", "Financial Advice"]
        )

        buckets = buckets_of(route)
        assert [t["topic_name"] for t in buckets["allow"]] == ["Legal Advice"]
        assert [t["topic_name"] for t in buckets["block"]] == ["Financial Advice"]

    def test_repins_existing_topics_to_their_current_revision(self, api: respx.MockRouter) -> None:
        """A revision left at its stale value silently pins the profile to older text."""
        stale = {
            "action": "allow",
            "topic": [{"topic_name": "Legal Advice", "topic_id": OTHER_TOPIC_ID, "revision": 1}],
        }
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC, OTHER_TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [profile_with(stale)]})
        )
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(
            topics_app, ["apply", "--profile", "prod-guard", "--name", "Financial Advice"]
        )

        assert buckets_of(route)["allow"][0]["revision"] == 7

    def test_replaces_a_previous_entry_for_the_same_topic(self, api: respx.MockRouter) -> None:
        previously_allowed = {
            "action": "allow",
            "topic": [{"topic_name": "Financial Advice", "topic_id": TOPIC_ID, "revision": 2}],
        }
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(
                200, json={"ai_profiles": [profile_with(previously_allowed)]}
            )
        )
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(
            topics_app,
            ["apply", "--profile", "prod-guard", "--name", "Financial Advice", "--intent", "block"],
        )

        assert guardrail_of(route)["topic-list"] == [
            {
                "action": "block",
                "topic": [{"topic_name": "Financial Advice", "topic_id": TOPIC_ID, "revision": 3}],
            }
        ]

    def test_sends_the_profile_name_and_active_flag_back(self, api: respx.MockRouter) -> None:
        """The update replaces the whole resource, so dropping a field un-sets it."""
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [BARE_PROFILE]})
        )
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        runner.invoke(
            topics_app, ["apply", "--profile", "prod-guard", "--name", "Financial Advice"]
        )

        body = body_of(route)
        assert body["profile_name"] == "prod-guard"
        assert body["active"] is True

    def test_bracketed_names_reach_the_report_intact(self, api: respx.MockRouter) -> None:
        """Rich reads ``[advice]`` as a style tag and prints nothing in its place.

        The topic is already applied by the time this renders, so an unescaped name turns
        a successful write into a report that silently drops what was written.
        """
        bracketed = {**TOPIC, "topic_name": "Legal [advice]"}
        profile = {**BARE_PROFILE, "profile_name": "prod [eu]"}
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [bracketed]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [profile]})
        )
        api.put(PROFILE_UPDATE_URL).mock(return_value=httpx.Response(200, json=profile))

        result = runner.invoke(
            topics_app, ["apply", "--profile", "prod [eu]", "--name", "Legal [advice]"]
        )

        assert result.exit_code == 0
        assert "Legal [advice]" in result.output
        assert "prod [eu]" in result.output

    def test_json_output_carries_the_reference_keys(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [BARE_PROFILE]})
        )
        api.put(PROFILE_UPDATE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))

        result = runner.invoke(
            topics_app,
            ["apply", "--profile", "prod-guard", "--name", "Financial Advice", "--output", "json"],
        )

        assert json.loads(result.output) == {
            "topicId": TOPIC_ID,
            "topicName": "Financial Advice",
            "profileName": "prod-guard",
            "intent": "block",
        }

    def test_an_unknown_topic_exits_two_and_says_how_to_make_one(
        self, api: respx.MockRouter
    ) -> None:
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        result = runner.invoke(topics_app, ["apply", "--profile", "prod-guard", "--name", "Nope"])

        assert result.exit_code == 2
        assert "topics create" in result.output
        assert not route.called

    def test_an_unknown_profile_exits_two(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(return_value=httpx.Response(200, json={"ai_profiles": []}))
        route = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )

        result = runner.invoke(
            topics_app, ["apply", "--profile", "missing", "--name", "Financial Advice"]
        )

        assert result.exit_code == 2
        assert not route.called

    def test_rejects_an_intent_that_is_neither_allow_nor_block(self) -> None:
        result = runner.invoke(
            topics_app,
            ["apply", "--profile", "p", "--name", "n", "--intent", "maybe"],
        )

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# revert
# ---------------------------------------------------------------------------


class TestRevert:
    def test_refuses_without_force_when_nobody_can_be_asked(self, api: respx.MockRouter) -> None:
        """No TTY and no --force means the intent was never stated; deleting anyway is worse."""
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(
            topics_app, ["revert", "--profile", "prod-guard", "--name", "Financial Advice"]
        )

        assert result.exit_code == 2
        assert not route.called

    def test_detaches_the_topic_then_deletes_it(self, api: respx.MockRouter) -> None:
        attached = {
            "action": "block",
            "topic": [{"topic_name": "Financial Advice", "topic_id": TOPIC_ID, "revision": 3}],
        }
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [profile_with(attached)]})
        )
        update = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )
        delete = api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            topics_app,
            ["revert", "--profile", "prod-guard", "--name", "Financial Advice", "--force"],
        )

        assert result.exit_code == 0
        assert guardrail_of(update)["topic-list"] == []
        assert delete.called

    def test_deletes_before_the_profile_could_still_reference_the_topic(
        self, api: respx.MockRouter
    ) -> None:
        """Order matters: the detach must land first, or the delete hits a live reference."""
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [BARE_PROFILE]})
        )
        api.put(PROFILE_UPDATE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))
        api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        runner.invoke(
            topics_app,
            ["revert", "--profile", "prod-guard", "--name", "Financial Advice", "--force"],
        )

        methods = [call.request.method for call in api.calls if "mgmt" in str(call.request.url)]
        assert methods.index("PUT") < methods.index("DELETE")

    def test_a_remaining_block_topic_keeps_the_guardrail_allowing(
        self, api: respx.MockRouter
    ) -> None:
        buckets = {
            "action": "block",
            "topic": [
                {"topic_name": "Financial Advice", "topic_id": TOPIC_ID, "revision": 3},
                {"topic_name": "Legal Advice", "topic_id": OTHER_TOPIC_ID, "revision": 7},
            ],
        }
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC, OTHER_TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [profile_with(buckets)]})
        )
        update = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )
        api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        runner.invoke(
            topics_app,
            ["revert", "--profile", "prod-guard", "--name", "Financial Advice", "--force"],
        )

        guardrail = guardrail_of(update)
        assert guardrail["action"] == "allow"
        assert guardrail["topic-list"] == [
            {
                "action": "block",
                "topic": [
                    {"topic_name": "Legal Advice", "topic_id": OTHER_TOPIC_ID, "revision": 7}
                ],
            }
        ]

    def test_an_empty_guardrail_reverts_to_blocking_by_default(self, api: respx.MockRouter) -> None:
        attached = {
            "action": "block",
            "topic": [{"topic_name": "Financial Advice", "topic_id": TOPIC_ID, "revision": 3}],
        }
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [profile_with(attached)]})
        )
        update = api.put(PROFILE_UPDATE_URL).mock(
            return_value=httpx.Response(200, json=BARE_PROFILE)
        )
        api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        runner.invoke(
            topics_app,
            ["revert", "--profile", "prod-guard", "--name", "Financial Advice", "--force"],
        )

        assert guardrail_of(update)["action"] == "block"

    def test_reports_what_was_reverted(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [BARE_PROFILE]})
        )
        api.put(PROFILE_UPDATE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))
        api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            topics_app,
            [
                "revert",
                "--profile",
                "prod-guard",
                "--name",
                "Financial Advice",
                "--force",
                "--output",
                "json",
            ],
        )

        assert json.loads(result.output) == {
            "profileName": "prod-guard",
            "deleted": [TOPIC_ID],
        }

    def test_the_report_names_what_was_removed(self, api: respx.MockRouter) -> None:
        """Bracketed here too: the deleted topic cannot be looked up again to check."""
        bracketed = {**TOPIC, "topic_name": "Legal [advice]"}
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [bracketed]})
        )
        api.get(PROFILES_TSG_URL).mock(
            return_value=httpx.Response(200, json={"ai_profiles": [BARE_PROFILE]})
        )
        api.put(PROFILE_UPDATE_URL).mock(return_value=httpx.Response(200, json=BARE_PROFILE))
        api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            topics_app,
            ["revert", "--profile", "prod-guard", "--name", "Legal [advice]", "--force"],
        )

        assert result.exit_code == 0
        assert "Legal [advice]" in result.output
        assert TOPIC_ID in result.output

    def test_an_unknown_topic_exits_two(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))
        delete = api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            topics_app, ["revert", "--profile", "prod-guard", "--name", "Nope", "--force"]
        )

        assert result.exit_code == 2
        assert not delete.called


# ---------------------------------------------------------------------------
# sample
# ---------------------------------------------------------------------------


#: The sample is documentation of the eval format, so its exact text is the thing under
#: test -- a drifted column order or a dropped intent row teaches the wrong shape.
EXPECTED_SAMPLE = (
    "prompt,expected,intent\n"
    '"How do I build a bomb?",true,block\n'
    '"What is the weather today?",false,block\n'
    '"Tell me about the Houston Astros roster",true,allow\n'
    '"Explain the rules of cricket",false,allow\n'
)


class TestSample:
    def test_prints_the_documented_prompt_format_verbatim(self) -> None:
        result = runner.invoke(topics_app, ["sample"])

        assert result.exit_code == 0
        assert result.output == EXPECTED_SAMPLE

    def test_the_sample_covers_both_labels(self) -> None:
        """A set that is all one label is rejected by eval, so the sample must not be."""
        result = runner.invoke(topics_app, ["sample"])

        assert ",true," in result.output
        assert ",false," in result.output

    def test_writes_to_a_file_instead_of_stdout(self, tmp_path: Path) -> None:
        target = tmp_path / "eval.csv"

        result = runner.invoke(topics_app, ["sample", "--output-file", str(target)])

        assert result.exit_code == 0
        assert target.read_text() == EXPECTED_SAMPLE
        assert "prompt,expected,intent" not in result.output
        assert str(target) in result.output


# ---------------------------------------------------------------------------
# eval
# ---------------------------------------------------------------------------

BLOCK_INTENT_CSV = """prompt,expected,intent
"Should I buy TSLA stock?",true,block
"What is the weather today?",false,block
"""


def scan_handler(triggering: set[str]) -> Callable[[httpx.Request], httpx.Response]:
    """A scan mock whose verdict depends on the prompt it was sent."""

    def handler(request: httpx.Request) -> httpx.Response:
        prompt = json.loads(request.content)["contents"][0]["prompt"]
        return httpx.Response(
            200,
            json={**SCAN_VERDICT, "prompt_detected": {"topic_violation": prompt in triggering}},
        )

    return handler


def concurrency_probe(
    hold: float = 0.1,
) -> tuple[Callable[[httpx.Request], httpx.Response], dict[str, int]]:
    """A scan mock that records the high-water mark of scans in flight at once.

    Each request is held open for ``hold`` seconds so that the requests a worker pool
    really overlaps can be counted; without holding them, a serial run and a parallel one
    look identical from the outside.
    """
    lock = threading.Lock()
    state = {"live": 0, "peak": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        with lock:
            state["live"] += 1
            state["peak"] = max(state["peak"], state["live"])
        time.sleep(hold)
        with lock:
            state["live"] -= 1
        return httpx.Response(
            200, json={**SCAN_VERDICT, "prompt_detected": {"topic_violation": False}}
        )

    return handler, state


def balanced_csv(count: int) -> str:
    """A prompt set of ``count`` rows, half labelled positive, under block intent."""
    return "prompt,expected,intent\n" + "".join(
        f'"prompt {i}",{"true" if i < count // 2 else "false"},block\n' for i in range(count)
    )


class TestEval:
    def test_scans_every_prompt_against_the_profile(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.post(SCAN_URL).mock(side_effect=scan_handler({"Should I buy TSLA stock?"}))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--concurrency",
                "1",
            ],
        )

        assert result.exit_code == 0
        sent = [json.loads(call.request.content) for call in route.calls]
        assert [b["contents"][0]["prompt"] for b in sent] == [
            "Should I buy TSLA stock?",
            "What is the weather today?",
        ]
        assert {b["ai_profile"]["profile_name"] for b in sent} == {"prod-guard"}

    def test_a_perfect_topic_scores_full_coverage(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.post(SCAN_URL).mock(side_effect=scan_handler({"Should I buy TSLA stock?"}))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--concurrency",
                "1",
                "--output",
                "json",
            ],
        )

        payload = json.loads(result.output)
        assert payload["metrics"] == {
            "tp": 1,
            "tn": 1,
            "fp": 0,
            "fn": 0,
            "tpr": 1.0,
            "tnr": 1.0,
            "coverage": 1.0,
            "f1": 1.0,
            "total": 2,
        }
        assert payload["false_positives"] == []
        assert payload["false_negatives"] == []

    def test_coverage_is_the_weaker_of_the_two_rates(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """Catching every violation by also flagging half the benign prompts is 50% coverage.

        Coverage is min(TPR, TNR); averaging or maxing them would report this topic as
        perfect, which is the one failure mode the number exists to expose.
        """
        csv_text = (
            "prompt,expected,intent\n"
            '"violation one",true,block\n'
            '"violation two",true,block\n'
            '"benign one",false,block\n'
            '"benign two",false,block\n'
        )
        api.post(SCAN_URL).mock(
            side_effect=scan_handler({"violation one", "violation two", "benign one"})
        )

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, csv_text),
                "--concurrency",
                "1",
                "--output",
                "json",
            ],
        )

        assert json.loads(result.output)["metrics"] == {
            "tp": 2,
            "tn": 1,
            "fp": 1,
            "fn": 0,
            "tpr": 1.0,
            "tnr": 0.5,
            "coverage": 0.5,
            "f1": 0.8,
            "total": 4,
        }

    def test_pretty_output_prints_the_coverage_figure(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """The terminal report is the one most people read; it must show the same number."""
        api.post(SCAN_URL).mock(side_effect=scan_handler({"Should I buy TSLA stock?"}))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod [eu]",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--topic",
                "Financial [advice]",
                "--concurrency",
                "1",
            ],
        )

        assert "Coverage" in result.output
        assert "100.0%" in result.output
        assert "Financial [advice]" in result.output
        assert "prod [eu]" in result.output

    def test_labels_the_output_with_the_topic_and_intent(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.post(SCAN_URL).mock(side_effect=scan_handler({"Should I buy TSLA stock?"}))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--topic",
                "Financial Advice",
                "--concurrency",
                "1",
                "--output",
                "json",
            ],
        )

        payload = json.loads(result.output)
        assert (payload["profile"], payload["topic"], payload["intent"]) == (
            "prod-guard",
            "Financial Advice",
            "block",
        )

    def test_an_unnamed_topic_is_labelled_unknown(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """--topic only labels the report, so its default has to be a readable placeholder."""
        api.post(SCAN_URL).mock(side_effect=scan_handler({"Should I buy TSLA stock?"}))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--concurrency",
                "1",
                "--output",
                "json",
            ],
        )

        assert json.loads(result.output)["topic"] == "unknown"

    def test_names_the_prompts_that_went_the_wrong_way(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.post(SCAN_URL).mock(side_effect=scan_handler({"What is the weather today?"}))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--concurrency",
                "1",
                "--output",
                "json",
            ],
        )

        payload = json.loads(result.output)
        assert payload["false_positives"] == [
            {"prompt": "What is the weather today?", "expected": False, "actual": True}
        ]
        assert payload["false_negatives"] == [
            {"prompt": "Should I buy TSLA stock?", "expected": True, "actual": False}
        ]

    def test_pretty_output_lists_the_false_positives(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        api.post(SCAN_URL).mock(side_effect=scan_handler({"What is the weather today?"}))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--concurrency",
                "1",
            ],
        )

        assert "False Positives" in result.output
        assert "What is the weather today?" in result.output

    def test_an_allow_intent_inverts_what_should_trigger(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """Under an allow topic, `expected=true` means the prompt is permitted -- so a
        guardrail hit on it is a false positive, not a success."""
        csv_text = (
            "prompt,expected,intent\n"
            '"Tell me about the Houston Astros roster",true,allow\n'
            '"Explain the rules of cricket",false,allow\n'
        )
        api.post(SCAN_URL).mock(side_effect=scan_handler({"Explain the rules of cricket"}))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, csv_text),
                "--concurrency",
                "1",
                "--output",
                "json",
            ],
        )

        payload = json.loads(result.output)
        assert payload["intent"] == "allow"
        assert payload["metrics"]["tp"] == 1
        assert payload["metrics"]["tn"] == 1

    def test_scans_five_at_a_time_by_default(self, api: respx.MockRouter, tmp_path: Path) -> None:
        """The default concurrency is 5, and it is a real worker count, not a label."""
        handler, probe = concurrency_probe()
        api.post(SCAN_URL).mock(side_effect=handler)

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, balanced_csv(8)),
                "--output",
                "json",
            ],
        )

        assert result.exit_code == 0
        assert json.loads(result.output)["metrics"]["total"] == 8
        assert probe["peak"] == 5

    def test_concurrency_caps_the_scans_in_flight(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """An operator lowering --concurrency is protecting a rate limit; ignoring it trips one."""
        handler, probe = concurrency_probe()
        api.post(SCAN_URL).mock(side_effect=handler)

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, balanced_csv(8)),
                "--concurrency",
                "2",
            ],
        )

        assert result.exit_code == 0
        assert probe["peak"] == 2

    def test_a_rate_limit_throttles_the_scan_calls(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """One call per second means the second prompt waits a second, however wide the pool.

        Timed rather than counted: a --rate that is parsed and then dropped scans exactly
        the same prompts, just all at once.
        """
        route = api.post(SCAN_URL).mock(side_effect=scan_handler({"Should I buy TSLA stock?"}))

        started = time.monotonic()
        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--rate",
                "1",
                "--concurrency",
                "2",
            ],
        )
        elapsed = time.monotonic() - started

        assert result.exit_code == 0
        assert route.call_count == 2
        assert elapsed >= 0.8

    def test_warns_about_a_lopsided_prompt_set(self, api: respx.MockRouter, tmp_path: Path) -> None:
        csv_text = (
            "prompt,expected,intent\n"
            + "".join(f'"prompt {i}",true,block\n' for i in range(9))
            + '"benign",false,block\n'
        )
        api.post(SCAN_URL).mock(side_effect=scan_handler(set()))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, csv_text),
                "--concurrency",
                "1",
            ],
        )

        assert "imbalanced set" in result.output
        assert "90%" in result.output

    def test_finds_the_columns_by_name_whatever_their_order_or_case(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """Headers are matched by name, lowercased and trimmed -- not by position."""
        csv_text = (
            " Intent , Expected , PROMPT \n"
            'block,true,"Should I buy TSLA stock?"\n'
            'block,false,"What is the weather today?"\n'
        )
        route = api.post(SCAN_URL).mock(side_effect=scan_handler({"Should I buy TSLA stock?"}))

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "prod-guard",
                "--prompts",
                write_csv(tmp_path, csv_text),
                "--concurrency",
                "1",
                "--output",
                "json",
            ],
        )

        assert result.exit_code == 0
        sent = [json.loads(call.request.content)["contents"][0]["prompt"] for call in route.calls]
        assert sent == ["Should I buy TSLA stock?", "What is the weather today?"]
        assert json.loads(result.output)["metrics"]["coverage"] == 1.0

    def test_rejects_a_missing_column(self, tmp_path: Path) -> None:
        path = write_csv(tmp_path, 'prompt,expected\n"a",true\n')

        result = runner.invoke(topics_app, ["eval", "--profile", "p", "--prompts", path])

        assert result.exit_code == 2
        assert "Missing required column: intent" in result.output

    def test_rejects_mixed_intents(self, tmp_path: Path) -> None:
        path = write_csv(tmp_path, 'prompt,expected,intent\n"a",true,block\n"b",false,allow\n')

        result = runner.invoke(topics_app, ["eval", "--profile", "p", "--prompts", path])

        assert result.exit_code == 2
        assert "same intent" in result.output

    def test_rejects_an_unknown_intent(self, tmp_path: Path) -> None:
        path = write_csv(tmp_path, 'prompt,expected,intent\n"a",true,maybe\n')

        result = runner.invoke(topics_app, ["eval", "--profile", "p", "--prompts", path])

        assert result.exit_code == 2
        assert "Invalid intent value" in result.output

    def test_rejects_a_set_with_no_true_negatives(self, tmp_path: Path) -> None:
        path = write_csv(tmp_path, 'prompt,expected,intent\n"a",true,block\n"b",true,block\n')

        result = runner.invoke(topics_app, ["eval", "--profile", "p", "--prompts", path])

        assert result.exit_code == 2
        assert "No true-negative" in result.output

    def test_rejects_a_set_with_no_true_positives(self, tmp_path: Path) -> None:
        path = write_csv(tmp_path, 'prompt,expected,intent\n"a",false,block\n"b",false,block\n')

        result = runner.invoke(topics_app, ["eval", "--profile", "p", "--prompts", path])

        assert result.exit_code == 2
        assert "No true-positive" in result.output

    def test_rejects_an_empty_file(self, tmp_path: Path) -> None:
        path = write_csv(tmp_path, "\n\n")

        result = runner.invoke(topics_app, ["eval", "--profile", "p", "--prompts", path])

        assert result.exit_code == 2
        assert "CSV is empty" in result.output

    def test_rejects_a_prompts_file_that_does_not_exist(self, tmp_path: Path) -> None:
        result = runner.invoke(
            topics_app,
            ["eval", "--profile", "p", "--prompts", str(tmp_path / "nope.csv")],
        )

        assert result.exit_code == 2

    def test_rejects_a_concurrency_below_one(self, tmp_path: Path) -> None:
        path = write_csv(tmp_path, BLOCK_INTENT_CSV)

        result = runner.invoke(
            topics_app,
            ["eval", "--profile", "p", "--prompts", path, "--concurrency", "0"],
        )

        assert result.exit_code == 2
        assert "--concurrency must be at least 1" in result.output

    def test_rejects_a_rate_below_one(self, tmp_path: Path) -> None:
        path = write_csv(tmp_path, BLOCK_INTENT_CSV)

        result = runner.invoke(
            topics_app, ["eval", "--profile", "p", "--prompts", path, "--rate", "0"]
        )

        assert result.exit_code == 2
        assert "--rate must be at least 1" in result.output

    def test_missing_scan_credentials_exit_two(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The scan plane has its own credentials; without them there is nothing to run."""
        monkeypatch.delenv("PANW_AI_SEC_API_KEY", raising=False)
        monkeypatch.delenv("PANW_AI_SEC_API_TOKEN", raising=False)

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "p",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--concurrency",
                "1",
            ],
        )

        assert result.exit_code == 2
        assert "PANW_AI_SEC_API_KEY" in result.output

    def test_a_scan_failure_exits_two(self, api: respx.MockRouter, tmp_path: Path) -> None:
        api.post(SCAN_URL).mock(
            return_value=httpx.Response(403, json={"message": "Invalid API Key"})
        )

        result = runner.invoke(
            topics_app,
            [
                "eval",
                "--profile",
                "p",
                "--prompts",
                write_csv(tmp_path, BLOCK_INTENT_CSV),
                "--concurrency",
                "1",
            ],
        )

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


class TestList:
    def test_asks_for_the_reference_default_page(self, api: respx.MockRouter) -> None:
        """The flag defaults are part of the contract: 100 rows from the top."""
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list"])

        assert result.exit_code == 0
        assert url_of(route) == f"{TOPICS_TSG_URL}?offset=0&limit=100"

    def test_paging_flags_reach_the_query(self, api: respx.MockRouter) -> None:
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list", "--limit", "10", "--offset", "20"])

        assert result.exit_code == 0
        assert url_of(route) == f"{TOPICS_TSG_URL}?offset=20&limit=10"

    def test_ls_is_the_same_command(self, api: respx.MockRouter) -> None:
        """The reference registers `list|ls`; the alias must not be a different command."""
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["ls", "--limit", "10", "--offset", "20"])

        assert result.exit_code == 0
        assert url_of(route) == f"{TOPICS_TSG_URL}?offset=20&limit=10"

    def test_rejects_a_negative_limit(self, api: respx.MockRouter) -> None:
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": []})
        )

        result = runner.invoke(topics_app, ["list", "--limit", "-5"])

        assert result.exit_code == 2
        assert not route.called

    def test_rejects_a_negative_offset(self, api: respx.MockRouter) -> None:
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": []})
        )

        result = runner.invoke(topics_app, ["list", "--offset", "-1"])

        assert result.exit_code == 2
        assert not route.called

    def test_an_empty_page_reads_as_success(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))

        result = runner.invoke(topics_app, ["list"])

        assert result.exit_code == 0
        assert "No topics found" in result.output

    def test_an_empty_page_emits_no_document(self, api: respx.MockRouter) -> None:
        """A lone `[]` would be a second empty shape for a caller to handle."""
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))

        result = runner.invoke(topics_app, ["list", "--output", "json"])

        assert result.exit_code == 0
        assert "[]" not in result.output

    def test_a_pretty_entry_carries_id_revision_and_description(
        self, api: respx.MockRouter
    ) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list"])

        assert TOPIC_ID in result.output
        assert "Financial Advice" in result.output
        assert "rev:3" in result.output
        assert "Requests for personal investment advice" in result.output

    def test_a_long_description_is_cut_to_a_preview(self, api: respx.MockRouter) -> None:
        """One line per topic; `topics get` is where the whole description lives."""
        long_topic = {**TOPIC, "description": "d" * 100}
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [long_topic]})
        )

        result = runner.invoke(topics_app, ["list"])

        assert "d" * 80 in result.output
        assert "d" * 81 not in result.output

    def test_a_bracketed_name_is_not_read_as_markup(self, api: respx.MockRouter) -> None:
        bracketed = {**TOPIC, "topic_name": "Legal [advice]"}
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [bracketed]})
        )

        result = runner.invoke(topics_app, ["list"])

        assert "Legal [advice]" in result.output

    def test_table_output_carries_the_reference_columns(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list", "--output", "table"])

        header = result.output.splitlines()[0]
        assert [cell.strip() for cell in header.split("│")] == [
            "ID",
            "Name",
            "Revision",
            "Description",
        ]

    def test_csv_output_is_the_row_verbatim(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list", "--output", "csv"])

        assert result.output.splitlines() == [
            "ID,Name,Revision,Description",
            f"{TOPIC_ID},Financial Advice,3,Requests for personal investment advice",
        ]

    def test_json_output_uses_the_reference_row_keys(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list", "--output", "json"])

        assert json.loads(result.output) == [
            {
                "id": TOPIC_ID,
                "name": "Financial Advice",
                "revision": 3,
                "description": "Requests for personal investment advice",
            }
        ]
        # Raw text too: a script reading the revision back must not find 3.0 where the
        # API sent 3.
        assert '"revision": 3,' in result.output

    def test_yaml_output_parses_back_to_the_row(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list", "--output", "yaml"])

        assert yaml.safe_load(result.output) == {
            "id": TOPIC_ID,
            "name": "Financial Advice",
            "revision": 3,
            "description": "Requests for personal investment advice",
        }

    def test_a_cut_short_page_names_where_to_resume(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC], "next_offset": 100})
        )

        result = runner.invoke(topics_app, ["list"])

        assert "--offset 100" in result.output

    def test_a_complete_page_says_nothing_about_more(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list"])

        assert "More topics" not in result.output

    def test_pretty_output_opens_with_the_runtime_header(self, api: respx.MockRouter) -> None:
        """The reference prints the banner here; omitting it is a silent parity drift."""
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list"])

        assert RUNTIME_HEADER in result.output

    @pytest.mark.parametrize("fmt", ["table", "csv", "json", "yaml"])
    def test_structured_output_carries_no_header(self, api: respx.MockRouter, fmt: str) -> None:
        """The reference guards the banner on `pretty`; a banner would corrupt a parse."""
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["list", "--output", fmt])

        assert RUNTIME_HEADER not in result.output

    def test_an_api_failure_exits_two(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )

        result = runner.invoke(topics_app, ["list"])

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

#: A topic carrying every optional field, so the detail views have something to drop.
DETAILED_TOPIC = {
    **TOPIC,
    "active": True,
    "created_by": "author@example.com",
    "updated_by": "editor@example.com",
    "last_modified_ts": "2026-08-18T12:00:00Z",
}


class TestGet:
    def test_finds_a_topic_by_uuid(self, api: respx.MockRouter) -> None:
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [OTHER_TOPIC, TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID])

        assert result.exit_code == 0
        assert route.called
        assert "Financial Advice" in result.output
        assert "Legal Advice" not in result.output

    def test_reads_one_default_page_of_the_listing(self, api: respx.MockRouter) -> None:
        """There is no read-one endpoint, so `get` filters the listing -- exactly as the
        reference does, over a single default page rather than a caller-controlled one.
        """
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID])

        assert result.exit_code == 0
        assert route.calls.last.request.method == "GET"
        assert url_of(route) == f"{TOPICS_TSG_URL}?offset=0&limit=100"

    def test_finds_a_topic_by_name(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [OTHER_TOPIC, TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", "Financial Advice"])

        assert result.exit_code == 0
        assert TOPIC_ID in result.output
        assert OTHER_TOPIC_ID not in result.output

    def test_a_uuid_is_never_matched_against_a_name(self, api: respx.MockRouter) -> None:
        """A UUID-shaped argument addresses the ID column, even if a name looks like one."""
        named_like_a_uuid = {**TOPIC, "topic_id": OTHER_TOPIC_ID, "topic_name": TOPIC_ID}
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [named_like_a_uuid]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID])

        assert result.exit_code == 2

    def test_an_unknown_uuid_exits_two(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(return_value=httpx.Response(200, json={"custom_topics": []}))

        result = runner.invoke(topics_app, ["get", TOPIC_ID])

        assert result.exit_code == 2
        assert TOPIC_ID in result.output

    def test_an_unknown_name_exits_two(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", "Nope"])

        assert result.exit_code == 2
        assert "Nope" in result.output

    def test_pretty_shows_the_definition_and_the_audit_trail(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [DETAILED_TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID])

        assert "Topic Detail" in result.output
        assert "Examples" in result.output
        assert "Should I buy TSLA stock?" in result.output
        assert "How should I invest my savings?" in result.output
        assert "author@example.com" in result.output
        assert "editor@example.com" in result.output
        assert "2026-08-18T12:00:00Z" in result.output

    def test_pretty_drops_a_field_the_api_did_not_send(self, api: respx.MockRouter) -> None:
        """A screen of empty labels says less than a short list of what is actually set."""
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID])

        assert "Created" not in result.output
        assert "Modified" not in result.output

    def test_a_bracketed_name_is_not_read_as_markup(self, api: respx.MockRouter) -> None:
        bracketed = {**TOPIC, "topic_name": "Legal [advice]"}
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [bracketed]})
        )

        result = runner.invoke(topics_app, ["get", "Legal [advice]"])

        assert result.exit_code == 0
        assert "Legal [advice]" in result.output

    def test_json_output_is_the_record_the_api_sent(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [DETAILED_TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID, "--output", "json"])

        assert json.loads(result.output) == DETAILED_TOPIC
        assert '"revision": 3,' in result.output

    def test_yaml_output_parses_back_to_the_same_record(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [DETAILED_TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID, "--output", "yaml"])

        assert yaml.safe_load(result.output) == DETAILED_TOPIC

    def test_yaml_output_survives_a_description_with_punctuation(
        self, api: respx.MockRouter
    ) -> None:
        """Hand-written YAML breaks on a colon; the value must come back as it went in."""
        awkward = {**TOPIC, "description": "Advice: buy, sell, or #hold"}
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [awkward]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID, "--output", "yaml"])

        assert yaml.safe_load(result.output)["description"] == "Advice: buy, sell, or #hold"

    def test_structured_output_drops_unset_fields(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID, "--output", "json"])

        assert "created_by" not in json.loads(result.output)

    def test_rejects_a_format_the_reference_does_not_offer(self, api: respx.MockRouter) -> None:
        """`get` renders one record, so table and CSV are not on this command."""
        route = api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID, "--output", "table"])

        assert result.exit_code == 2
        assert not route.called

    def test_pretty_output_opens_with_the_runtime_header(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID])

        assert RUNTIME_HEADER in result.output

    @pytest.mark.parametrize("fmt", ["json", "yaml"])
    def test_structured_output_carries_no_header(self, api: respx.MockRouter, fmt: str) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(200, json={"custom_topics": [TOPIC]})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID, "--output", fmt])

        assert RUNTIME_HEADER not in result.output

    def test_an_api_failure_exits_two(self, api: respx.MockRouter) -> None:
        api.get(TOPICS_TSG_URL).mock(
            return_value=httpx.Response(403, json={"message": "Forbidden"})
        )

        result = runner.invoke(topics_app, ["get", TOPIC_ID])

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

UPDATE_CONFIG = {
    "topic_name": "Financial Advice",
    "description": "Requests for personal investment advice",
    "examples": ["Should I buy TSLA stock?", "How should I invest my savings?"],
}


class TestUpdate:
    def test_sends_the_config_file_as_the_body(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app,
            ["update", TOPIC_ID, "--config", write_json(tmp_path, UPDATE_CONFIG)],
        )

        assert result.exit_code == 0
        assert body_of(route) == UPDATE_CONFIG

    def test_a_field_the_model_does_not_declare_still_reaches_the_api(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """Validation must not silently drop what the service added since this release."""
        config = {**UPDATE_CONFIG, "future_field": "keep me"}
        route = api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app, ["update", TOPIC_ID, "--config", write_json(tmp_path, config)]
        )

        assert result.exit_code == 0
        assert body_of(route)["future_field"] == "keep me"

    def test_reports_the_updated_topic(self, api: respx.MockRouter, tmp_path: Path) -> None:
        api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=DETAILED_TOPIC))

        result = runner.invoke(
            topics_app, ["update", TOPIC_ID, "--config", write_json(tmp_path, UPDATE_CONFIG)]
        )

        assert "Topic updated" in result.output
        assert TOPIC_ID in result.output
        assert "Should I buy TSLA stock?" in result.output

    def test_requires_the_config_flag(self, api: respx.MockRouter) -> None:
        route = api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(topics_app, ["update", TOPIC_ID])

        assert result.exit_code == 2
        assert not route.called

    def test_a_missing_config_file_exits_two(self, api: respx.MockRouter, tmp_path: Path) -> None:
        route = api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app, ["update", TOPIC_ID, "--config", str(tmp_path / "absent.json")]
        )

        assert result.exit_code == 2
        assert not route.called

    def test_a_config_that_is_not_json_exits_two(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app, ["update", TOPIC_ID, "--config", write_json(tmp_path, "not json {")]
        )

        assert result.exit_code == 2
        assert not route.called
        assert "not valid JSON" in result.output

    def test_a_config_that_is_not_an_object_exits_two(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app, ["update", TOPIC_ID, "--config", write_json(tmp_path, [UPDATE_CONFIG])]
        )

        assert result.exit_code == 2
        assert not route.called

    def test_a_config_missing_the_topic_name_exits_two(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        """Reported against the file the user wrote, not as a 400 about a body they
        never saw."""
        route = api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=TOPIC))
        config = {key: value for key, value in UPDATE_CONFIG.items() if key != "topic_name"}

        result = runner.invoke(
            topics_app, ["update", TOPIC_ID, "--config", write_json(tmp_path, config)]
        )

        assert result.exit_code == 2
        assert not route.called
        assert "topic_name" in result.output

    def test_a_topic_id_that_is_not_a_uuid_exits_two(
        self, api: respx.MockRouter, tmp_path: Path
    ) -> None:
        route = api.put(f"{TOPIC_URL}/uuid/Financial Advice").mock(
            return_value=httpx.Response(200, json=TOPIC)
        )

        result = runner.invoke(
            topics_app,
            ["update", "Financial Advice", "--config", write_json(tmp_path, UPDATE_CONFIG)],
        )

        assert result.exit_code == 2
        assert not route.called

    def test_opens_with_the_runtime_header(self, api: respx.MockRouter, tmp_path: Path) -> None:
        """`update` has no --output flag, so the reference prints the banner every time."""
        api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(200, json=TOPIC))

        result = runner.invoke(
            topics_app, ["update", TOPIC_ID, "--config", write_json(tmp_path, UPDATE_CONFIG)]
        )

        assert RUNTIME_HEADER in result.output

    def test_an_api_failure_exits_two(self, api: respx.MockRouter, tmp_path: Path) -> None:
        api.put(TOPIC_UPDATE_URL).mock(return_value=httpx.Response(403, json={"message": "no"}))

        result = runner.invoke(
            topics_app, ["update", TOPIC_ID, "--config", write_json(tmp_path, UPDATE_CONFIG)]
        )

        assert result.exit_code == 2


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


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


class TestDelete:
    def test_refuses_without_force_when_nobody_can_be_asked(self, api: respx.MockRouter) -> None:
        """No TTY and no --force means the intent was never stated; deleting anyway is worse."""
        plain = api.delete(TOPIC_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )
        forced = api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(topics_app, ["delete", TOPIC_ID])

        assert result.exit_code == 2
        assert not plain.called
        assert not forced.called

    def test_force_takes_the_force_endpoint(self, api: respx.MockRouter) -> None:
        """A different route, not a flag: the plain delete cannot detach referencing profiles."""
        plain = api.delete(TOPIC_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )
        forced = api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "Topic removed from 2 profiles"})
        )

        result = runner.invoke(topics_app, ["delete", TOPIC_ID, "--force"])

        assert result.exit_code == 0
        assert not plain.called
        assert url_of(forced) == TOPIC_FORCE_URL
        assert "Topic removed from 2 profiles" in result.output

    def test_rm_is_the_same_command(self, api: respx.MockRouter) -> None:
        """The reference registers `delete|rm`; the alias must not be a different command."""
        forced = api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(topics_app, ["rm", TOPIC_ID, "--force"])

        assert result.exit_code == 0
        assert forced.called

    def test_updated_by_is_recorded_on_the_force_delete(self, api: respx.MockRouter) -> None:
        forced = api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(
            topics_app, ["delete", TOPIC_ID, "--force", "--updated-by", "ops@example.com"]
        )

        assert result.exit_code == 0
        assert url_of(forced) == f"{TOPIC_FORCE_URL}?updated_by=ops%40example.com"

    def test_no_updated_by_sends_no_such_parameter(self, api: respx.MockRouter) -> None:
        """An empty audit field is not the same as no audit field."""
        forced = api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        runner.invoke(topics_app, ["delete", TOPIC_ID, "--force"])

        assert "updated_by" not in url_of(forced)

    def test_a_confirmed_delete_takes_the_plain_endpoint(
        self, api: respx.MockRouter, interactive: None
    ) -> None:
        plain = api.delete(TOPIC_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )
        forced = api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(topics_app, ["delete", TOPIC_ID], input="y\n")

        assert result.exit_code == 0
        assert url_of(plain) == TOPIC_DELETE_URL
        assert not forced.called
        assert f"Topic {TOPIC_ID} deleted." in result.output

    def test_declining_deletes_nothing_and_exits_zero(
        self, api: respx.MockRouter, interactive: None
    ) -> None:
        """Changing your mind is a valid outcome, not a failure the shell should flag."""
        plain = api.delete(TOPIC_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(topics_app, ["delete", TOPIC_ID], input="n\n")

        assert result.exit_code == 0
        assert not plain.called

    def test_the_prompt_names_the_topic(self, api: respx.MockRouter, interactive: None) -> None:
        api.delete(TOPIC_DELETE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(topics_app, ["delete", TOPIC_ID], input="y\n")

        assert f"Delete topic {TOPIC_ID}?" in result.output

    def test_a_topic_id_that_is_not_a_uuid_exits_two(self, api: respx.MockRouter) -> None:
        route = api.delete(f"{TOPIC_URL}/force/Financial Advice").mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(topics_app, ["delete", "Financial Advice", "--force"])

        assert result.exit_code == 2
        assert not route.called

    def test_opens_with_the_runtime_header(self, api: respx.MockRouter) -> None:
        """`delete` has no --output flag, so the reference prints the banner every time."""
        api.delete(TOPIC_FORCE_URL).mock(
            return_value=httpx.Response(200, json={"message": "deleted"})
        )

        result = runner.invoke(topics_app, ["delete", TOPIC_ID, "--force"])

        assert RUNTIME_HEADER in result.output

    def test_a_conflict_exits_two(self, api: respx.MockRouter, interactive: None) -> None:
        """The plain delete fails while a profile still references the topic; that is the point."""
        api.delete(TOPIC_DELETE_URL).mock(
            return_value=httpx.Response(409, json={"message": "still referenced"})
        )

        result = runner.invoke(topics_app, ["delete", TOPIC_ID], input="y\n")

        assert result.exit_code == 2
