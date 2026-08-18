"""Contract tests for the Red Team core clients.

These assert the exact request that goes on the wire -- method, URL, query parameters,
headers, and body -- which is what keeps the port honest against the reference
implementation. Three things in this API are easy to get subtly wrong and are pinned
here on purpose: which plane each call belongs to, the lower-case spelling of boolean
query parameters, and whether ``validate`` is sent at all.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
import respx

from prisma_airs.constants import (
    DEFAULT_RED_TEAM_DATA_ENDPOINT,
    DEFAULT_RED_TEAM_MGMT_ENDPOINT,
    DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
    ENV_PREFIX_MGMT,
    ENV_PREFIX_RED_TEAM,
)
from prisma_airs.errors import AISecMissingVariableError, AISecPayloadError, AISecServerError
from prisma_airs.models.red_team import (
    AdapterCreateRequest,
    AdapterUpdateRequest,
    AdapterValidateRequest,
    AdapterVar,
    AdapterVarType,
    AttackMultiTurnOutput,
    AttackOutput,
    JobCreateRequest,
    RestConnectionParams,
    SentimentRequest,
    StaticJobMetadata,
    TargetAuthValidationRequest,
    TargetContextUpdate,
    TargetCreateRequest,
    TargetJobRequest,
    TargetProbeRequest,
    TargetUpdateRequest,
)
from prisma_airs.red_team.red_team_core import RedTeamClient

DATA = DEFAULT_RED_TEAM_DATA_ENDPOINT
MGMT = DEFAULT_RED_TEAM_MGMT_ENDPOINT

TOKEN = "tok-abc"
TSG = "1016244978"

JOB_ID = "550e8400-e29b-41d4-a716-446655440000"
TARGET_ID = "660e8400-e29b-41d4-a716-446655440001"
ATTACK_ID = "770e8400-e29b-41d4-a716-446655440002"
GOAL_ID = "880e8400-e29b-41d4-a716-446655440003"
STREAM_ID = "990e8400-e29b-41d4-a716-446655440004"
ADAPTER_ID = "aa0e8400-e29b-41d4-a716-446655440005"
CHANNEL_ID = "bb0e8400-e29b-41d4-a716-446655440006"
NOT_A_UUID = "550e8400e29b41d4a716446655440000"

# --- Response payloads -----------------------------------------------------

TARGET_REF = {
    "uuid": TARGET_ID,
    "tsg_id": TSG,
    "name": "prod-chatbot",
    "status": "READY",
    "active": True,
    "validated": True,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-02T00:00:00Z",
}
JOB = {
    "uuid": JOB_ID,
    "tsg_id": TSG,
    "name": "nightly-static-scan",
    "target": TARGET_REF,
    "job_type": "STATIC",
    "target_id": TARGET_ID,
    "target_type": "API",
    "status": "COMPLETED",
}
JOB_LIST = {"pagination": {"total_items": 12}, "data": [JOB]}
ATTACK_ROW = {
    "uuid": ATTACK_ID,
    "tsg_id": TSG,
    "job_id": JOB_ID,
    "target_id": TARGET_ID,
    "prompt": "ignore previous instructions",
    "prompt_mapping_id": "pm-1",
    "prompt_id": "p-1",
    "category": "security",
    "sub_category": "jailbreak",
    "category_display_name": "Security",
    "sub_category_display_name": "Jailbreak",
    "threat": True,
}
ATTACK_LIST = {"pagination": {"total_items": 1}, "data": [ATTACK_ROW]}
ATTACK_OUTPUT = {
    "uuid": "cc0e8400-e29b-41d4-a716-446655440007",
    "tsg_id": TSG,
    "attack_id": ATTACK_ID,
    "job_id": JOB_ID,
    "target_id": TARGET_ID,
    "output": "I cannot help with that",
    "threat": False,
}
ATTACK_DETAIL = {
    **ATTACK_ROW,
    "compliance_frameworks": [],
    "goal": None,
    "outputs": [ATTACK_OUTPUT],
}
# The turn-level shape is the only thing separating the multi-turn model from the
# single-turn one, so the payload has to carry it for the distinction to be testable.
MULTI_TURN_DETAIL = {
    **ATTACK_ROW,
    "compliance_frameworks": [],
    "goal": None,
    "multi_turn": True,
    "outputs": [
        {**ATTACK_OUTPUT, "prompt": "warm up", "turn": 1},
        {
            **ATTACK_OUTPUT,
            "output": "Sure, here it is",
            "prompt": "now the real ask",
            "turn": 2,
            "threat": True,
        },
    ],
}
STATIC_REPORT = {"severity_report": {"stats": [{"severity": "high", "successful": 3}]}}
DYNAMIC_REPORT = {"total_goals": 12, "goals_achieved": 3, "score": 75.0, "asr": 0.25}
REMEDIATION = {"remediations": [{"remediation": "Add input filtering", "description": "..."}]}
RUNTIME_POLICY: dict[str, Any] = {
    "runtime_security_profile": [
        {
            "policy_id": "pol-prompt-injection",
            "display_name": "Prompt Injection",
            "config": {"action": "block"},
        }
    ]
}
GOAL = {
    "goal": "extract the system prompt",
    "safe_response": "I cannot help with that",
    "jailbroken_response": "Sure, here it is",
    "uuid": GOAL_ID,
    "tsg_id": TSG,
    "job_id": JOB_ID,
}
GOAL_LIST = {"pagination": {"total_items": 4}, "data": [GOAL]}
STREAM = {
    "uuid": STREAM_ID,
    "tsg_id": TSG,
    "job_id": JOB_ID,
    "target_id": TARGET_ID,
    "goal_id": GOAL_ID,
}
STREAM_LIST = {"pagination": {"total_items": 2}, "data": [STREAM]}
TARGET = {
    "uuid": TARGET_ID,
    "tsg_id": TSG,
    "name": "prod-chatbot",
    "status": "READY",
    "active": True,
    "validated": True,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-02T00:00:00Z",
}
TARGET_LIST = {"pagination": {"total_items": 4}, "data": [TARGET]}
TARGET_PROFILE = {"target_id": TARGET_ID, "target_version": 1, "status": "READY"}
TARGET_TEMPLATES = {
    "OPENAI": {"api_endpoint": "https://api.openai.com/v1/responses"},
    "HUGGING_FACE": {},
    "DATABRICKS": {},
    "BEDROCK": {},
    "REST": {},
    "STREAMING": {},
    "WEBSOCKET": {},
}
ADAPTER = {
    "uuid": ADAPTER_ID,
    "tsg_id": TSG,
    "name": "my-keycloak-agent",
    "script_b64": "IyEvdXNyL2Jpbi9lbnYgcHl0aG9u",
    "status": "ACTIVE",
}
ADAPTER_LIST = {
    "pagination": {"total_items": 1},
    "data": [
        {
            "uuid": ADAPTER_ID,
            "name": "my-keycloak-agent",
            "status": "ACTIVE",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
        }
    ],
}
DELETED = {"message": "ok", "status": 200}
QUOTA = {
    "static": {"allocated": 100, "unlimited": False, "consumed": 5},
    "dynamic": {"allocated": 10, "unlimited": False, "consumed": 1},
    "custom": {"allocated": 0, "unlimited": True, "consumed": 0},
}
ERROR_LOGS = {
    "pagination": {"total_items": 1},
    "data": [
        {
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "error_type": "TIMEOUT",
            "error_message": "target did not respond",
        }
    ],
}
LANGUAGES = {
    "multilingual_enabled": True,
    "supported_job_types": ["STATIC", "DYNAMIC"],
    "languages": [{"code": "en", "name": "English"}],
}
SCAN_STATISTICS = {"total_scans": 10, "targets_scanned": 5}
SCORE_TREND = {
    "labels": ["2026-04", "2026-05"],
    "series": [{"label": "risk", "data": [42.0, None]}],
}
SENTIMENT = {"job_id": JOB_ID, "up_vote": True}
OVERVIEW = {"total_targets": 7, "targets_by_type": [{"name": "API", "count": 4}]}


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer's real credentials and endpoint overrides out of these tests."""
    suffixes = (
        "CLIENT_ID",
        "CLIENT_SECRET",
        "TSG_ID",
        "TOKEN_ENDPOINT",
        "DATA_ENDPOINT",
        "MGMT_ENDPOINT",
        "NETWORK_BROKER_ENDPOINT",
    )
    for prefix in (ENV_PREFIX_RED_TEAM, ENV_PREFIX_MGMT):
        for suffix in suffixes:
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)


@pytest.fixture
def rt(respx_mock: respx.MockRouter) -> Iterator[RedTeamClient]:
    respx_mock.post(DEFAULT_TOKEN_ENDPOINT).mock(
        return_value=httpx.Response(200, json={"access_token": TOKEN, "expires_in": 900})
    )
    client = RedTeamClient(client_id="cid", client_secret="csecret", tsg_id=TSG, num_retries=0)
    yield client
    client.close()


def body_of(route: respx.Route) -> Any:
    """Decode the JSON body of the last request matched by ``route``."""
    return json.loads(route.calls.last.request.content)


def params_of(route: respx.Route) -> dict[str, str]:
    """Return the last request's query parameters as a plain mapping."""
    return dict(route.calls.last.request.url.params)


class TestConstruction:
    def test_defaults_to_the_published_endpoints(self) -> None:
        with RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG) as client:
            assert client.data_endpoint == DEFAULT_RED_TEAM_DATA_ENDPOINT
            assert client.mgmt_endpoint == DEFAULT_RED_TEAM_MGMT_ENDPOINT
            assert client.network_broker_endpoint == DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT

    def test_explicit_endpoints_win_over_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(f"{ENV_PREFIX_RED_TEAM}_DATA_ENDPOINT", "https://from-env.test")

        with RedTeamClient(
            client_id="c", client_secret="s", tsg_id=TSG, data_endpoint="https://explicit.test"
        ) as client:
            assert client.data_endpoint == "https://explicit.test"

    @pytest.mark.parametrize(
        ("suffix", "attribute"),
        [
            ("DATA_ENDPOINT", "data_endpoint"),
            ("MGMT_ENDPOINT", "mgmt_endpoint"),
            ("NETWORK_BROKER_ENDPOINT", "network_broker_endpoint"),
        ],
    )
    def test_each_endpoint_reads_its_own_environment_variable(
        self, monkeypatch: pytest.MonkeyPatch, suffix: str, attribute: str
    ) -> None:
        monkeypatch.setenv(f"{ENV_PREFIX_RED_TEAM}_{suffix}", "https://override.test")

        with RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG) as client:
            assert getattr(client, attribute) == "https://override.test"

    def test_requires_credentials(self) -> None:
        with pytest.raises(AISecMissingVariableError, match="PANW_RED_TEAM_CLIENT_ID"):
            RedTeamClient()

    def test_binds_scans_and_reports_to_the_data_plane(self) -> None:
        with RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG) as client:
            assert client.scans.base_url == DEFAULT_RED_TEAM_DATA_ENDPOINT
            assert client.reports.base_url == DEFAULT_RED_TEAM_DATA_ENDPOINT

    def test_binds_targets_and_adapters_to_the_management_plane(self) -> None:
        """A management call sent to the data plane 404s rather than redirecting."""
        with RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG) as client:
            assert client.targets.base_url == DEFAULT_RED_TEAM_MGMT_ENDPOINT
            assert client.adapters.base_url == DEFAULT_RED_TEAM_MGMT_ENDPOINT

    @pytest.mark.parametrize("value", [-1, 6, 1.5, True])
    def test_rejects_an_unusable_retry_count(self, value: object) -> None:
        """The reference clamps; this port raises so a typo cannot pass unnoticed."""
        with pytest.raises(AISecPayloadError, match="num_retries"):
            RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG, num_retries=value)  # type: ignore[arg-type]


class TestRetryBudget:
    """The resolved budget has to reach the transport, not just sit on the parent."""

    def test_threads_the_budget_into_every_sub_client(self) -> None:
        """A sub-client left on the default would spend a different budget than was asked for."""
        with RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG, num_retries=3) as client:
            assert {
                client.scans._num_retries,
                client.reports._num_retries,
                client.targets._num_retries,
                client.adapters._num_retries,
            } == {3}

    def test_a_zero_budget_makes_exactly_one_attempt(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """A 5xx is retryable, so only the budget stops it from being sent again."""
        route = respx_mock.get(f"{DATA}/v1/categories").mock(return_value=httpx.Response(503))

        with pytest.raises(AISecServerError):
            rt.scans.get_categories()

        assert route.call_count == 1

    def test_spends_the_budget_on_a_retryable_status(self, respx_mock: respx.MockRouter) -> None:
        """One retry configured, one 503 absorbed -- the number is used, not just stored."""
        respx_mock.post(DEFAULT_TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"access_token": TOKEN, "expires_in": 900})
        )
        route = respx_mock.get(f"{DATA}/v1/categories").mock(
            side_effect=[httpx.Response(503), httpx.Response(200, json=[])]
        )

        with RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG, num_retries=1) as client:
            assert client.scans.get_categories() == []

        assert route.call_count == 2


class TestAuthentication:
    def test_sends_the_bearer_token(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.get(f"{DATA}/v1/categories").mock(
            return_value=httpx.Response(200, json=[])
        )

        rt.scans.get_categories()

        assert route.calls.last.request.headers["Authorization"] == f"Bearer {TOKEN}"

    def test_does_not_send_the_tenant_header(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """Only the AI Gateway needs x-tsg-id; the tenant is already inside the token."""
        route = respx_mock.get(f"{DATA}/v1/categories").mock(
            return_value=httpx.Response(200, json=[])
        )

        rt.scans.get_categories()

        assert "x-tsg-id" not in route.calls.last.request.headers

    def test_falls_back_to_the_shared_management_credentials(
        self, monkeypatch: pytest.MonkeyPatch, respx_mock: respx.MockRouter
    ) -> None:
        """One service account should drive every plane without being repeated."""
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_ID", "mgmt-id")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_SECRET", "mgmt-secret")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_TSG_ID", "mgmt-tsg")
        token = respx_mock.post(DEFAULT_TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, json={"access_token": TOKEN, "expires_in": 900})
        )
        respx_mock.get(f"{DATA}/v1/categories").mock(return_value=httpx.Response(200, json=[]))

        with RedTeamClient() as client:
            client.scans.get_categories()

        expected = base64.b64encode(b"mgmt-id:mgmt-secret").decode()
        assert token.calls.last.request.headers["Authorization"] == f"Basic {expected}"
        assert b"tsg_id%3Amgmt-tsg" in token.calls.last.request.content


class TestScans:
    def test_creates_a_job(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.post(f"{DATA}/v1/scan").mock(return_value=httpx.Response(200, json=JOB))

        rt.scans.create(
            JobCreateRequest(
                name="nightly-static-scan",
                target=TargetJobRequest(uuid=TARGET_ID),
                job_type="STATIC",
                job_metadata=StaticJobMetadata(categories={"security": ["jailbreak"]}),
            )
        )

        assert body_of(route) == {
            "name": "nightly-static-scan",
            "target": {"uuid": TARGET_ID},
            "job_type": "STATIC",
            "job_metadata": {"categories": {"security": ["jailbreak"]}},
        }

    def test_returns_the_parsed_job(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.post(f"{DATA}/v1/scan").mock(return_value=httpx.Response(200, json=JOB))

        job = rt.scans.create(
            JobCreateRequest(
                name="nightly-static-scan",
                target=TargetJobRequest(uuid=TARGET_ID),
                job_type="STATIC",
                job_metadata=StaticJobMetadata(categories={}),
            )
        )

        assert (job.uuid, job.status, job.target.name) == (JOB_ID, "COMPLETED", "prod-chatbot")

    def test_sends_every_list_filter(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.get(f"{DATA}/v1/scan").mock(
            return_value=httpx.Response(200, json=JOB_LIST)
        )

        rt.scans.list(
            skip=10,
            limit=5,
            search="nightly",
            status="COMPLETED",
            job_type="STATIC",
            target_id=TARGET_ID,
        )

        assert params_of(route) == {
            "skip": "10",
            "limit": "5",
            "search": "nightly",
            "status": "COMPLETED",
            "job_type": "STATIC",
            "target_id": TARGET_ID,
        }

    def test_encodes_filters_as_distinct_single_valued_keys(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """Pagination first, then filters -- no key is ever repeated or comma-joined."""
        route = respx_mock.get(f"{DATA}/v1/scan").mock(
            return_value=httpx.Response(200, json=JOB_LIST)
        )

        rt.scans.list(skip=10, limit=5, status="COMPLETED", job_type="STATIC")

        assert (
            route.calls.last.request.url.query
            == b"skip=10&limit=5&status=COMPLETED&job_type=STATIC"
        )

    def test_omits_unset_list_filters(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """An empty filter must be absent, not sent as an empty string."""
        route = respx_mock.get(f"{DATA}/v1/scan").mock(
            return_value=httpx.Response(200, json=JOB_LIST)
        )

        rt.scans.list(limit=5)

        assert route.calls.last.request.url.query == b"limit=5"

    def test_gets_one_job_by_id(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(f"{DATA}/v1/scan/{JOB_ID}").mock(return_value=httpx.Response(200, json=JOB))

        job = rt.scans.get(JOB_ID)

        assert (job.uuid, job.job_type, job.target_id) == (JOB_ID, "STATIC", TARGET_ID)

    def test_aborts_with_a_post_and_no_body(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(f"{DATA}/v1/scan/{JOB_ID}/abort").mock(
            return_value=httpx.Response(200, json={"job_id": JOB_ID, "message": "aborted"})
        )

        result = rt.scans.abort(JOB_ID)

        sent = route.calls.last.request
        assert sent.content == b""
        assert "content-type" not in sent.headers
        assert result.message == "aborted"

    def test_lists_categories_as_a_bare_array(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """This endpoint has no pagination envelope, unlike every other list call."""
        payload = [
            {
                "id": "security",
                "display_name": "Security",
                "description": "d",
                "sub_categories": [
                    {"id": "jailbreak", "display_name": "Jailbreak", "description": "d"}
                ],
            }
        ]
        respx_mock.get(f"{DATA}/v1/categories").mock(return_value=httpx.Response(200, json=payload))

        categories = rt.scans.get_categories()

        assert [c.id for c in categories] == ["security"]
        assert categories[0].sub_categories[0].id == "jailbreak"

    @pytest.mark.parametrize("method", ["get", "abort"])
    def test_rejects_a_malformed_job_id(self, rt: RedTeamClient, method: str) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid job id"):
            getattr(rt.scans, method)(NOT_A_UUID)


class TestStaticReports:
    def test_sends_every_attack_filter(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.get(f"{DATA}/v1/report/static/{JOB_ID}/list-attacks").mock(
            return_value=httpx.Response(200, json=ATTACK_LIST)
        )

        rt.reports.list_attacks(
            JOB_ID,
            skip=0,
            limit=20,
            search="ignore",
            status="COMPLETED",
            severity="high",
            category="security",
            sub_category="jailbreak",
            attack_type="SINGLE_TURN",
            threat=True,
        )

        assert params_of(route) == {
            "skip": "0",
            "limit": "20",
            "search": "ignore",
            "status": "COMPLETED",
            "severity": "high",
            "category": "security",
            "sub_category": "jailbreak",
            "attack_type": "SINGLE_TURN",
            "threat": "true",
        }

    @pytest.mark.parametrize(("flag", "expected"), [(True, "true"), (False, "false")])
    def test_spells_the_threat_flag_in_lower_case(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter, flag: bool, expected: str
    ) -> None:
        """Python's str() would send 'True'; the service is fed the JavaScript spelling."""
        route = respx_mock.get(f"{DATA}/v1/report/static/{JOB_ID}/list-attacks").mock(
            return_value=httpx.Response(200, json=ATTACK_LIST)
        )

        rt.reports.list_attacks(JOB_ID, threat=flag)

        assert params_of(route) == {"threat": expected}

    def test_gets_a_single_turn_attack(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(f"{DATA}/v1/report/static/{JOB_ID}/attack/{ATTACK_ID}").mock(
            return_value=httpx.Response(200, json=ATTACK_DETAIL)
        )

        detail = rt.reports.get_attack_detail(JOB_ID, ATTACK_ID)

        assert (detail.uuid, detail.category, detail.threat) == (ATTACK_ID, "security", True)
        assert detail.goal is None
        assert detail.outputs is not None
        assert isinstance(detail.outputs[0], AttackOutput)
        assert detail.outputs[0].output == "I cannot help with that"

    def test_gets_a_multi_turn_attack_from_a_different_path(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """Multi-turn attacks live under their own segment; the single-turn path 404s."""
        respx_mock.get(f"{DATA}/v1/report/static/{JOB_ID}/attack-multi-turn/{ATTACK_ID}").mock(
            return_value=httpx.Response(200, json=MULTI_TURN_DETAIL)
        )

        detail = rt.reports.get_multi_turn_attack_detail(JOB_ID, ATTACK_ID)

        assert (detail.uuid, detail.sub_category) == (ATTACK_ID, "jailbreak")
        assert detail.outputs is not None
        # Binding this endpoint to the single-turn model would drop the per-turn fields.
        assert isinstance(detail.outputs[0], AttackMultiTurnOutput)
        assert [turn.turn for turn in detail.outputs] == [1, 2]
        assert detail.outputs[1].prompt == "now the real ask"

    def test_gets_the_static_report(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(f"{DATA}/v1/report/static/{JOB_ID}/report").mock(
            return_value=httpx.Response(200, json=STATIC_REPORT)
        )

        report = rt.reports.get_static_report(JOB_ID)

        assert report.severity_report.stats[0].severity == "high"

    def test_gets_static_remediation(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(f"{DATA}/v1/report/static/{JOB_ID}/remediation").mock(
            return_value=httpx.Response(200, json=REMEDIATION)
        )

        result = rt.reports.get_static_remediation(JOB_ID)

        assert result.remediations is not None
        assert result.remediations[0].remediation == "Add input filtering"

    def test_gets_the_static_runtime_policy(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(f"{DATA}/v1/report/static/{JOB_ID}/runtime-policy-config").mock(
            return_value=httpx.Response(200, json=RUNTIME_POLICY)
        )

        policy = rt.reports.get_static_runtime_policy(JOB_ID)

        assert policy.runtime_security_profile is not None
        assert policy.runtime_security_profile[0].policy_id == "pol-prompt-injection"
        assert policy.runtime_security_profile[0].config == {"action": "block"}

    @pytest.mark.parametrize(
        "method",
        [
            "list_attacks",
            "get_static_report",
            "get_static_remediation",
            "get_static_runtime_policy",
        ],
    )
    def test_rejects_a_malformed_job_id(self, rt: RedTeamClient, method: str) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid job id"):
            getattr(rt.reports, method)(NOT_A_UUID)

    @pytest.mark.parametrize("method", ["get_attack_detail", "get_multi_turn_attack_detail"])
    def test_rejects_a_malformed_attack_id(self, rt: RedTeamClient, method: str) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid attack id"):
            getattr(rt.reports, method)(JOB_ID, NOT_A_UUID)

    @pytest.mark.parametrize("method", ["get_attack_detail", "get_multi_turn_attack_detail"])
    def test_attack_lookups_reject_a_malformed_job_id(self, rt: RedTeamClient, method: str) -> None:
        """Both segments reach the path, so the job id is checked as well as the attack id."""
        with pytest.raises(AISecPayloadError, match="Invalid job id"):
            getattr(rt.reports, method)(NOT_A_UUID, ATTACK_ID)


class TestDynamicReports:
    def test_gets_the_dynamic_report(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(f"{DATA}/v1/report/dynamic/{JOB_ID}/report").mock(
            return_value=httpx.Response(200, json=DYNAMIC_REPORT)
        )

        report = rt.reports.get_dynamic_report(JOB_ID)

        assert (report.total_goals, report.goals_achieved) == (12, 3)

    def test_gets_dynamic_remediation(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(f"{DATA}/v1/report/dynamic/{JOB_ID}/remediation").mock(
            return_value=httpx.Response(200, json=REMEDIATION)
        )

        result = rt.reports.get_dynamic_remediation(JOB_ID)

        assert result.remediations is not None
        assert result.remediations[0].remediation == "Add input filtering"

    def test_gets_the_dynamic_runtime_policy(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(f"{DATA}/v1/report/dynamic/{JOB_ID}/runtime-policy-config").mock(
            return_value=httpx.Response(200, json=RUNTIME_POLICY)
        )

        policy = rt.reports.get_dynamic_runtime_policy(JOB_ID)

        assert policy.runtime_security_profile is not None
        assert policy.runtime_security_profile[0].display_name == "Prompt Injection"

    def test_sends_every_goal_filter(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.get(f"{DATA}/v1/report/dynamic/{JOB_ID}/list-goals").mock(
            return_value=httpx.Response(200, json=GOAL_LIST)
        )

        rt.reports.list_goals(
            JOB_ID,
            skip=5,
            limit=10,
            search="secrets",
            goal_type="CUSTOM",
            status="ACHIEVED",
            count=False,
        )

        assert params_of(route) == {
            "skip": "5",
            "limit": "10",
            "search": "secrets",
            "goal_type": "CUSTOM",
            "status": "ACHIEVED",
            "count": "false",
        }

    def test_sends_count_false_rather_than_omitting_it(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """False is a supplied value; only `None` means "do not send this filter"."""
        route = respx_mock.get(f"{DATA}/v1/report/dynamic/{JOB_ID}/list-goals").mock(
            return_value=httpx.Response(200, json=GOAL_LIST)
        )

        rt.reports.list_goals(JOB_ID, count=False)

        assert route.calls.last.request.url.query == b"count=false"

    def test_lists_streams_for_one_goal(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.get(
            f"{DATA}/v1/report/dynamic/{JOB_ID}/goal/{GOAL_ID}/list-streams"
        ).mock(return_value=httpx.Response(200, json=STREAM_LIST))

        rt.reports.list_goal_streams(JOB_ID, GOAL_ID, limit=3)

        assert params_of(route) == {"limit": "3"}

    def test_gets_a_stream_from_the_dynamic_prefix(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """Addressed by stream id alone, but still under /report/dynamic."""
        respx_mock.get(f"{DATA}/v1/report/dynamic/stream/{STREAM_ID}").mock(
            return_value=httpx.Response(200, json=STREAM)
        )

        stream = rt.reports.get_stream_detail(STREAM_ID)

        assert (stream.uuid, stream.job_id, stream.goal_id) == (STREAM_ID, JOB_ID, GOAL_ID)

    @pytest.mark.parametrize(
        "method",
        [
            "get_dynamic_report",
            "get_dynamic_remediation",
            "get_dynamic_runtime_policy",
            "list_goals",
        ],
    )
    def test_rejects_a_malformed_job_id(self, rt: RedTeamClient, method: str) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid job id"):
            getattr(rt.reports, method)(NOT_A_UUID)

    def test_stream_listing_checks_the_job_id_before_the_goal_id(self, rt: RedTeamClient) -> None:
        """Both segments are interpolated into the path, so both are checked."""
        with pytest.raises(AISecPayloadError, match="Invalid job id"):
            rt.reports.list_goal_streams(NOT_A_UUID, GOAL_ID)

    def test_rejects_a_malformed_goal_id(self, rt: RedTeamClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid goal id"):
            rt.reports.list_goal_streams(JOB_ID, NOT_A_UUID)

    def test_rejects_a_malformed_stream_id(self, rt: RedTeamClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid stream id"):
            rt.reports.get_stream_detail(NOT_A_UUID)


class TestReportDownloads:
    def test_passes_the_format_as_a_query_parameter(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.get(f"{DATA}/v1/report/{JOB_ID}/download").mock(
            return_value=httpx.Response(200, json={"url": "https://files.test/r.pdf"})
        )

        result = rt.reports.download_report(JOB_ID, "pdf")

        assert params_of(route) == {"file_format": "pdf"}
        assert result == {"url": "https://files.test/r.pdf"}

    def test_returns_the_download_payload_unvalidated(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """The shape follows file_format, so a model here would reject valid responses."""
        respx_mock.get(f"{DATA}/v1/report/{JOB_ID}/download").mock(
            return_value=httpx.Response(200, json=[1, 2, 3])
        )

        assert rt.reports.download_report(JOB_ID, "csv") == [1, 2, 3]

    def test_generates_a_partial_report_with_a_post(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(f"{DATA}/v1/report/{JOB_ID}/generate-partial-report").mock(
            return_value=httpx.Response(200, json={"unlocked": True})
        )

        result = rt.reports.generate_partial_report(JOB_ID)

        assert route.calls.last.request.content == b""
        assert result == {"unlocked": True}

    @pytest.mark.parametrize("method", ["download_report", "generate_partial_report"])
    def test_rejects_a_malformed_job_id(self, rt: RedTeamClient, method: str) -> None:
        args = [NOT_A_UUID, "pdf"] if method == "download_report" else [NOT_A_UUID]
        with pytest.raises(AISecPayloadError, match="Invalid job id"):
            getattr(rt.reports, method)(*args)


class TestTargets:
    def _create_body(self) -> TargetCreateRequest:
        return TargetCreateRequest(
            name="prod-chatbot",
            target_type="API",
            connection_params=RestConnectionParams(
                api_endpoint="https://api.openai.com/v1/responses",
                response_key="output[0].content[0].text",
            ),
        )

    def test_creates_a_target_on_the_management_plane(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(f"{MGMT}/v1/target").mock(
            return_value=httpx.Response(200, json=TARGET)
        )

        rt.targets.create(self._create_body())

        assert body_of(route) == {
            "name": "prod-chatbot",
            "target_type": "API",
            "connection_params": {
                "api_endpoint": "https://api.openai.com/v1/responses",
                "response_key": "output[0].content[0].text",
            },
        }

    def test_omits_validate_when_it_is_not_supplied(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """Unlike adapters, targets leave the decision to the service by default."""
        route = respx_mock.post(f"{MGMT}/v1/target").mock(
            return_value=httpx.Response(200, json=TARGET)
        )

        rt.targets.create(self._create_body())

        assert route.calls.last.request.url.query == b""

    @pytest.mark.parametrize(("flag", "expected"), [(True, "true"), (False, "false")])
    def test_sends_validate_when_it_is_supplied(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter, flag: bool, expected: str
    ) -> None:
        route = respx_mock.post(f"{MGMT}/v1/target").mock(
            return_value=httpx.Response(200, json=TARGET)
        )

        rt.targets.create(self._create_body(), validate=flag)

        assert params_of(route) == {"validate": expected}

    def test_sends_every_list_filter(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.get(f"{MGMT}/v1/target").mock(
            return_value=httpx.Response(200, json=TARGET_LIST)
        )

        rt.targets.list(skip=0, limit=10, search="chatbot", target_type="API", status="READY")

        assert params_of(route) == {
            "skip": "0",
            "limit": "10",
            "search": "chatbot",
            "target_type": "API",
            "status": "READY",
        }

    def test_gets_one_target(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(f"{MGMT}/v1/target/{TARGET_ID}").mock(
            return_value=httpx.Response(200, json=TARGET)
        )

        assert rt.targets.get(TARGET_ID).name == "prod-chatbot"

    def test_updates_with_a_put(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.put(f"{MGMT}/v1/target/{TARGET_ID}").mock(
            return_value=httpx.Response(200, json=TARGET)
        )

        rt.targets.update(TARGET_ID, TargetUpdateRequest(name="prod-chatbot-v2"), validate=False)

        assert body_of(route) == {"name": "prod-chatbot-v2"}
        assert params_of(route) == {"validate": "false"}

    def test_delete_accepts_an_empty_body(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """This endpoint answers 200-with-body or 204-with-none from the same call."""
        respx_mock.delete(f"{MGMT}/v1/target/{TARGET_ID}").mock(return_value=httpx.Response(204))

        assert rt.targets.delete(TARGET_ID) is None

    def test_delete_parses_a_message_envelope(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.delete(f"{MGMT}/v1/target/{TARGET_ID}").mock(
            return_value=httpx.Response(200, json=DELETED)
        )

        result = rt.targets.delete(TARGET_ID)

        assert result is not None
        assert (result.message, result.status) == ("ok", 200)

    def test_probes_without_a_target_id_in_the_path(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """The whole definition rides in the body so an unsaved draft can be probed."""
        route = respx_mock.post(f"{MGMT}/v1/target/probe").mock(
            return_value=httpx.Response(200, json=TARGET)
        )

        rt.targets.probe(
            TargetProbeRequest(
                name="prod-chatbot", uuid=TARGET_ID, probe_fields=["multi_turn", "rate_limit"]
            )
        )

        assert body_of(route) == {
            "name": "prod-chatbot",
            "uuid": TARGET_ID,
            "probe_fields": ["multi_turn", "rate_limit"],
        }

    def test_gets_a_profile(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(f"{MGMT}/v1/target/{TARGET_ID}/profile").mock(
            return_value=httpx.Response(200, json=TARGET_PROFILE)
        )

        assert rt.targets.get_profile(TARGET_ID).target_version == 1

    def test_updates_a_profile_with_a_put(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.put(f"{MGMT}/v1/target/{TARGET_ID}/profile").mock(
            return_value=httpx.Response(200, json=TARGET)
        )

        rt.targets.update_profile(
            TARGET_ID,
            TargetContextUpdate.model_validate({"target_background": {"industry": "Healthcare"}}),
        )

        assert body_of(route) == {"target_background": {"industry": "Healthcare"}}

    def test_validates_auth_on_its_own_path(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.post(f"{MGMT}/v1/target/validate-auth").mock(
            return_value=httpx.Response(200, json={"validated": True})
        )

        result = rt.targets.validate_auth(
            TargetAuthValidationRequest(
                auth_type="HEADERS", auth_config={"Authorization": "Bearer sk-xxx"}
            )
        )

        assert body_of(route) == {
            "auth_type": "HEADERS",
            "auth_config": {"Authorization": "Bearer sk-xxx"},
        }
        assert result.validated

    def test_reads_target_metadata_from_the_template_path(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(f"{MGMT}/v1/template/target-metadata").mock(
            return_value=httpx.Response(200, json={"rate_limit": {"type": "number"}})
        )

        assert rt.targets.get_target_metadata() == {"rate_limit": {"type": "number"}}

    def test_reads_target_templates_by_upper_case_wire_key(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(f"{MGMT}/v1/template/target-templates").mock(
            return_value=httpx.Response(200, json=TARGET_TEMPLATES)
        )

        templates = rt.targets.get_target_templates()

        assert templates.openai == {"api_endpoint": "https://api.openai.com/v1/responses"}

    @pytest.mark.parametrize("method", ["get", "delete", "get_profile"])
    def test_rejects_a_malformed_uuid(self, rt: RedTeamClient, method: str) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid target uuid"):
            getattr(rt.targets, method)(NOT_A_UUID)

    def test_update_rejects_a_malformed_uuid(self, rt: RedTeamClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid target uuid"):
            rt.targets.update(NOT_A_UUID, TargetUpdateRequest(name="x"))

    def test_update_profile_rejects_a_malformed_uuid(self, rt: RedTeamClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid target uuid"):
            rt.targets.update_profile(NOT_A_UUID, TargetContextUpdate())


class TestAdapters:
    def _create_body(self) -> AdapterCreateRequest:
        return AdapterCreateRequest(
            name="my-keycloak-agent",
            script_b64="IyEvdXNyL2Jpbi9lbnYgcHl0aG9u",
            network_broker_channel_uuid=CHANNEL_ID,
            variables=[
                AdapterVar(key="endpoint", value="http://agent.svc:8080", type=AdapterVarType.VAR)
            ],
            prompt="What is the capital of France?",
        )

    def test_creates_an_adapter(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.post(f"{MGMT}/v1/adapters").mock(
            return_value=httpx.Response(200, json=ADAPTER)
        )

        rt.adapters.create(self._create_body())

        assert body_of(route) == {
            "name": "my-keycloak-agent",
            "script_b64": "IyEvdXNyL2Jpbi9lbnYgcHl0aG9u",
            "network_broker_channel_uuid": CHANNEL_ID,
            "variables": [{"key": "endpoint", "value": "http://agent.svc:8080", "type": "VAR"}],
            "prompt": "What is the capital of France?",
        }

    def test_always_sends_validate_and_defaults_it_to_true(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """Adapters differ from targets here: the parameter is never omitted."""
        route = respx_mock.post(f"{MGMT}/v1/adapters").mock(
            return_value=httpx.Response(200, json=ADAPTER)
        )

        rt.adapters.create(self._create_body())

        assert params_of(route) == {"validate": "true"}

    def test_can_save_as_a_draft(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.post(f"{MGMT}/v1/adapters").mock(
            return_value=httpx.Response(200, json={**ADAPTER, "status": "DRAFT"})
        )

        adapter = rt.adapters.create(self._create_body(), validate=False)

        assert params_of(route) == {"validate": "false"}
        assert adapter.status == "DRAFT"

    def test_lists_adapters_with_pagination(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.get(f"{MGMT}/v1/adapters").mock(
            return_value=httpx.Response(200, json=ADAPTER_LIST)
        )

        result = rt.adapters.list(skip=20, limit=20, search="keycloak")

        assert params_of(route) == {"skip": "20", "limit": "20", "search": "keycloak"}
        assert result.data is not None
        assert result.data[0].uuid == ADAPTER_ID

    def test_gets_one_adapter(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.get(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(
            return_value=httpx.Response(200, json=ADAPTER)
        )

        assert rt.adapters.get(ADAPTER_ID).status == "ACTIVE"

    def test_updates_with_a_put_and_still_sends_validate(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.put(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(
            return_value=httpx.Response(200, json=ADAPTER)
        )

        rt.adapters.update(
            ADAPTER_ID,
            AdapterUpdateRequest(
                name="my-keycloak-agent",
                script_b64="IyEvdXNyL2Jpbi9lbnYgcHl0aG9u",
                prompt="What is the capital of France?",
            ),
        )

        assert params_of(route) == {"validate": "true"}
        assert body_of(route) == {
            "name": "my-keycloak-agent",
            "script_b64": "IyEvdXNyL2Jpbi9lbnYgcHl0aG9u",
            "prompt": "What is the capital of France?",
        }

    def test_a_none_valued_variable_is_sent_as_an_absent_key(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """The "keep the stored secret" idiom, and the one place this port is not
        byte-identical to the reference.

        The reference sends ``"value": null``; the shared serialiser drops ``None`` keys,
        so this sends the variable with no ``value`` at all. The variable stays in the
        list either way -- which is what decides whether the service keeps or deletes it
        -- and a nullable field reads both spellings as "unset". Pinned so a change to the
        serialiser surfaces here rather than silently wiping a tenant's secrets.
        """
        route = respx_mock.put(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(
            return_value=httpx.Response(200, json=ADAPTER)
        )

        rt.adapters.update(
            ADAPTER_ID,
            AdapterUpdateRequest(
                name="my-keycloak-agent",
                script_b64="IyEvdXNyL2Jpbi9lbnYgcHl0aG9u",
                prompt="What is the capital of France?",
                variables=[
                    AdapterVar(
                        key="endpoint", value="http://agent.svc:8080", type=AdapterVarType.VAR
                    ),
                    AdapterVar(key="client_secret", value=None, type=AdapterVarType.SECRET),
                ],
            ),
        )

        assert body_of(route)["variables"] == [
            {"key": "endpoint", "value": "http://agent.svc:8080", "type": "VAR"},
            {"key": "client_secret", "type": "SECRET"},
        ]

    def test_deletes_an_adapter(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        respx_mock.delete(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(
            return_value=httpx.Response(200, json=DELETED)
        )

        result = rt.adapters.delete(ADAPTER_ID)

        assert result is not None
        assert (result.message, result.status) == ("ok", 200)

    def test_delete_accepts_an_empty_body(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """Like targets, this endpoint answers 200-with-body or 204-with-none."""
        respx_mock.delete(f"{MGMT}/v1/adapters/{ADAPTER_ID}").mock(return_value=httpx.Response(204))

        assert rt.adapters.delete(ADAPTER_ID) is None

    def test_validates_a_script_without_saving(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """A separate path and a different request shape from create."""
        route = respx_mock.post(f"{MGMT}/v1/adapters/validate").mock(
            return_value=httpx.Response(
                200, json={"validated": False, "traceback": "KeyError: 'endpoint'"}
            )
        )

        result = rt.adapters.validate(
            AdapterValidateRequest(
                script_b64="IyEvdXNyL2Jpbi9lbnYgcHl0aG9u",
                network_broker_channel_uuid=CHANNEL_ID,
                prompt="Hello",
                adapter_uuid=ADAPTER_ID,
            )
        )

        assert body_of(route) == {
            "script_b64": "IyEvdXNyL2Jpbi9lbnYgcHl0aG9u",
            "network_broker_channel_uuid": CHANNEL_ID,
            "prompt": "Hello",
            "adapter_uuid": ADAPTER_ID,
        }
        assert route.calls.last.request.url.query == b""
        assert result.traceback == "KeyError: 'endpoint'"

    @pytest.mark.parametrize("method", ["get", "delete"])
    def test_rejects_a_malformed_uuid(self, rt: RedTeamClient, method: str) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid adapter uuid"):
            getattr(rt.adapters, method)(NOT_A_UUID)

    def test_update_rejects_a_malformed_uuid(self, rt: RedTeamClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid adapter uuid"):
            rt.adapters.update(
                NOT_A_UUID, AdapterUpdateRequest(name="a", script_b64="Yg==", prompt="p")
            )


class TestDataPlaneConvenience:
    def test_gets_scan_statistics_with_filters(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.get(f"{DATA}/v1/dashboard/scan-statistics").mock(
            return_value=httpx.Response(200, json=SCAN_STATISTICS)
        )

        stats = rt.get_scan_statistics(date_range="30d", target_id=TARGET_ID)

        assert params_of(route) == {"date_range": "30d", "target_id": TARGET_ID}
        assert (stats.total_scans, stats.targets_scanned) == (10, 5)

    def test_gets_scan_statistics_without_filters(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.get(f"{DATA}/v1/dashboard/scan-statistics").mock(
            return_value=httpx.Response(200, json=SCAN_STATISTICS)
        )

        rt.get_scan_statistics()

        assert route.calls.last.request.url.query == b""

    def test_gets_a_score_trend_for_one_target(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        route = respx_mock.get(f"{DATA}/v1/dashboard/score-trend").mock(
            return_value=httpx.Response(200, json=SCORE_TREND)
        )

        trend = rt.get_score_trend(TARGET_ID)

        assert params_of(route) == {"target_id": TARGET_ID}
        # A null in the series is a bucket with no scan, not a score of zero.
        assert trend.series[0].data == [42.0, None]

    def test_score_trend_rejects_a_malformed_target_id(self, rt: RedTeamClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid target id"):
            rt.get_score_trend(NOT_A_UUID)

    def test_reads_quota_with_a_post(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        """A pure read defined as POST upstream; a GET to the same path does not answer."""
        route = respx_mock.post(f"{DATA}/v1/metering/quota").mock(
            return_value=httpx.Response(200, json=QUOTA)
        )

        quota = rt.get_quota()

        assert route.calls.last.request.content == b""
        assert (quota.static.consumed, quota.custom.unlimited) == (5, True)

    def test_lists_job_error_logs(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.get(f"{DATA}/v1/error-log/job/{JOB_ID}").mock(
            return_value=httpx.Response(200, json=ERROR_LOGS)
        )

        logs = rt.get_error_logs(JOB_ID, limit=10)

        assert params_of(route) == {"limit": "10"}
        assert logs.data[0].error_type == "TIMEOUT"

    def test_lists_target_profile_error_logs_from_a_different_path(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """Profiling failures predate any job, so they are keyed by target."""
        route = respx_mock.get(f"{DATA}/v1/error-log/target-profile/{TARGET_ID}").mock(
            return_value=httpx.Response(200, json=ERROR_LOGS)
        )

        rt.get_target_profile_error_logs(TARGET_ID, skip=5, limit=10, search="probe")

        assert params_of(route) == {"skip": "5", "limit": "10", "search": "probe"}

    def test_error_logs_reject_a_malformed_job_id(self, rt: RedTeamClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid job id"):
            rt.get_error_logs(NOT_A_UUID)

    def test_profile_error_logs_reject_a_malformed_target_id(self, rt: RedTeamClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid target id"):
            rt.get_target_profile_error_logs(NOT_A_UUID)

    def test_reads_languages_from_the_data_plane(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(f"{DATA}/v1/languages").mock(
            return_value=httpx.Response(200, json=LANGUAGES)
        )

        result = rt.get_languages()

        assert result.supported_job_types == ["STATIC", "DYNAMIC"]

    def test_posts_a_sentiment_vote(self, rt: RedTeamClient, respx_mock: respx.MockRouter) -> None:
        route = respx_mock.post(f"{DATA}/v1/sentiment").mock(
            return_value=httpx.Response(200, json=SENTIMENT)
        )

        rt.update_sentiment(SentimentRequest(job_id=JOB_ID, up_vote=True))

        assert body_of(route) == {"job_id": JOB_ID, "up_vote": True}

    def test_reads_a_sentiment_vote_by_job_id(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        respx_mock.get(f"{DATA}/v1/sentiment/{JOB_ID}").mock(
            return_value=httpx.Response(200, json=SENTIMENT)
        )

        assert rt.get_sentiment(JOB_ID).up_vote is True

    def test_sentiment_rejects_a_malformed_job_id(self, rt: RedTeamClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid job id"):
            rt.get_sentiment(NOT_A_UUID)


class TestManagementPlaneConvenience:
    def test_reads_languages_from_the_management_endpoint(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """Same path as the data plane call, different base URL -- that is the whole point."""
        route = respx_mock.get(f"{MGMT}/v1/languages").mock(
            return_value=httpx.Response(200, json=LANGUAGES)
        )

        rt.get_management_languages()

        assert str(route.calls.last.request.url) == f"{MGMT}/v1/languages"

    def test_reads_the_dashboard_overview(
        self, rt: RedTeamClient, respx_mock: respx.MockRouter
    ) -> None:
        """/v1/dashboard/overview is management-plane; /v1/dashboard/* is data-plane."""
        respx_mock.get(f"{MGMT}/v1/dashboard/overview").mock(
            return_value=httpx.Response(200, json=OVERVIEW)
        )

        overview = rt.get_dashboard_overview()

        assert overview.total_targets == 7


class TestLifecycle:
    def test_closes_a_client_it_created(self) -> None:
        client = RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG)

        client.close()

        assert client.scans._http.is_closed

    def test_leaves_an_injected_client_open(self) -> None:
        """The caller owns a client it passed in; closing it would be a surprise."""
        http = httpx.Client()

        with RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG, http_client=http):
            pass

        assert not http.is_closed
        http.close()

    def test_shares_one_http_client_across_sub_clients(self) -> None:
        """One pool and one cached token, however many sub-clients are in play."""
        with RedTeamClient(client_id="c", client_secret="s", tsg_id=TSG) as client:
            assert client.scans._http is client.targets._http is client.adapters._http
