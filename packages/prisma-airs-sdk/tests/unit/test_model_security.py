"""Contract tests for the Model Security client.

These assert the exact request that goes on the wire -- method, URL, query string,
headers, and body -- which is what keeps the port honest against the reference
implementation. Model Security straddles two base URLs behind one token, so several
tests exist purely to pin which plane a call lands on.
"""

from __future__ import annotations

import base64
import json
import random
from collections.abc import Iterator

import httpx
import pytest
import respx

from prisma_airs.auth.oauth import DEFAULT_TOKEN_BUFFER_MS
from prisma_airs.constants import (
    DEFAULT_MODEL_SEC_DATA_ENDPOINT,
    DEFAULT_MODEL_SEC_MGMT_ENDPOINT,
    DEFAULT_TIMEOUT_SECONDS,
    DEFAULT_TOKEN_ENDPOINT,
    ENV_PREFIX_MGMT,
    ENV_PREFIX_MODEL_SEC,
    MAX_NUMBER_OF_RETRIES,
)
from prisma_airs.errors import AISecMissingVariableError, AISecPayloadError, AISecServerError
from prisma_airs.model_security.model_security import (
    ENV_MODEL_SEC_DATA_ENDPOINT,
    ENV_MODEL_SEC_MGMT_ENDPOINT,
    ModelSecurityClient,
)
from prisma_airs.models.model_security import (
    Label,
    LabelsCreateRequest,
    ModelSecurityGroupCreateRequest,
    ModelSecurityGroupUpdateRequest,
    ModelSecurityRuleInstanceUpdateRequest,
    ScanCreateRequest,
)

DATA = DEFAULT_MODEL_SEC_DATA_ENDPOINT
MGMT = DEFAULT_MODEL_SEC_MGMT_ENDPOINT

CLIENT_ID = "cid"
CLIENT_SECRET = "csec"
TSG_ID = "1234567890"
TOKEN = "access-token-one"

SCAN_UUID = "550e8400-e29b-41d4-a716-446655440000"
GROUP_UUID = "660e8400-e29b-41d4-a716-446655440000"
RULE_UUID = "770e8400-e29b-41d4-a716-446655440000"
INSTANCE_UUID = "880e8400-e29b-41d4-a716-446655440000"
MODEL_UUID = "990e8400-e29b-41d4-a716-446655440000"
VERSION_UUID = "aa0e8400-e29b-41d4-a716-446655440000"
EVAL_UUID = "bb0e8400-e29b-41d4-a716-446655440000"
VIOLATION_UUID = "cc0e8400-e29b-41d4-a716-446655440000"
BAD_UUID = "not-a-uuid"

# --- response fixtures ------------------------------------------------------

SCAN = {
    "uuid": SCAN_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "model_uri": "hf://org/model",
    "owner": "svc",
    "scan_origin": "MODEL_SECURITY_SDK",
    "security_group_uuid": GROUP_UUID,
    "security_group_name": "hf-strict",
    "eval_outcome": "ALLOWED",
    "source_type": "HUGGING_FACE",
}
SCAN_LIST = {"pagination": {"total_items": 1}, "scans": [SCAN]}

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
EVALUATION_LIST = {"pagination": {}, "evaluations": [EVALUATION]}

FILE = {
    "uuid": "dd0e8400-e29b-41d4-a716-446655440000",
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "path": "/model.safetensors",
    "parent_path": "/",
    "type": "FILE",
    "result": "SUCCESS",
    "model_version_uuid": VERSION_UUID,
}
FILE_LIST = {"pagination": {"total_items": 1}, "files": [FILE]}

VIOLATION = {
    "uuid": VIOLATION_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "description": "Unsafe pickle opcode",
    "rule_instance_uuid": INSTANCE_UUID,
    "rule_name": "Pickle Scan",
    "rule_description": "Flags unsafe pickle opcodes",
    "rule_instance_state": "BLOCKING",
    "remediation": {"steps": ["Repackage as safetensors"], "url": "https://docs.example"},
}
VIOLATION_LIST = {"pagination": {}, "violations": [VIOLATION]}

LABEL_KEYS = {"pagination": {"total_items": 3}, "keys": ["env", "team", "owner"]}
LABEL_VALUES = {"pagination": {"total_items": 2}, "values": ["prod", "staging"]}

MODEL = {
    "uuid": MODEL_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "name": "org/llama",
    "latest_version_uuid": VERSION_UUID,
    "latest_version_outcome": "ALLOWED",
}
MODEL_LIST = {"pagination": {"total_items": 1}, "models": [MODEL]}

MODEL_VERSION = {
    "uuid": VERSION_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "revision": "main",
    "model_uuid": MODEL_UUID,
    "file_count": 12,
}
MODEL_VERSION_LIST = {"pagination": {}, "model_versions": [MODEL_VERSION]}

RULE = {
    "uuid": RULE_UUID,
    "name": "Pickle Scan",
    "description": "Flags unsafe pickle opcodes",
    "rule_type": "ARTIFACT",
    "compatible_sources": ["HUGGING_FACE"],
    "default_state": "BLOCKING",
    "remediation": {
        "description": "Repackage the model",
        "steps": ["Convert to safetensors"],
        "url": "https://docs.example",
    },
    "editable_fields": [],
    "constant_values": {},
    "default_values": {},
}
RULE_LIST = {"pagination": {}, "rules": [RULE]}

RULE_INSTANCE = {
    "uuid": INSTANCE_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "security_group_uuid": GROUP_UUID,
    "security_rule_uuid": RULE_UUID,
    "state": "BLOCKING",
    "rule": RULE,
}
RULE_INSTANCE_LIST = {"pagination": {}, "rule_instances": [RULE_INSTANCE]}

GROUP = {
    "uuid": GROUP_UUID,
    "tsg_id": TSG_ID,
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:01Z",
    "name": "hf-strict",
    "description": "Block unsafe Hugging Face models",
    "source_type": "HUGGING_FACE",
    "state": "ACTIVE",
    "is_tombstone": False,
}
GROUP_LIST = {"pagination": {"total_items": 1}, "security_groups": [GROUP]}

PYPI_AUTH = {
    "url": "https://_token:ya29.example@us-python.pkg.dev/proj/repo/simple",
    "expires_at": "2026-01-01T01:00:00Z",
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a developer's real credentials out of the resolution tests."""
    for prefix in (ENV_PREFIX_MODEL_SEC, ENV_PREFIX_MGMT):
        for suffix in ("CLIENT_ID", "CLIENT_SECRET", "TSG_ID", "TOKEN_ENDPOINT"):
            monkeypatch.delenv(f"{prefix}_{suffix}", raising=False)
    monkeypatch.delenv(ENV_MODEL_SEC_DATA_ENDPOINT, raising=False)
    monkeypatch.delenv(ENV_MODEL_SEC_MGMT_ENDPOINT, raising=False)


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    """A mocked network with the token endpoint already answering."""
    with respx.mock(assert_all_called=False) as router:
        router.post(DEFAULT_TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": TOKEN, "expires_in": 900},
            )
        )
        yield router


@pytest.fixture
def no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collapse the retry backoff so a full-budget run costs milliseconds, not seconds.

    ``execute_with_retry`` binds ``time.sleep`` as a default argument and so cannot be
    replaced, but ``backoff_delay_ms`` resolves ``random.uniform`` at call time. Zeroing
    the jitter leaves the retry *count* -- the thing under test -- untouched.
    """
    monkeypatch.setattr(random, "uniform", lambda _low, _high: 0.0)


@pytest.fixture
def client() -> Iterator[ModelSecurityClient]:
    ms = ModelSecurityClient(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        tsg_id=TSG_ID,
        num_retries=0,
    )
    yield ms
    ms.close()


class TestConstruction:
    def test_defaults_to_the_published_plane_endpoints(self) -> None:
        ms = ModelSecurityClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID)

        assert (ms.data_endpoint, ms.mgmt_endpoint) == (DATA, MGMT)

    def test_the_endpoint_override_variables_are_named_as_documented(self) -> None:
        """Spelled out rather than rebuilt from the prefix: these are what a user types
        into a shell, so the literal names are the contract. Every other test reaches for
        the same symbol and would stay green through a rename."""
        assert ENV_MODEL_SEC_DATA_ENDPOINT == "PANW_MODEL_SEC_DATA_ENDPOINT"
        assert ENV_MODEL_SEC_MGMT_ENDPOINT == "PANW_MODEL_SEC_MGMT_ENDPOINT"

    def test_reads_each_plane_endpoint_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_MODEL_SEC_DATA_ENDPOINT, "https://data.internal")
        monkeypatch.setenv(ENV_MODEL_SEC_MGMT_ENDPOINT, "https://mgmt.internal")

        ms = ModelSecurityClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID)

        assert (ms.data_endpoint, ms.mgmt_endpoint) == (
            "https://data.internal",
            "https://mgmt.internal",
        )

    def test_an_explicit_endpoint_beats_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_MODEL_SEC_DATA_ENDPOINT, "https://data.internal")

        ms = ModelSecurityClient(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            tsg_id=TSG_ID,
            data_endpoint="https://explicit.internal",
        )

        assert ms.data_endpoint == "https://explicit.internal"

    def test_the_two_planes_get_different_base_urls(self, client: ModelSecurityClient) -> None:
        """Scans on the data plane, groups and rules on management -- crossing them 404s."""
        assert (client.scans.base_url, client.models.base_url) == (DATA, DATA)
        assert (client.security_groups.base_url, client.security_rules.base_url) == (MGMT, MGMT)

    def test_requires_credentials(self) -> None:
        with pytest.raises(AISecMissingVariableError, match="CLIENT_ID"):
            ModelSecurityClient()

    def test_resolves_credentials_from_the_service_prefix(
        self, monkeypatch: pytest.MonkeyPatch, api: respx.MockRouter
    ) -> None:
        for suffix, value in (("CLIENT_ID", "svc-id"), ("CLIENT_SECRET", "svc-secret")):
            monkeypatch.setenv(f"{ENV_PREFIX_MODEL_SEC}_{suffix}", value)
        monkeypatch.setenv(f"{ENV_PREFIX_MODEL_SEC}_TSG_ID", "999")
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )

        with ModelSecurityClient(num_retries=0) as ms:
            ms.get_pypi_auth()

        token_request = api.calls[0].request
        expected = base64.b64encode(b"svc-id:svc-secret").decode()
        assert token_request.headers["Authorization"] == f"Basic {expected}"

    def test_falls_back_to_the_management_prefix(
        self, monkeypatch: pytest.MonkeyPatch, api: respx.MockRouter
    ) -> None:
        """One service account drives every management-plane client, so PANW_MGMT_* wins
        when no Model Security specific value is set."""
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_ID", "shared-id")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_SECRET", "shared-secret")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_TSG_ID", "42")
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )

        with ModelSecurityClient(num_retries=0) as ms:
            ms.get_pypi_auth()

        token_request = api.calls[0].request
        expected = base64.b64encode(b"shared-id:shared-secret").decode()
        assert token_request.headers["Authorization"] == f"Basic {expected}"
        assert b"scope=tsg_id%3A42" in token_request.content

    def test_the_service_prefix_beats_the_fallback(
        self, monkeypatch: pytest.MonkeyPatch, api: respx.MockRouter
    ) -> None:
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_ID", "shared-id")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_CLIENT_SECRET", "shared-secret")
        monkeypatch.setenv(f"{ENV_PREFIX_MGMT}_TSG_ID", "42")
        monkeypatch.setenv(f"{ENV_PREFIX_MODEL_SEC}_CLIENT_ID", "svc-id")
        api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )

        with ModelSecurityClient(num_retries=0) as ms:
            ms.get_pypi_auth()

        expected = base64.b64encode(b"svc-id:shared-secret").decode()
        assert api.calls[0].request.headers["Authorization"] == f"Basic {expected}"

    @pytest.mark.parametrize(
        ("requested", "attempts"),
        [
            pytest.param(-1, 1, id="negative clamps to no retries"),
            pytest.param(0, 1, id="zero disables retries"),
            pytest.param(2, 3, id="a count inside the range is honoured"),
            pytest.param(99, MAX_NUMBER_OF_RETRIES + 1, id="oversized clamps to the maximum"),
        ],
    )
    def test_clamps_the_retry_count_into_the_supported_range(
        self, api: respx.MockRouter, no_backoff: None, requested: int, attempts: int
    ) -> None:
        """The reference clamps rather than raising, so -1 means "no retries" and 99
        means five -- neither is an error and neither retries forever."""
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(500, json={}))

        with (
            ModelSecurityClient(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                tsg_id=TSG_ID,
                num_retries=requested,
            ) as ms,
            pytest.raises(AISecServerError),
        ):
            ms.scans.list()

        assert route.call_count == attempts

    def test_defaults_to_the_full_retry_budget(
        self, api: respx.MockRouter, no_backoff: None
    ) -> None:
        """An unspecified count is five retries, not zero -- silently dropping the budget
        would turn a transient 500 into a hard failure."""
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(500, json={}))

        with (
            ModelSecurityClient(
                client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID
            ) as ms,
            pytest.raises(AISecServerError),
        ):
            ms.scans.list()

        assert route.call_count == MAX_NUMBER_OF_RETRIES + 1

    def test_the_retry_budget_reaches_the_management_plane_call(
        self, api: respx.MockRouter, no_backoff: None
    ) -> None:
        """get_pypi_auth issues its request from the facade rather than a sub-client, so
        it has its own path for the retry count to go missing on."""
        route = api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(500, json={})
        )

        with (
            ModelSecurityClient(
                client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID
            ) as ms,
            pytest.raises(AISecServerError),
        ):
            ms.get_pypi_auth()

        assert route.call_count == MAX_NUMBER_OF_RETRIES + 1

    def test_applies_the_default_timeout_to_the_pool_it_creates(self) -> None:
        with ModelSecurityClient(
            client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID
        ) as ms:
            assert ms._http.timeout.read == DEFAULT_TIMEOUT_SECONDS


class TestAuthentication:
    def test_sends_the_bearer_token(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        client.scans.list()

        assert route.calls.last.request.headers["Authorization"] == f"Bearer {TOKEN}"

    def test_does_not_send_the_tenant_header(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """Model Security is not the AI Gateway: the tenant lives in the token scope, and
        an x-tsg-id header here would be an unrequested deviation from the reference."""
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        client.scans.list()

        assert "x-tsg-id" not in route.calls.last.request.headers

    def test_refreshes_the_token_once_after_a_403(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """The management planes answer 403 for an expired token, so the free retry has
        to re-fetch rather than surface an authorisation error."""
        api.post(DEFAULT_TOKEN_ENDPOINT).mock(
            side_effect=[
                httpx.Response(200, json={"access_token": "stale", "expires_in": 900}),
                httpx.Response(200, json={"access_token": "fresh", "expires_in": 900}),
            ]
        )
        route = api.get(f"{DATA}/v1/scans").mock(
            side_effect=[
                httpx.Response(403, json={"message": "denied"}),
                httpx.Response(200, json=SCAN_LIST),
            ]
        )

        client.scans.list()

        assert [call.request.headers["Authorization"] for call in route.calls] == [
            "Bearer stale",
            "Bearer fresh",
        ]

    def test_reuses_a_live_token_across_calls(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """A token good for fifteen minutes is fetched once, not per request."""
        token_route = api.post(DEFAULT_TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": TOKEN, "expires_in": DEFAULT_TOKEN_BUFFER_MS / 1000 + 600},
            )
        )
        api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        client.scans.list()
        client.scans.list()

        assert token_route.call_count == 1


class TestPyPIAuth:
    def test_gets_credentials_from_the_management_plane(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """Management plane, even though the credentials serve the data-plane scanner."""
        route = api.get(f"{MGMT}/v1/pypi/authenticate").mock(
            return_value=httpx.Response(200, json=PYPI_AUTH)
        )

        result = client.get_pypi_auth()

        assert route.calls.last.request.method == "GET"
        assert str(route.calls.last.request.url) == f"{MGMT}/v1/pypi/authenticate"
        assert result.url == PYPI_AUTH["url"]
        assert result.expires_at == PYPI_AUTH["expires_at"]


class TestScanCreate:
    def test_posts_to_the_data_plane_scans_collection(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN))

        client.scans.create(
            ScanCreateRequest(
                model_uri="hf://org/model",
                security_group_uuid=GROUP_UUID,
                scan_origin="MODEL_SECURITY_SDK",
            )
        )

        sent = route.calls.last.request
        assert sent.method == "POST"
        assert str(sent.url) == f"{DATA}/v1/scans"

    def test_sends_the_documented_body_and_content_type(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN))

        client.scans.create(
            ScanCreateRequest(
                model_uri="hf://org/model",
                security_group_uuid=GROUP_UUID,
                scan_origin="MODEL_SECURITY_SDK",
            )
        )

        sent = route.calls.last.request
        assert sent.headers["Content-Type"] == "application/json"
        assert json.loads(sent.content) == {
            "model_uri": "hf://org/model",
            "security_group_uuid": GROUP_UUID,
            "scan_origin": "MODEL_SECURITY_SDK",
        }

    def test_omits_unset_optional_fields(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """An absent key and an explicit null are not the same thing to this service."""
        route = api.post(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN))

        client.scans.create(
            ScanCreateRequest(model_uri="hf://org/model", security_group_uuid=GROUP_UUID)
        )

        body = json.loads(route.calls.last.request.content)
        assert set(body) == {"model_uri", "security_group_uuid"}

    def test_returns_the_parsed_scan(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        api.post(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN))

        scan = client.scans.create(
            ScanCreateRequest(model_uri="hf://org/model", security_group_uuid=GROUP_UUID)
        )

        assert (scan.uuid, scan.eval_outcome) == (SCAN_UUID, "ALLOWED")


class TestScanList:
    def test_sends_no_query_string_when_unfiltered(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        client.scans.list()

        assert route.calls.last.request.url.query == b""

    def test_builds_the_pagination_parameters(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        client.scans.list(skip=20, limit=5, search="llama")

        assert route.calls.last.request.url.query.decode() == "skip=20&limit=5&search=llama"

    def test_keeps_a_zero_offset(self, client: ModelSecurityClient, api: respx.MockRouter) -> None:
        """skip=0 is a real request for the first page, not an unset filter."""
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        client.scans.list(skip=0)

        assert route.calls.last.request.url.query.decode() == "skip=0"

    def test_repeats_multi_valued_filters_rather_than_joining_them(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """The reference appends each value to URLSearchParams; a comma-joined value
        would be read as one literal outcome name."""
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        client.scans.list(eval_outcomes=["ALLOWED", "BLOCKED"], source_types=["HUGGING_FACE"])

        query = route.calls.last.request.url.query.decode()
        assert query == "eval_outcomes=ALLOWED&eval_outcomes=BLOCKED&source_types=HUGGING_FACE"

    def test_uses_sort_by_not_sort_field(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """The scan list is the only endpoint in this domain spelled sort_by."""
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        client.scans.list(sort_by="created_at", sort_order="desc")

        params = route.calls.last.request.url.params
        assert (params["sort_by"], params["sort_order"]) == ("created_at", "desc")
        assert "sort_field" not in params

    def test_passes_every_scalar_filter_through(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        client.scans.list(
            search_query="llama",
            security_group_uuid=GROUP_UUID,
            start_time="2026-01-01T00:00:00Z",
            end_time="2026-02-01T00:00:00Z",
            labels_query="env=prod",
        )

        params = route.calls.last.request.url.params
        assert dict(params) == {
            "search_query": "llama",
            "security_group_uuid": GROUP_UUID,
            "start_time": "2026-01-01T00:00:00Z",
            "end_time": "2026-02-01T00:00:00Z",
            "labels_query": "env=prod",
        }

    def test_returns_the_parsed_page(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        api.get(f"{DATA}/v1/scans").mock(return_value=httpx.Response(200, json=SCAN_LIST))

        page = client.scans.list()

        assert page.pagination.total_items == 1
        assert [s.uuid for s in page.scans] == [SCAN_UUID]


class TestScanGet:
    def test_gets_one_scan_by_uuid(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}").mock(
            return_value=httpx.Response(200, json=SCAN)
        )

        client.scans.get(SCAN_UUID)

        assert route.calls.last.request.method == "GET"
        assert str(route.calls.last.request.url) == f"{DATA}/v1/scans/{SCAN_UUID}"

    def test_rejects_a_malformed_uuid_before_sending(self, client: ModelSecurityClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid scan uuid"):
            client.scans.get(BAD_UUID)


class TestScanEvaluations:
    def test_gets_the_evaluations_subresource(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/evaluations").mock(
            return_value=httpx.Response(200, json=EVALUATION_LIST)
        )

        client.scans.get_evaluations(SCAN_UUID)

        assert str(route.calls.last.request.url) == f"{DATA}/v1/scans/{SCAN_UUID}/evaluations"

    def test_builds_the_filter_parameters(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/evaluations").mock(
            return_value=httpx.Response(200, json=EVALUATION_LIST)
        )

        client.scans.get_evaluations(
            SCAN_UUID,
            skip=10,
            limit=2,
            search="pickle",
            sort_field="updated_at",
            sort_order="asc",
            result="FAILED",
            rule_instance_uuid=INSTANCE_UUID,
        )

        assert dict(route.calls.last.request.url.params) == {
            "skip": "10",
            "limit": "2",
            "search": "pickle",
            "sort_field": "updated_at",
            "sort_order": "asc",
            "result": "FAILED",
            "rule_instance_uuid": INSTANCE_UUID,
        }

    def test_returns_the_parsed_evaluations(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        api.get(f"{DATA}/v1/scans/{SCAN_UUID}/evaluations").mock(
            return_value=httpx.Response(200, json=EVALUATION_LIST)
        )

        page = client.scans.get_evaluations(SCAN_UUID)

        assert page.evaluations[0].violation_count == 2

    def test_rejects_a_malformed_scan_uuid(self, client: ModelSecurityClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid scan uuid"):
            client.scans.get_evaluations(BAD_UUID)


class TestScanFiles:
    def test_gets_the_files_subresource(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/files").mock(
            return_value=httpx.Response(200, json=FILE_LIST)
        )

        client.scans.get_files(SCAN_UUID)

        assert str(route.calls.last.request.url) == f"{DATA}/v1/scans/{SCAN_UUID}/files"

    def test_sends_file_type_as_the_type_parameter(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """The Python name avoids shadowing the builtin; the wire name must not change."""
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/files").mock(
            return_value=httpx.Response(200, json=FILE_LIST)
        )

        client.scans.get_files(SCAN_UUID, file_type="FILE")

        params = route.calls.last.request.url.params
        assert params["type"] == "FILE"
        assert "file_type" not in params

    def test_uses_sort_dir_not_sort_order(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/files").mock(
            return_value=httpx.Response(200, json=FILE_LIST)
        )

        client.scans.get_files(SCAN_UUID, sort_field="path", sort_dir="desc", result="SUCCESS")

        params = route.calls.last.request.url.params
        assert (params["sort_field"], params["sort_dir"]) == ("path", "desc")
        assert "sort_order" not in params

    def test_passes_the_subtree_filter(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/files").mock(
            return_value=httpx.Response(200, json=FILE_LIST)
        )

        client.scans.get_files(SCAN_UUID, query_path="/weights", limit=50)

        assert dict(route.calls.last.request.url.params) == {
            "limit": "50",
            "query_path": "/weights",
        }

    def test_rejects_a_malformed_scan_uuid(self, client: ModelSecurityClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid scan uuid"):
            client.scans.get_files(BAD_UUID)


class TestScanLabels:
    LABELS = LabelsCreateRequest(labels=[Label(key="env", value="prod")])

    def test_add_labels_posts_to_merge(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """POST merges, PUT replaces -- the verb is the whole difference."""
        route = api.post(f"{DATA}/v1/scans/{SCAN_UUID}/labels").mock(
            return_value=httpx.Response(200, json={})
        )

        client.scans.add_labels(SCAN_UUID, self.LABELS)

        sent = route.calls.last.request
        assert sent.method == "POST"
        assert str(sent.url) == f"{DATA}/v1/scans/{SCAN_UUID}/labels"
        assert json.loads(sent.content) == {"labels": [{"key": "env", "value": "prod"}]}

    def test_set_labels_puts_to_replace(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{DATA}/v1/scans/{SCAN_UUID}/labels").mock(
            return_value=httpx.Response(200, json={})
        )

        client.scans.set_labels(SCAN_UUID, self.LABELS)

        sent = route.calls.last.request
        assert sent.method == "PUT"
        assert str(sent.url) == f"{DATA}/v1/scans/{SCAN_UUID}/labels"
        assert json.loads(sent.content) == {"labels": [{"key": "env", "value": "prod"}]}

    def test_delete_labels_repeats_the_keys_parameter(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """Keys travel in the query string as repeated keys, not comma-joined."""
        route = api.delete(f"{DATA}/v1/scans/{SCAN_UUID}/labels").mock(
            return_value=httpx.Response(204)
        )

        client.scans.delete_labels(SCAN_UUID, ["env", "team"])

        sent = route.calls.last.request
        assert sent.method == "DELETE"
        assert sent.url.query.decode() == "keys=env&keys=team"

    def test_delete_labels_sends_no_body(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.delete(f"{DATA}/v1/scans/{SCAN_UUID}/labels").mock(
            return_value=httpx.Response(204)
        )

        client.scans.delete_labels(SCAN_UUID, ["env"])

        assert route.calls.last.request.content == b""

    def test_delete_labels_returns_nothing(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """The reference resolves to void, so no response model is declared here -- an
        empty 204 body must neither trip validation nor hydrate into an empty object."""
        route = api.delete(f"{DATA}/v1/scans/{SCAN_UUID}/labels").mock(
            return_value=httpx.Response(204)
        )

        # Asserting the return is None would be tautological -- the signature says so, and
        # mypy rejects the comparison. What matters is that an empty 204 completes the call
        # without tripping response validation.
        client.scans.delete_labels(SCAN_UUID, ["env"])

        assert route.called

    @pytest.mark.parametrize("method", ["add_labels", "set_labels"])
    def test_label_writes_reject_a_malformed_scan_uuid(
        self, client: ModelSecurityClient, method: str
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid scan uuid"):
            getattr(client.scans, method)(BAD_UUID, self.LABELS)

    def test_delete_labels_rejects_a_malformed_scan_uuid(self, client: ModelSecurityClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid scan uuid"):
            client.scans.delete_labels(BAD_UUID, ["env"])


class TestScanViolations:
    def test_uses_the_rule_violations_segment(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """Under a scan the segment is rule-violations; the standalone collection is
        /v1/violations. They are not the same path."""
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/rule-violations").mock(
            return_value=httpx.Response(200, json=VIOLATION_LIST)
        )

        client.scans.get_violations(SCAN_UUID, limit=10)

        sent = route.calls.last.request
        assert sent.url.path.endswith(f"/v1/scans/{SCAN_UUID}/rule-violations")
        assert sent.url.query.decode() == "limit=10"

    def test_accepts_only_pagination_parameters(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans/{SCAN_UUID}/rule-violations").mock(
            return_value=httpx.Response(200, json=VIOLATION_LIST)
        )

        client.scans.get_violations(SCAN_UUID, skip=5, limit=10, search="pickle")

        assert route.calls.last.request.url.query.decode() == "skip=5&limit=10&search=pickle"

    def test_rejects_a_malformed_scan_uuid(self, client: ModelSecurityClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid scan uuid"):
            client.scans.get_violations(BAD_UUID)


class TestLabelCatalogue:
    def test_label_keys_is_tenant_wide(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """A sibling of /v1/scans/{uuid}, not a child of it -- no scan identifier."""
        route = api.get(f"{DATA}/v1/scans/label-keys").mock(
            return_value=httpx.Response(200, json=LABEL_KEYS)
        )

        result = client.scans.get_label_keys(limit=50)

        assert str(route.calls.last.request.url) == f"{DATA}/v1/scans/label-keys?limit=50"
        assert result.keys == ["env", "team", "owner"]

    def test_label_values_nests_under_the_key(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/scans/label-keys/env/values").mock(
            return_value=httpx.Response(200, json=LABEL_VALUES)
        )

        result = client.scans.get_label_values("env", skip=0, limit=50)

        sent = route.calls.last.request
        assert sent.url.path.endswith("/v1/scans/label-keys/env/values")
        assert sent.url.query.decode() == "skip=0&limit=50"
        assert result.values == ["prod", "staging"]

    def test_percent_encodes_a_label_key_containing_a_slash(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """Label keys are free-form caller input; an unescaped slash would reshape the
        path into a different endpoint."""
        route = api.get(f"{DATA}/v1/scans/label-keys/team%2Fowner/values").mock(
            return_value=httpx.Response(200, json=LABEL_VALUES)
        )

        client.scans.get_label_values("team/owner")

        assert str(route.calls.last.request.url) == (
            f"{DATA}/v1/scans/label-keys/team%2Fowner/values"
        )


class TestStandaloneEvaluationsAndViolations:
    def test_gets_an_evaluation_from_its_own_collection(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/evaluations/{EVAL_UUID}").mock(
            return_value=httpx.Response(200, json=EVALUATION)
        )

        result = client.scans.get_evaluation(EVAL_UUID)

        assert str(route.calls.last.request.url) == f"{DATA}/v1/evaluations/{EVAL_UUID}"
        assert result.rule_name == "Pickle Scan"

    def test_gets_a_violation_from_its_own_collection(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/violations/{VIOLATION_UUID}").mock(
            return_value=httpx.Response(200, json=VIOLATION)
        )

        result = client.scans.get_violation(VIOLATION_UUID)

        assert str(route.calls.last.request.url) == f"{DATA}/v1/violations/{VIOLATION_UUID}"
        assert result.remediation.url == "https://docs.example"

    def test_rejects_a_malformed_evaluation_uuid(self, client: ModelSecurityClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid evaluation uuid"):
            client.scans.get_evaluation(BAD_UUID)

    def test_rejects_a_malformed_violation_uuid(self, client: ModelSecurityClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid violation uuid"):
            client.scans.get_violation(BAD_UUID)


class TestModels:
    def test_lists_models_on_the_data_plane(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/models").mock(return_value=httpx.Response(200, json=MODEL_LIST))

        page = client.models.list_models()

        assert str(route.calls.last.request.url) == f"{DATA}/v1/models"
        assert [m.name for m in page.models] == ["org/llama"]

    def test_repeats_the_latest_version_filters(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/models").mock(return_value=httpx.Response(200, json=MODEL_LIST))

        client.models.list_models(
            latest_version_outcomes=["ALLOWED", "BLOCKED"],
            latest_version_formats=["safetensors"],
            latest_version_source_types=["HUGGING_FACE", "S3"],
        )

        assert route.calls.last.request.url.query.decode() == (
            "latest_version_outcomes=ALLOWED&latest_version_outcomes=BLOCKED"
            "&latest_version_formats=safetensors"
            "&latest_version_source_types=HUGGING_FACE&latest_version_source_types=S3"
        )

    def test_passes_the_scalar_model_filters(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/models").mock(return_value=httpx.Response(200, json=MODEL_LIST))

        client.models.list_models(
            skip=1,
            limit=10,
            search="llama",
            search_query="org/llama",
            sort_field="created_at",
            sort_order="desc",
            latest_version_scan_time_before="2026-01-01T00:00:00Z",
            start_time="2025-01-01T00:00:00Z",
            end_time="2026-01-01T00:00:00Z",
        )

        assert dict(route.calls.last.request.url.params) == {
            "skip": "1",
            "limit": "10",
            "search": "llama",
            "search_query": "org/llama",
            "sort_field": "created_at",
            "sort_order": "desc",
            "latest_version_scan_time_before": "2026-01-01T00:00:00Z",
            "start_time": "2025-01-01T00:00:00Z",
            "end_time": "2026-01-01T00:00:00Z",
        }

    def test_gets_one_model(self, client: ModelSecurityClient, api: respx.MockRouter) -> None:
        route = api.get(f"{DATA}/v1/models/{MODEL_UUID}").mock(
            return_value=httpx.Response(200, json=MODEL)
        )

        result = client.models.get_model(MODEL_UUID)

        assert str(route.calls.last.request.url) == f"{DATA}/v1/models/{MODEL_UUID}"
        assert result.latest_version_uuid == VERSION_UUID

    def test_lists_versions_under_the_model(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/models/{MODEL_UUID}/model-versions").mock(
            return_value=httpx.Response(200, json=MODEL_VERSION_LIST)
        )

        page = client.models.list_model_versions(MODEL_UUID, limit=5, sort_order="desc")

        sent = route.calls.last.request
        assert sent.url.path.endswith(f"/v1/models/{MODEL_UUID}/model-versions")
        assert sent.url.query.decode() == "limit=5&sort_order=desc"
        assert [v.revision for v in page.model_versions] == ["main"]

    def test_version_listing_has_no_sort_field(self, client: ModelSecurityClient) -> None:
        """This route takes a direction only; the server owns the field. Offering a
        sort_field here would invent a filter the service does not implement."""
        with pytest.raises(TypeError, match="sort_field"):
            client.models.list_model_versions(MODEL_UUID, sort_field="created_at")  # type: ignore[call-arg]

    def test_gets_one_model_version_from_its_own_collection(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/model-versions/{VERSION_UUID}").mock(
            return_value=httpx.Response(200, json=MODEL_VERSION)
        )

        result = client.models.get_model_version(VERSION_UUID)

        assert str(route.calls.last.request.url) == f"{DATA}/v1/model-versions/{VERSION_UUID}"
        assert result.file_count == 12

    def test_lists_a_versions_files(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DATA}/v1/model-versions/{VERSION_UUID}/files").mock(
            return_value=httpx.Response(200, json=FILE_LIST)
        )

        page = client.models.list_model_version_files(VERSION_UUID, skip=0, limit=50)

        sent = route.calls.last.request
        assert sent.url.path.endswith(f"/v1/model-versions/{VERSION_UUID}/files")
        assert sent.url.query.decode() == "skip=0&limit=50"
        assert [f.path for f in page.files] == ["/model.safetensors"]

    @pytest.mark.parametrize(
        ("method", "message"),
        [
            ("get_model", "Invalid model uuid"),
            ("list_model_versions", "Invalid model uuid"),
            ("get_model_version", "Invalid model version uuid"),
            ("list_model_version_files", "Invalid model version uuid"),
        ],
    )
    def test_rejects_a_malformed_identifier(
        self, client: ModelSecurityClient, method: str, message: str
    ) -> None:
        with pytest.raises(AISecPayloadError, match=message):
            getattr(client.models, method)(BAD_UUID)


class TestSecurityGroups:
    def test_creates_on_the_management_plane(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.post(f"{MGMT}/v1/security-groups").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        client.security_groups.create(
            ModelSecurityGroupCreateRequest(name="hf-strict", source_type="HUGGING_FACE")
        )

        sent = route.calls.last.request
        assert str(sent.url) == f"{MGMT}/v1/security-groups"
        assert json.loads(sent.content) == {
            "name": "hf-strict",
            "source_type": "HUGGING_FACE",
            "description": "",
        }

    def test_lists_with_filters(self, client: ModelSecurityClient, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-groups").mock(
            return_value=httpx.Response(200, json=GROUP_LIST)
        )

        page = client.security_groups.list(
            skip=0,
            limit=10,
            search="hf",
            sort_field="created_at",
            sort_dir="desc",
            source_types=["HUGGING_FACE", "S3"],
            search_query="strict",
            enabled_rules=[RULE_UUID],
        )

        assert route.calls.last.request.url.query.decode() == (
            "skip=0&limit=10&search=hf&sort_field=created_at&sort_dir=desc"
            f"&source_types=HUGGING_FACE&source_types=S3&search_query=strict"
            f"&enabled_rules={RULE_UUID}"
        )
        assert [g.name for g in page.security_groups] == ["hf-strict"]

    def test_gets_one_group(self, client: ModelSecurityClient, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        result = client.security_groups.get(GROUP_UUID)

        assert str(route.calls.last.request.url) == f"{MGMT}/v1/security-groups/{GROUP_UUID}"
        assert result.state == "ACTIVE"

    def test_updates_with_put(self, client: ModelSecurityClient, api: respx.MockRouter) -> None:
        route = api.put(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        client.security_groups.update(
            GROUP_UUID,
            ModelSecurityGroupUpdateRequest(name="hf-strict-v2", description="Updated"),
        )

        sent = route.calls.last.request
        assert sent.method == "PUT"
        assert json.loads(sent.content) == {"name": "hf-strict-v2", "description": "Updated"}

    def test_update_omits_fields_left_alone(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.put(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(200, json=GROUP)
        )

        client.security_groups.update(GROUP_UUID, ModelSecurityGroupUpdateRequest(name="renamed"))

        assert json.loads(route.calls.last.request.content) == {"name": "renamed"}

    def test_deletes_with_no_body_and_no_response_model(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.delete(f"{MGMT}/v1/security-groups/{GROUP_UUID}").mock(
            return_value=httpx.Response(204)
        )

        client.security_groups.delete(GROUP_UUID)

        sent = route.calls.last.request
        assert sent.method == "DELETE"
        assert str(sent.url) == f"{MGMT}/v1/security-groups/{GROUP_UUID}"
        assert sent.content == b""

    def test_lists_rule_instances(self, client: ModelSecurityClient, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-groups/{GROUP_UUID}/rule-instances").mock(
            return_value=httpx.Response(200, json=RULE_INSTANCE_LIST)
        )

        page = client.security_groups.list_rule_instances(
            GROUP_UUID, limit=25, security_rule_uuid=RULE_UUID, state="BLOCKING"
        )

        sent = route.calls.last.request
        assert sent.url.path.endswith(f"/v1/security-groups/{GROUP_UUID}/rule-instances")
        assert dict(sent.url.params) == {
            "limit": "25",
            "security_rule_uuid": RULE_UUID,
            "state": "BLOCKING",
        }
        assert page.rule_instances[0].rule.name == "Pickle Scan"

    def test_gets_one_rule_instance(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        url = f"{MGMT}/v1/security-groups/{GROUP_UUID}/rule-instances/{INSTANCE_UUID}"
        route = api.get(url).mock(return_value=httpx.Response(200, json=RULE_INSTANCE))

        client.security_groups.get_rule_instance(GROUP_UUID, INSTANCE_UUID)

        assert str(route.calls.last.request.url) == url

    def test_updates_a_rule_instance(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """The group UUID is required in the body as well as the path -- the service does
        not infer it from the URL."""
        url = f"{MGMT}/v1/security-groups/{GROUP_UUID}/rule-instances/{INSTANCE_UUID}"
        route = api.put(url).mock(return_value=httpx.Response(200, json=RULE_INSTANCE))

        client.security_groups.update_rule_instance(
            GROUP_UUID,
            INSTANCE_UUID,
            ModelSecurityRuleInstanceUpdateRequest(
                security_group_uuid=GROUP_UUID, state="ALLOWING"
            ),
        )

        sent = route.calls.last.request
        assert sent.method == "PUT"
        assert str(sent.url) == url
        assert json.loads(sent.content) == {
            "security_group_uuid": GROUP_UUID,
            "state": "ALLOWING",
        }

    @pytest.mark.parametrize("method", ["get", "delete"])
    def test_rejects_a_malformed_group_uuid(self, client: ModelSecurityClient, method: str) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid security group uuid"):
            getattr(client.security_groups, method)(BAD_UUID)

    def test_update_rejects_a_malformed_group_uuid(self, client: ModelSecurityClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid security group uuid"):
            client.security_groups.update(BAD_UUID, ModelSecurityGroupUpdateRequest(name="x"))

    def test_list_rule_instances_rejects_a_malformed_group_uuid(
        self, client: ModelSecurityClient
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid security group uuid"):
            client.security_groups.list_rule_instances(BAD_UUID)

    def test_get_rule_instance_rejects_a_malformed_group_uuid(
        self, client: ModelSecurityClient
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid security group uuid"):
            client.security_groups.get_rule_instance(BAD_UUID, INSTANCE_UUID)

    def test_get_rule_instance_rejects_a_malformed_instance_uuid(
        self, client: ModelSecurityClient
    ) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid rule instance uuid"):
            client.security_groups.get_rule_instance(GROUP_UUID, BAD_UUID)

    def test_update_rule_instance_rejects_a_malformed_instance_uuid(
        self, client: ModelSecurityClient
    ) -> None:
        body = ModelSecurityRuleInstanceUpdateRequest(security_group_uuid=GROUP_UUID)
        with pytest.raises(AISecPayloadError, match="Invalid rule instance uuid"):
            client.security_groups.update_rule_instance(GROUP_UUID, BAD_UUID, body)

    def test_update_rule_instance_rejects_a_malformed_group_uuid(
        self, client: ModelSecurityClient
    ) -> None:
        body = ModelSecurityRuleInstanceUpdateRequest(security_group_uuid=GROUP_UUID)
        with pytest.raises(AISecPayloadError, match="Invalid security group uuid"):
            client.security_groups.update_rule_instance(BAD_UUID, INSTANCE_UUID, body)

    def test_rule_instance_reads_report_the_group_uuid_first(
        self, client: ModelSecurityClient
    ) -> None:
        """Both identifiers are checked, so when both are junk the message has to name
        the one the reference checks first -- otherwise a caller debugging a bad group
        UUID is sent after the rule instance instead."""
        with pytest.raises(AISecPayloadError, match="Invalid security group uuid"):
            client.security_groups.get_rule_instance(BAD_UUID, BAD_UUID)

    def test_rule_instance_writes_report_the_group_uuid_first(
        self, client: ModelSecurityClient
    ) -> None:
        body = ModelSecurityRuleInstanceUpdateRequest(security_group_uuid=GROUP_UUID)
        with pytest.raises(AISecPayloadError, match="Invalid security group uuid"):
            client.security_groups.update_rule_instance(BAD_UUID, BAD_UUID, body)


class TestSecurityRules:
    def test_lists_the_catalogue_on_the_management_plane(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{MGMT}/v1/security-rules").mock(
            return_value=httpx.Response(200, json=RULE_LIST)
        )

        page = client.security_rules.list(
            skip=0, limit=20, search="pickle", source_type="HUGGING_FACE", search_query="Pickle"
        )

        assert route.calls.last.request.url.query.decode() == (
            "skip=0&limit=20&search=pickle&source_type=HUGGING_FACE&search_query=Pickle"
        )
        assert [r.name for r in page.rules] == ["Pickle Scan"]

    def test_source_type_is_singular_here(
        self, client: ModelSecurityClient, api: respx.MockRouter
    ) -> None:
        """The rule catalogue filters on one source type; groups and scans take a list."""
        route = api.get(f"{MGMT}/v1/security-rules").mock(
            return_value=httpx.Response(200, json=RULE_LIST)
        )

        client.security_rules.list(source_type="S3")

        params = route.calls.last.request.url.params
        assert params["source_type"] == "S3"
        assert "source_types" not in params

    def test_gets_one_rule(self, client: ModelSecurityClient, api: respx.MockRouter) -> None:
        route = api.get(f"{MGMT}/v1/security-rules/{RULE_UUID}").mock(
            return_value=httpx.Response(200, json=RULE)
        )

        result = client.security_rules.get(RULE_UUID)

        assert str(route.calls.last.request.url) == f"{MGMT}/v1/security-rules/{RULE_UUID}"
        assert result.rule_type == "ARTIFACT"

    def test_rejects_a_malformed_rule_uuid(self, client: ModelSecurityClient) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid security rule uuid"):
            client.security_rules.get(BAD_UUID)


class TestLifecycle:
    def test_closes_a_client_it_created(self) -> None:
        ms = ModelSecurityClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID)

        ms.close()

        assert ms._http.is_closed

    def test_leaves_an_injected_client_open(self) -> None:
        """A caller-supplied pool is shared with the rest of their application."""
        injected = httpx.Client()

        with ModelSecurityClient(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            tsg_id=TSG_ID,
            http_client=injected,
        ):
            pass

        assert not injected.is_closed
        injected.close()

    def test_the_context_manager_closes_on_exit(self) -> None:
        with ModelSecurityClient(
            client_id=CLIENT_ID, client_secret=CLIENT_SECRET, tsg_id=TSG_ID
        ) as ms:
            pass

        assert ms._http.is_closed
