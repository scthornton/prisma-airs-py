"""Contract tests for the Scanner client.

These assert the exact request that goes on the wire, which is what keeps the port
honest against the reference implementation.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from prisma_airs._utils import generate_payload_hash
from prisma_airs.constants import AIRS_ENDPOINTS, DEFAULT_ENDPOINT, ENV_AI_SEC_API_ENDPOINT
from prisma_airs.errors import AISecMissingVariableError, AISecPayloadError
from prisma_airs.models.scan import AiProfile, AsyncScanObject, Content, ScanRequest
from prisma_airs.scan.scanner import Scanner, resolve_endpoint

API_KEY = "test-key"
SYNC_URL = f"{DEFAULT_ENDPOINT}/v1/scan/sync/request"
ASYNC_URL = f"{DEFAULT_ENDPOINT}/v1/scan/async/request"
RESULTS_URL = f"{DEFAULT_ENDPOINT}/v1/scan/results"
REPORTS_URL = f"{DEFAULT_ENDPOINT}/v1/scan/reports"

VERDICT = {
    "report_id": "R1",
    "scan_id": "S1",
    "category": "malicious",
    "action": "block",
    "timeout": False,
    "error": False,
    "errors": [],
}


@pytest.fixture
def scanner() -> Scanner:
    return Scanner(api_key=API_KEY, num_retries=0)


class TestEndpointResolution:
    def test_defaults_to_the_us_endpoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ENV_AI_SEC_API_ENDPOINT, raising=False)

        assert resolve_endpoint() == DEFAULT_ENDPOINT

    @pytest.mark.parametrize("region", ["us", "de", "in", "sg"])
    def test_resolves_each_region(self, region: str) -> None:
        assert resolve_endpoint(region=region) == AIRS_ENDPOINTS[region]

    def test_region_is_case_insensitive(self) -> None:
        assert resolve_endpoint(region="DE") == AIRS_ENDPOINTS["de"]

    def test_rejects_an_unknown_region_by_name(self) -> None:
        """A silent fallback to US would send regulated data to the wrong jurisdiction."""
        with pytest.raises(AISecPayloadError, match="Unknown region"):
            resolve_endpoint(region="antarctica")

    def test_an_explicit_endpoint_wins(self) -> None:
        assert resolve_endpoint("https://proxy.internal", "de") == "https://proxy.internal"

    def test_reads_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_AI_SEC_API_ENDPOINT, "https://from-env.test")

        assert resolve_endpoint() == "https://from-env.test"


class TestConstruction:
    def test_requires_a_credential(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PANW_AI_SEC_API_KEY", raising=False)
        monkeypatch.delenv("PANW_AI_SEC_API_TOKEN", raising=False)

        with pytest.raises(AISecMissingVariableError, match="PANW_AI_SEC_API_KEY"):
            Scanner()

    def test_reads_the_key_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PANW_AI_SEC_API_KEY", "env-key")

        assert Scanner().endpoint == DEFAULT_ENDPOINT

    @pytest.mark.parametrize("value", [-1, 6, 1.5, True])
    def test_rejects_an_unusable_retry_count(self, value: object) -> None:
        with pytest.raises(AISecPayloadError, match="num_retries"):
            Scanner(api_key=API_KEY, num_retries=value)  # type: ignore[arg-type]


class TestSyncScan:
    @respx.mock
    def test_posts_to_the_sync_scan_path(self, scanner: Scanner) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=VERDICT))

        scanner.scan(prompt="hi", profile_name="prod")

        assert route.called

    @respx.mock
    def test_sends_the_api_key_header(self, scanner: Scanner) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=VERDICT))

        scanner.scan(prompt="hi", profile_name="prod")

        assert route.calls.last.request.headers["x-pan-token"] == API_KEY

    @respx.mock
    def test_signs_the_body_with_the_api_key(self, scanner: Scanner) -> None:
        """The service verifies this HMAC; a mismatch presents as a bad API key."""
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=VERDICT))

        scanner.scan(prompt="hi", profile_name="prod")

        sent = route.calls.last.request
        expected = generate_payload_hash(sent.content.decode(), API_KEY)
        assert sent.headers["x-payload-hash"] == expected

    @respx.mock
    def test_builds_the_documented_body_shape(self, scanner: Scanner) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=VERDICT))

        scanner.scan(prompt="hi", profile_name="prod")

        body = json.loads(route.calls.last.request.content)
        assert body == {"ai_profile": {"profile_name": "prod"}, "contents": [{"prompt": "hi"}]}

    @respx.mock
    def test_omits_unset_optional_fields(self, scanner: Scanner) -> None:
        """The service treats an explicit null differently from an absent key."""
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=VERDICT))

        scanner.scan(prompt="hi", profile_name="prod")

        body = json.loads(route.calls.last.request.content)
        assert "tr_id" not in body
        assert "session_id" not in body
        assert "response" not in body["contents"][0]

    @respx.mock
    def test_includes_tracing_identifiers_when_supplied(self, scanner: Scanner) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=VERDICT))

        scanner.scan(prompt="hi", profile_name="prod", tr_id="T1", session_id="S1")

        body = json.loads(route.calls.last.request.content)
        assert (body["tr_id"], body["session_id"]) == ("T1", "S1")

    @respx.mock
    def test_returns_the_parsed_verdict(self, scanner: Scanner) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=VERDICT))

        result = scanner.scan(prompt="hi", profile_name="prod")

        assert result.action == "block"
        assert result.is_blocked

    def test_rejects_an_over_long_transaction_id(self, scanner: Scanner) -> None:
        with pytest.raises(AISecPayloadError, match="tr_id"):
            scanner.sync_scan(
                ai_profile=AiProfile(profile_name="p"),
                content=Content(prompt="hi"),
                tr_id="x" * 101,
            )


class TestAsyncScan:
    def _object(self, req_id: int = 1) -> AsyncScanObject:
        return AsyncScanObject(
            req_id=req_id,
            scan_req=ScanRequest(
                ai_profile=AiProfile(profile_name="prod"), contents=[Content(prompt="hi")]
            ),
        )

    @respx.mock
    def test_posts_the_batch_as_a_list(self, scanner: Scanner) -> None:
        route = respx.post(ASYNC_URL).mock(
            return_value=httpx.Response(200, json={"received": "2026-01-01", "scan_id": "S1"})
        )

        scanner.async_scan([self._object()])

        assert isinstance(json.loads(route.calls.last.request.content), list)

    def test_rejects_an_empty_batch(self, scanner: Scanner) -> None:
        with pytest.raises(AISecPayloadError, match="At least 1"):
            scanner.async_scan([])

    def test_rejects_an_oversized_batch(self, scanner: Scanner) -> None:
        """The service caps a batch at twenty; failing here saves a round trip."""
        with pytest.raises(AISecPayloadError, match="Max of 20"):
            scanner.async_scan([self._object(i) for i in range(21)])


class TestQueryByScanIds:
    UUID = "123e4567-e89b-12d3-a456-426614174000"

    @respx.mock
    def test_joins_ids_with_commas(self, scanner: Scanner) -> None:
        """Comma-joined in one parameter, not repeated keys."""
        route = respx.get(RESULTS_URL).mock(return_value=httpx.Response(200, json=[]))
        second = "223e4567-e89b-12d3-a456-426614174000"

        scanner.query_by_scan_ids([self.UUID, second])

        assert route.calls.last.request.url.params["scan_ids"] == f"{self.UUID},{second}"

    @respx.mock
    def test_preserves_server_row_order(self, scanner: Scanner) -> None:
        """One scan ID can yield several rows; they are not sorted or deduplicated."""
        rows = [{"req_id": 2, "scan_id": self.UUID}, {"req_id": 1, "scan_id": self.UUID}]
        respx.get(RESULTS_URL).mock(return_value=httpx.Response(200, json=rows))

        results = scanner.query_by_scan_ids([self.UUID])

        assert [r.req_id for r in results] == [2, 1]

    def test_rejects_an_empty_list(self, scanner: Scanner) -> None:
        with pytest.raises(AISecPayloadError, match="At least 1 scan_id"):
            scanner.query_by_scan_ids([])

    def test_rejects_more_than_five(self, scanner: Scanner) -> None:
        with pytest.raises(AISecPayloadError, match="Max of 5"):
            scanner.query_by_scan_ids([self.UUID] * 6)

    def test_rejects_a_malformed_id(self, scanner: Scanner) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid scan_id"):
            scanner.query_by_scan_ids(["not-a-uuid"])


class TestQueryByReportIds:
    @respx.mock
    def test_joins_ids_with_commas(self, scanner: Scanner) -> None:
        route = respx.get(REPORTS_URL).mock(return_value=httpx.Response(200, json=[]))

        scanner.query_by_report_ids(["R1", "R2"])

        assert route.calls.last.request.url.params["report_ids"] == "R1,R2"

    def test_does_not_require_uuid_format(self, scanner: Scanner) -> None:
        """Report IDs are not UUIDs, so validating them as such would reject valid input."""
        with respx.mock:
            respx.get(REPORTS_URL).mock(return_value=httpx.Response(200, json=[]))

            assert scanner.query_by_report_ids(["R000000123"]) == []

    def test_rejects_an_empty_list(self, scanner: Scanner) -> None:
        with pytest.raises(AISecPayloadError, match="At least 1 report_id"):
            scanner.query_by_report_ids([])

    def test_rejects_more_than_five(self, scanner: Scanner) -> None:
        with pytest.raises(AISecPayloadError, match="Max of 5"):
            scanner.query_by_report_ids(["R1"] * 6)
