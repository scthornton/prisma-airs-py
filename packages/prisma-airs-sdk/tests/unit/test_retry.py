"""Retry policy, error-envelope extraction, and Retry-After normalisation.

These behaviours are matched deliberately against the reference implementation, so the
tests pin the specifics rather than the general shape.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from prisma_airs._http.retry import (
    backoff_delay_ms,
    classify_error_type,
    execute_with_retry,
    extract_error_message,
    is_retryable_status,
    parse_retry_after_body,
    parse_retry_after_header,
)
from prisma_airs.errors import AISecClientError, AISecSDKException, AISecServerError, ErrorType


def response(status: int, text: str = "", headers: dict[str, str] | None = None) -> httpx.Response:
    """Build a response detached from any real transport."""
    return httpx.Response(
        status, text=text, headers=headers, request=httpx.Request("GET", "https://example.test")
    )


class TestBackoff:
    @pytest.mark.parametrize("attempt", range(6))
    def test_stays_within_the_full_jitter_window(self, attempt: int) -> None:
        """Uniform over [0, 2**attempt seconds]; never negative, never over the ceiling."""
        for _ in range(200):
            delay = backoff_delay_ms(attempt)
            assert 0 <= delay <= 2**attempt * 1000

    def test_window_widens_with_each_attempt(self) -> None:
        early = max(backoff_delay_ms(0) for _ in range(200))
        late = max(backoff_delay_ms(4) for _ in range(200))

        assert late > early


class TestStatusClassification:
    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    def test_retries_the_transient_server_statuses(self, status: int) -> None:
        assert is_retryable_status(status)

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 429, 501])
    def test_does_not_retry_anything_else(self, status: int) -> None:
        """429 is deliberately excluded: the service supplies guidance, the caller decides."""
        assert not is_retryable_status(status)

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (400, ErrorType.CLIENT_SIDE_ERROR),
            (499, ErrorType.CLIENT_SIDE_ERROR),
            (500, ErrorType.SERVER_SIDE_ERROR),
            (503, ErrorType.SERVER_SIDE_ERROR),
        ],
    )
    def test_classifies_by_status_family(self, status: int, expected: ErrorType) -> None:
        assert classify_error_type(status) is expected


class TestErrorMessageExtraction:
    """Four services front these APIs and each wraps errors differently."""

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ('{"error_message":"scan rejected"}', "scan rejected"),
            ('{"message":"bad request"}', "bad request"),
            ('{"success":false,"data":{"message":"forbidden"}}', "forbidden"),
            ('{"error":{"message":"nested"}}', "nested"),
            ('{"msg":"Access denied"}', "Access denied"),
        ],
    )
    def test_reads_every_known_envelope(self, body: str, expected: str) -> None:
        assert extract_error_message(body, 400) == expected

    def test_prefers_the_earliest_envelope_when_several_are_present(self) -> None:
        body = '{"error_message":"first","message":"second","msg":"third"}'

        assert extract_error_message(body, 400) == "first"

    def test_appends_the_ai_gateway_error_code(self) -> None:
        """AB01/AB02/AB03 distinguish denial reasons that share a status code."""
        body = '{"data":{"message":"forbidden","errorCode":"AB05"}}'

        assert extract_error_message(body, 403) == "forbidden (errorCode: AB05)"

    def test_falls_back_to_the_status_for_an_unrecognised_envelope(self) -> None:
        assert extract_error_message('{"unexpected":"shape"}', 418) == "API error 418"

    def test_includes_the_raw_body_when_it_is_not_json(self) -> None:
        assert extract_error_message("<html>502 Bad Gateway</html>", 502) == (
            "API error 502: <html>502 Bad Gateway</html>"
        )

    def test_handles_an_empty_body(self) -> None:
        assert extract_error_message("", 500) == "API error 500"

    def test_handles_a_json_scalar_body(self) -> None:
        assert extract_error_message('"just a string"', 400) == 'API error 400: "just a string"'


class TestRetryAfterHeader:
    def test_reads_delta_seconds(self) -> None:
        assert parse_retry_after_header("120") == 120_000

    def test_treats_absent_as_unknown(self) -> None:
        assert parse_retry_after_header(None) is None

    def test_treats_empty_as_unknown(self) -> None:
        assert parse_retry_after_header("   ") is None

    @pytest.mark.parametrize(
        "value",
        [
            "Sun, 06 Nov 1994 08:49:37 GMT",  # IMF-fixdate
            "Sunday, 06-Nov-94 08:49:37 GMT",  # obsolete RFC 850
            "Sun Nov  6 08:49:37 1994",  # asctime, space-padded day
        ],
    )
    def test_accepts_all_three_http_date_spellings(self, value: str) -> None:
        """RFC 9110 lists three; a client that reads only one silently mistimes retries."""
        assert parse_retry_after_header(value) is not None

    def test_computes_the_delay_from_a_future_date(self) -> None:
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        future = (now + timedelta(seconds=90)).strftime("%a, %d %b %Y %H:%M:%S GMT")

        assert parse_retry_after_header(future, now=lambda: now) == pytest.approx(90_000)

    def test_clamps_a_past_date_to_zero(self) -> None:
        """A stale date means retry now, not retry in negative time."""
        now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        past = (now - timedelta(hours=1)).strftime("%a, %d %b %Y %H:%M:%S GMT")

        assert parse_retry_after_header(past, now=lambda: now) == 0.0

    def test_ignores_an_unparseable_value_rather_than_guessing(self) -> None:
        assert parse_retry_after_header("next tuesday") is None


class TestRetryAfterBody:
    @pytest.mark.parametrize(
        ("unit", "expected"),
        [
            ("ms", 30.0),
            ("milliseconds", 30.0),
            ("s", 30_000.0),
            ("seconds", 30_000.0),
            ("m", 1_800_000.0),
            ("minutes", 1_800_000.0),
        ],
    )
    def test_converts_each_known_unit(self, unit: str, expected: float) -> None:
        body = f'{{"retry_after":{{"interval":30,"unit":"{unit}"}}}}'

        assert parse_retry_after_body(body) == expected

    def test_is_case_insensitive_about_units(self) -> None:
        assert parse_retry_after_body('{"retry_after":{"interval":1,"unit":"SECONDS"}}') == 1000.0

    def test_rejects_an_unknown_unit_rather_than_guessing(self) -> None:
        """Treating hours as milliseconds would hammer a struggling endpoint."""
        assert parse_retry_after_body('{"retry_after":{"interval":1,"unit":"hours"}}') is None

    @pytest.mark.parametrize(
        "body",
        [
            '{"retry_after":{"interval":-5,"unit":"s"}}',  # negative
            '{"retry_after":{"interval":true,"unit":"s"}}',  # bool is not an interval
            '{"retry_after":{"interval":"30","unit":"s"}}',  # string
            '{"retry_after":{"interval":30}}',  # no unit
            '{"retry_after":"soon"}',  # not an object
            "{}",  # absent
            "not json",
        ],
    )
    def test_rejects_malformed_guidance(self, body: str) -> None:
        assert parse_retry_after_body(body) is None


class TestExecuteWithRetry:
    @staticmethod
    def _run(**kwargs: object) -> httpx.Response:
        defaults: dict[str, object] = {"sleep": lambda _s: None, "delay_ms": lambda _a: 0.0}
        return execute_with_retry(**{**defaults, **kwargs})  # type: ignore[arg-type]

    def test_returns_the_first_success_without_retrying(self) -> None:
        calls: list[int] = []

        def execute(attempt: int) -> httpx.Response:
            calls.append(attempt)
            return response(200)

        result = self._run(max_retries=3, execute=execute)

        assert result.status_code == 200
        assert calls == [0]

    def test_retries_a_transient_server_error_then_succeeds(self) -> None:
        statuses = [503, 503, 200]
        calls: list[int] = []

        def execute(attempt: int) -> httpx.Response:
            calls.append(attempt)
            return response(statuses[attempt])

        assert self._run(max_retries=3, execute=execute).status_code == 200
        assert calls == [0, 1, 2]

    def test_raises_a_server_error_once_the_budget_is_spent(self) -> None:
        attempts: list[int] = []

        def execute(attempt: int) -> httpx.Response:
            attempts.append(attempt)
            return response(500, '{"message":"down"}')

        with pytest.raises(AISecServerError) as caught:
            self._run(max_retries=2, execute=execute)

        assert attempts == [0, 1, 2]  # initial attempt plus two retries
        assert caught.value.status_code == 500
        assert caught.value.raw_message == "down"

    def test_does_not_retry_a_client_error(self) -> None:
        attempts: list[int] = []

        def execute(attempt: int) -> httpx.Response:
            attempts.append(attempt)
            return response(400, '{"message":"bad"}')

        with pytest.raises(AISecClientError) as caught:
            self._run(max_retries=3, execute=execute)

        assert attempts == [0]
        assert caught.value.status_code == 400

    def test_surfaces_retry_after_on_the_exception(self) -> None:
        with pytest.raises(AISecClientError) as caught:
            self._run(
                max_retries=0,
                execute=lambda _a: response(429, "", {"Retry-After": "42"}),
            )

        assert caught.value.retry_after_seconds == 42.0

    def test_falls_back_to_body_retry_guidance(self) -> None:
        body = '{"message":"slow down","retry_after":{"interval":2,"unit":"seconds"}}'

        with pytest.raises(AISecClientError) as caught:
            self._run(max_retries=0, execute=lambda _a: response(429, body))

        assert caught.value.retry_after_seconds == 2.0

    def test_retries_a_network_failure(self) -> None:
        calls: list[int] = []

        def execute(attempt: int) -> httpx.Response:
            calls.append(attempt)
            if attempt < 2:
                raise httpx.ConnectError("connection refused")
            return response(200)

        assert self._run(max_retries=3, execute=execute).status_code == 200
        assert calls == [0, 1, 2]

    def test_reports_a_network_failure_that_never_recovers(self) -> None:
        def execute(_attempt: int) -> httpx.Response:
            raise httpx.ConnectTimeout("timed out")

        with pytest.raises(AISecClientError) as caught:
            self._run(max_retries=1, execute=execute)

        assert caught.value.failure_kind is not None
        assert caught.value.failure_kind.value == "network"

    def test_propagates_sdk_exceptions_without_retrying(self) -> None:
        """A programming error inside the pipeline must not be retried five times."""
        attempts: list[int] = []

        def execute(attempt: int) -> httpx.Response:
            attempts.append(attempt)
            raise AISecSDKException("bad spec")

        with pytest.raises(AISecSDKException, match="bad spec"):
            self._run(max_retries=3, execute=execute)

        assert attempts == [0]

    def test_an_auth_retry_does_not_consume_the_retry_budget(self) -> None:
        """The central claim: a token expiring mid-run costs a request, not the budget."""
        statuses = [401, 500, 500, 500, 200]
        calls: list[int] = []
        refreshed = False

        def execute(_attempt: int) -> httpx.Response:
            calls.append(len(calls))
            return response(statuses[len(calls) - 1])

        def on_failure(resp: httpx.Response) -> bool:
            nonlocal refreshed
            if resp.status_code == 401 and not refreshed:
                refreshed = True
                return True
            return False

        result = self._run(max_retries=3, execute=execute, on_retryable_failure=on_failure)

        # Five calls total: one spent on auth, then the full budget of three retries
        # still available for the 500s.
        assert len(calls) == 5
        assert result.status_code == 200
