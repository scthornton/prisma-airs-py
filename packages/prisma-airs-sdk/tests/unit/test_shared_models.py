"""Shared enums and cross-cutting payloads."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from prisma_airs.models.scan import (
    ContentError,
    PromptDetected,
    ResponseDetected,
    ScanResponse,
    ToolDetectionFlags,
)
from prisma_airs.models.shared import (
    Action,
    Category,
    ContentErrorType,
    DetectionServiceName,
    ErrorDetail,
    ErrorResponse,
    ErrorStatus,
    OAuthTokenResponse,
    RetryAfter,
    Verdict,
)


class TestEnumVocabularies:
    def test_verdict_values(self) -> None:
        assert {member.value for member in Verdict} == {"benign", "malicious", "unknown"}

    def test_action_values(self) -> None:
        assert {member.value for member in Action} == {"allow", "block", "alert"}

    def test_category_mirrors_verdict_today(self) -> None:
        """They are separate types, but the two vocabularies are currently identical."""
        assert {m.value for m in Category} == {m.value for m in Verdict}

    def test_detection_service_name_values(self) -> None:
        """The largest vocabulary, pinned name-by-name so a dropped member is caught here."""
        assert {member.name: member.value for member in DetectionServiceName} == {
            "DLP": "dlp",
            "INJECTION": "injection",
            "URL_CATS": "url_cats",
            "TOXIC_CONTENT": "toxic_content",
            "MALICIOUS_CODE": "malicious_code",
            "AGENT": "agent",
            "TOPIC_VIOLATION": "topic_violation",
            "DB_SECURITY": "db_security",
            "UNGROUNDED": "ungrounded",
        }

    def test_content_error_type_values(self) -> None:
        assert {member.value for member in ContentErrorType} == {"prompt", "response"}

    def test_error_status_values(self) -> None:
        assert {member.value for member in ErrorStatus} == {"error", "timeout"}

    def test_rendering_a_member_yields_its_wire_value(self) -> None:
        """Guards a real portability trap, not a style preference.

        A plain ``(str, Enum)`` renders as the value on Python 3.10 but as
        ``Action.BLOCK`` from 3.11, because 3.11 changed ``Enum.__format__`` for mixin
        enums. These values go into URLs and query strings, so the same code would send
        different text depending on the interpreter. ``WireEnum`` pins all three forms.
        """
        assert f"{Action.BLOCK}" == "block"
        assert str(Action.BLOCK) == "block"
        assert "{}".format(Action.BLOCK) == "block"  # noqa: UP032 - format() is the point
        assert Action.BLOCK.value == "block"
        assert json.dumps({"action": Action.BLOCK}) == '{"action": "block"}'


class TestEnumsAgainstResponseModels:
    """The enums are only useful if they line up with what the response models carry."""

    def test_members_compare_equal_to_raw_response_strings(self) -> None:
        """Response models keep these fields as ``str``; the str mixin bridges the gap."""
        response = ScanResponse.model_validate(
            {"report_id": "R1", "scan_id": "S1", "category": "malicious", "action": "block"}
        )

        assert response.action == Action.BLOCK
        assert response.category == Category.MALICIOUS
        assert response.action != Action.ALLOW

    def test_response_fields_accept_a_value_the_enums_do_not_carry(self) -> None:
        """Why the enums are not applied as field types: they are closed, responses are not."""
        with pytest.raises(ValueError, match="quarantine"):
            Action("quarantine")

        response = ScanResponse.model_validate(
            {
                "report_id": "R1",
                "scan_id": "S1",
                "category": "suspicious",
                "action": "quarantine",
            }
        )

        assert response.action == "quarantine"
        assert response.category == "suspicious"

    def test_every_service_name_names_a_detection_flag(self) -> None:
        flags = (
            set(PromptDetected.model_fields)
            | set(ResponseDetected.model_fields)
            | set(ToolDetectionFlags.model_fields)
        )

        assert {member.value for member in DetectionServiceName} <= flags

    def test_source_code_is_a_flag_with_no_service_name(self) -> None:
        """A documented gap: walking the enum to enumerate detections misses this one."""
        assert "source_code" in PromptDetected.model_fields
        assert "source_code" not in {member.value for member in DetectionServiceName}

    def test_content_error_fields_come_from_these_vocabularies(self) -> None:
        error = ContentError.model_validate(
            {"content_type": "response", "feature": "dlp", "status": "timeout"}
        )

        assert ContentErrorType(error.content_type) is ContentErrorType.RESPONSE
        assert ErrorStatus(error.status) is ErrorStatus.TIMEOUT


class TestErrorResponse:
    def test_parses_a_rate_limited_body(self) -> None:
        error = ErrorResponse.model_validate(
            {
                "status_code": 429,
                "message": "Rate limit exceeded",
                "retry_after": {"interval": 30, "unit": "seconds"},
            }
        )

        assert error.status_code == 429
        assert error.message == "Rate limit exceeded"
        assert error.retry_after is not None
        assert error.retry_after.interval == 30.0
        assert error.retry_after.unit == "seconds"

    def test_parses_a_body_with_only_a_nested_message(self) -> None:
        error = ErrorResponse.model_validate(
            {"status_code": 400, "error": {"message": "ai_profile is required"}}
        )

        assert error.message is None
        assert error.error is not None
        assert error.error.message == "ai_profile is required"

    def test_accepts_an_empty_body(self) -> None:
        """A failure can arrive with nothing in it; parsing must not be the thing that fails."""
        assert ErrorResponse().detail is None

    def test_status_code_is_a_float_that_still_compares_as_an_int(self) -> None:
        error = ErrorResponse(status_code=503)

        assert isinstance(error.status_code, float)
        assert error.status_code == 503

    def test_rejects_a_non_numeric_status_code(self) -> None:
        with pytest.raises(ValidationError):
            ErrorResponse.model_validate({"status_code": "gateway timeout"})

    def test_rejects_a_scalar_where_the_error_object_belongs(self) -> None:
        with pytest.raises(ValidationError):
            ErrorResponse.model_validate({"error": "something went wrong"})

    def test_rejects_malformed_retry_guidance(self) -> None:
        """The transport reads ``interval`` as a number; a header-style string is not one."""
        with pytest.raises(ValidationError):
            ErrorResponse.model_validate({"retry_after": "30s"})

        with pytest.raises(ValidationError):
            ErrorResponse.model_validate({"retry_after": {"interval": "half a minute"}})

    def test_preserves_unmodelled_error_envelopes(self) -> None:
        """Several AIRS services wrap errors as ``error_message``; nothing may be dropped."""
        error = ErrorResponse.model_validate(
            {"status_code": 403, "error_message": "Invalid API key", "errorCode": "AB01"}
        )

        assert error.model_extra is not None
        assert error.model_extra["error_message"] == "Invalid API key"
        assert error.model_extra["errorCode"] == "AB01"

    def test_preserves_unknown_fields_inside_retry_guidance(self) -> None:
        error = ErrorResponse.model_validate(
            {"retry_after": {"interval": 2, "unit": "min", "reason": "capacity"}}
        )

        assert error.retry_after is not None
        assert error.retry_after.model_extra == {"reason": "capacity"}

    def test_round_trips_without_inventing_fields(self) -> None:
        payload = {
            "status_code": 429,
            "message": "Rate limit exceeded",
            "retry_after": {"interval": 30, "unit": "seconds"},
        }

        dumped = ErrorResponse.model_validate(payload).model_dump(exclude_none=True)

        assert dumped == payload


class TestErrorResponseDetail:
    def test_prefers_the_top_level_message(self) -> None:
        error = ErrorResponse(
            message="Rate limit exceeded", error=ErrorDetail(message="too many requests")
        )

        assert error.detail == "Rate limit exceeded"

    def test_falls_back_to_the_nested_message(self) -> None:
        error = ErrorResponse(error=ErrorDetail(message="quota exhausted"))

        assert error.detail == "quota exhausted"

    def test_is_none_when_the_body_carries_no_message(self) -> None:
        error = ErrorResponse(status_code=502, retry_after=RetryAfter(interval=1, unit="s"))

        assert error.detail is None

    def test_is_none_when_the_nested_error_carries_no_message(self) -> None:
        """The nested object can arrive holding only a code, which is not human-readable."""
        error = ErrorResponse.model_validate({"status_code": 500, "error": {"code": "AB05"}})

        assert error.error is not None
        assert error.error.message is None
        assert error.detail is None

    def test_ignores_an_empty_message(self) -> None:
        """An empty string is not a message; fall through rather than return ``""``."""
        error = ErrorResponse(message="", error=ErrorDetail(message="upstream refused"))

        assert error.detail == "upstream refused"

    def test_shadows_a_wire_field_of_the_same_name(self) -> None:
        """If a service ever sends ``detail``, the property wins -- read it from extras."""
        error = ErrorResponse.model_validate({"message": "modelled", "detail": "raw"})

        assert error.detail == "modelled"
        assert error.model_extra is not None
        assert error.model_extra["detail"] == "raw"


class TestOAuthTokenResponse:
    def _payload(self, **extra: object) -> dict[str, object]:
        return {
            "access_token": "eyJhbGciOiJSUzI1NiJ9.stub-token",
            "token_type": "Bearer",
            "expires_in": 899,
            "scope": "tsg_id:1234567890",
            **extra,
        }

    def test_parses_a_token_response(self) -> None:
        token = OAuthTokenResponse.model_validate(self._payload())

        assert token.access_token == "eyJhbGciOiJSUzI1NiJ9.stub-token"
        assert token.token_type == "Bearer"
        assert token.expires_in == 899.0
        assert token.scope == "tsg_id:1234567890"

    def test_expires_in_is_a_float(self) -> None:
        """It feeds a clock arithmetic expression, so the int is widened at the boundary."""
        assert isinstance(OAuthTokenResponse.model_validate(self._payload()).expires_in, float)

    def test_requires_an_access_token(self) -> None:
        with pytest.raises(ValidationError, match="access_token"):
            OAuthTokenResponse.model_validate({"expires_in": 899})

    def test_requires_an_expiry(self) -> None:
        """Without it there is no way to know when to refresh, so it is not optional."""
        with pytest.raises(ValidationError, match="expires_in"):
            OAuthTokenResponse.model_validate({"access_token": "t"})

    def test_rejects_a_non_numeric_expiry(self) -> None:
        with pytest.raises(ValidationError):
            OAuthTokenResponse.model_validate(self._payload(expires_in="in a while"))

    def test_treats_the_optional_fields_as_optional(self) -> None:
        token = OAuthTokenResponse.model_validate({"access_token": "t", "expires_in": 60})

        assert (token.token_type, token.scope) == (None, None)

    def test_permits_an_empty_access_token(self) -> None:
        """The schema does not police this; ``OAuthClient`` raises ``AISecOAuthError`` instead."""
        token = OAuthTokenResponse.model_validate({"access_token": "", "expires_in": 60})

        assert token.access_token == ""

    def test_preserves_unknown_fields(self) -> None:
        token = OAuthTokenResponse.model_validate(self._payload(refresh_token="r", jti="abc"))

        assert token.model_extra is not None
        assert token.model_extra["refresh_token"] == "r"
        assert token.model_extra["jti"] == "abc"
