"""The exception contract: classification, message shape, and transport metadata."""

from __future__ import annotations

import pytest

from prisma_airs.errors import (
    AISecClientError,
    AISecOAuthError,
    AISecSDKException,
    AISecServerError,
    ErrorType,
    FailureKind,
)


class TestMessageShape:
    def test_prefixes_the_message_with_the_error_type(self) -> None:
        """Log lines must stay greppable across the Python, TypeScript, and service."""
        err = AISecSDKException("Invalid API Key", ErrorType.CLIENT_SIDE_ERROR)

        assert str(err) == "AISEC_CLIENT_SIDE_ERROR:Invalid API Key"

    def test_omits_the_prefix_when_unclassified(self) -> None:
        assert str(AISecSDKException("something went wrong")) == "something went wrong"

    def test_keeps_the_undecorated_message_available(self) -> None:
        """Renderers want the message without the machine-readable prefix."""
        err = AISecServerError("upstream exploded")

        assert err.raw_message == "upstream exploded"
        assert str(err) == "AISEC_SERVER_SIDE_ERROR:upstream exploded"


class TestClassification:
    @pytest.mark.parametrize(
        ("cls", "expected"),
        [
            (AISecServerError, ErrorType.SERVER_SIDE_ERROR),
            (AISecClientError, ErrorType.CLIENT_SIDE_ERROR),
            (AISecOAuthError, ErrorType.OAUTH_ERROR),
        ],
    )
    def test_subclasses_supply_their_own_error_type(
        self, cls: type[AISecSDKException], expected: ErrorType
    ) -> None:
        assert cls("boom").error_type is expected

    def test_an_explicit_error_type_overrides_the_subclass_default(self) -> None:
        err = AISecClientError("boom", ErrorType.USER_REQUEST_PAYLOAD_ERROR)

        assert err.error_type is ErrorType.USER_REQUEST_PAYLOAD_ERROR

    def test_every_subclass_is_catchable_as_the_base(self) -> None:
        """Callers should be able to catch broadly without enumerating subclasses."""
        with pytest.raises(AISecSDKException):
            raise AISecOAuthError("token expired")


class TestTransportMetadata:
    def test_carries_status_and_failure_kind(self) -> None:
        err = AISecClientError(
            "not found", failure_kind=FailureKind.HTTP, status_code=404, retry_after_ms=1500
        )

        assert err.status_code == 404
        assert err.failure_kind is FailureKind.HTTP
        assert err.retry_after_seconds == 1.5

    def test_retry_after_seconds_is_none_when_unset(self) -> None:
        assert AISecClientError("nope").retry_after_seconds is None
