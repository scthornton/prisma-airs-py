"""Scan request and response models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from prisma_airs.constants import MAX_CONTENT_PROMPT_LENGTH
from prisma_airs.models.scan import (
    AiProfile,
    Content,
    ScanRequest,
    ScanResponse,
    ThreatScanReport,
)


class TestAiProfile:
    def test_accepts_a_name(self) -> None:
        assert AiProfile(profile_name="prod").profile_name == "prod"

    def test_accepts_an_id(self) -> None:
        assert AiProfile(profile_id="a-uuid").profile_id == "a-uuid"

    def test_requires_at_least_one_identifier(self) -> None:
        """Sending neither is accepted by some clients, then rejected opaquely upstream."""
        with pytest.raises(ValidationError, match="profile_id or profile_name"):
            AiProfile()

    def test_rejects_an_over_long_name(self) -> None:
        with pytest.raises(ValidationError):
            AiProfile(profile_name="x" * 101)


class TestContent:
    def test_requires_something_scannable(self) -> None:
        with pytest.raises(ValidationError, match="At least one of"):
            Content()

    def test_context_alone_is_not_scannable(self) -> None:
        """Context frames other content; on its own there is nothing to evaluate."""
        with pytest.raises(ValidationError, match="At least one of"):
            Content(context="the user is asking about geography")

    @pytest.mark.parametrize("field", ["prompt", "response", "code_prompt", "code_response"])
    def test_any_single_content_field_suffices(self, field: str) -> None:
        assert Content.model_validate({field: "something"}) is not None

    def test_a_tool_event_alone_suffices(self) -> None:
        content = Content.model_validate({"tool_event": {"input": "ls -la"}})

        assert content.tool_event is not None

    def test_enforces_the_prompt_byte_ceiling(self) -> None:
        with pytest.raises(ValidationError, match="exceeds max length"):
            Content(prompt="x" * (MAX_CONTENT_PROMPT_LENGTH + 1))

    def test_measures_bytes_not_characters(self) -> None:
        """A four-byte emoji hits the ceiling four times sooner than its length implies."""
        emoji = "🔐"
        assert len(emoji) == 1
        with pytest.raises(ValidationError, match="exceeds max length"):
            Content(prompt=emoji * (MAX_CONTENT_PROMPT_LENGTH // 4 + 1))

    def test_an_empty_prompt_is_nothing_to_scan(self) -> None:
        """Verified against the reference, which refuses `scan --profile p ""` identically.

        Tempting to treat "" as supplied-but-empty and send it. The reference does not,
        and a differential test caught the divergence when this port briefly did.
        """
        with pytest.raises(ValidationError, match="At least one of"):
            Content(prompt="")

    def test_an_empty_response_is_also_nothing_to_scan(self) -> None:
        with pytest.raises(ValidationError, match="At least one of"):
            Content(response="")

    def test_accepts_content_exactly_at_the_ceiling(self) -> None:
        assert Content(prompt="x" * MAX_CONTENT_PROMPT_LENGTH) is not None


class TestScanRequest:
    def test_requires_at_least_one_content_item(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest(ai_profile=AiProfile(profile_name="p"), contents=[])

    def test_rejects_an_over_long_transaction_id(self) -> None:
        with pytest.raises(ValidationError):
            ScanRequest(
                ai_profile=AiProfile(profile_name="p"),
                contents=[Content(prompt="hi")],
                tr_id="x" * 101,
            )


class TestScanResponse:
    def _minimal(self, **extra: object) -> dict[str, object]:
        return {
            "report_id": "R123",
            "scan_id": "S123",
            "category": "benign",
            "action": "allow",
            "timeout": False,
            "error": False,
            "errors": [],
            **extra,
        }

    def test_parses_a_minimal_verdict(self) -> None:
        result = ScanResponse.model_validate(self._minimal())

        assert (result.category, result.action) == ("benign", "allow")

    def test_exposes_a_blocked_convenience(self) -> None:
        assert ScanResponse.model_validate(self._minimal(action="block")).is_blocked
        assert not ScanResponse.model_validate(self._minimal()).is_blocked

    def test_parses_nested_detections(self) -> None:
        result = ScanResponse.model_validate(
            self._minimal(prompt_detected={"injection": True, "dlp": False})
        )

        assert result.prompt_detected is not None
        assert result.prompt_detected.injection is True

    def test_preserves_unknown_fields(self) -> None:
        """The services add response fields without a version bump."""
        result = ScanResponse.model_validate(self._minimal(brand_new_field="surprise"))

        assert result.model_extra is not None
        assert result.model_extra["brand_new_field"] == "surprise"

    def test_still_requires_the_fields_the_verdict_depends_on(self) -> None:
        with pytest.raises(ValidationError):
            ScanResponse.model_validate({"report_id": "R1", "scan_id": "S1"})


class TestThreatScanReport:
    def test_parses_nested_detection_results(self) -> None:
        report = ThreatScanReport.model_validate(
            {
                "report_id": "R1",
                "detection_results": [
                    {
                        "detection_service": "dlp",
                        "verdict": "malicious",
                        "result_detail": {
                            "dlp_report": {"dlp_profile_name": "pci", "dlp_profile_version": 3}
                        },
                    }
                ],
            }
        )

        assert report.detection_results is not None
        detail = report.detection_results[0].result_detail
        assert detail is not None
        assert detail.dlp_report is not None
        assert detail.dlp_report.dlp_profile_name == "pci"

    def test_tolerates_nulls_where_the_service_sends_them(self) -> None:
        """The DLP report marks most fields nullish, not merely optional."""
        report = ThreatScanReport.model_validate(
            {"detection_results": [{"result_detail": {"dlp_report": {"dlp_report_id": None}}}]}
        )

        assert report.detection_results is not None
