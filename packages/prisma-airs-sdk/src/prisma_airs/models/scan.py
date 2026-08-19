"""Request and response models for the AI Runtime Security scan API."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field, field_validator, model_validator

from prisma_airs.constants import (
    MAX_AI_PROFILE_NAME_LENGTH,
    MAX_CONTENT_CONTEXT_LENGTH,
    MAX_CONTENT_PROMPT_LENGTH,
    MAX_CONTENT_RESPONSE_LENGTH,
    MAX_SESSION_ID_STR_LENGTH,
    MAX_TRANSACTION_ID_STR_LENGTH,
)
from prisma_airs.models.base import AirsModel

#: Character offsets into scanned text, as ``[[start, end], ...]``.
Offset = list[list[float]]


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AgentMeta(AirsModel):
    """Identifying details for an agent that produced the scanned content."""

    agent_id: str | None = None
    agent_version: str | None = None
    agent_arn: str | None = None


class Metadata(AirsModel):
    """Application metadata attached to a scan, used for reporting and filtering."""

    app_name: str | None = None
    app_user: str | None = None
    ai_model: str | None = None
    user_ip: str | None = None
    agent_meta: AgentMeta | None = None


class AiProfile(AirsModel):
    """Identifies the security profile to evaluate against.

    Exactly one of the two identifiers is enough, and at least one is required. Sending
    neither is accepted by the model layer of some clients and then rejected by the
    service with an opaque message, so it is caught here instead.
    """

    profile_id: str | None = None
    profile_name: Annotated[str | None, Field(max_length=MAX_AI_PROFILE_NAME_LENGTH)] = None

    @model_validator(mode="after")
    def _require_an_identifier(self) -> AiProfile:
        if not self.profile_id and not self.profile_name:
            raise ValueError("Either profile_id or profile_name must be provided")
        return self


class ToolEventMetadata(AirsModel):
    """Describes the tool or MCP server that produced a tool event."""

    ecosystem: str | None = None
    method: str | None = None
    server_name: str | None = None
    tool_invoked: str | None = None


class ToolEvent(AirsModel):
    """A tool or function invocation, scanned as a unit."""

    metadata: ToolEventMetadata | None = None
    input: str | None = None
    output: str | None = None


def _check_byte_length(value: str | None, limit: int, field: str) -> str | None:
    """Enforce a byte-length ceiling.

    The service measures bytes, not characters, so a prompt of emoji reaches the limit
    four times sooner than its character count suggests.

    Raises ``ValueError`` rather than an SDK error so Pydantic wraps it into a
    ``ValidationError`` alongside the field name. Building a model is Pydantic's
    contract; SDK errors belong to client calls.
    """
    if value is not None and len(value.encode()) > limit:
        raise ValueError(f"{field} exceeds max length of {limit} bytes")
    return value


class Content(AirsModel):
    """One unit of content to scan.

    At least one of ``prompt``, ``response``, ``code_prompt``, ``code_response``, or
    ``tool_event`` must be present -- ``context`` alone gives the service nothing to
    evaluate.

    "Present" means truthy, so an empty string does not count. That matches the reference
    client, which refuses an empty prompt with this same error rather than sending one.
    """

    prompt: str | None = None
    response: str | None = None
    code_prompt: str | None = None
    code_response: str | None = None
    context: str | None = None
    tool_event: ToolEvent | None = None

    @field_validator("prompt")
    @classmethod
    def _validate_prompt(cls, value: str | None) -> str | None:
        return _check_byte_length(value, MAX_CONTENT_PROMPT_LENGTH, "prompt")

    @field_validator("response")
    @classmethod
    def _validate_response(cls, value: str | None) -> str | None:
        return _check_byte_length(value, MAX_CONTENT_RESPONSE_LENGTH, "response")

    @field_validator("code_prompt")
    @classmethod
    def _validate_code_prompt(cls, value: str | None) -> str | None:
        return _check_byte_length(value, MAX_CONTENT_PROMPT_LENGTH, "code_prompt")

    @field_validator("code_response")
    @classmethod
    def _validate_code_response(cls, value: str | None) -> str | None:
        return _check_byte_length(value, MAX_CONTENT_RESPONSE_LENGTH, "code_response")

    @field_validator("context")
    @classmethod
    def _validate_context(cls, value: str | None) -> str | None:
        return _check_byte_length(value, MAX_CONTENT_CONTEXT_LENGTH, "context")

    @model_validator(mode="after")
    def _require_scannable_content(self) -> Content:
        # Falsiness, not `is None`: an empty string counts as nothing to scan. Verified
        # against the reference, which rejects `scan --profile p ""` with this same
        # message rather than sending {"prompt": ""}.
        if not any(
            (self.prompt, self.response, self.code_prompt, self.code_response, self.tool_event)
        ):
            raise ValueError(
                "At least one of prompt, response, code_prompt, code_response, "
                "or tool_event must be provided"
            )
        return self


class ScanRequest(AirsModel):
    """A complete scan request payload."""

    ai_profile: AiProfile
    contents: Annotated[list[Content], Field(min_length=1)]
    tr_id: Annotated[str | None, Field(max_length=MAX_TRANSACTION_ID_STR_LENGTH)] = None
    session_id: Annotated[str | None, Field(max_length=MAX_SESSION_ID_STR_LENGTH)] = None
    metadata: Metadata | None = None


# ---------------------------------------------------------------------------
# Detection reports
# ---------------------------------------------------------------------------


class TcReport(AirsModel):
    """Toxic-content finding."""

    confidence: str | None = None
    verdict: str | None = None


class DbsEntry(AirsModel):
    """One database-security finding."""

    sub_type: str | None = None
    verdict: str | None = None
    action: str | None = None


class McEntry(AirsModel):
    """Per-file-type analysis within a malicious-code report."""

    file_type: str | None = None
    code_sha256: str | None = None


class MalwareReport(AirsModel):
    """Malware-script verdict."""

    verdict: str | None = None


class CmdEntry(AirsModel):
    """One command-injection finding."""

    code_block: str | None = None
    verdict: str | None = None


class McReport(AirsModel):
    """Malicious-code analysis across the extracted code blocks."""

    all_code_blocks: list[str] | None = None
    code_analysis_by_type: list[McEntry] | None = None
    verdict: str | None = None
    malware_script_report: MalwareReport | None = None
    command_injection_report: list[CmdEntry] | None = None


class AgentEntry(AirsModel):
    """One agent-pattern finding."""

    category_type: str | None = None
    verdict: str | None = None


class AgentReport(AirsModel):
    """Agent-framework detection results."""

    model_verdict: str | None = None
    agent_framework: str | None = None
    agent_patterns: list[AgentEntry] | None = None


class TgReport(AirsModel):
    """Topic-guardrail evaluation."""

    allowed_topic_list: str | None = None
    blocked_topic_list: str | None = None
    allowed_topics: Annotated[list[str] | None, Field(alias="allowedTopics")] = None
    blocked_topics: Annotated[list[str] | None, Field(alias="blockedTopics")] = None


class CgReport(AirsModel):
    """Contextual-grounding evaluation."""

    status: str | None = None
    explanation: str | None = None
    category: str | None = None


class DlpPatternDetection(AirsModel):
    """A DLP pattern match, with confidence-banded locations."""

    data_pattern_id: str | None = None
    version: float | None = None
    name: str | None = None
    high_confidence_detections: Offset | None = None
    medium_confidence_detections: Offset | None = None
    low_confidence_detections: Offset | None = None


class PatternDetection(AirsModel):
    """A pattern match and where it occurred."""

    pattern: str | None = None
    locations: Offset | None = None


class ContentError(AirsModel):
    """A per-content failure that did not fail the whole scan."""

    content_type: str | None = None
    feature: str | None = None
    status: str | None = None


class MaskedData(AirsModel):
    """Redacted content, with the patterns that triggered redaction."""

    data: str | None = None
    pattern_detections: list[PatternDetection] | None = None


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class PromptDetectionDetails(AirsModel):
    """Extended detail for prompt-side detections."""

    topic_guardrails_details: dict[str, Any] | None = None


class PromptDetected(AirsModel):
    """Which detection services triggered on the prompt."""

    url_cats: bool | None = None
    dlp: bool | None = None
    injection: bool | None = None
    toxic_content: bool | None = None
    malicious_code: bool | None = None
    source_code: bool | None = None
    agent: bool | None = None
    topic_violation: bool | None = None


class ResponseDetectionDetails(AirsModel):
    """Extended detail for response-side detections."""

    topic_guardrails_details: dict[str, Any] | None = None


class ResponseDetected(AirsModel):
    """Which detection services triggered on the model response."""

    url_cats: bool | None = None
    dlp: bool | None = None
    db_security: bool | None = None
    toxic_content: bool | None = None
    malicious_code: bool | None = None
    agent: bool | None = None
    ungrounded: bool | None = None
    topic_violation: bool | None = None


class ToolDetectionFlags(AirsModel):
    """Detection flags for a single tool invocation."""

    injection: bool | None = None
    url_cats: bool | None = None
    dlp: bool | None = None
    db_security: bool | None = None
    toxic_content: bool | None = None
    malicious_code: bool | None = None
    agent: bool | None = None
    topic_violation: bool | None = None


class ToolDetectionDetails(AirsModel):
    """Nested detail for a tool detection entry."""

    topic_guardrails_details: Any | None = None


class ToolDetectionEntry(AirsModel):
    """Detections for one tool invocation."""

    tool_invoked: str | None = None
    detections: ToolDetectionFlags | None = None
    threats: list[str] | None = None
    details: ToolDetectionDetails | None = None
    masked_data: MaskedData | None = None


class IODetected(AirsModel):
    """Per-tool detection entries on the input or output side."""

    detection_entries: list[ToolDetectionEntry] | None = None


class ScanSummary(AirsModel):
    """Aggregated detections and threats across tool invocations.

    The top-level verdict stays on :attr:`ScanResponse.category` and
    :attr:`ScanResponse.action`; this summarises the tool dimension only.
    """

    detections: ToolDetectionFlags | None = None
    threats: list[str] | None = None


class ToolDetected(AirsModel):
    """Detection results for tool and agent interactions."""

    verdict: str | None = None
    metadata: ToolEventMetadata | None = None
    summary: ScanSummary | None = None
    input_detected: IODetected | None = None
    output_detected: IODetected | None = None


class ScanResponse(AirsModel):
    """The verdict for one scan."""

    report_id: str
    scan_id: str
    category: str
    action: str
    timeout: bool = False
    error: bool = False
    errors: list[ContentError] = Field(default_factory=list)
    source: str | None = None
    tr_id: str | None = None
    session_id: str | None = None
    profile_id: str | None = None
    profile_name: str | None = None
    prompt_detected: PromptDetected | None = None
    response_detected: ResponseDetected | None = None
    prompt_masked_data: MaskedData | None = None
    response_masked_data: MaskedData | None = None
    prompt_detection_details: PromptDetectionDetails | None = None
    response_detection_details: ResponseDetectionDetails | None = None
    tool_detected: ToolDetected | None = None
    created_at: str | None = None
    completed_at: str | None = None

    @property
    def is_blocked(self) -> bool:
        """Whether the service instructed the caller to block this content."""
        return self.action == "block"


class AsyncScanObject(AirsModel):
    """One request within a batch scan, tagged so results can be correlated."""

    req_id: int
    scan_req: ScanRequest


class AsyncScanResponse(AirsModel):
    """Acknowledgement that a batch was accepted for processing."""

    received: str
    scan_id: str
    report_id: str | None = None
    source: str | None = None


class ScanIdResult(AirsModel):
    """A batch result, retrieved by scan ID."""

    source: str | None = None
    req_id: float | None = None
    status: str | None = None
    scan_id: str | None = None
    result: ScanResponse | None = None


# ---------------------------------------------------------------------------
# Threat reports
# ---------------------------------------------------------------------------


class UrlfEntry(AirsModel):
    """One URL-filtering finding."""

    url: str | None = None
    risk_level: str | None = None
    action: str | None = None
    categories: list[str] | None = None


class DlpReport(AirsModel):
    """Data-loss-prevention findings for one content item."""

    dlp_report_id: str | None = None
    dlp_profile_name: str | None = None
    dlp_profile_id: str | None = None
    dlp_profile_version: float | None = None
    data_pattern_rule1_verdict: str | None = None
    data_pattern_rule2_verdict: str | None = None
    data_pattern_detection_offsets: list[DlpPatternDetection] | None = None


class DSDetailResult(AirsModel):
    """Per-service detail behind a detection verdict."""

    urlf_report: list[UrlfEntry] | None = None
    dlp_report: DlpReport | None = None
    dbs_report: list[DbsEntry] | None = None
    tc_report: TcReport | None = None
    mc_report: McReport | None = None
    agent_report: AgentReport | None = None
    topic_guardrails_report: TgReport | None = None
    cg_report: CgReport | None = None


class DSResultMetadata(AirsModel):
    """Scoring and provenance for one detection result."""

    score: float | None = None
    confidence: str | None = None
    ecosystem: str | None = None
    method: str | None = None
    server_name: str | None = None
    tool_invoked: str | None = None
    direction: str | None = None


class DetectionServiceResult(AirsModel):
    """One detection service's verdict and supporting detail."""

    data_type: str | None = None
    detection_service: str | None = None
    verdict: str | None = None
    action: str | None = None
    metadata: DSResultMetadata | None = None
    result_detail: DSDetailResult | None = None


class ThreatScanReport(AirsModel):
    """A detailed threat report.

    One report ID can yield several rows; correlate on ``(report_id, req_id)`` rather
    than array position.
    """

    source: str | None = None
    report_id: str | None = None
    scan_id: str | None = None
    req_id: float | None = None
    transaction_id: str | None = None
    session_id: str | None = None
    detection_results: list[DetectionServiceResult] | None = None
