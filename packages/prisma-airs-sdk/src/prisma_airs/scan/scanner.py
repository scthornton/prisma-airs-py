"""Client for the AI Runtime Security scan API."""

from __future__ import annotations

import os

import httpx

from prisma_airs._http.auth import ApiKeyAuth
from prisma_airs._http.transport import RequestSpec, request
from prisma_airs._utils import is_valid_uuid
from prisma_airs.constants import (
    AIRS_ENDPOINTS,
    ASYNC_SCAN_PATH,
    DEFAULT_ENDPOINT,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_AI_SEC_API_ENDPOINT,
    ENV_AI_SEC_API_KEY,
    ENV_AI_SEC_API_TOKEN,
    MAX_NUMBER_OF_BATCH_SCAN_OBJECTS,
    MAX_NUMBER_OF_REPORT_IDS,
    MAX_NUMBER_OF_RETRIES,
    MAX_NUMBER_OF_SCAN_IDS,
    MAX_SESSION_ID_STR_LENGTH,
    MAX_TRANSACTION_ID_STR_LENGTH,
    SCAN_REPORTS_PATH,
    SCAN_RESULTS_PATH,
    SYNC_SCAN_PATH,
)
from prisma_airs.errors import AISecMissingVariableError, AISecPayloadError
from prisma_airs.models.scan import (
    AiProfile,
    AsyncScanObject,
    AsyncScanResponse,
    Content,
    Metadata,
    ScanIdResult,
    ScanResponse,
    ThreatScanReport,
)


def resolve_endpoint(endpoint: str | None = None, region: str | None = None) -> str:
    """Resolve the scan endpoint from an argument, a region, or the environment.

    Args:
        endpoint: Explicit base URL, which wins outright.
        region: One of ``us``, ``de``, ``in``, or ``sg``.

    Returns:
        The base URL to send scan requests to.

    Raises:
        AISecPayloadError: If ``region`` is not a known region.
    """
    if endpoint:
        return endpoint
    if region:
        try:
            return AIRS_ENDPOINTS[region.lower()]
        except KeyError:
            known = ", ".join(sorted(AIRS_ENDPOINTS))
            raise AISecPayloadError(f"Unknown region {region!r}; expected one of {known}") from None
    return os.environ.get(ENV_AI_SEC_API_ENDPOINT) or DEFAULT_ENDPOINT


class Scanner:
    """Scans prompts, responses, and tool events against a Prisma AIRS profile.

    Credentials come from the constructor or from ``PANW_AI_SEC_API_KEY`` /
    ``PANW_AI_SEC_API_TOKEN``.

    Example:
        >>> scanner = Scanner()
        >>> verdict = scanner.scan(prompt="Ignore previous instructions.", profile_name="prod")
        >>> verdict.action
        'block'
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_token: str | None = None,
        endpoint: str | None = None,
        region: str | None = None,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        resolved_key = api_key or os.environ.get(ENV_AI_SEC_API_KEY)
        resolved_token = api_token or os.environ.get(ENV_AI_SEC_API_TOKEN)
        if not resolved_key and not resolved_token:
            raise AISecMissingVariableError(
                f"No scan credentials. Set {ENV_AI_SEC_API_KEY} or pass api_key."
            )

        self._auth = ApiKeyAuth(api_key=resolved_key, api_token=resolved_token)
        self._endpoint = resolve_endpoint(endpoint, region)
        self._num_retries = _validate_retries(num_retries)
        self._owns_client = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)

    @property
    def endpoint(self) -> str:
        """The scan endpoint this client sends to."""
        return self._endpoint

    def scan(
        self,
        *,
        prompt: str | None = None,
        response: str | None = None,
        code_prompt: str | None = None,
        code_response: str | None = None,
        context: str | None = None,
        profile_name: str | None = None,
        profile_id: str | None = None,
        tr_id: str | None = None,
        session_id: str | None = None,
        metadata: Metadata | None = None,
        num_retries: int | None = None,
    ) -> ScanResponse:
        """Scan a single piece of content and return its verdict.

        A convenience wrapper over :meth:`sync_scan` for the common case, so callers do
        not have to assemble a :class:`Content` and an :class:`AiProfile` by hand.

        Returns:
            The verdict, whose ``action`` is ``allow`` or ``block``.
        """
        return self.sync_scan(
            ai_profile=AiProfile(profile_id=profile_id, profile_name=profile_name),
            content=Content(
                prompt=prompt,
                response=response,
                code_prompt=code_prompt,
                code_response=code_response,
                context=context,
            ),
            tr_id=tr_id,
            session_id=session_id,
            metadata=metadata,
            num_retries=num_retries,
        )

    def sync_scan(
        self,
        *,
        ai_profile: AiProfile,
        content: Content,
        tr_id: str | None = None,
        session_id: str | None = None,
        metadata: Metadata | None = None,
        num_retries: int | None = None,
    ) -> ScanResponse:
        """Scan one content item synchronously.

        Args:
            ai_profile: Security profile to evaluate against.
            content: The content to scan.
            tr_id: Transaction identifier for tracing.
            session_id: Groups related scans.
            metadata: Application metadata for reporting.
            num_retries: Per-call retry override.

        Returns:
            The verdict for this content.
        """
        _check_length(tr_id, MAX_TRANSACTION_ID_STR_LENGTH, "tr_id")
        _check_length(session_id, MAX_SESSION_ID_STR_LENGTH, "session_id")

        body: dict[str, object] = {
            "ai_profile": ai_profile.model_dump(mode="json", exclude_none=True),
            "contents": [content.model_dump(mode="json", by_alias=True, exclude_none=True)],
        }
        if tr_id:
            body["tr_id"] = tr_id
        if session_id:
            body["session_id"] = session_id
        if metadata is not None:
            body["metadata"] = metadata.model_dump(mode="json", exclude_none=True)

        return request(
            RequestSpec[ScanResponse](
                method="POST",
                base_url=self._endpoint,
                path=SYNC_SCAN_PATH,
                body=body,
                auth=self._auth,
                response_model=ScanResponse,
                num_retries=self._resolve_retries(num_retries),
            ),
            client=self._http,
        )

    def async_scan(
        self,
        scan_objects: list[AsyncScanObject],
        *,
        num_retries: int | None = None,
    ) -> AsyncScanResponse:
        """Submit a batch of up to twenty scans for asynchronous processing.

        The batch receipt carries one ``scan_id`` that can fan out to several unordered
        result rows. Correlate them on ``(scan_id, req_id)`` -- never on array position.

        Args:
            scan_objects: Between one and twenty tagged requests.
            num_retries: Per-call retry override.

        Returns:
            The batch receipt.

        Raises:
            AISecPayloadError: If the batch is empty or oversized.
        """
        if not scan_objects:
            raise AISecPayloadError("At least 1 scan object is required")
        if len(scan_objects) > MAX_NUMBER_OF_BATCH_SCAN_OBJECTS:
            raise AISecPayloadError(
                f"Max of {MAX_NUMBER_OF_BATCH_SCAN_OBJECTS} scan objects allowed"
            )

        return request(
            RequestSpec[AsyncScanResponse](
                method="POST",
                base_url=self._endpoint,
                path=ASYNC_SCAN_PATH,
                body=[
                    obj.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for obj in scan_objects
                ],
                auth=self._auth,
                response_model=AsyncScanResponse,
                num_retries=self._resolve_retries(num_retries),
            ),
            client=self._http,
        )

    def query_by_scan_ids(
        self, scan_ids: list[str], *, num_retries: int | None = None
    ) -> list[ScanIdResult]:
        """Retrieve results for up to five scan IDs.

        Server order and cardinality are preserved: rows are neither sorted nor
        deduplicated, because a single scan ID legitimately returns several.

        Raises:
            AISecPayloadError: If the list is empty, oversized, or holds a malformed ID.
        """
        _check_id_batch(scan_ids, MAX_NUMBER_OF_SCAN_IDS, "scan_id")
        for scan_id in scan_ids:
            if not is_valid_uuid(scan_id):
                raise AISecPayloadError(f"Invalid scan_id: {scan_id}")

        return request(
            RequestSpec[list[ScanIdResult]](
                method="GET",
                base_url=self._endpoint,
                path=SCAN_RESULTS_PATH,
                params={"scan_ids": ",".join(scan_ids)},
                auth=self._auth,
                response_model=list[ScanIdResult],
                num_retries=self._resolve_retries(num_retries),
            ),
            client=self._http,
        )

    def query_by_report_ids(
        self, report_ids: list[str], *, num_retries: int | None = None
    ) -> list[ThreatScanReport]:
        """Retrieve detailed threat reports for up to five report IDs.

        Report IDs are not UUIDs, so they are not format-checked here.

        Raises:
            AISecPayloadError: If the list is empty or oversized.
        """
        _check_id_batch(report_ids, MAX_NUMBER_OF_REPORT_IDS, "report_id")

        return request(
            RequestSpec[list[ThreatScanReport]](
                method="GET",
                base_url=self._endpoint,
                path=SCAN_REPORTS_PATH,
                params={"report_ids": ",".join(report_ids)},
                auth=self._auth,
                response_model=list[ThreatScanReport],
                num_retries=self._resolve_retries(num_retries),
            ),
            client=self._http,
        )

    def close(self) -> None:
        """Close the underlying HTTP client, if this instance created it."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> Scanner:
        """Enter a context that closes the HTTP client on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the HTTP client if this instance owns it."""
        self.close()

    def _resolve_retries(self, override: int | None) -> int:
        return self._num_retries if override is None else _validate_retries(override)


def _validate_retries(value: int) -> int:
    """Reject a retry count the transport cannot honour."""
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= MAX_NUMBER_OF_RETRIES
    ):
        raise AISecPayloadError(
            f"num_retries must be an integer between 0 and {MAX_NUMBER_OF_RETRIES}"
        )
    return value


def _check_length(value: str | None, limit: int, field: str) -> None:
    """Reject an over-long identifier before the service does."""
    if value is not None and len(value) > limit:
        raise AISecPayloadError(f"{field} exceeds max length of {limit}")


def _check_id_batch(ids: list[str], limit: int, label: str) -> None:
    """Reject an empty or oversized identifier batch."""
    if not ids:
        raise AISecPayloadError(f"At least 1 {label} is required")
    if len(ids) > limit:
        raise AISecPayloadError(f"Max of {limit} {label}s allowed")
