"""Client for the AI Model Security API.

Model Security spans two base URLs behind a single OAuth2 token. The data plane carries
scans and everything derived from them -- files, models, model versions, rule
evaluations, violations, labels -- while the management plane carries security groups,
the rule catalogue, and the PyPI credentials for the scanner package. The two are not
interchangeable: a data-plane path answers 404 against the management base URL and vice
versa, which is why each sub-client is built with its plane's URL fixed rather than
choosing one per call.

Credentials resolve from ``PANW_MODEL_SEC_*`` and fall back to ``PANW_MGMT_*``, so one
service account can drive this client alongside the other management-plane clients.

Example:
    >>> ms = ModelSecurityClient()
    >>> ms.scans.list(limit=5).scans[0].eval_outcome
    'ALLOWED'
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from urllib.parse import quote

import httpx

from prisma_airs._http.auth import OAuthAuth
from prisma_airs._http.transport import RequestSpec, request
from prisma_airs._http.types import AuthAdapter
from prisma_airs._utils import is_valid_uuid
from prisma_airs.auth.oauth import OAuthClient, resolve_credentials
from prisma_airs.constants import (
    DEFAULT_MODEL_SEC_DATA_ENDPOINT,
    DEFAULT_MODEL_SEC_MGMT_ENDPOINT,
    DEFAULT_TIMEOUT_SECONDS,
    ENV_MODEL_SEC_DATA_ENDPOINT,
    ENV_MODEL_SEC_MGMT_ENDPOINT,
    ENV_PREFIX_MGMT,
    ENV_PREFIX_MODEL_SEC,
    MAX_NUMBER_OF_RETRIES,
    MODEL_SEC_EVALUATIONS_PATH,
    MODEL_SEC_MODEL_VERSIONS_PATH,
    MODEL_SEC_MODELS_PATH,
    MODEL_SEC_PYPI_AUTH_PATH,
    MODEL_SEC_SCANS_PATH,
    MODEL_SEC_SECURITY_GROUPS_PATH,
    MODEL_SEC_SECURITY_RULES_PATH,
    MODEL_SEC_VIOLATIONS_PATH,
)
from prisma_airs.errors import AISecPayloadError
from prisma_airs.models.model_security import (
    FileList,
    LabelKeyList,
    LabelsCreateRequest,
    LabelsResponse,
    LabelValueList,
    ListModelSecurityGroupsResponse,
    ListModelSecurityRuleInstancesResponse,
    ListModelSecurityRulesResponse,
    ModelList,
    ModelResponse,
    ModelSecurityGroupCreateRequest,
    ModelSecurityGroupResponse,
    ModelSecurityGroupUpdateRequest,
    ModelSecurityRuleInstanceResponse,
    ModelSecurityRuleInstanceUpdateRequest,
    ModelSecurityRuleResponse,
    ModelVersionList,
    ModelVersionResponse,
    PyPIAuthResponse,
    RuleEvaluationList,
    RuleEvaluationResponse,
    ScanBaseResponse,
    ScanCreateRequest,
    ScanList,
    ViolationList,
    ViolationResponse,
)

#: Endpoint overrides are read per-plane rather than through a credential prefix, so the
#: names are derived from the same prefix the credentials use.


def _assert_uuid(value: str, field_name: str) -> None:
    """Reject a malformed identifier before it is interpolated into a request path.

    Args:
        value: Identifier supplied by the caller.
        field_name: Name to quote in the error message.

    Raises:
        AISecPayloadError: If ``value`` is not a canonical RFC 4122 UUID.
    """
    if not is_valid_uuid(value):
        raise AISecPayloadError(f"Invalid {field_name}: {value}")


def _build_params(
    values: Mapping[str, str | int | Sequence[str] | None],
) -> dict[str, str | Sequence[str]]:
    """Drop unset filters and render the rest as query parameters.

    Values are tested against ``None`` rather than truthiness because ``skip=0`` and an
    empty ``search`` both mean something to the service. Sequence values are handed to
    the transport as sequences so they expand into repeated keys, matching the reference
    client's ``URLSearchParams.append`` loop -- these filters are not comma-joined.

    Args:
        values: Parameter name to value, in the order they should be sent.

    Returns:
        Query parameters with unset entries removed.
    """
    params: dict[str, str | Sequence[str]] = {}
    for key, value in values.items():
        if value is None:
            continue
        params[key] = str(value) if isinstance(value, (str, int)) else list(value)
    return params


def _clamp_retries(value: int) -> int:
    """Clamp a retry count into the range the transport honours.

    The reference client clamps here rather than raising, unlike the scan client, so a
    caller asking for fifty retries gets five instead of an error.

    Args:
        value: Requested retry count.

    Returns:
        The count, bounded to ``[0, MAX_NUMBER_OF_RETRIES]``.
    """
    return min(max(value, 0), MAX_NUMBER_OF_RETRIES)


class _PlaneClient:
    """Base for the sub-clients, each pinned to one plane's base URL.

    Constructed by :class:`ModelSecurityClient`; the HTTP client and auth adapter are
    shared across all four so one token serves both planes.
    """

    def __init__(
        self,
        *,
        base_url: str,
        auth: AuthAdapter,
        num_retries: int,
        http_client: httpx.Client,
    ) -> None:
        self._base_url = base_url
        self._auth = auth
        self._num_retries = num_retries
        self._http = http_client

    @property
    def base_url(self) -> str:
        """The plane base URL this sub-client sends to."""
        return self._base_url


class ModelSecurityScansClient(_PlaneClient):
    """Data plane scan operations: scans, their files, labels, evaluations, violations.

    The sort-parameter names differ per endpoint and are not interchangeable: the scan
    list takes ``sort_by``/``sort_order``, evaluations take ``sort_field``/``sort_order``,
    and files take ``sort_field``/``sort_dir``. An unrecognised pair is not rejected, so
    the wrong one presents as results arriving in the server's default order rather than
    as an error.
    """

    def create(self, body: ScanCreateRequest) -> ScanBaseResponse:
        """Register a model security scan.

        Args:
            body: Scan creation request. ``scan_details`` carries findings from a
                scanner the caller already ran, so the service records them instead of
                fetching the artifacts itself.

        Returns:
            The created scan, whose ``eval_outcome`` starts at ``PENDING``; poll
            :meth:`get` until it settles.
        """
        return request(
            RequestSpec[ScanBaseResponse](
                method="POST",
                base_url=self._base_url,
                path=MODEL_SEC_SCANS_PATH,
                body=body,
                auth=self._auth,
                response_model=ScanBaseResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        sort_by: str | None = None,
        sort_order: str | None = None,
        search_query: str | None = None,
        eval_outcomes: Sequence[str] | None = None,
        source_types: Sequence[str] | None = None,
        security_group_uuid: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        labels_query: str | None = None,
    ) -> ScanList:
        """List scans with optional filters.

        Args:
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.
            sort_by: ``created_at`` or ``updated_at``. This endpoint spells it
                ``sort_by``, not ``sort_field``.
            sort_order: ``asc`` or ``desc``.
            search_query: Matches a scan UUID or name.
            eval_outcomes: Outcomes to include; sent as repeated keys.
            source_types: Source types to include; sent as repeated keys.
            security_group_uuid: Restrict to scans evaluated by one security group.
            start_time: ISO datetime lower bound.
            end_time: ISO datetime upper bound.
            labels_query: Label filter expression.

        Returns:
            One page of scans. ``pagination.total_items`` may be absent, in which case
            it means "unknown" rather than zero -- do not use it to detect the last page.
        """
        return request(
            RequestSpec[ScanList](
                method="GET",
                base_url=self._base_url,
                path=MODEL_SEC_SCANS_PATH,
                params=_build_params(
                    {
                        "skip": skip,
                        "limit": limit,
                        "search": search,
                        "sort_by": sort_by,
                        "sort_order": sort_order,
                        "search_query": search_query,
                        "eval_outcomes": eval_outcomes,
                        "source_types": source_types,
                        "security_group_uuid": security_group_uuid,
                        "start_time": start_time,
                        "end_time": end_time,
                        "labels_query": labels_query,
                    }
                ),
                auth=self._auth,
                response_model=ScanList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, uuid: str) -> ScanBaseResponse:
        """Fetch one scan.

        Args:
            uuid: Scan UUID.

        Returns:
            The scan.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "scan uuid")
        return request(
            RequestSpec[ScanBaseResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SCANS_PATH}/{uuid}",
                auth=self._auth,
                response_model=ScanBaseResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_evaluations(
        self,
        scan_uuid: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        sort_field: str | None = None,
        sort_order: str | None = None,
        result: str | None = None,
        rule_instance_uuid: str | None = None,
    ) -> RuleEvaluationList:
        """List the rule evaluations recorded for one scan.

        Args:
            scan_uuid: Scan UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.
            sort_field: ``created_at`` or ``updated_at``.
            sort_order: ``asc`` or ``desc``.
            result: ``PASSED``, ``FAILED``, or ``ERROR``.
            rule_instance_uuid: Restrict to one rule instance.

        Returns:
            One page of evaluations. A non-zero ``violation_count`` on a row is the
            signal to fetch the violations themselves via :meth:`get_violations`.

        Raises:
            AISecPayloadError: If ``scan_uuid`` is not a UUID.
        """
        _assert_uuid(scan_uuid, "scan uuid")
        return request(
            RequestSpec[RuleEvaluationList](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SCANS_PATH}/{scan_uuid}/evaluations",
                params=_build_params(
                    {
                        "skip": skip,
                        "limit": limit,
                        "search": search,
                        "sort_field": sort_field,
                        "sort_order": sort_order,
                        "result": result,
                        "rule_instance_uuid": rule_instance_uuid,
                    }
                ),
                auth=self._auth,
                response_model=RuleEvaluationList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_files(
        self,
        scan_uuid: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        sort_field: str | None = None,
        sort_dir: str | None = None,
        file_type: str | None = None,
        result: str | None = None,
        query_path: str | None = None,
    ) -> FileList:
        """List the files in a scan's model tree.

        Args:
            scan_uuid: Scan UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.
            sort_field: ``path`` or ``type``.
            sort_dir: ``asc`` or ``desc``. This endpoint spells it ``sort_dir``, not
                ``sort_order``.
            file_type: Node kind, ``FILE`` or ``DIRECTORY``. Sent as the wire parameter
                ``type``; the Python name avoids shadowing the builtin.
            result: Per-file scan result.
            query_path: Subtree to list. The service defaults it to ``/``, so leaving it
                unset lists from the repository root.

        Returns:
            One page of file tree nodes; directories appear as nodes too.

        Raises:
            AISecPayloadError: If ``scan_uuid`` is not a UUID.
        """
        _assert_uuid(scan_uuid, "scan uuid")
        return request(
            RequestSpec[FileList](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SCANS_PATH}/{scan_uuid}/files",
                params=_build_params(
                    {
                        "skip": skip,
                        "limit": limit,
                        "search": search,
                        "sort_field": sort_field,
                        "sort_dir": sort_dir,
                        "type": file_type,
                        "result": result,
                        "query_path": query_path,
                    }
                ),
                auth=self._auth,
                response_model=FileList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def add_labels(self, scan_uuid: str, body: LabelsCreateRequest) -> LabelsResponse:
        """Merge labels into a scan's existing set.

        The POST/PUT split is load-bearing: this call adds, :meth:`set_labels` replaces.

        Args:
            scan_uuid: Scan UUID.
            body: Labels to add.

        Returns:
            An empty object on success.

        Raises:
            AISecPayloadError: If ``scan_uuid`` is not a UUID.
        """
        _assert_uuid(scan_uuid, "scan uuid")
        return request(
            RequestSpec[LabelsResponse](
                method="POST",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SCANS_PATH}/{scan_uuid}/labels",
                body=body,
                auth=self._auth,
                response_model=LabelsResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def set_labels(self, scan_uuid: str, body: LabelsCreateRequest) -> LabelsResponse:
        """Replace every label on a scan.

        Labels absent from ``body`` are dropped. Use :meth:`add_labels` to merge.

        Args:
            scan_uuid: Scan UUID.
            body: The complete label set.

        Returns:
            An empty object on success.

        Raises:
            AISecPayloadError: If ``scan_uuid`` is not a UUID.
        """
        _assert_uuid(scan_uuid, "scan uuid")
        return request(
            RequestSpec[LabelsResponse](
                method="PUT",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SCANS_PATH}/{scan_uuid}/labels",
                body=body,
                auth=self._auth,
                response_model=LabelsResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete_labels(self, scan_uuid: str, keys: Sequence[str]) -> None:
        """Delete labels from a scan by key.

        The keys go in the query string as repeated ``keys`` parameters, not as a
        comma-joined value and not in a request body.

        Args:
            scan_uuid: Scan UUID.
            keys: Label keys to remove.

        Raises:
            AISecPayloadError: If ``scan_uuid`` is not a UUID.
        """
        _assert_uuid(scan_uuid, "scan uuid")
        request(
            RequestSpec[None](
                method="DELETE",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SCANS_PATH}/{scan_uuid}/labels",
                params={"keys": list(keys)},
                auth=self._auth,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_violations(
        self,
        scan_uuid: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
    ) -> ViolationList:
        """List the rule violations recorded for one scan.

        The path segment is ``rule-violations`` here, while a single violation is fetched
        from the top-level ``/v1/violations`` collection by :meth:`get_violation`.

        Args:
            scan_uuid: Scan UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.

        Returns:
            One page of violations.

        Raises:
            AISecPayloadError: If ``scan_uuid`` is not a UUID.
        """
        _assert_uuid(scan_uuid, "scan uuid")
        return request(
            RequestSpec[ViolationList](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SCANS_PATH}/{scan_uuid}/rule-violations",
                params=_build_params({"skip": skip, "limit": limit, "search": search}),
                auth=self._auth,
                response_model=ViolationList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_label_keys(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
    ) -> LabelKeyList:
        """List the distinct label keys in use across every scan.

        ``label-keys`` is a sibling of the ``/v1/scans/{uuid}`` segment rather than a
        child of one, so this is tenant-wide and takes no scan identifier.

        Args:
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.

        Returns:
            One page of label keys.
        """
        return request(
            RequestSpec[LabelKeyList](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SCANS_PATH}/label-keys",
                params=_build_params({"skip": skip, "limit": limit, "search": search}),
                auth=self._auth,
                response_model=LabelKeyList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_label_values(
        self,
        key: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
    ) -> LabelValueList:
        """List the distinct values recorded for one label key.

        Label keys are free-form caller-supplied text, so the key is percent-encoded
        into the path -- otherwise a key containing ``/`` would reshape the request.

        Args:
            key: Label key to enumerate.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.

        Returns:
            One page of label values.
        """
        return request(
            RequestSpec[LabelValueList](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SCANS_PATH}/label-keys/{quote(key, safe='')}/values",
                params=_build_params({"skip": skip, "limit": limit, "search": search}),
                auth=self._auth,
                response_model=LabelValueList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_evaluation(self, uuid: str) -> RuleEvaluationResponse:
        """Fetch one rule evaluation by its own UUID.

        Lives on the top-level ``/v1/evaluations`` collection, not under the scan that
        produced it.

        Args:
            uuid: Evaluation UUID.

        Returns:
            The evaluation.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "evaluation uuid")
        return request(
            RequestSpec[RuleEvaluationResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_EVALUATIONS_PATH}/{uuid}",
                auth=self._auth,
                response_model=RuleEvaluationResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_violation(self, uuid: str) -> ViolationResponse:
        """Fetch one violation by its own UUID.

        Lives on the top-level ``/v1/violations`` collection, not under the scan that
        produced it.

        Args:
            uuid: Violation UUID.

        Returns:
            The violation, with the rule that produced it inlined.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "violation uuid")
        return request(
            RequestSpec[ViolationResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_VIOLATIONS_PATH}/{uuid}",
                auth=self._auth,
                response_model=ViolationResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class ModelSecurityModelsClient(_PlaneClient):
    """Data plane model and model-version operations. Read-only.

    A model is the aggregate across its versions; a version is one revision of it. Both
    live on the data plane alongside scans, because a version is what a scan resolves to.
    """

    def list_models(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        search_query: str | None = None,
        sort_field: str | None = None,
        sort_order: str | None = None,
        latest_version_outcomes: Sequence[str] | None = None,
        latest_version_formats: Sequence[str] | None = None,
        latest_version_source_types: Sequence[str] | None = None,
        latest_version_scan_time_before: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> ModelList:
        """List models with optional search, sort, and latest-version filters.

        The ``latest_version_*`` filters read the denormalised summary of each model's
        newest version, so a model that has never been scanned matches none of them.

        Args:
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.
            search_query: Matches a model UUID or name.
            sort_field: ``created_at`` or ``updated_at``.
            sort_order: ``asc`` or ``desc``.
            latest_version_outcomes: Outcomes to include; sent as repeated keys.
            latest_version_formats: Model formats to include; sent as repeated keys.
            latest_version_source_types: Source types to include; sent as repeated keys.
            latest_version_scan_time_before: ISO datetime; keeps models last scanned
                before it, which is how stale-scan reporting is driven.
            start_time: ISO datetime lower bound on model creation.
            end_time: ISO datetime upper bound on model creation.

        Returns:
            One page of models.
        """
        return request(
            RequestSpec[ModelList](
                method="GET",
                base_url=self._base_url,
                path=MODEL_SEC_MODELS_PATH,
                params=_build_params(
                    {
                        "skip": skip,
                        "limit": limit,
                        "search": search,
                        "search_query": search_query,
                        "sort_field": sort_field,
                        "sort_order": sort_order,
                        "latest_version_outcomes": latest_version_outcomes,
                        "latest_version_formats": latest_version_formats,
                        "latest_version_source_types": latest_version_source_types,
                        "latest_version_scan_time_before": latest_version_scan_time_before,
                        "start_time": start_time,
                        "end_time": end_time,
                    }
                ),
                auth=self._auth,
                response_model=ModelList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_model(self, uuid: str) -> ModelResponse:
        """Fetch one model.

        Args:
            uuid: Model UUID.

        Returns:
            The model, including the summary of its latest version.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "model uuid")
        return request(
            RequestSpec[ModelResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_MODELS_PATH}/{uuid}",
                auth=self._auth,
                response_model=ModelResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_model_versions(
        self,
        model_uuid: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        sort_order: str | None = None,
    ) -> ModelVersionList:
        """List the versions of one model.

        This endpoint takes a direction but no sort field -- the server picks the field
        -- so there is deliberately no ``sort_field`` argument here.

        Args:
            model_uuid: Model UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.
            sort_order: ``asc`` or ``desc``.

        Returns:
            One page of model versions.

        Raises:
            AISecPayloadError: If ``model_uuid`` is not a UUID.
        """
        _assert_uuid(model_uuid, "model uuid")
        return request(
            RequestSpec[ModelVersionList](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_MODELS_PATH}/{model_uuid}/model-versions",
                params=_build_params(
                    {
                        "skip": skip,
                        "limit": limit,
                        "search": search,
                        "sort_order": sort_order,
                    }
                ),
                auth=self._auth,
                response_model=ModelVersionList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_model_version(self, uuid: str) -> ModelVersionResponse:
        """Fetch one model version.

        Args:
            uuid: Model version UUID.

        Returns:
            The model version.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "model version uuid")
        return request(
            RequestSpec[ModelVersionResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_MODEL_VERSIONS_PATH}/{uuid}",
                auth=self._auth,
                response_model=ModelVersionResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_model_version_files(
        self,
        model_version_uuid: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
    ) -> FileList:
        """List the files belonging to one model version.

        Same response shape as :meth:`ModelSecurityScansClient.get_files`, but scoped to
        the version rather than to a scan of it. This route accepts pagination only --
        the type, result, and subtree filters are specific to the scan route.

        Args:
            model_version_uuid: Model version UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.

        Returns:
            One page of files.

        Raises:
            AISecPayloadError: If ``model_version_uuid`` is not a UUID.
        """
        _assert_uuid(model_version_uuid, "model version uuid")
        return request(
            RequestSpec[FileList](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_MODEL_VERSIONS_PATH}/{model_version_uuid}/files",
                params=_build_params({"skip": skip, "limit": limit, "search": search}),
                auth=self._auth,
                response_model=FileList,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class ModelSecurityGroupsClient(_PlaneClient):
    """Management plane security group and rule instance operations.

    A security group is the policy a scan is evaluated against; its rule instances are
    the catalogue rules bound to it, each with its own state and field overrides.
    """

    def create(self, body: ModelSecurityGroupCreateRequest) -> ModelSecurityGroupResponse:
        """Create a security group.

        Args:
            body: Group definition. ``rule_configurations`` overrides individual rules
                as the group's instances are created; omitting it takes every default.

        Returns:
            The created group. Its ``state`` is ``PENDING`` until the rule instances
            exist, which is expected rather than a failure.
        """
        return request(
            RequestSpec[ModelSecurityGroupResponse](
                method="POST",
                base_url=self._base_url,
                path=MODEL_SEC_SECURITY_GROUPS_PATH,
                body=body,
                auth=self._auth,
                response_model=ModelSecurityGroupResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        sort_field: str | None = None,
        sort_dir: str | None = None,
        source_types: Sequence[str] | None = None,
        search_query: str | None = None,
        enabled_rules: Sequence[str] | None = None,
    ) -> ListModelSecurityGroupsResponse:
        """List security groups with optional filters.

        Args:
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.
            sort_field: ``created_at`` or ``updated_at``.
            sort_dir: ``asc`` or ``desc``. This endpoint spells it ``sort_dir``, not
                ``sort_order``.
            source_types: Source types to include; sent as repeated keys.
            search_query: Matches a group UUID or name.
            enabled_rules: Rule UUIDs that must be ``ALLOWING`` or ``BLOCKING`` in the
                group; sent as repeated keys. A ``DISABLED`` instance does not match.

        Returns:
            One page of security groups.
        """
        return request(
            RequestSpec[ListModelSecurityGroupsResponse](
                method="GET",
                base_url=self._base_url,
                path=MODEL_SEC_SECURITY_GROUPS_PATH,
                params=_build_params(
                    {
                        "skip": skip,
                        "limit": limit,
                        "search": search,
                        "sort_field": sort_field,
                        "sort_dir": sort_dir,
                        "source_types": source_types,
                        "search_query": search_query,
                        "enabled_rules": enabled_rules,
                    }
                ),
                auth=self._auth,
                response_model=ListModelSecurityGroupsResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, uuid: str) -> ModelSecurityGroupResponse:
        """Fetch one security group.

        Args:
            uuid: Security group UUID.

        Returns:
            The security group.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "security group uuid")
        return request(
            RequestSpec[ModelSecurityGroupResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SECURITY_GROUPS_PATH}/{uuid}",
                auth=self._auth,
                response_model=ModelSecurityGroupResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update(
        self, uuid: str, body: ModelSecurityGroupUpdateRequest
    ) -> ModelSecurityGroupResponse:
        """Update a security group's name or description.

        ``source_type`` is deliberately absent from the update body: a group's source
        cannot be changed once scans have been evaluated against it.

        Args:
            uuid: Security group UUID.
            body: Fields to change.

        Returns:
            The updated security group.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "security group uuid")
        return request(
            RequestSpec[ModelSecurityGroupResponse](
                method="PUT",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SECURITY_GROUPS_PATH}/{uuid}",
                body=body,
                auth=self._auth,
                response_model=ModelSecurityGroupResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def delete(self, uuid: str) -> None:
        """Delete a security group.

        The service soft-deletes: the group comes back with ``is_tombstone`` set so that
        scans which already referenced it still resolve.

        Args:
            uuid: Security group UUID.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "security group uuid")
        request(
            RequestSpec[None](
                method="DELETE",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SECURITY_GROUPS_PATH}/{uuid}",
                auth=self._auth,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def list_rule_instances(
        self,
        security_group_uuid: str,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        security_rule_uuid: str | None = None,
        state: str | None = None,
    ) -> ListModelSecurityRuleInstancesResponse:
        """List the rule instances bound to a security group.

        Args:
            security_group_uuid: Security group UUID.
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.
            security_rule_uuid: Restrict to instances of one catalogue rule.
            state: ``DISABLED``, ``ALLOWING``, or ``BLOCKING``.

        Returns:
            One page of rule instances, each with its catalogue rule inlined so no
            second pass over the rule catalogue is needed.

        Raises:
            AISecPayloadError: If ``security_group_uuid`` is not a UUID.
        """
        _assert_uuid(security_group_uuid, "security group uuid")
        return request(
            RequestSpec[ListModelSecurityRuleInstancesResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SECURITY_GROUPS_PATH}/{security_group_uuid}/rule-instances",
                params=_build_params(
                    {
                        "skip": skip,
                        "limit": limit,
                        "search": search,
                        "security_rule_uuid": security_rule_uuid,
                        "state": state,
                    }
                ),
                auth=self._auth,
                response_model=ListModelSecurityRuleInstancesResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get_rule_instance(
        self, security_group_uuid: str, rule_instance_uuid: str
    ) -> ModelSecurityRuleInstanceResponse:
        """Fetch one rule instance within a security group.

        Args:
            security_group_uuid: Security group UUID.
            rule_instance_uuid: Rule instance UUID.

        Returns:
            The rule instance.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        _assert_uuid(security_group_uuid, "security group uuid")
        _assert_uuid(rule_instance_uuid, "rule instance uuid")
        return request(
            RequestSpec[ModelSecurityRuleInstanceResponse](
                method="GET",
                base_url=self._base_url,
                path=(
                    f"{MODEL_SEC_SECURITY_GROUPS_PATH}/{security_group_uuid}"
                    f"/rule-instances/{rule_instance_uuid}"
                ),
                auth=self._auth,
                response_model=ModelSecurityRuleInstanceResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def update_rule_instance(
        self,
        security_group_uuid: str,
        rule_instance_uuid: str,
        body: ModelSecurityRuleInstanceUpdateRequest,
    ) -> ModelSecurityRuleInstanceResponse:
        """Update a rule instance's state or field values.

        ``body.security_group_uuid`` is required even though the path already names the
        group; the service does not infer it from the URL.

        Args:
            security_group_uuid: Security group UUID.
            rule_instance_uuid: Rule instance UUID.
            body: Fields to change.

        Returns:
            The updated rule instance.

        Raises:
            AISecPayloadError: If either identifier is not a UUID.
        """
        _assert_uuid(security_group_uuid, "security group uuid")
        _assert_uuid(rule_instance_uuid, "rule instance uuid")
        return request(
            RequestSpec[ModelSecurityRuleInstanceResponse](
                method="PUT",
                base_url=self._base_url,
                path=(
                    f"{MODEL_SEC_SECURITY_GROUPS_PATH}/{security_group_uuid}"
                    f"/rule-instances/{rule_instance_uuid}"
                ),
                body=body,
                auth=self._auth,
                response_model=ModelSecurityRuleInstanceResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class ModelSecurityRulesClient(_PlaneClient):
    """Management plane security rule catalogue. Read-only.

    These are rule definitions, not rules bound to a group -- binding happens through
    :class:`ModelSecurityGroupsClient` and its rule instances.
    """

    def list(
        self,
        *,
        skip: int | None = None,
        limit: int | None = None,
        search: str | None = None,
        source_type: str | None = None,
        search_query: str | None = None,
    ) -> ListModelSecurityRulesResponse:
        """List the available rule definitions.

        Args:
            skip: Records to skip from the start.
            limit: Maximum records to return.
            search: Free-text search filter.
            source_type: One source type. Singular here, unlike the plural
                ``source_types`` the group and scan lists take.
            search_query: Matches a rule UUID or name.

        Returns:
            One page of rule definitions.
        """
        return request(
            RequestSpec[ListModelSecurityRulesResponse](
                method="GET",
                base_url=self._base_url,
                path=MODEL_SEC_SECURITY_RULES_PATH,
                params=_build_params(
                    {
                        "skip": skip,
                        "limit": limit,
                        "search": search,
                        "source_type": source_type,
                        "search_query": search_query,
                    }
                ),
                auth=self._auth,
                response_model=ListModelSecurityRulesResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def get(self, uuid: str) -> ModelSecurityRuleResponse:
        """Fetch one rule definition.

        Args:
            uuid: Security rule UUID.

        Returns:
            The rule, including which of its fields a group may override.

        Raises:
            AISecPayloadError: If ``uuid`` is not a UUID.
        """
        _assert_uuid(uuid, "security rule uuid")
        return request(
            RequestSpec[ModelSecurityRuleResponse](
                method="GET",
                base_url=self._base_url,
                path=f"{MODEL_SEC_SECURITY_RULES_PATH}/{uuid}",
                auth=self._auth,
                response_model=ModelSecurityRuleResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )


class ModelSecurityClient:
    """Entry point for the Model Security API.

    Groups the four sub-clients and owns the credentials, the OAuth2 token, and the HTTP
    connection pool they share. Reads ``PANW_MODEL_SEC_*``, falling back to
    ``PANW_MGMT_*``, for anything not passed explicitly.

    Example:
        >>> ms = ModelSecurityClient()
        >>> ms.scans.list(limit=5).scans[0].eval_outcome
        'ALLOWED'
    """

    def __init__(
        self,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        tsg_id: str | None = None,
        data_endpoint: str | None = None,
        mgmt_endpoint: str | None = None,
        token_endpoint: str | None = None,
        num_retries: int = MAX_NUMBER_OF_RETRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        http_client: httpx.Client | None = None,
    ) -> None:
        resolved_data = (
            data_endpoint
            or os.environ.get(ENV_MODEL_SEC_DATA_ENDPOINT)
            or DEFAULT_MODEL_SEC_DATA_ENDPOINT
        )
        resolved_mgmt = (
            mgmt_endpoint
            or os.environ.get(ENV_MODEL_SEC_MGMT_ENDPOINT)
            or DEFAULT_MODEL_SEC_MGMT_ENDPOINT
        )

        credentials = resolve_credentials(
            primary_env_prefix=ENV_PREFIX_MODEL_SEC,
            client_id=client_id,
            client_secret=client_secret,
            tsg_id=tsg_id,
            token_endpoint=token_endpoint,
            fallback_env_prefix=ENV_PREFIX_MGMT,
        )

        self._owns_client = http_client is None
        self._http = http_client if http_client is not None else httpx.Client(timeout=timeout)
        # The token endpoint shares the pool: both planes and the auth host are ordinary
        # HTTPS origins, and one client keeps the caller's close() a single call.
        self._oauth = OAuthClient(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            tsg_id=credentials.tsg_id,
            token_endpoint=credentials.token_endpoint,
            http_client=self._http,
            timeout=timeout,
        )
        # Model Security is not the AI Gateway: it authenticates with the bearer token
        # alone and does not want an x-tsg-id header. The tenant is already encoded in
        # the token's scope.
        self._auth: AuthAdapter = OAuthAuth(self._oauth)
        self._num_retries = _clamp_retries(num_retries)

        self._data_endpoint = resolved_data
        self._mgmt_endpoint = resolved_mgmt

        self.scans = ModelSecurityScansClient(
            base_url=resolved_data,
            auth=self._auth,
            num_retries=self._num_retries,
            http_client=self._http,
        )
        self.models = ModelSecurityModelsClient(
            base_url=resolved_data,
            auth=self._auth,
            num_retries=self._num_retries,
            http_client=self._http,
        )
        self.security_groups = ModelSecurityGroupsClient(
            base_url=resolved_mgmt,
            auth=self._auth,
            num_retries=self._num_retries,
            http_client=self._http,
        )
        self.security_rules = ModelSecurityRulesClient(
            base_url=resolved_mgmt,
            auth=self._auth,
            num_retries=self._num_retries,
            http_client=self._http,
        )

    @property
    def data_endpoint(self) -> str:
        """Base URL for scans, files, models, and model versions."""
        return self._data_endpoint

    @property
    def mgmt_endpoint(self) -> str:
        """Base URL for security groups, the rule catalogue, and PyPI auth."""
        return self._mgmt_endpoint

    def get_pypi_auth(self) -> PyPIAuthResponse:
        """Fetch short-lived PyPI credentials for the Artifact Registry.

        Management plane, despite serving the data-plane scanner. The returned ``url``
        embeds a bearer token, so treat it as credential material: keep it out of logs,
        shell history, and committed config, and refetch after ``expires_at``.

        Returns:
            The index URL and its expiry.
        """
        return request(
            RequestSpec[PyPIAuthResponse](
                method="GET",
                base_url=self._mgmt_endpoint,
                path=MODEL_SEC_PYPI_AUTH_PATH,
                auth=self._auth,
                response_model=PyPIAuthResponse,
                num_retries=self._num_retries,
            ),
            client=self._http,
        )

    def close(self) -> None:
        """Close the underlying HTTP client, if this instance created it."""
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> ModelSecurityClient:
        """Enter a context that closes the HTTP client on exit."""
        return self

    def __exit__(self, *_exc: object) -> None:
        """Close the HTTP client if this instance owns it."""
        self.close()


__all__ = [
    "ENV_MODEL_SEC_DATA_ENDPOINT",
    "ENV_MODEL_SEC_MGMT_ENDPOINT",
    "ModelSecurityClient",
    "ModelSecurityGroupsClient",
    "ModelSecurityModelsClient",
    "ModelSecurityRulesClient",
    "ModelSecurityScansClient",
]
