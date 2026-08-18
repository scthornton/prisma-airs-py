"""Request and response models for the AI Model Security API.

The domain spans two planes that share these schemas: the data plane (scans, files,
models and their versions, rule evaluations, violations, labels) and the management
plane (security groups, rules, rule instances, PyPI auth).

Enum-typed fields are declared as plain ``str`` rather than as the ``Enum`` classes
below, deliberately and consistently across the whole domain. The backend adds new
outcomes, source types, and threat codes without a version bump, and a client that
validates them into a closed set turns a harmless server-side addition into a parse
failure. The enums are here for callers to compare and branch on -- each subclasses
``str``, so ``scan.eval_outcome == EvalOutcome.BLOCKED`` works -- and to record the
values known at the time of writing.
"""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict

from prisma_airs.models.base import AirsModel, WireEnum

# ---------------------------------------------------------------------------
# Enums
#
# Reference values only. No field below is typed as one of these -- see the module
# docstring for why.
# ---------------------------------------------------------------------------


class ErrorCodes(WireEnum):
    """Error codes reported by the Model Security scan service.

    Carried on the ``error_code`` fields of a scan and its per-file records. The paired
    ``error_message`` is free text, so branch on the code and log the message.
    """

    UNKNOWN_ERROR = "UNKNOWN_ERROR"
    SCAN_ERROR = "SCAN_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    ACCESS_DENIED = "ACCESS_DENIED"
    MISSING_CREDENTIALS = "MISSING_CREDENTIALS"
    NO_SUCH_KEY = "NO_SUCH_KEY"
    NO_SUCH_BUCKET = "NO_SUCH_BUCKET"
    INVALID_BUCKET_NAME = "INVALID_BUCKET_NAME"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    INVALID_OBJECT_STATE = "INVALID_OBJECT_STATE"
    UNKNOWN_REMOTE_SERVICE_ERROR = "UNKNOWN_REMOTE_SERVICE_ERROR"
    UNSUPPORTED_REMOTE_STORAGE = "UNSUPPORTED_REMOTE_STORAGE"
    MISSING_ARTIFACTS = "MISSING_ARTIFACTS"
    WORKER_ERROR = "WORKER_ERROR"
    POLICY_EVAL_ERROR = "POLICY_EVAL_ERROR"


class EvalOutcome(WireEnum):
    """Result of evaluating a security group's rules against a scan.

    ``PENDING`` is where every newly created scan starts, not a failure state.
    """

    PENDING = "PENDING"
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class FileScanResult(WireEnum):
    """Per-file outcome the service records on :attr:`FileResponse.result`.

    Distinct from :class:`ModelScanStatus`, which is what the scanner itself reports on
    the records a caller uploads. The two vocabularies overlap but are not the same set.
    """

    SKIPPED = "SKIPPED"
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"
    FAILED = "FAILED"


class FileType(WireEnum):
    """Node kind in the scanned model's file tree."""

    DIRECTORY = "DIRECTORY"
    FILE = "FILE"


class ModelScanStatus(WireEnum):
    """Scanner-reported status for one file in an uploaded :class:`ScanDetails`."""

    SCANNED = "SCANNED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class RuleEvaluationResult(WireEnum):
    """Verdict of one rule against one scan."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    ERROR = "ERROR"


class RuleState(WireEnum):
    """Enforcement mode of a rule instance within a security group.

    ``DISABLED`` skips the rule outright; the difference between ``ALLOWING`` and
    ``BLOCKING`` is whether a failure drives the scan's outcome to ``BLOCKED``.
    """

    DISABLED = "DISABLED"
    ALLOWING = "ALLOWING"
    BLOCKING = "BLOCKING"


class ScanOrigin(WireEnum):
    """What submitted the scan."""

    MODEL_SECURITY_SDK = "MODEL_SECURITY_SDK"
    HUGGING_FACE = "HUGGING_FACE"


class SortByDateField(WireEnum):
    """Sortable date fields on list queries.

    The values are wire field names in lowercase, unlike the SCREAMING_CASE used by the
    outcome and status enums -- passing ``CREATED_AT`` is rejected.
    """

    CREATED_AT = "created_at"
    UPDATED_AT = "updated_at"


class SortByFileField(WireEnum):
    """Sortable fields on the file-listing query. Lowercase wire names, as above."""

    PATH = "path"
    TYPE = "type"


class SortDirection(WireEnum):
    """Sort direction for list queries."""

    ASC = "asc"
    DESC = "desc"


class SourceType(WireEnum):
    """Where a model artifact came from, and which sources a security group covers."""

    LOCAL = "LOCAL"
    HUGGING_FACE = "HUGGING_FACE"
    S3 = "S3"
    GCS = "GCS"
    AZURE = "AZURE"
    ARTIFACTORY = "ARTIFACTORY"
    GITLAB = "GITLAB"
    ALL = "ALL"


class ThreatCategory(WireEnum):
    """Threat codes attached to a model scan issue.

    The ``PAIT-*`` codes belong to the modelscan-pai scanner rather than to this SDK and
    must stay in sync with that project's issue codes; new ones land whenever it learns
    another format. Member names use underscores, wire values use hyphens.
    """

    PAIT_ARV_100 = "PAIT-ARV-100"
    PAIT_GGUF_100 = "PAIT-GGUF-100"
    PAIT_GGUF_101 = "PAIT-GGUF-101"
    PAIT_KERAS_100 = "PAIT-KERAS-100"
    PAIT_KERAS_101 = "PAIT-KERAS-101"
    PAIT_KERAS_102 = "PAIT-KERAS-102"
    PAIT_JOBLIB_100 = "PAIT-JOBLIB-100"
    PAIT_JOBLIB_101 = "PAIT-JOBLIB-101"
    PAIT_PKL_100 = "PAIT-PKL-100"
    PAIT_PKL_101 = "PAIT-PKL-101"
    PAIT_PYTCH_100 = "PAIT-PYTCH-100"
    PAIT_PYTCH_101 = "PAIT-PYTCH-101"
    PAIT_EXDIR_100 = "PAIT-EXDIR-100"
    PAIT_EXDIR_101 = "PAIT-EXDIR-101"
    PAIT_ONNX_200 = "PAIT-ONNX-200"
    PAIT_TF_200 = "PAIT-TF-200"
    PAIT_LMAFL_300 = "PAIT-LMAFL-300"
    PAIT_LITERT_300 = "PAIT-LITERT-300"
    PAIT_LITERT_301 = "PAIT-LITERT-301"
    PAIT_LITERT_302 = "PAIT-LITERT-302"
    PAIT_KERAS_300 = "PAIT-KERAS-300"
    PAIT_KERAS_301 = "PAIT-KERAS-301"
    PAIT_TCHST_300 = "PAIT-TCHST-300"
    PAIT_TCHST_301 = "PAIT-TCHST-301"
    PAIT_TF_300 = "PAIT-TF-300"
    PAIT_TF_301 = "PAIT-TF-301"
    PAIT_TF_302 = "PAIT-TF-302"
    PAIT_TMT_300 = "PAIT-TMT-300"
    PAIT_TMT_301 = "PAIT-TMT-301"
    UNAPPROVED_FORMATS = "UNAPPROVED_FORMATS"


class ModelSecurityGroupState(WireEnum):
    """Lifecycle state of a security group.

    A group is created ``PENDING`` and becomes ``ACTIVE`` once its rule instances exist,
    so a create response reporting ``PENDING`` is expected rather than a failure.
    """

    PENDING = "PENDING"
    ACTIVE = "ACTIVE"


class RuleType(WireEnum):
    """What a rule inspects.

    ``METADATA`` rules judge what a model claims about itself -- license, publishing
    organisation -- while ``ARTIFACT`` rules judge what the files actually contain.
    """

    METADATA = "METADATA"
    ARTIFACT = "ARTIFACT"


class RuleEditableFieldType(WireEnum):
    """Widget hint for rendering an editable rule field.

    ``SELECT`` fields carry :attr:`RuleEditableField.dropdown_values`; ``LIST`` fields
    take free-form entries.
    """

    SELECT = "SELECT"
    LIST = "LIST"


class RuleFieldValueKey(WireEnum):
    """Keys accepted inside a rule's ``field_values`` map.

    Which keys a given rule accepts is declared by its ``editable_fields``; this is the
    union shipped today, not a per-rule contract.
    """

    APPROVED_FORMATS = "approved_formats"
    APPROVED_LOCATIONS = "approved_locations"
    APPROVED_LICENSES = "approved_licenses"
    DENY_ORGS = "deny_orgs"
    DENIED_ORG_MODELS = "denied_org_models"
    APPROVED_ORG_MODELS = "approved_org_models"


# ---------------------------------------------------------------------------
# Shared base
# ---------------------------------------------------------------------------


class _ModelPrefixedFields(AirsModel):
    """Base for payloads whose wire fields begin with ``model_``.

    Pydantic reserves that prefix. Under pydantic < 2.10 -- which this package still
    supports, its floor being 2.9 -- ``protected_namespaces`` defaulted to the whole
    ``model_`` prefix, so every one of ``model_uri``, ``model_formats``,
    ``model_versions`` and friends emits a ``UserWarning`` at class-definition time.
    These names are the wire contract and cannot be renamed, so the guard is turned off
    for the models that carry them instead. Config declared on a subclass merges with
    the parent's, so ``extra="allow"`` and ``populate_by_name`` still apply.
    """

    model_config = ConfigDict(protected_namespaces=())


# ---------------------------------------------------------------------------
# Shared / utility
# ---------------------------------------------------------------------------


class ModelSecurityPagination(AirsModel):
    """Pagination metadata on every Model Security list response.

    ``total_items`` is both optional and nullable on the wire, so a missing count means
    "unknown", not zero -- do not use it to decide whether a page is the last one.
    """

    total_items: int | None = None


# ---------------------------------------------------------------------------
# Data plane -- labels
# ---------------------------------------------------------------------------


class Label(AirsModel):
    """One key-value label on a scan.

    Labels are the filtering dimension for scan lists, which is why the service exposes
    distinct keys and values through their own endpoints.
    """

    key: str
    value: str


class LabelsCreateRequest(AirsModel):
    """Request body for creating or replacing the labels on a scan."""

    labels: list[Label]


class LabelsResponse(AirsModel):
    """Response to a label create/set.

    The service answers with an empty object, so the model declares no fields. Anything
    it starts returning later lands in ``model_extra`` rather than being dropped.
    """


class LabelKeyList(AirsModel):
    """Paginated list of the distinct label keys in use."""

    pagination: ModelSecurityPagination
    keys: list[str]


class LabelValueList(AirsModel):
    """Paginated list of the distinct values recorded for one label key."""

    pagination: ModelSecurityPagination
    values: list[str]


# ---------------------------------------------------------------------------
# Data plane -- eval summary
# ---------------------------------------------------------------------------


class EvalSummary(AirsModel):
    """Rule pass/fail counts for a scan.

    The counts default to 0 rather than to ``None`` so callers can do arithmetic without
    a null check; the service omits them on scans that never reached rule evaluation.
    An explicit ``null`` is still rejected, matching the TypeScript reference client.
    """

    rules_failed: int = 0
    rules_passed: int = 0
    total_rules: int = 0


# ---------------------------------------------------------------------------
# Data plane -- model scan issues and per-file scan data
# ---------------------------------------------------------------------------


class ModelScanIssue(AirsModel):
    """One issue the model scanner found in a file.

    ``threat`` carries a :class:`ThreatCategory` code when the scanner attributes the
    issue to a known category; ``module`` and ``operator`` name the specific construct
    (for example a pickle opcode) that triggered it.
    """

    description: str
    source: str
    threat: str | None = None
    module: str | None = None
    operator: str | None = None


class FileScanData(AirsModel):
    """Per-file result uploaded as part of a scan creation.

    ``modelscan_status`` carries a :class:`ModelScanStatus` value, and ``blob_id`` is
    how the service correlates this record with content it already has.
    """

    file_path: str
    modelscan_status: str
    blob_id: str
    error_message: str | None = None
    formats: list[str] | None = None
    issues_detected: list[ModelScanIssue] | None = None


# ---------------------------------------------------------------------------
# Data plane -- scan details (nested in the create request)
# ---------------------------------------------------------------------------


class ScanDetails(_ModelPrefixedFields):
    """Scanner output submitted with a scan creation.

    This travels caller-to-service, never back: it is how a locally run scanner reports
    what it found, so the service records the findings instead of fetching the artifacts
    itself.
    """

    scanner_version: str
    time_started: str
    files: list[FileScanData]
    total_files_scanned: int
    total_files_skipped: int
    model_formats: list[str]
    model_size_bytes: int
    scan_duration_ms: int
    error_code: str | None = None
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Data plane -- scan creation
# ---------------------------------------------------------------------------


class ScanCreateRequest(_ModelPrefixedFields):
    """Request body for registering a model security scan.

    ``allow_patterns`` and ``ignore_patterns`` record which files inside the model
    repository were considered, and ``scan_details`` carries results from a scan the
    caller already ran -- optional, because not every origin supplies them.
    """

    model_uri: str
    security_group_uuid: str
    #: Optional per the OpenAPI spec, since the server defaults it, but the reference
    #: TypeScript client still sets it on every create.
    scan_origin: str | None = None
    allow_patterns: list[str] | None = None
    ignore_patterns: list[str] | None = None
    labels: list[Label] | None = None
    model_author: str | None = None
    model_name: str | None = None
    model_version: str | None = None
    scan_details: ScanDetails | None = None


# ---------------------------------------------------------------------------
# Data plane -- scan responses
# ---------------------------------------------------------------------------


class ScanBaseResponse(_ModelPrefixedFields):
    """A scan as the service reports it.

    A create returns ``eval_outcome`` of ``PENDING``; poll until it settles to one of
    the other :class:`EvalOutcome` values. ``enabled_rule_count_snapshot`` freezes how
    many rules were enabled when the scan ran, so an outcome stays explainable after the
    security group is edited.

    Field order mirrors the API schema, which puts the optional ``model_version_uuid``
    between two required fields.
    """

    uuid: str
    tsg_id: str
    created_at: str
    updated_at: str
    model_uri: str
    owner: str
    scan_origin: str
    security_group_uuid: str
    security_group_name: str
    #: Optional per the OpenAPI spec -- a scan may not have a resolved model version yet.
    model_version_uuid: str | None = None
    eval_outcome: str
    source_type: str
    created_by: str | None = None
    enabled_rule_count_snapshot: int | None = None
    error_code: str | None = None
    error_message: str | None = None
    eval_summary: EvalSummary | None = None
    labels: list[Label] | None = None
    model_formats: list[str] | None = None
    scanner_version: str | None = None
    time_started: str | None = None
    total_files_scanned: int | None = None
    total_files_skipped: int | None = None


class ScanList(AirsModel):
    """Paginated list of scans."""

    pagination: ModelSecurityPagination
    scans: list[ScanBaseResponse]


# ---------------------------------------------------------------------------
# Data plane -- files
# ---------------------------------------------------------------------------


class FileResponse(_ModelPrefixedFields):
    """One node in a scanned model's file tree.

    Directories are nodes here too (see :class:`FileType`), which is why ``blob_id`` and
    ``formats`` are optional -- only leaf files carry content.
    """

    uuid: str
    tsg_id: str
    created_at: str
    updated_at: str
    path: str
    parent_path: str
    type: str
    result: str
    model_version_uuid: str
    blob_id: str | None = None
    formats: list[str] | None = None
    scan_uuid: str | None = None


class FileList(AirsModel):
    """Paginated list of scanned model files."""

    pagination: ModelSecurityPagination
    files: list[FileResponse]


# ---------------------------------------------------------------------------
# Data plane -- models and model versions
# ---------------------------------------------------------------------------


class ModelResponse(AirsModel):
    """A model, aggregated over its versions.

    The ``latest_version_*`` fields are a denormalised copy of the newest version so a
    list view can show an outcome without a second call. They are all nullable: a model
    that has been registered but never scanned has no latest version to summarise.
    """

    uuid: str
    tsg_id: str
    created_at: str
    updated_at: str
    name: str
    latest_version_uuid: str | None = None
    latest_version_fingerprint: str | None = None
    latest_version_revision: str | None = None
    latest_version_hf_commit_sha: str | None = None
    latest_version_outcome: str | None = None
    latest_version_formats: list[str] | None = None
    latest_version_source_types: list[str] | None = None
    latest_version_scan_time: str | None = None


class ModelList(AirsModel):
    """Paginated list of models."""

    pagination: ModelSecurityPagination
    models: list[ModelResponse]


class ModelVersionResponse(_ModelPrefixedFields):
    """One revision of a model.

    The ``hf_*`` fields are populated only for Hugging Face sources, where the commit
    SHA is what makes a revision reproducible; ``fingerprint`` is the service's own
    content identity and is the field to compare across sources.
    """

    uuid: str
    tsg_id: str
    created_at: str
    updated_at: str
    revision: str
    model_uuid: str
    fingerprint: str | None = None
    file_count: int | None = None
    license: str | None = None
    latest_scan_time: str | None = None
    hf_commit_sha: str | None = None
    hf_commit_title: str | None = None
    hf_commit_authors: list[str] | None = None
    hf_model_name: str | None = None
    hf_organization: str | None = None
    model_formats: list[str] | None = None
    source_types: list[str] | None = None
    last_eval_outcome: str | None = None
    last_eval_summary: EvalSummary | None = None


class ModelVersionList(_ModelPrefixedFields):
    """Paginated list of model versions."""

    pagination: ModelSecurityPagination
    model_versions: list[ModelVersionResponse]


# ---------------------------------------------------------------------------
# Data plane -- rule evaluations
# ---------------------------------------------------------------------------


class RuleEvaluationResponse(AirsModel):
    """One rule's verdict for one scan.

    ``violation_count`` is how many :class:`ViolationResponse` rows the evaluation
    produced; the violations themselves come from a separate endpoint, so a non-zero
    count here is the signal to go fetch them.
    """

    uuid: str
    tsg_id: str
    created_at: str
    updated_at: str
    result: str
    violation_count: int
    rule_instance_uuid: str
    scan_uuid: str
    rule_name: str
    rule_description: str
    rule_instance_state: str


class RuleEvaluationList(AirsModel):
    """Paginated list of rule evaluations."""

    pagination: ModelSecurityPagination
    evaluations: list[RuleEvaluationResponse]


# ---------------------------------------------------------------------------
# Data plane -- violations
# ---------------------------------------------------------------------------


class ViolationRemediation(AirsModel):
    """How to clear a violation: ordered steps plus a documentation link."""

    steps: list[str]
    url: str


class ViolationResponse(AirsModel):
    """One violation, with the rule that produced it inlined.

    ``file``, ``hash``, ``module``, and ``operator`` locate the offending construct and
    are typically populated only for ``ARTIFACT`` rules; a ``METADATA`` rule violation
    (a disallowed license, say) has nothing to point at inside the files.
    """

    uuid: str
    tsg_id: str
    created_at: str
    updated_at: str
    description: str
    rule_instance_uuid: str
    rule_name: str
    rule_description: str
    rule_instance_state: str
    remediation: ViolationRemediation
    file: str | None = None
    hash: str | None = None
    module: str | None = None
    operator: str | None = None
    threat: str | None = None
    threat_description: str | None = None


class ViolationList(AirsModel):
    """Paginated list of violations."""

    pagination: ModelSecurityPagination
    violations: list[ViolationResponse]


# ---------------------------------------------------------------------------
# Management -- rule editable fields and remediation
# ---------------------------------------------------------------------------


class RuleEditableFieldDropdown(AirsModel):
    """One option in a ``SELECT`` rule field: the stored value and its display label."""

    value: str
    label: str


class RuleEditableField(AirsModel):
    """One configurable field on a rule, described well enough for a UI to render it.

    ``type`` is the data type, ``display_type`` the widget (see
    :class:`RuleEditableFieldType`), and ``attribute_name`` the key to use inside
    ``field_values`` when overriding it.
    """

    attribute_name: str
    type: str
    display_name: str
    display_type: str
    description: str | None = None
    dropdown_values: list[RuleEditableFieldDropdown] | None = None


class RuleRemediation(AirsModel):
    """Remediation guidance published with a rule definition."""

    description: str
    steps: list[str]
    url: str


# ---------------------------------------------------------------------------
# Management -- rule configuration
# ---------------------------------------------------------------------------


class RuleConfiguration(AirsModel):
    """Overrides applied to one rule while creating a security group.

    ``field_values`` is untyped on the wire because its accepted keys and value shapes
    are declared per-rule by :attr:`ModelSecurityRuleResponse.editable_fields`; see
    :class:`RuleFieldValueKey` for the keys in use today.
    """

    field_values: dict[str, Any] | None = None
    state: str | None = None


# ---------------------------------------------------------------------------
# Management -- rule definitions
# ---------------------------------------------------------------------------


class ModelSecurityRuleResponse(AirsModel):
    """A rule definition from the catalogue, not a rule bound to a group.

    ``constant_values`` are fixed by the rule and cannot be overridden; ``default_values``
    seed a new instance's ``field_values``; ``editable_fields`` says which keys a caller
    may then change.
    """

    uuid: str
    name: str
    description: str
    rule_type: str
    compatible_sources: list[str]
    default_state: str
    remediation: RuleRemediation
    editable_fields: list[RuleEditableField]
    constant_values: dict[str, Any]
    default_values: dict[str, Any]


class ListModelSecurityRulesResponse(AirsModel):
    """Paginated list of rule definitions."""

    pagination: ModelSecurityPagination
    rules: list[ModelSecurityRuleResponse]


# ---------------------------------------------------------------------------
# Management -- rule instances
# ---------------------------------------------------------------------------


class ModelSecurityRuleInstanceResponse(AirsModel):
    """A rule bound to a security group -- the thing that actually evaluates scans.

    The full ``rule`` definition is inlined, so listing a group's instances does not
    require a second pass over the rule catalogue.
    """

    uuid: str
    tsg_id: str
    created_at: str
    updated_at: str
    security_group_uuid: str
    security_rule_uuid: str
    state: str
    rule: ModelSecurityRuleResponse
    field_values: dict[str, Any] | None = None


class ModelSecurityRuleInstanceUpdateRequest(AirsModel):
    """Request body for updating a rule instance.

    ``security_group_uuid`` is required in the body even though the path already
    identifies the group. Leaving ``state`` or ``field_values`` out leaves them alone.
    """

    security_group_uuid: str
    state: str | None = None
    field_values: dict[str, Any] | None = None


class ListModelSecurityRuleInstancesResponse(AirsModel):
    """Paginated list of rule instances."""

    pagination: ModelSecurityPagination
    rule_instances: list[ModelSecurityRuleInstanceResponse]


# ---------------------------------------------------------------------------
# Management -- security groups
# ---------------------------------------------------------------------------


class ModelSecurityGroupCreateRequest(AirsModel):
    """Request body for creating a security group.

    ``description`` defaults to an empty string rather than being omitted, matching the
    API schema. ``rule_configurations`` maps a rule identifier to the overrides applied
    when the group's rule instances are created; omitting it takes every rule's default.
    """

    name: str
    source_type: str
    description: str = ""
    rule_configurations: dict[str, RuleConfiguration] | None = None


class ModelSecurityGroupResponse(AirsModel):
    """A security group and its state.

    A create comes back ``PENDING`` and flips to ``ACTIVE`` once its rule instances
    exist. ``is_tombstone`` marks a soft-deleted group, kept so that scans which already
    referenced it still resolve.
    """

    uuid: str
    tsg_id: str
    created_at: str
    updated_at: str
    name: str
    description: str
    source_type: str
    state: str
    is_tombstone: bool


class ModelSecurityGroupUpdateRequest(AirsModel):
    """Request body for updating a security group.

    Both fields are optional; ``source_type`` is absent by design, as a group's source
    cannot be changed after creation.
    """

    name: str | None = None
    description: str | None = None


class ListModelSecurityGroupsResponse(AirsModel):
    """Paginated list of security groups."""

    pagination: ModelSecurityPagination
    security_groups: list[ModelSecurityGroupResponse]


# ---------------------------------------------------------------------------
# Management -- PyPI auth
# ---------------------------------------------------------------------------


class PyPIAuthResponse(AirsModel):
    """Short-lived credentials for the Artifact Registry that serves the scanner package.

    ``url`` embeds a bearer token (``https://_token:ya29...@us-python.pkg.dev/...``), so
    it is credential material: feed it to pip as an index URL, and keep it out of logs,
    shell history, and committed config. It stops working at ``expires_at``.
    """

    url: str
    expires_at: str
