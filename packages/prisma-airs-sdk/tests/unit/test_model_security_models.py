"""Model Security request and response models."""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from typing import get_args

import pytest
from pydantic import ValidationError

from prisma_airs.models import model_security
from prisma_airs.models.base import AirsModel
from prisma_airs.models.model_security import (
    ErrorCodes,
    EvalOutcome,
    EvalSummary,
    FileList,
    FileResponse,
    FileScanData,
    FileScanResult,
    FileType,
    Label,
    LabelKeyList,
    LabelsCreateRequest,
    LabelsResponse,
    LabelValueList,
    ListModelSecurityGroupsResponse,
    ListModelSecurityRuleInstancesResponse,
    ListModelSecurityRulesResponse,
    ModelList,
    ModelResponse,
    ModelScanIssue,
    ModelScanStatus,
    ModelSecurityGroupCreateRequest,
    ModelSecurityGroupResponse,
    ModelSecurityGroupState,
    ModelSecurityGroupUpdateRequest,
    ModelSecurityPagination,
    ModelSecurityRuleInstanceResponse,
    ModelSecurityRuleInstanceUpdateRequest,
    ModelSecurityRuleResponse,
    ModelVersionList,
    ModelVersionResponse,
    PyPIAuthResponse,
    RuleConfiguration,
    RuleEditableField,
    RuleEditableFieldDropdown,
    RuleEditableFieldType,
    RuleEvaluationList,
    RuleEvaluationResponse,
    RuleEvaluationResult,
    RuleFieldValueKey,
    RuleRemediation,
    RuleState,
    RuleType,
    ScanBaseResponse,
    ScanCreateRequest,
    ScanDetails,
    ScanList,
    ScanOrigin,
    SortByDateField,
    SortByFileField,
    SortDirection,
    SourceType,
    ThreatCategory,
    ViolationList,
    ViolationRemediation,
    ViolationResponse,
)

GROUP_UUID = "550e8400-e29b-41d4-a716-446655440000"
RULE_UUID = "660e8400-e29b-41d4-a716-446655440000"


# ---------------------------------------------------------------------------
# The wire contract
#
# Every payload in this domain, transcribed field-by-field from the API schemas
# rather than from the Python models: names in wire order, ``!`` marking the ones
# the service requires. Two things make this worth spelling out.
#
# First, ``AirsModel`` allows extra fields, so a field that never got ported does
# not fail to parse -- it lands in ``model_extra``, and ``scan.total_files_skipped``
# still reads back whatever the service sent. The gap only surfaces later, as an
# ``AttributeError`` on a payload that happens to omit the field, or as a request
# field that silently stops being sent. Nothing below this table would catch it.
#
# Second, requiredness is the one thing a client cannot be relaxed about in either
# direction: too strict rejects responses the service legitimately sends, too loose
# lets a request go out incomplete and fail at the server.
# ---------------------------------------------------------------------------

WIRE_SCHEMAS: list[tuple[type[AirsModel], str]] = [
    (ModelSecurityPagination, "total_items"),
    (Label, "!key !value"),
    (LabelsCreateRequest, "!labels"),
    (LabelsResponse, ""),
    (LabelKeyList, "!pagination !keys"),
    (LabelValueList, "!pagination !values"),
    (EvalSummary, "rules_failed rules_passed total_rules"),
    (ModelScanIssue, "!description !source threat module operator"),
    (FileScanData, "!file_path !modelscan_status !blob_id error_message formats issues_detected"),
    (
        ScanDetails,
        "!scanner_version !time_started !files !total_files_scanned !total_files_skipped "
        "!model_formats !model_size_bytes !scan_duration_ms error_code error_message",
    ),
    (
        ScanCreateRequest,
        "!model_uri !security_group_uuid scan_origin allow_patterns ignore_patterns labels "
        "model_author model_name model_version scan_details",
    ),
    (
        ScanBaseResponse,
        "!uuid !tsg_id !created_at !updated_at !model_uri !owner !scan_origin "
        "!security_group_uuid !security_group_name model_version_uuid !eval_outcome "
        "!source_type created_by enabled_rule_count_snapshot error_code error_message "
        "eval_summary labels model_formats scanner_version time_started total_files_scanned "
        "total_files_skipped",
    ),
    (ScanList, "!pagination !scans"),
    (
        FileResponse,
        "!uuid !tsg_id !created_at !updated_at !path !parent_path !type !result "
        "!model_version_uuid blob_id formats scan_uuid",
    ),
    (FileList, "!pagination !files"),
    (
        ModelResponse,
        "!uuid !tsg_id !created_at !updated_at !name latest_version_uuid "
        "latest_version_fingerprint latest_version_revision latest_version_hf_commit_sha "
        "latest_version_outcome latest_version_formats latest_version_source_types "
        "latest_version_scan_time",
    ),
    (ModelList, "!pagination !models"),
    (
        ModelVersionResponse,
        "!uuid !tsg_id !created_at !updated_at !revision !model_uuid fingerprint file_count "
        "license latest_scan_time hf_commit_sha hf_commit_title hf_commit_authors "
        "hf_model_name hf_organization model_formats source_types last_eval_outcome "
        "last_eval_summary",
    ),
    (ModelVersionList, "!pagination !model_versions"),
    (
        RuleEvaluationResponse,
        "!uuid !tsg_id !created_at !updated_at !result !violation_count !rule_instance_uuid "
        "!scan_uuid !rule_name !rule_description !rule_instance_state",
    ),
    (RuleEvaluationList, "!pagination !evaluations"),
    (ViolationRemediation, "!steps !url"),
    (
        ViolationResponse,
        "!uuid !tsg_id !created_at !updated_at !description !rule_instance_uuid !rule_name "
        "!rule_description !rule_instance_state !remediation file hash module operator threat "
        "threat_description",
    ),
    (ViolationList, "!pagination !violations"),
    (RuleEditableFieldDropdown, "!value !label"),
    (
        RuleEditableField,
        "!attribute_name !type !display_name !display_type description dropdown_values",
    ),
    (RuleRemediation, "!description !steps !url"),
    (RuleConfiguration, "field_values state"),
    (
        ModelSecurityRuleResponse,
        "!uuid !name !description !rule_type !compatible_sources !default_state !remediation "
        "!editable_fields !constant_values !default_values",
    ),
    (ListModelSecurityRulesResponse, "!pagination !rules"),
    (
        ModelSecurityRuleInstanceResponse,
        "!uuid !tsg_id !created_at !updated_at !security_group_uuid !security_rule_uuid "
        "!state !rule field_values",
    ),
    (ModelSecurityRuleInstanceUpdateRequest, "!security_group_uuid state field_values"),
    (ListModelSecurityRuleInstancesResponse, "!pagination !rule_instances"),
    (ModelSecurityGroupCreateRequest, "!name !source_type description rule_configurations"),
    (
        ModelSecurityGroupResponse,
        "!uuid !tsg_id !created_at !updated_at !name !description !source_type !state "
        "!is_tombstone",
    ),
    (ModelSecurityGroupUpdateRequest, "name description"),
    (ListModelSecurityGroupsResponse, "!pagination !security_groups"),
    (PyPIAuthResponse, "!url !expires_at"),
]

_wire_schema_cases = pytest.mark.parametrize(
    ("model", "spec"),
    WIRE_SCHEMAS,
    ids=[model.__name__ for model, _ in WIRE_SCHEMAS],
)

# The same transcription for the enums: wire values, in source order. These are reference
# values rather than field types, so a member dropped in the port fails nothing at parse
# time -- it just leaves callers with nothing to branch on for a value the service sends.
WIRE_ENUMS: list[tuple[type[Enum], str]] = [
    (
        ErrorCodes,
        "UNKNOWN_ERROR SCAN_ERROR INVALID_RESPONSE ACCESS_DENIED MISSING_CREDENTIALS "
        "NO_SUCH_KEY NO_SUCH_BUCKET INVALID_BUCKET_NAME INTERNAL_ERROR SERVICE_UNAVAILABLE "
        "INVALID_OBJECT_STATE UNKNOWN_REMOTE_SERVICE_ERROR UNSUPPORTED_REMOTE_STORAGE "
        "MISSING_ARTIFACTS WORKER_ERROR POLICY_EVAL_ERROR",
    ),
    (EvalOutcome, "PENDING ALLOWED BLOCKED ERROR"),
    (FileScanResult, "SKIPPED SUCCESS ERROR FAILED"),
    (FileType, "DIRECTORY FILE"),
    (ModelScanStatus, "SCANNED SKIPPED ERROR"),
    (RuleEvaluationResult, "PASSED FAILED ERROR"),
    (RuleState, "DISABLED ALLOWING BLOCKING"),
    (ScanOrigin, "MODEL_SECURITY_SDK HUGGING_FACE"),
    (SortByDateField, "created_at updated_at"),
    (SortByFileField, "path type"),
    (SortDirection, "asc desc"),
    (SourceType, "LOCAL HUGGING_FACE S3 GCS AZURE ARTIFACTORY GITLAB ALL"),
    (
        ThreatCategory,
        "PAIT-ARV-100 PAIT-GGUF-100 PAIT-GGUF-101 PAIT-KERAS-100 PAIT-KERAS-101 "
        "PAIT-KERAS-102 PAIT-JOBLIB-100 PAIT-JOBLIB-101 PAIT-PKL-100 PAIT-PKL-101 "
        "PAIT-PYTCH-100 PAIT-PYTCH-101 PAIT-EXDIR-100 PAIT-EXDIR-101 PAIT-ONNX-200 "
        "PAIT-TF-200 PAIT-LMAFL-300 PAIT-LITERT-300 PAIT-LITERT-301 PAIT-LITERT-302 "
        "PAIT-KERAS-300 PAIT-KERAS-301 PAIT-TCHST-300 PAIT-TCHST-301 PAIT-TF-300 PAIT-TF-301 "
        "PAIT-TF-302 PAIT-TMT-300 PAIT-TMT-301 UNAPPROVED_FORMATS",
    ),
    (ModelSecurityGroupState, "PENDING ACTIVE"),
    (RuleType, "METADATA ARTIFACT"),
    (RuleEditableFieldType, "SELECT LIST"),
    (
        RuleFieldValueKey,
        "approved_formats approved_locations approved_licenses deny_orgs denied_org_models "
        "approved_org_models",
    ),
]


# ---------------------------------------------------------------------------
# Payload builders -- shapes taken from the reference client's worked examples
# ---------------------------------------------------------------------------


def _scan_payload(**extra: object) -> dict[str, object]:
    return {
        "uuid": "770e8400-e29b-41d4-a716-446655440000",
        "tsg_id": "1234567890",
        "created_at": "2026-01-05T12:00:00Z",
        "updated_at": "2026-01-05T12:04:11Z",
        "model_uri": "hf://org/model",
        "owner": "scanner@example.com",
        "scan_origin": "MODEL_SECURITY_SDK",
        "security_group_uuid": GROUP_UUID,
        "security_group_name": "hf-strict",
        "model_version_uuid": "880e8400-e29b-41d4-a716-446655440000",
        "eval_outcome": "BLOCKED",
        "source_type": "HUGGING_FACE",
        "created_by": "scanner@example.com",
        "enabled_rule_count_snapshot": 7,
        "eval_summary": {"rules_failed": 2, "rules_passed": 5, "total_rules": 7},
        "labels": [{"key": "env", "value": "prod"}],
        "model_formats": ["pytorch", "safetensors"],
        "scanner_version": "1.4.2",
        "time_started": "2026-01-05T12:00:01Z",
        "total_files_scanned": 12,
        "total_files_skipped": 3,
        **extra,
    }


def _scan_details_payload(**extra: object) -> dict[str, object]:
    return {
        "scanner_version": "1.4.2",
        "time_started": "2026-01-05T12:00:01Z",
        "files": [],
        "total_files_scanned": 12,
        "total_files_skipped": 3,
        "model_formats": ["pytorch"],
        "model_size_bytes": 4_294_967_296,
        "scan_duration_ms": 18_500,
        **extra,
    }


def _version_payload(**extra: object) -> dict[str, object]:
    return {
        "uuid": "880e8400-e29b-41d4-a716-446655440000",
        "tsg_id": "1234567890",
        "created_at": "2026-01-05T12:00:00Z",
        "updated_at": "2026-01-05T12:00:00Z",
        "revision": "main",
        "model_uuid": "bb0e8400-e29b-41d4-a716-446655440000",
        **extra,
    }


def _evaluation_payload(**extra: object) -> dict[str, object]:
    return {
        "uuid": "cc0e8400-e29b-41d4-a716-446655440000",
        "tsg_id": "1234567890",
        "created_at": "2026-01-05T12:04:00Z",
        "updated_at": "2026-01-05T12:04:00Z",
        "result": "FAILED",
        "violation_count": 2,
        "rule_instance_uuid": RULE_UUID,
        "scan_uuid": "770e8400-e29b-41d4-a716-446655440000",
        "rule_name": "Pickle Scan",
        "rule_description": "Flags unsafe pickle opcodes in model artifacts",
        "rule_instance_state": "BLOCKING",
        **extra,
    }


def _rule_payload(**extra: object) -> dict[str, object]:
    return {
        "uuid": RULE_UUID,
        "name": "Pickle Scan",
        "description": "Flags unsafe pickle opcodes in model artifacts",
        "rule_type": "ARTIFACT",
        "compatible_sources": ["HUGGING_FACE", "S3"],
        "default_state": "BLOCKING",
        "remediation": {
            "description": "Re-export the checkpoint in a safe format",
            "steps": ["Convert the checkpoint to safetensors", "Re-run the scan"],
            "url": "https://example.invalid/docs/pickle",
        },
        "editable_fields": [
            {
                "attribute_name": "approved_formats",
                "type": "LIST",
                "display_name": "Approved formats",
                "display_type": "SELECT",
                "description": "Formats this rule lets through",
                "dropdown_values": [{"value": "safetensors", "label": "SafeTensors"}],
            }
        ],
        "constant_values": {"severity": "HIGH"},
        "default_values": {"approved_formats": ["safetensors"]},
        **extra,
    }


def _violation_payload(**extra: object) -> dict[str, object]:
    return {
        "uuid": "990e8400-e29b-41d4-a716-446655440000",
        "tsg_id": "1234567890",
        "created_at": "2026-01-05T12:04:00Z",
        "updated_at": "2026-01-05T12:04:00Z",
        "description": "Unsafe pickle opcode reachable at load time",
        "rule_instance_uuid": RULE_UUID,
        "rule_name": "Pickle Scan",
        "rule_description": "Flags unsafe pickle opcodes in model artifacts",
        "rule_instance_state": "BLOCKING",
        "remediation": {
            "steps": ["Convert the checkpoint to safetensors"],
            "url": "https://example.invalid/docs/pickle",
        },
        "file": "pytorch_model.bin",
        "hash": "e3b0c44298fc1c149afbf4c8996fb924",
        "module": "posix",
        "operator": "system",
        "threat": "PAIT-PKL-100",
        "threat_description": "Arbitrary code execution during unpickling",
        **extra,
    }


# ---------------------------------------------------------------------------
# Shared / utility
# ---------------------------------------------------------------------------


class TestModelSecurityPagination:
    def test_an_absent_count_stays_unknown(self) -> None:
        """Absent must not collapse to 0, or paging code reads it as an empty result."""
        assert ModelSecurityPagination.model_validate({}).total_items is None

    def test_an_explicit_null_count_stays_unknown(self) -> None:
        assert ModelSecurityPagination.model_validate({"total_items": None}).total_items is None

    def test_parses_a_reported_count(self) -> None:
        assert ModelSecurityPagination.model_validate({"total_items": 42}).total_items == 42

    def test_rejects_a_non_numeric_count(self) -> None:
        with pytest.raises(ValidationError):
            ModelSecurityPagination.model_validate({"total_items": "many"})


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


class TestLabels:
    def test_a_label_needs_both_halves(self) -> None:
        with pytest.raises(ValidationError):
            Label.model_validate({"key": "env"})

    def test_create_request_round_trips_to_the_wire_shape(self) -> None:
        request = LabelsCreateRequest(labels=[Label(key="env", value="prod")])

        assert request.model_dump() == {"labels": [{"key": "env", "value": "prod"}]}

    def test_response_accepts_the_empty_success_body(self) -> None:
        assert LabelsResponse.model_validate({}).model_dump() == {}

    def test_response_keeps_anything_the_service_starts_returning(self) -> None:
        result = LabelsResponse.model_validate({"updated": 3})

        assert result.model_extra == {"updated": 3}

    def test_key_list_parses_with_its_pagination(self) -> None:
        keys = LabelKeyList.model_validate(
            {"pagination": {"total_items": 3}, "keys": ["env", "team", "owner"]}
        )

        assert keys.pagination.total_items == 3
        assert keys.keys == ["env", "team", "owner"]

    def test_value_list_parses_with_its_pagination(self) -> None:
        values = LabelValueList.model_validate(
            {"pagination": {"total_items": 2}, "values": ["prod", "staging"]}
        )

        assert values.values == ["prod", "staging"]

    def test_a_key_list_without_pagination_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            LabelKeyList.model_validate({"keys": []})


# ---------------------------------------------------------------------------
# Eval summary
# ---------------------------------------------------------------------------


class TestEvalSummary:
    def test_counts_default_to_zero(self) -> None:
        """The service omits the counts on scans that never reached evaluation."""
        assert EvalSummary().model_dump() == {
            "rules_failed": 0,
            "rules_passed": 0,
            "total_rules": 0,
        }

    def test_parses_reported_counts(self) -> None:
        summary = EvalSummary.model_validate({"rules_failed": 2, "rules_passed": 5})

        assert (summary.rules_failed, summary.rules_passed, summary.total_rules) == (2, 5, 0)

    def test_rejects_an_explicit_null_count(self) -> None:
        """Defaulted, not nullable -- same contract as the TypeScript reference client."""
        with pytest.raises(ValidationError):
            EvalSummary.model_validate({"rules_failed": None})

    def test_rejects_a_fractional_count(self) -> None:
        with pytest.raises(ValidationError):
            EvalSummary.model_validate({"total_rules": 2.5})


# ---------------------------------------------------------------------------
# Scan creation
# ---------------------------------------------------------------------------


class TestScanCreateRequest:
    def test_a_minimal_create_sends_only_what_was_set(self) -> None:
        request = ScanCreateRequest(model_uri="hf://org/model", security_group_uuid=GROUP_UUID)

        assert request.model_dump(exclude_none=True) == {
            "model_uri": "hf://org/model",
            "security_group_uuid": GROUP_UUID,
        }

    def test_scan_origin_is_optional(self) -> None:
        """The server defaults it, even though the reference client always sends it."""
        request = ScanCreateRequest(model_uri="hf://org/model", security_group_uuid=GROUP_UUID)

        assert request.scan_origin is None

    def test_requires_a_security_group(self) -> None:
        with pytest.raises(ValidationError):
            ScanCreateRequest.model_validate({"model_uri": "hf://org/model"})

    def test_parses_nested_scanner_output(self) -> None:
        request = ScanCreateRequest.model_validate(
            {
                "model_uri": "hf://org/model",
                "security_group_uuid": GROUP_UUID,
                "scan_origin": "MODEL_SECURITY_SDK",
                "labels": [{"key": "env", "value": "prod"}],
                "model_author": "org",
                "model_name": "model",
                "model_version": "main",
                "scan_details": {
                    "scanner_version": "1.4.2",
                    "time_started": "2026-01-05T12:00:01Z",
                    "files": [
                        {
                            "file_path": "pytorch_model.bin",
                            "modelscan_status": "SCANNED",
                            "blob_id": "blob-1",
                            "formats": ["pytorch"],
                            "issues_detected": [
                                {
                                    "description": "Unsafe pickle opcode",
                                    "source": "pytorch_model.bin",
                                    "threat": "PAIT-PKL-100",
                                    "module": "posix",
                                    "operator": "system",
                                }
                            ],
                        }
                    ],
                    "total_files_scanned": 12,
                    "total_files_skipped": 3,
                    "model_formats": ["pytorch"],
                    "model_size_bytes": 4_294_967_296,
                    "scan_duration_ms": 18_500,
                },
            }
        )

        assert isinstance(request.scan_details, ScanDetails)
        scanned_file = request.scan_details.files[0]
        assert isinstance(scanned_file, FileScanData)
        issue = (scanned_file.issues_detected or [])[0]
        assert isinstance(issue, ModelScanIssue)
        assert issue.threat == ThreatCategory.PAIT_PKL_100
        assert request.labels is not None
        assert request.labels[0].key == "env"

    def test_scan_details_requires_the_totals(self) -> None:
        payload = _scan_details_payload()
        del payload["total_files_scanned"]
        del payload["total_files_skipped"]

        with pytest.raises(ValidationError):
            ScanDetails.model_validate(payload)

    def test_model_prefixed_fields_keep_their_wire_names(self) -> None:
        """A rename here would silently drop the fields the service keys on."""
        request = ScanCreateRequest(
            model_uri="hf://org/model",
            security_group_uuid=GROUP_UUID,
            model_author="org",
            model_name="model",
            model_version="main",
        )
        dumped = request.model_dump(exclude_none=True)

        assert set(dumped) == {
            "model_uri",
            "security_group_uuid",
            "model_author",
            "model_name",
            "model_version",
        }

    def test_relaxing_that_guard_did_not_cost_the_shared_config(self) -> None:
        assert ScanCreateRequest.model_config["extra"] == "allow"
        assert ScanCreateRequest.model_config["populate_by_name"] is True


# ---------------------------------------------------------------------------
# Scan responses
# ---------------------------------------------------------------------------


class TestScanBaseResponse:
    def test_parses_a_realistic_scan(self) -> None:
        scan = ScanBaseResponse.model_validate(_scan_payload())

        assert scan.eval_outcome == EvalOutcome.BLOCKED
        assert scan.eval_summary is not None
        assert scan.eval_summary.rules_failed == 2
        assert scan.labels is not None
        assert scan.labels[0].value == "prod"
        assert scan.enabled_rule_count_snapshot == 7

    def test_a_scan_without_a_resolved_version_parses(self) -> None:
        """A create returns before the model version is resolved."""
        payload = _scan_payload(eval_outcome="PENDING")
        del payload["model_version_uuid"]

        scan = ScanBaseResponse.model_validate(payload)

        assert scan.model_version_uuid is None
        assert scan.eval_outcome == EvalOutcome.PENDING

    def test_tolerates_an_outcome_this_release_has_never_heard_of(self) -> None:
        """Outcomes are plain strings on purpose: a new backend value must not fail parsing."""
        scan = ScanBaseResponse.model_validate(_scan_payload(eval_outcome="QUARANTINED"))

        assert scan.eval_outcome == "QUARANTINED"

    def test_still_requires_the_fields_the_outcome_depends_on(self) -> None:
        payload = _scan_payload()
        del payload["eval_outcome"]

        with pytest.raises(ValidationError):
            ScanBaseResponse.model_validate(payload)

    def test_keeps_unknown_fields(self) -> None:
        scan = ScanBaseResponse.model_validate(_scan_payload(risk_score=91))

        assert scan.model_extra is not None
        assert scan.model_extra["risk_score"] == 91

    def test_a_null_eval_summary_is_accepted(self) -> None:
        scan = ScanBaseResponse.model_validate(_scan_payload(eval_summary=None))

        assert scan.eval_summary is None


class TestScanList:
    def test_parses_a_page_of_scans(self) -> None:
        page = ScanList.model_validate(
            {"pagination": {"total_items": 42}, "scans": [_scan_payload()]}
        )

        assert page.pagination.total_items == 42
        assert isinstance(page.scans[0], ScanBaseResponse)
        assert page.scans[0].security_group_name == "hf-strict"

    def test_parses_an_empty_page(self) -> None:
        page = ScanList.model_validate({"pagination": {}, "scans": []})

        assert page.scans == []

    def test_rejects_a_page_whose_scans_are_malformed(self) -> None:
        with pytest.raises(ValidationError):
            ScanList.model_validate({"pagination": {}, "scans": [{"uuid": "u"}]})


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------


class TestFiles:
    def _file(self, **extra: object) -> dict[str, object]:
        return {
            "uuid": "aa0e8400-e29b-41d4-a716-446655440000",
            "tsg_id": "1234567890",
            "created_at": "2026-01-05T12:00:00Z",
            "updated_at": "2026-01-05T12:00:00Z",
            "path": "pytorch_model.bin",
            "parent_path": "/",
            "type": "FILE",
            "result": "SUCCESS",
            "model_version_uuid": "880e8400-e29b-41d4-a716-446655440000",
            "blob_id": "blob-1",
            "formats": ["pytorch"],
            "scan_uuid": "770e8400-e29b-41d4-a716-446655440000",
            **extra,
        }

    def test_parses_a_scanned_file(self) -> None:
        entry = FileResponse.model_validate(self._file())

        assert entry.blob_id == "blob-1"
        assert entry.formats == ["pytorch"]

    def test_a_directory_node_carries_no_blob(self) -> None:
        payload = self._file(path="weights", type="DIRECTORY", result="SKIPPED")
        del payload["blob_id"]
        del payload["formats"]

        entry = FileResponse.model_validate(payload)

        assert (entry.blob_id, entry.formats) == (None, None)
        assert entry.type == "DIRECTORY"

    def test_requires_the_owning_model_version(self) -> None:
        payload = self._file()
        del payload["model_version_uuid"]

        with pytest.raises(ValidationError):
            FileResponse.model_validate(payload)

    def test_file_list_parses(self) -> None:
        page = FileList.model_validate({"pagination": {"total_items": 1}, "files": [self._file()]})

        assert page.files[0].path == "pytorch_model.bin"


# ---------------------------------------------------------------------------
# Models and model versions
# ---------------------------------------------------------------------------


class TestModels:
    def _model(self, **extra: object) -> dict[str, object]:
        return {
            "uuid": "bb0e8400-e29b-41d4-a716-446655440000",
            "tsg_id": "1234567890",
            "created_at": "2026-01-05T12:00:00Z",
            "updated_at": "2026-01-05T12:00:00Z",
            "name": "org/model",
            **extra,
        }

    def test_a_model_that_was_never_scanned_has_no_latest_version(self) -> None:
        entry = ModelResponse.model_validate(self._model())

        assert entry.latest_version_uuid is None
        assert entry.latest_version_outcome is None

    def test_carries_the_denormalised_latest_version(self) -> None:
        entry = ModelResponse.model_validate(
            self._model(
                latest_version_uuid="880e8400-e29b-41d4-a716-446655440000",
                latest_version_outcome="ALLOWED",
                latest_version_formats=["safetensors"],
                latest_version_source_types=["HUGGING_FACE"],
                latest_version_scan_time="2026-01-05T12:04:11Z",
            )
        )

        assert entry.latest_version_outcome == EvalOutcome.ALLOWED
        assert entry.latest_version_source_types == [SourceType.HUGGING_FACE]

    def test_model_list_parses(self) -> None:
        page = ModelList.model_validate(
            {"pagination": {"total_items": 1}, "models": [self._model()]}
        )

        assert page.models[0].name == "org/model"


class TestModelVersions:
    def test_parses_hugging_face_provenance(self) -> None:
        version = ModelVersionResponse.model_validate(
            _version_payload(
                fingerprint="sha256:abc",
                file_count=12,
                license="apache-2.0",
                hf_commit_sha="deadbeef",
                hf_commit_title="Add safetensors weights",
                hf_commit_authors=["alice", "bob"],
                hf_model_name="model",
                hf_organization="org",
                model_formats=["safetensors"],
                source_types=["HUGGING_FACE"],
                last_eval_outcome="ALLOWED",
                last_eval_summary={"rules_failed": 0, "rules_passed": 7, "total_rules": 7},
            )
        )

        assert version.hf_commit_authors == ["alice", "bob"]
        assert isinstance(version.last_eval_summary, EvalSummary)
        assert version.last_eval_summary.rules_passed == 7

    def test_a_non_hugging_face_version_omits_the_hf_fields(self) -> None:
        version = ModelVersionResponse.model_validate(_version_payload(source_types=["S3"]))

        assert version.hf_commit_sha is None
        assert version.last_eval_summary is None

    def test_the_list_keeps_its_model_prefixed_key(self) -> None:
        page = ModelVersionList.model_validate(
            {"pagination": {"total_items": 1}, "model_versions": [_version_payload()]}
        )

        assert "model_versions" in page.model_dump()
        assert page.model_versions[0].revision == "main"


# ---------------------------------------------------------------------------
# Rule evaluations and violations
# ---------------------------------------------------------------------------


class TestRuleEvaluations:
    def test_parses_an_evaluation(self) -> None:
        evaluation = RuleEvaluationResponse.model_validate(_evaluation_payload())

        assert evaluation.violation_count == 2
        assert evaluation.rule_instance_state == RuleState.BLOCKING

    def test_requires_the_violation_count(self) -> None:
        """Callers branch on it to decide whether to fetch violations, so it cannot default."""
        payload = _evaluation_payload()
        del payload["violation_count"]

        with pytest.raises(ValidationError):
            RuleEvaluationResponse.model_validate(payload)

    def test_evaluation_list_parses(self) -> None:
        page = RuleEvaluationList.model_validate(
            {"pagination": {"total_items": 1}, "evaluations": [_evaluation_payload()]}
        )

        assert page.evaluations[0].result == "FAILED"


class TestViolations:
    def test_parses_a_violation_with_its_remediation(self) -> None:
        violation = ViolationResponse.model_validate(_violation_payload())

        assert violation.remediation.steps == ["Convert the checkpoint to safetensors"]
        assert violation.threat == ThreatCategory.PAIT_PKL_100
        assert violation.file == "pytorch_model.bin"

    def test_requires_remediation(self) -> None:
        payload = _violation_payload()
        del payload["remediation"]

        with pytest.raises(ValidationError):
            ViolationResponse.model_validate(payload)

    def test_a_metadata_violation_has_nothing_to_point_at(self) -> None:
        payload = _violation_payload(
            description="License apache-2.0 is not approved",
            rule_name="Approved Licenses",
            threat="UNAPPROVED_FORMATS",
        )
        for locator in ("file", "hash", "module", "operator"):
            del payload[locator]

        violation = ViolationResponse.model_validate(payload)

        assert (violation.file, violation.hash, violation.module, violation.operator) == (
            None,
            None,
            None,
            None,
        )

    def test_violation_list_parses(self) -> None:
        page = ViolationList.model_validate(
            {"pagination": {"total_items": 1}, "violations": [_violation_payload()]}
        )

        assert page.violations[0].rule_name == "Pickle Scan"


# ---------------------------------------------------------------------------
# Management -- rules
# ---------------------------------------------------------------------------


class TestSecurityRules:
    def test_parses_a_rule_definition(self) -> None:
        rule = ModelSecurityRuleResponse.model_validate(_rule_payload())

        assert rule.rule_type == "ARTIFACT"
        assert rule.constant_values == {"severity": "HIGH"}
        assert rule.default_values == {"approved_formats": ["safetensors"]}
        editable = rule.editable_fields[0]
        assert isinstance(editable, RuleEditableField)
        assert editable.attribute_name == RuleFieldValueKey.APPROVED_FORMATS
        assert editable.dropdown_values is not None
        assert editable.dropdown_values[0].label == "SafeTensors"

    def test_requires_the_value_maps(self) -> None:
        payload = _rule_payload()
        del payload["constant_values"]

        with pytest.raises(ValidationError):
            ModelSecurityRuleResponse.model_validate(payload)

    def test_an_editable_field_without_a_dropdown_parses(self) -> None:
        field = RuleEditableField.model_validate(
            {
                "attribute_name": "deny_orgs",
                "type": "LIST",
                "display_name": "Denied organisations",
                "display_type": "LIST",
            }
        )

        assert field.dropdown_values is None
        assert field.description is None

    def test_rule_list_parses(self) -> None:
        page = ListModelSecurityRulesResponse.model_validate(
            {"pagination": {"total_items": 1}, "rules": [_rule_payload()]}
        )

        assert page.rules[0].name == "Pickle Scan"


# ---------------------------------------------------------------------------
# Management -- rule instances
# ---------------------------------------------------------------------------


class TestRuleInstances:
    def _instance(self, **extra: object) -> dict[str, object]:
        return {
            "uuid": "dd0e8400-e29b-41d4-a716-446655440000",
            "tsg_id": "1234567890",
            "created_at": "2026-01-05T11:00:00Z",
            "updated_at": "2026-01-05T11:00:00Z",
            "security_group_uuid": GROUP_UUID,
            "security_rule_uuid": RULE_UUID,
            "state": "BLOCKING",
            "rule": _rule_payload(),
            "field_values": {"approved_formats": ["safetensors"]},
            **extra,
        }

    def test_parses_an_instance_with_the_rule_inlined(self) -> None:
        instance = ModelSecurityRuleInstanceResponse.model_validate(self._instance())

        assert isinstance(instance.rule, ModelSecurityRuleResponse)
        assert instance.rule.name == "Pickle Scan"
        assert instance.field_values == {"approved_formats": ["safetensors"]}

    def test_requires_the_inlined_rule(self) -> None:
        payload = self._instance()
        del payload["rule"]

        with pytest.raises(ValidationError):
            ModelSecurityRuleInstanceResponse.model_validate(payload)

    def test_an_instance_may_carry_no_overrides(self) -> None:
        payload = self._instance()
        del payload["field_values"]

        assert ModelSecurityRuleInstanceResponse.model_validate(payload).field_values is None

    def test_an_update_repeats_the_group_uuid(self) -> None:
        """The path already identifies the group, yet the body still has to name it."""
        with pytest.raises(ValidationError):
            ModelSecurityRuleInstanceUpdateRequest.model_validate({"state": "ALLOWING"})

    def test_an_update_sends_only_the_fields_it_touches(self) -> None:
        request = ModelSecurityRuleInstanceUpdateRequest(
            security_group_uuid=GROUP_UUID, state=RuleState.ALLOWING
        )

        assert request.model_dump(exclude_none=True) == {
            "security_group_uuid": GROUP_UUID,
            "state": "ALLOWING",
        }

    def test_instance_list_parses(self) -> None:
        page = ListModelSecurityRuleInstancesResponse.model_validate(
            {"pagination": {"total_items": 1}, "rule_instances": [self._instance()]}
        )

        assert page.rule_instances[0].state == RuleState.BLOCKING


# ---------------------------------------------------------------------------
# Management -- security groups
# ---------------------------------------------------------------------------


class TestSecurityGroups:
    def _group(self, **extra: object) -> dict[str, object]:
        return {
            "uuid": GROUP_UUID,
            "tsg_id": "1234567890",
            "created_at": "2026-01-05T10:00:00Z",
            "updated_at": "2026-01-05T10:00:02Z",
            "name": "hf-strict",
            "description": "Block unsafe Hugging Face models",
            "source_type": "HUGGING_FACE",
            "state": "ACTIVE",
            "is_tombstone": False,
            **extra,
        }

    def test_create_defaults_the_description_to_empty(self) -> None:
        request = ModelSecurityGroupCreateRequest(name="hf-strict", source_type="HUGGING_FACE")

        assert request.description == ""

    def test_create_parses_per_rule_overrides(self) -> None:
        request = ModelSecurityGroupCreateRequest.model_validate(
            {
                "name": "hf-strict",
                "source_type": "HUGGING_FACE",
                "rule_configurations": {
                    RULE_UUID: {
                        "state": "BLOCKING",
                        "field_values": {"approved_formats": ["safetensors"]},
                    }
                },
            }
        )

        assert request.rule_configurations is not None
        configuration = request.rule_configurations[RULE_UUID]
        assert isinstance(configuration, RuleConfiguration)
        assert configuration.state == RuleState.BLOCKING
        assert configuration.field_values == {"approved_formats": ["safetensors"]}

    def test_create_requires_a_source_type(self) -> None:
        with pytest.raises(ValidationError):
            ModelSecurityGroupCreateRequest.model_validate({"name": "hf-strict"})

    def test_parses_a_freshly_created_group(self) -> None:
        """A create answers PENDING; the group only becomes ACTIVE once its instances exist."""
        group = ModelSecurityGroupResponse.model_validate(self._group(state="PENDING"))

        assert group.state == ModelSecurityGroupState.PENDING
        assert group.is_tombstone is False

    def test_requires_the_tombstone_flag(self) -> None:
        payload = self._group()
        del payload["is_tombstone"]

        with pytest.raises(ValidationError):
            ModelSecurityGroupResponse.model_validate(payload)

    def test_an_update_can_touch_one_field_alone(self) -> None:
        request = ModelSecurityGroupUpdateRequest(name="hf-strict-v2")

        assert request.model_dump(exclude_none=True) == {"name": "hf-strict-v2"}

    def test_group_list_parses(self) -> None:
        page = ListModelSecurityGroupsResponse.model_validate(
            {"pagination": {"total_items": 1}, "security_groups": [self._group()]}
        )

        assert page.security_groups[0].name == "hf-strict"


# ---------------------------------------------------------------------------
# Management -- PyPI auth
# ---------------------------------------------------------------------------


class TestPyPIAuth:
    def test_parses_the_registry_credentials(self) -> None:
        auth = PyPIAuthResponse.model_validate(
            {
                "url": "https://_token:ya29.example@us-python.pkg.dev/proj/repo/simple/",
                "expires_at": "2026-01-05T13:00:00Z",
            }
        )

        assert auth.url.startswith("https://_token:")
        assert auth.expires_at == "2026-01-05T13:00:00Z"

    def test_both_halves_are_required(self) -> None:
        """A URL with no expiry would be used past the point where it stops working."""
        with pytest.raises(ValidationError):
            PyPIAuthResponse.model_validate({"url": "https://example.invalid/simple/"})


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    @pytest.mark.parametrize(
        "enum", [enum for enum, _ in WIRE_ENUMS], ids=[enum.__name__ for enum, _ in WIRE_ENUMS]
    )
    def test_members_are_interchangeable_with_their_wire_string(self, enum: type[Enum]) -> None:
        """Every enum here subclasses ``str``, and both directions depend on it.

        Fields are typed ``str``, so ``scan.eval_outcome == EvalOutcome.BLOCKED`` only
        works if a member compares equal to the raw value; and a caller narrowing a
        response string needs ``EvalOutcome(value)`` to find the member. Drop the mixin
        and both go quietly false rather than loud.
        """
        for member in enum:
            assert isinstance(member, str)
            assert member == member.value
            assert enum(member.value) is member

    def test_threat_categories_belong_to_the_scanner(self) -> None:
        """The ``PAIT-*`` codes are modelscan-pai's, so their shape is not ours to change."""
        values = {member.value for member in ThreatCategory}

        assert all(value.startswith("PAIT-") for value in values - {"UNAPPROVED_FORMATS"})

    def test_a_member_can_be_sent_where_the_wire_expects_a_string(self) -> None:
        """Fields stay ``str`` to tolerate new values; passing a member must still work."""
        request = ScanCreateRequest(
            model_uri="hf://org/model",
            security_group_uuid=GROUP_UUID,
            scan_origin=ScanOrigin.MODEL_SECURITY_SDK,
        )

        assert request.model_dump()["scan_origin"] == "MODEL_SECURITY_SDK"
        assert '"scan_origin":"MODEL_SECURITY_SDK"' in request.model_dump_json()


# ---------------------------------------------------------------------------
# Wire contract
# ---------------------------------------------------------------------------


def _annotation_types(annotation: object) -> set[object]:
    """Every type mentioned anywhere in an annotation, unwrapping ``|`` and ``list[...]``."""
    found: set[object] = {annotation}
    for argument in get_args(annotation):
        found |= _annotation_types(argument)
    return found


@_wire_schema_cases
def test_declares_exactly_the_wire_fields(model: type[AirsModel], spec: str) -> None:
    """A field left out of the port parses fine and then reads back as an AttributeError."""
    assert list(model.model_fields) == [name.lstrip("!") for name in spec.split()]


@_wire_schema_cases
def test_requiredness_matches_the_wire_contract(model: type[AirsModel], spec: str) -> None:
    """Too strict rejects valid responses; too loose lets an incomplete request go out."""
    expected = {name.lstrip("!") for name in spec.split() if name.startswith("!")}
    actual = {name for name, field in model.model_fields.items() if field.is_required()}

    assert actual == expected


def _domain_enums() -> set[type[Enum]]:
    return {
        value
        for value in vars(model_security).values()
        if isinstance(value, type)
        and issubclass(value, Enum)
        and value.__module__ == model_security.__name__
    }


@pytest.mark.parametrize(
    ("enum", "spec"),
    WIRE_ENUMS,
    ids=[enum.__name__ for enum, _ in WIRE_ENUMS],
)
def test_enum_members_match_the_wire_values(enum: type[Enum], spec: str) -> None:
    """A member dropped in the port leaves callers unable to name a value the service sends."""
    assert [member.value for member in enum] == spec.split()


def test_the_enum_transcription_is_exhaustive() -> None:
    """Guards the table above: an enum added later must be pinned, not just declared."""
    assert {enum.__name__ for enum, _ in WIRE_ENUMS} == {enum.__name__ for enum in _domain_enums()}


def test_member_names_are_their_wire_values_upper_cased() -> None:
    """The whole domain follows one rule, including the two places it is easy to get wrong.

    ``SortByDateField.CREATED_AT`` is lowercase on the wire and ``ThreatCategory``'s codes
    are hyphenated, so member name and wire value are not identical strings -- but they are
    always the same identifier. Checking the relation rather than the pairs catches a typo
    in either half.
    """
    for enum in _domain_enums():
        for member in enum:
            assert member.name == member.value.upper().replace("-", "_"), enum.__name__


def test_enum_valued_fields_stay_plain_strings() -> None:
    """The domain's central call: outcomes, states, and threat codes are ``str``, not enums.

    The backend adds values without a version bump, so typing these fields as the enums
    would turn a new server-side outcome into a parse failure for every scan that carries
    it. If a future change makes one of them enum-typed, this is the test that says why
    not -- and ``test_tolerates_an_outcome_this_release_has_never_heard_of`` shows the
    behaviour being protected.
    """
    domain_enums = _domain_enums()
    enum_typed = [
        f"{model.__name__}.{name}"
        for model, _ in WIRE_SCHEMAS
        for name, field in model.model_fields.items()
        if _annotation_types(field.annotation) & domain_enums
    ]

    assert enum_typed == []


# Every ``z.number().int()`` in the domain, with a payload that is valid apart from it.
WHOLE_NUMBER_FIELDS: list[tuple[type[AirsModel], Callable[..., dict[str, object]], str]] = [
    # ``dict`` is the builder where the model needs no other field to validate.
    (ModelSecurityPagination, dict, "total_items"),
    (EvalSummary, dict, "rules_failed"),
    (EvalSummary, dict, "rules_passed"),
    (EvalSummary, dict, "total_rules"),
    (ScanDetails, _scan_details_payload, "total_files_scanned"),
    (ScanDetails, _scan_details_payload, "total_files_skipped"),
    (ScanDetails, _scan_details_payload, "model_size_bytes"),
    (ScanDetails, _scan_details_payload, "scan_duration_ms"),
    (ScanBaseResponse, _scan_payload, "enabled_rule_count_snapshot"),
    (ScanBaseResponse, _scan_payload, "total_files_scanned"),
    (ScanBaseResponse, _scan_payload, "total_files_skipped"),
    (ModelVersionResponse, _version_payload, "file_count"),
    (RuleEvaluationResponse, _evaluation_payload, "violation_count"),
]


@pytest.mark.parametrize(
    ("model", "build", "field"),
    WHOLE_NUMBER_FIELDS,
    ids=[f"{model.__name__}.{field}" for model, _, field in WHOLE_NUMBER_FIELDS],
)
def test_counts_are_whole_numbers(
    model: type[AirsModel], build: Callable[..., dict[str, object]], field: str
) -> None:
    """Every count in this domain is ``.int()`` on the wire, not a float.

    Widening one to ``float`` costs nothing at parse time and shows up much later, in a
    caller that slices, indexes, or formats with it.
    """
    assert getattr(model.model_validate(build(**{field: 7})), field) == 7

    with pytest.raises(ValidationError):
        model.model_validate(build(**{field: 2.5}))


def test_the_whole_number_coverage_is_exhaustive() -> None:
    """Guards the table above: a count added later must be checked, not just declared."""
    declared = {
        f"{model.__name__}.{name}"
        for model, _ in WIRE_SCHEMAS
        for name, field in model.model_fields.items()
        if int in _annotation_types(field.annotation)
    }

    assert declared == {f"{model.__name__}.{field}" for model, _, field in WHOLE_NUMBER_FIELDS}


def test_every_payload_with_model_prefixed_fields_relaxes_the_reserved_prefix() -> None:
    """Pydantic < 2.10 warns on every ``model_`` field, and 2.9 is this package's floor.

    Computed rather than listed, so a model that later gains a ``model_``-prefixed field
    cannot quietly start warning at import time.
    """
    carrying = {
        model
        for model, _ in WIRE_SCHEMAS
        if any(name.startswith("model_") for name in model.model_fields)
    }

    assert {model.__name__ for model in carrying} == {
        "ScanDetails",
        "ScanCreateRequest",
        "ScanBaseResponse",
        "FileResponse",
        "ModelVersionResponse",
        "ModelVersionList",
    }
    for model in carrying:
        assert model.model_config.get("protected_namespaces") == (), model.__name__


# ---------------------------------------------------------------------------
# Forward compatibility
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (ModelSecurityPagination, {"total_items": 1}),
        (Label, {"key": "env", "value": "prod"}),
        (EvalSummary, {}),
        (
            PyPIAuthResponse,
            {"url": "https://example.invalid", "expires_at": "2026-01-05T13:00:00Z"},
        ),
    ],
)
def test_unknown_fields_survive_validation(
    model: type[AirsModel], payload: dict[str, object]
) -> None:
    """The services add response fields without a version bump."""
    result = model.model_validate({**payload, "field_from_the_future": ["x"]})

    assert result.model_extra is not None
    assert result.model_extra["field_from_the_future"] == ["x"]
