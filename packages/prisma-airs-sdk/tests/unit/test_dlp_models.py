"""DLP resource models: data profiles, data patterns, dictionaries, filtering profiles."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from prisma_airs._http.transport import serialize_body
from prisma_airs.models.dlp import (
    AdvancedDataProfileRequest,
    AuditResponse,
    ComparisonOperatorType,
    DataFilteringDetails,
    DataFilteringProfileRequest,
    DataFilteringProfileResponse,
    DataPatternDetectionConfig,
    DataPatternMatchingRules,
    DataPatternPatchRequest,
    DataPatternRequest,
    DataPatternResponse,
    DataPatternStatus,
    DataPatternTechnique,
    DataPatternType,
    DataProfilePatchRequest,
    DataProfileResponse,
    DataProfileType,
    DefaultTreeDetectionRule,
    DetectionRuleItem,
    DictionaryCategory,
    DictionaryDetectionTechnique,
    DictionaryPatchRequest,
    DictionaryRequest,
    DictionaryResponse,
    ExpressionTreeNode,
    MetadataCriterion,
    MultiProfileDetectionRule,
    PageDataFilteringProfileResponse,
    PageDataPatternResponse,
    PageDataProfileResponse,
    PageDictionaryResponse,
    RuleItemDetectionTechnique,
    RuleItemOccurrenceOperatorType,
    WeightedRegex,
)


class TestPageEnvelope:
    def _payload(self, **extra: Any) -> dict[str, Any]:
        return {
            "content": [{"id": "dp-1", "name": "SSN"}],
            "empty": False,
            "first": True,
            "last": True,
            "number": 0,
            "numberOfElements": 1,
            "pageable": {"offset": 0, "pageNumber": 0, "pageSize": 20, "paged": True},
            "size": 20,
            "sort": {"empty": False, "sorted": True, "unsorted": False},
            "totalElements": 1,
            "totalPages": 1,
            **extra,
        }

    def test_maps_camel_case_wire_names_to_snake_case(self) -> None:
        page = PageDataProfileResponse.model_validate(self._payload())

        assert page.number_of_elements == 1
        assert page.total_elements == 1
        assert page.total_pages == 1
        assert page.pageable is not None
        assert (page.pageable.page_number, page.pageable.page_size) == (0, 20)

    def test_round_trips_back_to_the_wire_names(self) -> None:
        page = PageDataProfileResponse.model_validate(self._payload())

        dumped = page.model_dump(by_alias=True, exclude_none=True)

        assert dumped["totalElements"] == 1
        assert dumped["numberOfElements"] == 1
        assert dumped["pageable"]["pageSize"] == 20
        assert "total_elements" not in dumped
        assert "page_size" not in dumped["pageable"]

    def test_also_accepts_the_snake_case_attribute_names(self) -> None:
        """populate_by_name lets a caller build a page from Python-side names."""
        page = PageDataProfileResponse.model_validate(
            {"content": [], "total_elements": 7, "pageable": {"page_size": 50}}
        )

        assert page.total_elements == 7
        assert page.pageable is not None
        assert page.pageable.page_size == 50

    def test_parses_content_into_the_concrete_item_model(self) -> None:
        page = PageDictionaryResponse.model_validate(
            {"content": [{"id": "d-1", "name": "keywords", "type": "custom"}]}
        )

        assert isinstance(page.content[0], DictionaryResponse)
        assert page.content[0].name == "keywords"

    def test_rejects_a_page_without_content(self) -> None:
        with pytest.raises(ValidationError):
            PageDataPatternResponse.model_validate({"totalElements": 0})

    def test_preserves_unknown_page_metadata(self) -> None:
        page = PageDataProfileResponse.model_validate(self._payload(scrollId="abc"))

        assert page.model_extra is not None
        assert page.model_extra["scrollId"] == "abc"


class TestAuditResponse:
    def test_keeps_an_iso_timestamp_as_a_string(self) -> None:
        audit = AuditResponse.model_validate({"created_at": "2026-01-14T10:00:00Z"})

        assert audit.created_at == "2026-01-14T10:00:00Z"

    def test_accepts_a_numeric_epoch_for_the_same_field(self) -> None:
        """The service emits ISO strings on some records and epoch millis on others.

        The numeric arm lands as a ``float`` -- the spec types it as an unconstrained JSON
        number -- so callers doing arithmetic on it must not assume an ``int``.
        """
        audit = AuditResponse.model_validate({"created_at": 1768384800000})

        assert audit.created_at == 1768384800000
        assert isinstance(audit.created_at, float)

    def test_tolerates_explicit_nulls(self) -> None:
        audit = AuditResponse.model_validate(
            {"created_at": None, "created_by": None, "updated_by": "svc-account"}
        )

        assert audit.created_by is None
        assert audit.updated_by == "svc-account"


class TestTechniqueEnums:
    def test_the_three_technique_vocabularies_stay_in_sync(self) -> None:
        """They are deliberately separate enums; a new technique has to land in all three."""
        pattern = {member.value for member in DataPatternTechnique}
        rule_item = {member.value for member in RuleItemDetectionTechnique}
        dictionary = {member.value for member in DictionaryDetectionTechnique}

        assert pattern == rule_item == dictionary
        assert len(pattern) == 13

    def test_pins_the_two_confusable_comparison_vocabularies(self) -> None:
        """Occurrence operators drop the ``or`` that metadata comparison operators keep."""
        assert RuleItemOccurrenceOperatorType.LESS_THAN_EQUAL_TO.value == "less_than_equal_to"
        assert ComparisonOperatorType.LESS_THAN_OR_EQUAL_TO.value == "less_than_or_equal_to"
        assert "less_than_or_equal_to" not in {m.value for m in RuleItemOccurrenceOperatorType}

    def test_pattern_status_covers_the_tuning_states(self) -> None:
        assert DataPatternStatus.SILENT.value == "silent"
        assert {"deprecated", "silent"} <= {member.value for member in DataPatternStatus}


class TestDataPatternRequest:
    def _minimal(self, **extra: Any) -> dict[str, Any]:
        return {
            "name": "Employee ID",
            "type": "custom",
            "detection_config": {"technique": "weighted_regex"},
            **extra,
        }

    def test_parses_a_create_body(self) -> None:
        request = DataPatternRequest.model_validate(
            self._minimal(
                description="Internal employee identifiers",
                matching_rules={
                    "delimiter": ",",
                    "proximity_distance": 30,
                    "proximity_keywords": ["employee", "badge"],
                    "regexes": [{"regex": r"EMP-\d{6}", "weight": 5}],
                },
                tags={"classification": ["internal"], "compliance": ["SOC2"]},
            )
        )

        assert request.detection_config.technique is DataPatternTechnique.WEIGHTED_REGEX
        assert request.matching_rules is not None
        assert request.matching_rules.regexes is not None
        assert request.matching_rules.regexes[0].weight == 5

    def test_requires_a_detection_config(self) -> None:
        with pytest.raises(ValidationError):
            DataPatternRequest.model_validate({"name": "x", "type": "custom"})

    def test_rejects_an_unknown_technique(self) -> None:
        with pytest.raises(ValidationError):
            DataPatternRequest.model_validate(
                self._minimal(detection_config={"technique": "vibes"})
            )

    def test_rejects_an_empty_name(self) -> None:
        with pytest.raises(ValidationError):
            DataPatternRequest.model_validate(self._minimal(name=""))

    @pytest.mark.parametrize("name", ["x", "x" * 64])
    def test_accepts_a_name_at_the_bounds(self, name: str) -> None:
        """Both ends of the 1..64 rule have to validate, or the bound is off by one."""
        assert DataPatternRequest.model_validate(self._minimal(name=name)).name == name

    def test_rejects_a_name_over_the_ceiling(self) -> None:
        with pytest.raises(ValidationError):
            DataPatternRequest.model_validate(self._minimal(name="x" * 65))

    @pytest.mark.parametrize("distance", [2, 1000])
    def test_accepts_proximity_distance_at_the_bounds(self, distance: int) -> None:
        request = DataPatternRequest.model_validate(
            self._minimal(matching_rules={"proximity_distance": distance})
        )

        assert request.matching_rules is not None
        assert request.matching_rules.proximity_distance == distance

    @pytest.mark.parametrize("distance", [1, 0, 1001])
    def test_rejects_proximity_distance_outside_the_bounds(self, distance: int) -> None:
        with pytest.raises(ValidationError):
            DataPatternRequest.model_validate(
                self._minimal(matching_rules={"proximity_distance": distance})
            )

    def test_omitting_proximity_distance_skips_the_bound(self) -> None:
        request = DataPatternRequest.model_validate(
            self._minimal(matching_rules={"proximity_distance": None, "delimiter": ";"})
        )

        assert request.matching_rules is not None
        assert request.matching_rules.proximity_distance is None


class TestWeightedRegex:
    def test_rejects_an_empty_regex(self) -> None:
        with pytest.raises(ValidationError):
            WeightedRegex(regex="", weight=1)

    def test_requires_a_weight(self) -> None:
        with pytest.raises(ValidationError):
            WeightedRegex.model_validate({"regex": r"\d+"})

    def test_keeps_a_fractional_weight(self) -> None:
        """``weight`` is a plain JSON number, not an integer -- an ``int`` field would reject
        this outright, and scoring thresholds are routinely tuned in fractions."""
        assert WeightedRegex(regex=r"\d+", weight=0.25).weight == 0.25


class TestMetadataCriterion:
    def test_reads_the_camel_case_operator_key(self) -> None:
        criterion = MetadataCriterion.model_validate(
            {"comparisonOperatorType": "greater_than", "name": "size", "value": "1024"}
        )

        assert criterion.comparison_operator_type is ComparisonOperatorType.GREATER_THAN

    def test_round_trips_the_operator_key(self) -> None:
        criterion = MetadataCriterion(comparison_operator_type=ComparisonOperatorType.EQUAL_TO)

        dumped = criterion.model_dump(by_alias=True, exclude_none=True)

        assert dumped == {"comparisonOperatorType": "equal_to"}

    def test_rejects_an_unknown_operator(self) -> None:
        with pytest.raises(ValidationError):
            MetadataCriterion.model_validate({"comparisonOperatorType": "roughly_equal_to"})


class TestDataPatternResponse:
    def test_parses_a_full_payload(self) -> None:
        response = DataPatternResponse.model_validate(
            {
                "id": "dp-9f2c",
                "name": "US Social Security Number",
                "description": "Predefined SSN detector",
                "tenant_id": "1234567890",
                "type": "predefined",
                "status": "active",
                "license_type": "enterprise",
                "is_parent_managed": True,
                "version": 4,
                "detection_config": {
                    "technique": "regex",
                    "supported_confidence_levels": ["low", "high"],
                },
                "matching_rules": {
                    "delimiter": None,
                    "proximity_distance": 50,
                    "proximity_keywords": ["ssn", "social security"],
                    "regexes": [{"regex": r"\d{3}-\d{2}-\d{4}", "weight": 10}],
                    "metadata_criteria": [
                        {
                            "comparisonOperatorType": "less_than",
                            "name": "file_size",
                            "type": "number",
                            "value": "5000000",
                        }
                    ],
                },
                "tags": {"classification": ["pii"], "compliance": ["PCI"], "geography": ["US"]},
                "audit_metadata": {
                    "created_at": "2026-01-14T10:00:00Z",
                    "created_by": "system",
                    "updated_at": "2026-02-02T08:30:00Z",
                    "updated_by": "scott@example.com",
                },
            }
        )

        assert response.status is DataPatternStatus.ACTIVE
        assert response.matching_rules is not None
        assert response.matching_rules.metadata_criteria is not None
        criterion = response.matching_rules.metadata_criteria[0]
        assert criterion.comparison_operator_type is ComparisonOperatorType.LESS_THAN
        assert response.audit_metadata is not None
        assert response.audit_metadata.updated_by == "scott@example.com"

    def test_tolerates_the_nulls_the_service_sends_for_unset_fields(self) -> None:
        response = DataPatternResponse.model_validate(
            {"id": "dp-1", "description": None, "tags": None, "matching_rules": None}
        )

        assert response.tags is None
        assert response.id == "dp-1"

    def test_preserves_unknown_fields(self) -> None:
        response = DataPatternResponse.model_validate({"id": "dp-1", "risk_score": 42})

        assert response.model_extra is not None
        assert response.model_extra["risk_score"] == 42

    def test_preserves_unknown_fields_on_nested_models(self) -> None:
        response = DataPatternResponse.model_validate(
            {"detection_config": {"technique": "ml", "model_version": "2026-01"}}
        )

        assert response.detection_config is not None
        assert response.detection_config.model_extra is not None
        assert response.detection_config.model_extra["model_version"] == "2026-01"


class TestDetectionRuleUnion:
    def test_resolves_the_expression_tree_variant(self) -> None:
        request = AdvancedDataProfileRequest.model_validate(
            {
                "name": "PII",
                "detection_rules": [
                    {
                        "rule_type": "expression_tree",
                        "expression_tree": {
                            "operator_type": "or",
                            "sub_expressions": [
                                {"rule_item": {"detection_technique": "regex", "id": "dp-1"}}
                            ],
                        },
                    }
                ],
            }
        )

        rule = request.detection_rules[0]
        assert isinstance(rule, DefaultTreeDetectionRule)
        assert rule.expression_tree is not None
        assert rule.expression_tree.sub_expressions is not None

    def test_resolves_the_multi_profile_variant(self) -> None:
        request = AdvancedDataProfileRequest.model_validate(
            {
                "name": "Combined",
                "detection_rules": [
                    {
                        "rule_type": "multi_profile",
                        "multi_profile": {"data_profile_ids": [11, 12], "operator_type": "and"},
                    }
                ],
            }
        )

        rule = request.detection_rules[0]
        assert isinstance(rule, MultiProfileDetectionRule)
        assert rule.multi_profile is not None
        assert rule.multi_profile.data_profile_ids == [11, 12]

    def test_rejects_an_unknown_rule_type(self) -> None:
        with pytest.raises(ValidationError, match="rule_type"):
            AdvancedDataProfileRequest.model_validate(
                {"name": "x", "detection_rules": [{"rule_type": "regex_tree"}]}
            )

    def test_rejects_a_rule_missing_its_discriminator(self) -> None:
        with pytest.raises(ValidationError, match="rule_type"):
            AdvancedDataProfileRequest.model_validate(
                {"name": "x", "detection_rules": [{"expression_tree": {"operator_type": "and"}}]}
            )

    def test_does_not_default_the_discriminator(self) -> None:
        """A default would let exclude_unset drop the tag out of a merge-patch body."""
        with pytest.raises(ValidationError):
            DefaultTreeDetectionRule.model_validate({"expression_tree": None})

    def test_keeps_int64_profile_ids_exact(self) -> None:
        """Typing these as float would round an id past 2^53 to a different id."""
        big = 9007199254740993

        rule = MultiProfileDetectionRule.model_validate(
            {"rule_type": "multi_profile", "multi_profile": {"data_profile_ids": [big]}}
        )

        assert rule.multi_profile is not None
        assert rule.multi_profile.data_profile_ids == [big]


class TestExpressionTree:
    def test_recurses_through_nested_sub_expressions(self) -> None:
        node = ExpressionTreeNode.model_validate(
            {
                "operator_type": "and",
                "sub_expressions": [
                    {
                        "operator_type": "or",
                        "sub_expressions": [
                            {"rule_item": {"detection_technique": "dictionary", "score": 7}}
                        ],
                    }
                ],
            }
        )

        assert node.sub_expressions is not None
        inner = node.sub_expressions[0]
        assert isinstance(inner, ExpressionTreeNode)
        assert inner.sub_expressions is not None
        leaf = inner.sub_expressions[0].rule_item
        assert leaf is not None
        assert leaf.score == 7

    def test_rejects_an_unknown_operator(self) -> None:
        with pytest.raises(ValidationError):
            ExpressionTreeNode.model_validate({"operator_type": "xor"})

    def test_allows_a_node_with_neither_branch_nor_leaf(self) -> None:
        """The service does not enforce the branch/leaf split, so neither can be required."""
        node = ExpressionTreeNode()

        assert (node.operator_type, node.rule_item, node.sub_expressions) == (None, None, None)
        # An untouched node claims nothing: it must not serialise into a merge patch as a
        # triple-null that would wipe the operator and children already on the server.
        assert node.model_dump(exclude_unset=True) == {}


class TestDetectionRuleItem:
    def test_requires_a_detection_technique(self) -> None:
        with pytest.raises(ValidationError):
            DetectionRuleItem.model_validate({"id": "dp-1", "name": "SSN"})

    def test_accepts_edm_and_occurrence_fields_on_the_same_flat_object(self) -> None:
        item = DetectionRuleItem.model_validate(
            {
                "detection_technique": "edm",
                "edm_dataset_id": "ds-1",
                "primary_fields": ["ssn"],
                "primary_match_criteria": "all",
                "primary_match_any_count": 2,
                "occurrence_operator_type": "between",
                "occurrence_low": 1,
                "occurrence_high": 5,
            }
        )

        assert item.detection_technique is RuleItemDetectionTechnique.EDM
        assert item.occurrence_operator_type is RuleItemOccurrenceOperatorType.BETWEEN
        assert item.primary_match_any_count == 2


class TestDataProfileResponse:
    def test_parses_a_full_payload(self) -> None:
        response = DataProfileResponse.model_validate(
            {
                "id": "42",
                "name": "Customer PII",
                "description": "SSN or credit card, excluding test data",
                "tenant_id": "1234567890",
                "type": "custom",
                "profile_status": "active",
                "profile_type": "basic",
                "is_granular_data_profile": False,
                "is_parent_managed": False,
                "version": 3,
                "advance_data_patterns_rule_request": [],
                "detection_rules": [
                    {
                        "rule_type": "expression_tree",
                        "expression_tree": {
                            "operator_type": "and_not",
                            "sub_expressions": [
                                {
                                    "rule_item": {
                                        "detection_technique": "regex",
                                        "id": "dp-ssn",
                                        "name": "SSN",
                                        "version": 4,
                                        "match_type": "include",
                                        "confidence_level": "high",
                                        "supported_confidence_levels": ["low", "medium", "high"],
                                        "occurrence_operator_type": "more_than_equal_to",
                                        "occurrence_count": 2,
                                    }
                                },
                                {
                                    "rule_item": {
                                        "detection_technique": "dictionary",
                                        "id": "d-test",
                                        "match_type": "exclude",
                                        "score": 20,
                                    }
                                },
                            ],
                        },
                    }
                ],
                "audit_metadata": {"created_at": 1768384800000, "created_by": "scott"},
            }
        )

        assert response.profile_type is DataProfileType.BASIC
        assert response.detection_rules is not None
        rule = response.detection_rules[0]
        assert isinstance(rule, DefaultTreeDetectionRule)
        assert rule.expression_tree is not None
        assert rule.expression_tree.sub_expressions is not None
        leaves = [node.rule_item for node in rule.expression_tree.sub_expressions]
        assert [leaf.match_type for leaf in leaves if leaf is not None] == ["include", "exclude"]

    def test_rejects_an_unknown_profile_status(self) -> None:
        with pytest.raises(ValidationError):
            DataProfileResponse.model_validate({"profile_status": "archived"})

    def test_preserves_unknown_fields(self) -> None:
        response = DataProfileResponse.model_validate({"id": "42", "shadow_mode": True})

        assert response.model_extra is not None
        assert response.model_extra["shadow_mode"] is True


class TestAdvancedDataProfileRequest:
    def test_rejects_an_empty_name(self) -> None:
        with pytest.raises(ValidationError):
            AdvancedDataProfileRequest.model_validate({"name": "", "detection_rules": []})

    def test_rejects_a_name_over_the_ceiling(self) -> None:
        with pytest.raises(ValidationError):
            AdvancedDataProfileRequest.model_validate({"name": "x" * 65, "detection_rules": []})

    @pytest.mark.parametrize("name", ["x", "x" * 64])
    def test_accepts_a_name_at_the_bounds(self, name: str) -> None:
        """Profiles carry the same 1..64 rule as patterns; both ends have to validate."""
        request = AdvancedDataProfileRequest.model_validate({"name": name, "detection_rules": []})

        assert request.name == name

    def test_requires_detection_rules_to_be_present(self) -> None:
        with pytest.raises(ValidationError):
            AdvancedDataProfileRequest.model_validate({"name": "PII"})

    def test_accepts_an_empty_rule_list(self) -> None:
        """The spec sets no minimum, so an empty list must survive as an empty list.

        Distinct from omitting the key, which is the error above: sending ``[]`` is how a
        caller clears every rule on a profile, and a min-items bound would block that.
        """
        request = AdvancedDataProfileRequest(name="PII", detection_rules=[])

        assert request.detection_rules == []
        assert request.model_dump(exclude_unset=True)["detection_rules"] == []


class TestMergePatchSerialisation:
    def _pattern_patch(self, **extra: Any) -> DataPatternPatchRequest:
        return DataPatternPatchRequest(
            name="Employee ID",
            type=DataPatternType.CUSTOM,
            detection_config=DataPatternDetectionConfig(technique=DataPatternTechnique.REGEX),
            **extra,
        )

    def test_omits_fields_the_caller_never_touched(self) -> None:
        body = self._pattern_patch().merge_patch_dump()

        assert "description" not in body
        assert "tags" not in body
        assert body["name"] == "Employee ID"

    def test_keeps_an_explicit_null_so_the_field_gets_cleared(self) -> None:
        body = self._pattern_patch(description=None).merge_patch_dump()

        assert "description" in body
        assert body["description"] is None

    def test_a_plain_dump_would_clear_everything(self) -> None:
        """This contrast is why merge_patch_dump exists at all."""
        patch = self._pattern_patch()

        assert patch.model_dump()["description"] is None
        assert "description" not in patch.merge_patch_dump()

    def test_handing_the_model_to_the_transport_would_drop_the_clearing_null(self) -> None:
        """Why the caller must send the dict, not the model.

        ``serialize_body`` dumps a model with ``exclude_none=True``, which strips exactly the
        ``null`` that tells the service to clear a field -- silently turning "clear the
        description" into a no-op. The dict from ``merge_patch_dump`` bypasses that path.
        """
        patch = self._pattern_patch(description=None)

        assert "description" not in json.loads(serialize_body(patch))
        assert json.loads(serialize_body(patch.merge_patch_dump()))["description"] is None

    def test_a_nested_object_carries_only_the_keys_the_caller_set(self) -> None:
        """exclude_unset recurses, so a partial nested object must not null its own siblings."""
        body = self._pattern_patch(
            matching_rules=DataPatternMatchingRules(proximity_distance=10)
        ).merge_patch_dump()

        assert body["matching_rules"] == {"proximity_distance": 10}
        assert body["detection_config"] == {"technique": "regex"}
        # Nested enums have to reach the wire as values too, not just top-level ones.
        assert type(body["detection_config"]["technique"]) is str

    def test_the_patch_body_keeps_the_same_name_bounds_as_the_create_body(self) -> None:
        """A patch is not a way around the 1..64 rule the create body enforces."""
        with pytest.raises(ValidationError):
            DataPatternPatchRequest.model_validate(
                {"name": "x" * 65, "type": "custom", "detection_config": {"technique": "regex"}}
            )

    def test_replaces_a_field_when_a_value_is_given(self) -> None:
        patch = DictionaryPatchRequest(
            category=DictionaryCategory.FINANCIAL,
            name="card-terms",
            original_file_name="card-terms.txt",
            is_case_sensitive=True,
        )

        body = patch.merge_patch_dump()

        assert body["is_case_sensitive"] is True
        assert "region_name" not in body
        # The enum has to reach the wire as its value, not as a member.
        assert type(body["category"]) is str
        assert body["category"] == "Financial"

    def test_keeps_the_discriminator_on_nested_rules(self) -> None:
        """exclude_unset reaches into nested models; an untagged rule is a 400 upstream."""
        patch = DataProfilePatchRequest.model_validate(
            {
                "name": "Customer PII",
                "profile_type": "advanced",
                "detection_rules": [
                    {"rule_type": "multi_profile", "multi_profile": {"data_profile_ids": [11]}}
                ],
            }
        )

        body = patch.merge_patch_dump()

        assert body["detection_rules"][0]["rule_type"] == "multi_profile"
        assert "description" not in body

    def test_still_enforces_the_fields_that_cannot_be_cleared(self) -> None:
        with pytest.raises(ValidationError):
            DataProfilePatchRequest.model_validate({"name": "Customer PII"})

        with pytest.raises(ValidationError):
            DictionaryPatchRequest.model_validate(
                {"category": "Legal", "original_file_name": "terms.txt"}
            )


class TestDictionary:
    def test_source_code_category_keeps_its_literal_space(self) -> None:
        assert DictionaryCategory.SOURCE_CODE.value == "Source Code"

    def test_rejects_a_normalised_category_spelling(self) -> None:
        with pytest.raises(ValidationError):
            DictionaryRequest.model_validate(
                {
                    "category": "source_code",
                    "name": "repo-terms",
                    "original_file_name": "repo.txt",
                    "region_name": "us-east-1",
                }
            )

    def test_requires_the_uploaded_file_name(self) -> None:
        with pytest.raises(ValidationError):
            DictionaryRequest.model_validate(
                {"category": "Legal", "name": "terms", "region_name": "us-east-1"}
            )

    def test_parses_a_full_response(self) -> None:
        response = DictionaryResponse.model_validate(
            {
                "id": "d-77",
                "name": "internal-project-names",
                "description": "Codenames that must not leave the tenant",
                "category": "Confidential",
                "region_name": "us-east-1",
                "type": "custom",
                "is_case_sensitive": False,
                "is_parent_managed": False,
                "detection_technique": "dictionary",
                "detection_sub_technique": "threshold",
                "dictionary_metadata": {
                    "number_of_keywords": 412,
                    "original_file_name": "codenames.txt",
                    "original_file_size_in_byte": 8192,
                },
                "keywords": ["bluebird", "starling"],
                "tags": {"classification": ["endpoint"]},
                "attributes": [{"key": "owner", "value": "security"}],
                "audit_metadata": {"created_at": "2026-03-01T00:00:00Z", "created_by": "scott"},
            }
        )

        assert response.detection_technique is DictionaryDetectionTechnique.DICTIONARY
        assert response.dictionary_metadata is not None
        assert response.dictionary_metadata.number_of_keywords == 412
        assert response.attributes is not None
        assert response.attributes[0].key == "owner"

    def test_keywords_are_absent_unless_requested(self) -> None:
        """The list endpoint omits keywords entirely unless ``keywords=true`` is passed."""
        response = DictionaryResponse.model_validate({"id": "d-77", "name": "x"})

        assert response.keywords is None

    def test_response_category_stays_free_form(self) -> None:
        """A category the SDK has not seen must not break a list call."""
        response = DictionaryResponse.model_validate({"category": "Aerospace"})

        assert response.category == "Aerospace"

    def test_rejects_an_unknown_classification_tag(self) -> None:
        with pytest.raises(ValidationError):
            DictionaryResponse.model_validate({"tags": {"classification": ["mainframe"]}})


class TestDataFilteringProfile:
    def test_parses_a_full_response(self) -> None:
        response = DataFilteringProfileResponse.model_validate(
            {
                "id": "dfp-1",
                "name": "Default filtering",
                "tenant_id": "1234567890",
                "type": "predefined",
                "data_profile_id": 42,
                "direction": "BOTH",
                "file_based": True,
                "non_file_based": True,
                "log_severity": "HIGH",
                "scan_type": "include",
                "is_end_user_coaching_enabled": False,
                "is_granular_profile": True,
                "is_parent_managed": False,
                "euc_template_id": None,
                "version": 2,
                "file_type": ["pdf", "docx"],
                "criteria_details": [
                    {
                        "action": "block",
                        "dataProfileId": 42,
                        "direction": "UPLOAD",
                        "euc_template_id": "euc-1",
                        "fileBased": "true",
                        "fileTypes": ["pdf"],
                        "is_end_user_coaching_enabled": True,
                        "logSeverity": "CRITICAL",
                        "nonFileBased": "false",
                        "scanType": "include",
                    }
                ],
                "exception_rules": [
                    {
                        "id": "ex-1",
                        "action": "ALLOW",
                        "log_severity": "INFORMATIONAL",
                        "data_profile_ids": [42],
                        "source_attributes": {"match_any": True, "user_ids": ["u-1"]},
                        "destination_attributes": {
                            "match_any": False,
                            "app_ids": ["app-1"],
                            "url_patterns": ["*.internal.example.com"],
                        },
                    }
                ],
                "exclusions": {
                    "app_exclusion_list": [{"app_id": "a-1", "app_name": "Jira", "type": "saas"}],
                    "url_exclusion_list": [{"type": "custom", "url_id": "u-9", "url_name": "wiki"}],
                    "exclusion_list": {"keywords": ["sample", "test"], "domains": ["example.com"]},
                },
                "rule1": {"action": "alert", "response_page": "default", "show_rsp_page": "true"},
                "rule2": None,
                "audit_metadata": {"created_at": "2026-04-01T12:00:00Z", "created_by": "scott"},
            }
        )

        assert response.scan_type == "include"
        assert response.criteria_details is not None
        detail = response.criteria_details[0]
        assert detail.data_profile_id == 42
        assert detail.file_types == ["pdf"]
        assert detail.log_severity == "CRITICAL"
        assert response.exception_rules is not None
        assert response.exception_rules[0].action == "ALLOW"
        assert response.exclusions is not None
        assert response.exclusions.exclusion_list == {
            "keywords": ["sample", "test"],
            "domains": ["example.com"],
        }
        assert response.rule2 is None

    def test_criteria_detail_round_trips_its_mixed_case_keys(self) -> None:
        detail = DataFilteringDetails(
            action="block",
            data_profile_id=42,
            file_based="true",
            file_types=["pdf"],
            euc_template_id="euc-1",
        )

        dumped = detail.model_dump(by_alias=True, exclude_none=True)

        assert dumped == {
            "action": "block",
            "dataProfileId": 42,
            "fileBased": "true",
            "fileTypes": ["pdf"],
            "euc_template_id": "euc-1",
        }

    @pytest.mark.parametrize(
        ("field", "value"),
        [("direction", "SIDEWAYS"), ("log_severity", "SEVERE"), ("type", "hybrid")],
    )
    def test_response_side_fields_stay_free_form(self, field: str, value: str) -> None:
        """The request constrains these to enums; the response deliberately does not.

        The response is the side that has to survive the service adding a value, so a
        vocabulary the SDK has never seen must not break a list call.
        """
        response = DataFilteringProfileResponse.model_validate({field: value})

        assert getattr(response, field) == value

    def test_response_scan_type_is_still_constrained(self) -> None:
        """The one response field the spec does pin -- the looseness above is not blanket."""
        with pytest.raises(ValidationError):
            DataFilteringProfileResponse.model_validate({"scan_type": "everything"})

    def test_request_requires_both_content_switches(self) -> None:
        with pytest.raises(ValidationError):
            DataFilteringProfileRequest.model_validate({"file_based": True})

    def test_request_rejects_an_unknown_direction(self) -> None:
        with pytest.raises(ValidationError):
            DataFilteringProfileRequest.model_validate(
                {"file_based": True, "non_file_based": False, "direction": "SIDEWAYS"}
            )

    def test_request_rejects_an_unknown_log_severity(self) -> None:
        with pytest.raises(ValidationError):
            DataFilteringProfileRequest.model_validate(
                {"file_based": True, "non_file_based": False, "log_severity": "SEVERE"}
            )

    def test_rejects_a_scalar_where_the_exclusion_map_wants_a_list(self) -> None:
        with pytest.raises(ValidationError):
            DataFilteringProfileResponse.model_validate(
                {"exclusions": {"exclusion_list": {"keywords": "sample"}}}
            )

    def test_keeps_an_int64_data_profile_id_exact(self) -> None:
        big = 9007199254740993

        response = DataFilteringProfileResponse.model_validate({"data_profile_id": big})

        assert response.data_profile_id == big

    def test_preserves_unknown_fields(self) -> None:
        response = DataFilteringProfileResponse.model_validate(
            {"id": "dfp-1", "new_toggle": "enabled"}
        )

        assert response.model_extra is not None
        assert response.model_extra["new_toggle"] == "enabled"

    def test_page_parses_content_into_profiles(self) -> None:
        page = PageDataFilteringProfileResponse.model_validate(
            {"content": [{"id": "dfp-1", "scan_type": "exclude"}], "totalElements": 1}
        )

        assert isinstance(page.content[0], DataFilteringProfileResponse)
        assert page.content[0].scan_type == "exclude"
