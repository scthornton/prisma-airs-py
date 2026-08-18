"""Management API request and response models."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from prisma_airs.models.management import (
    AiSecurityProfile,
    ApiKey,
    ApiKeyCreateRequest,
    ApiKeyDeleteResponse,
    ApiKeyListResponse,
    ApiKeyRegenerateRequest,
    ClientIdAndCustomerApp,
    CreateCustomTopicRequest,
    CreateSecurityProfileRequest,
    CustomerApp,
    CustomerAppDeleteResponse,
    CustomerAppListResponse,
    CustomerAppWithKeys,
    CustomTopic,
    CustomTopicListResponse,
    DashboardApplication,
    DashboardApplicationsOverview,
    DashboardApplicationViolationBreakdown,
    DataLeakDetection,
    DataProtection,
    DeleteProfileConflict,
    DeleteProfileResponse,
    DeleteTopicConflict,
    DeleteTopicResponse,
    DeploymentProfileEntry,
    DeploymentProfilesResponse,
    DlpProfileListResponse,
    ModelConfiguration,
    Oauth2Token,
    PaginatedScanResults,
    PolicyLatency,
    SecurityProfile,
    SecurityProfileListResponse,
    TopicArray,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def unmodelled(value: object, path: str = "") -> list[str]:
    """Paths of every parsed key that no declared field claimed.

    ``extra="allow"`` makes Pydantic serve unknown keys through ``__getattr__``, so
    ``entry.ave_text_records == 100_000`` keeps passing even after that field is
    deleted from the model -- the value simply arrives from ``model_extra`` instead.
    Asserting on attributes therefore does not pin field coverage; asserting that a
    realistic payload leaves *nothing* in ``model_extra`` does, and it catches a
    mistyped alias (which drops the wire key into extras) at the same time.
    """
    found: list[str] = []
    if isinstance(value, BaseModel):
        found += [f"{path}.{key}" for key in (value.model_extra or {})]
        for name in type(value).model_fields:
            found += unmodelled(getattr(value, name), f"{path}.{name}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found += unmodelled(item, f"{path}[{index}]")
    return found


# ---------------------------------------------------------------------------
# Shared fixtures for the realistic payloads
# ---------------------------------------------------------------------------

POLICY: dict[str, Any] = {
    "ai-security-profiles": [
        {
            "model-type": "any",
            "content-type": "any",
            "model-configuration": {
                "mask-data-in-storage": True,
                "latency": {"inline-timeout-action": "allow", "max-inline-latency": 5000},
                "data-protection": {
                    "data-leak-detection": {
                        "member": [{"text": "pci-dss", "id": "17", "version": "3"}],
                        "action": "block",
                        "mask-data-inline": True,
                    },
                    "database-security": [{"name": "sql-injection", "action": "block"}],
                },
                "app-protection": {
                    "alert-url-category": {"member": ["gambling"]},
                    "block-url-category": {"member": ["malware", "phishing"]},
                    "allow-url-category": {"member": None},
                    "default-url-category": {"member": ["unknown"]},
                    "url-detected-action": "block",
                    "malicious-code-protection": {"name": "malicious-code", "action": "block"},
                },
                "model-protection": [
                    {
                        "name": "topic-guardrails",
                        "action": "block",
                        "topic-list": [
                            {
                                "action": "allow",
                                "topic": [
                                    {"topic_name": "billing", "topic_id": "t-1", "revision": 2}
                                ],
                            },
                            {"action": "block", "topic": None},
                        ],
                        "options": [],
                    }
                ],
                "agent-protection": [{"name": "agent-security", "action": "alert"}],
            },
        }
    ],
    "dlp-data-profiles": [
        {
            "name": "pci",
            "uuid": "0f2c9d1e-1111-4b8a-9c2f-aaaaaaaaaaaa",
            "id": "17",
            "version": "1",
            "description": "Payment card data",
            "rule1": {"action": "block"},
            "rule2": {"action": "alert"},
            "log-severity": "high",
            "non-file-based": "enabled",
            "file-based": "disabled",
        }
    ],
}

PROFILE: dict[str, Any] = {
    "profile_id": "b1e0f6a4-2222-4c3d-8e7f-bbbbbbbbbbbb",
    "profile_name": "prod-strict",
    "csp_id": "csp-1",
    "tsg_id": "1234567890",
    "revision": 7,
    "active": True,
    "policy": POLICY,
    "created_by": "scott@example.com",
    "updated_by": "scott@example.com",
    "last_modified_ts": "2026-05-28T12:00:00Z",
}


# ---------------------------------------------------------------------------
# DELETE responses that arrive as a bare JSON string
# ---------------------------------------------------------------------------

# Spelled out as a union rather than ``type[_MessageResponse]``: pydantic's
# dataclass_transform gives each subclass its own __init__ signature, so the shared
# private base is not a supertype of them as *type objects*.
MessageResponseClass = (
    type[DeleteProfileResponse]
    | type[DeleteTopicResponse]
    | type[CustomerAppDeleteResponse]
    | type[ApiKeyDeleteResponse]
)

MESSAGE_RESPONSES: list[MessageResponseClass] = [
    DeleteProfileResponse,
    DeleteTopicResponse,
    CustomerAppDeleteResponse,
    ApiKeyDeleteResponse,
]


class TestMessageResponseNormalization:
    @pytest.mark.parametrize("model", MESSAGE_RESPONSES)
    def test_normalizes_a_bare_string_body(self, model: MessageResponseClass) -> None:
        """A successful DELETE answers with a JSON string, not an object."""
        result = model.model_validate("successfully deleted profileId: p-1")

        assert result.message == "successfully deleted profileId: p-1"

    @pytest.mark.parametrize("model", MESSAGE_RESPONSES)
    def test_passes_an_object_body_through_untouched(self, model: MessageResponseClass) -> None:
        assert model.model_validate({"message": "gone"}).message == "gone"

    @pytest.mark.parametrize("model", MESSAGE_RESPONSES)
    @pytest.mark.parametrize("body", [123, ["gone"], None, True])
    def test_rejects_bodies_that_are_neither_string_nor_object(
        self, model: MessageResponseClass, body: object
    ) -> None:
        with pytest.raises(ValidationError):
            model.model_validate(body)

    def test_normalizes_an_empty_string_rather_than_dropping_it(self) -> None:
        assert DeleteProfileResponse.model_validate("").message == ""

    @pytest.mark.parametrize(
        "model", [DeleteProfileResponse, DeleteTopicResponse, CustomerAppDeleteResponse]
    )
    def test_requires_a_message_on_the_object_form(self, model: MessageResponseClass) -> None:
        with pytest.raises(ValidationError, match="message"):
            model.model_validate({"deleted": True})

    def test_api_key_delete_alone_tolerates_a_missing_message(self) -> None:
        """Only the API key delete marks ``message`` optional; the other three require it."""
        assert ApiKeyDeleteResponse.model_validate({}).message is None

    def test_preserves_unknown_keys_on_the_object_form(self) -> None:
        result = DeleteTopicResponse.model_validate({"message": "gone", "deleted_at": "2026-05-28"})

        assert result.model_extra == {"deleted_at": "2026-05-28"}


# ---------------------------------------------------------------------------
# Security profile policy
# ---------------------------------------------------------------------------


class TestPolicyAliases:
    def test_reads_kebab_case_wire_names(self) -> None:
        latency = PolicyLatency.model_validate(
            {"inline-timeout-action": "block", "max-inline-latency": 2500}
        )

        assert latency.inline_timeout_action == "block"
        assert latency.max_inline_latency == 2500

    def test_also_accepts_the_snake_case_attribute_name(self) -> None:
        """populate_by_name lets callers build requests without knowing the wire spelling."""
        latency = PolicyLatency(inline_timeout_action="allow", max_inline_latency=100)

        # Without populate_by_name the kwarg would be swallowed as an extra and the
        # field would read back as None, so the extras check is what proves the point.
        assert latency.model_extra == {}
        assert latency.inline_timeout_action == "allow"

    def test_round_trips_back_to_the_wire_names(self) -> None:
        latency = PolicyLatency(inline_timeout_action="allow", max_inline_latency=100)

        assert latency.model_dump(by_alias=True, exclude_none=True) == {
            "inline-timeout-action": "allow",
            "max-inline-latency": 100.0,
        }

    def test_dumps_snake_case_when_not_asked_for_aliases(self) -> None:
        """A caller who forgets ``by_alias`` gets attribute names, not wire names.

        Asserted as a whole-dict equality rather than a membership check: with
        ``extra="allow"`` a key that never reached its field is still dumped from
        ``model_extra``, so ``"inline_timeout_action" in dump`` holds either way.
        """
        latency = PolicyLatency.model_validate({"inline-timeout-action": "allow"})

        assert latency.model_dump(exclude_none=True) == {"inline_timeout_action": "allow"}

    def test_model_configuration_round_trips_every_kebab_key(self) -> None:
        raw = POLICY["ai-security-profiles"][0]["model-configuration"]
        config = ModelConfiguration.model_validate(raw)

        # The extras check is load-bearing: with extra="allow" a wrong alias leaves the
        # real wire key in model_extra, which model_dump re-emits, so the key set alone
        # looks identical whether or not the alias is right.
        assert unmodelled(config) == []
        assert set(config.model_dump(by_alias=True, exclude_none=True)) == {
            "mask-data-in-storage",
            "latency",
            "data-protection",
            "app-protection",
            "model-protection",
            "agent-protection",
        }

    def test_ai_security_profile_keeps_model_prefixed_fields(self) -> None:
        """``model-type``/``model-configuration`` collide with Pydantic's protected prefix."""
        profile = AiSecurityProfile.model_validate({"model-type": "any", "content-type": "text"})

        assert (profile.model_type, profile.content_type) == ("any", "text")


class TestTopicArray:
    def test_accepts_a_null_topic_bucket(self) -> None:
        """An empty bucket serialises as ``"topic": null``, not ``[]``."""
        assert TopicArray.model_validate({"action": "block", "topic": None}).topic is None

    def test_requires_the_topic_key_to_be_present(self) -> None:
        with pytest.raises(ValidationError, match="topic"):
            TopicArray.model_validate({"action": "block"})

    def test_parses_topic_references(self) -> None:
        bucket = TopicArray.model_validate(
            {"action": "allow", "topic": [{"topic_name": "b", "topic_id": "t", "revision": 4}]}
        )

        assert bucket.topic is not None
        assert (bucket.topic[0].topic_name, bucket.topic[0].topic_id) == ("b", "t")
        assert bucket.topic[0].revision == 4
        assert unmodelled(bucket) == []


class TestDataProtection:
    def test_accepts_a_null_data_leak_detection_member(self) -> None:
        """The spec marks ``member`` required, but live profiles return null."""
        detection = DataLeakDetection.model_validate({"member": None, "action": "alert"})

        assert detection.member is None

    def test_still_requires_the_detection_action(self) -> None:
        with pytest.raises(ValidationError, match="action"):
            DataLeakDetection.model_validate({"member": None})

    def test_keeps_database_security_absent_from_the_spec(self) -> None:
        protection = DataProtection.model_validate(
            {"database-security": [{"name": "sqli", "action": "block"}]}
        )

        assert protection.database_security is not None
        assert protection.database_security[0].name == "sqli"


class TestSecurityProfile:
    def test_parses_a_full_profile(self) -> None:
        profile = SecurityProfile.model_validate(PROFILE)

        assert profile.policy is not None
        assert profile.policy.ai_security_profiles is not None
        config = profile.policy.ai_security_profiles[0].model_configuration
        assert config is not None
        assert config.mask_data_in_storage is True
        assert config.data_protection is not None
        assert config.data_protection.data_leak_detection is not None
        assert config.data_protection.data_leak_detection.member is not None
        assert config.data_protection.data_leak_detection.member[0].text == "pci-dss"
        assert config.data_protection.data_leak_detection.mask_data_inline is True
        assert config.model_protection is not None
        assert config.model_protection[0].topic_list is not None
        assert [b.action for b in config.model_protection[0].topic_list] == ["allow", "block"]
        assert config.agent_protection is not None
        assert config.agent_protection[0].name == "agent-security"

    def test_every_key_of_a_full_profile_lands_on_a_declared_field(self) -> None:
        """No part of a live policy may fall through to ``model_extra``.

        A kebab-case alias that does not match the wire spelling still "works" under
        attribute access, so this is the assertion that actually pins them.
        """
        assert unmodelled(SecurityProfile.model_validate(PROFILE)) == []

    def test_parses_every_app_protection_bucket(self) -> None:
        profile = SecurityProfile.model_validate(PROFILE)

        assert profile.policy is not None
        assert profile.policy.ai_security_profiles is not None
        config = profile.policy.ai_security_profiles[0].model_configuration
        assert config is not None
        app = config.app_protection
        assert app is not None
        assert app.alert_url_category is not None
        assert app.alert_url_category.member == ["gambling"]
        assert app.block_url_category is not None
        assert app.block_url_category.member == ["malware", "phishing"]
        assert app.default_url_category is not None
        assert app.default_url_category.member == ["unknown"]
        assert app.url_detected_action == "block"
        assert app.malicious_code_protection is not None
        assert app.malicious_code_protection.action == "block"

    def test_a_url_category_bucket_may_carry_a_null_member_list(self) -> None:
        """Empty allow-lists arrive as ``{"member": null}``, not ``{"member": []}``."""
        profile = SecurityProfile.model_validate(PROFILE)

        assert profile.policy is not None
        assert profile.policy.ai_security_profiles is not None
        config = profile.policy.ai_security_profiles[0].model_configuration
        assert config is not None
        assert config.app_protection is not None
        assert config.app_protection.allow_url_category is not None
        assert config.app_protection.allow_url_category.member is None

    def test_parses_the_embedded_dlp_profiles(self) -> None:
        profile = SecurityProfile.model_validate(PROFILE)

        assert profile.policy is not None
        assert profile.policy.dlp_data_profiles is not None
        dlp = profile.policy.dlp_data_profiles[0]
        assert dlp.log_severity == "high"
        assert dlp.non_file_based == "enabled"
        assert dlp.file_based == "disabled"
        assert dlp.description == "Payment card data"
        assert unmodelled(dlp) == []
        assert dlp.rule1 is not None
        assert dlp.rule1.action == "block"
        assert dlp.rule2 is not None
        assert dlp.rule2.action == "alert"

    def test_requires_a_profile_name(self) -> None:
        with pytest.raises(ValidationError, match="profile_name"):
            SecurityProfile.model_validate({"profile_id": "p-1"})

    def test_a_name_alone_is_enough(self) -> None:
        """The scan API resolves profiles by name, so an ID-less profile is still usable."""
        assert SecurityProfile(profile_name="prod").profile_id is None

    def test_preserves_unknown_fields_deep_in_the_policy(self) -> None:
        payload = {
            "profile_name": "prod",
            "policy": {
                "ai-security-profiles": [{"model-type": "any", "brand-new-guardrail": {"on": True}}]
            },
        }

        profile = SecurityProfile.model_validate(payload)

        assert profile.policy is not None
        assert profile.policy.ai_security_profiles is not None
        assert profile.policy.ai_security_profiles[0].model_extra == {
            "brand-new-guardrail": {"on": True}
        }


class TestCreateSecurityProfileRequest:
    def test_takes_the_whole_resource_back_on_update(self) -> None:
        """The update endpoint wants the full resource, server-assigned fields included."""
        request = CreateSecurityProfileRequest.model_validate(PROFILE)

        assert unmodelled(request) == []
        assert request.revision == 7
        assert request.profile_id == PROFILE["profile_id"]

    def test_requires_a_profile_name(self) -> None:
        with pytest.raises(ValidationError, match="profile_name"):
            CreateSecurityProfileRequest.model_validate({"profile_id": "p-1"})

    def test_round_trips_a_read_profile_byte_for_byte(self) -> None:
        """A profile read from the API must be sendable back unchanged.

        ``exclude_unset`` rather than ``exclude_none``: see
        :meth:`test_exclude_none_corrupts_a_policy_on_the_way_back_out`.
        """
        request = CreateSecurityProfileRequest.model_validate(PROFILE)

        assert request.model_dump(by_alias=True, exclude_unset=True) == PROFILE

    def test_exclude_none_corrupts_a_policy_on_the_way_back_out(self) -> None:
        """``exclude_none=True`` is the wrong dump mode for an update body.

        ``TopicArray.topic`` is required-but-nullable and an empty URL-category bucket
        is ``{"member": null}``; ``exclude_none`` erases both, turning "explicitly
        empty" into "absent" and dropping a key the server requires. Pinned as a test
        because the mistake produces a body that still looks plausible.
        """
        request = CreateSecurityProfileRequest.model_validate(PROFILE)

        lossy = request.model_dump(by_alias=True, exclude_none=True)["policy"]
        config = lossy["ai-security-profiles"][0]["model-configuration"]

        assert config["app-protection"]["allow-url-category"] == {}
        assert "topic" not in config["model-protection"][0]["topic-list"][1]
        assert lossy != POLICY


class TestSecurityProfileListResponse:
    def test_parses_a_page(self) -> None:
        page = SecurityProfileListResponse.model_validate(
            {"ai_profiles": [PROFILE], "next_offset": 25}
        )

        assert page.next_offset == 25
        assert page.ai_profiles[0].profile_name == "prod-strict"

    def test_a_final_page_omits_the_offset(self) -> None:
        """Absence of ``next_offset`` is the only end-of-pagination signal."""
        assert SecurityProfileListResponse(ai_profiles=[]).next_offset is None

    def test_requires_the_profile_array(self) -> None:
        with pytest.raises(ValidationError, match="ai_profiles"):
            SecurityProfileListResponse.model_validate({"next_offset": 25})


class TestDeleteProfileConflict:
    def test_names_the_policies_blocking_deletion(self) -> None:
        conflict = DeleteProfileConflict.model_validate(
            {
                "message": "profile in use",
                "payload": [
                    {"policy_id": "pol-1", "policy_name": "egress", "priority": 1},
                    {"policy_id": "pol-2", "policy_name": "ingress", "priority": 2},
                ],
            }
        )

        assert unmodelled(conflict) == []
        assert conflict.message == "profile in use"
        assert [p.policy_name for p in conflict.payload] == ["egress", "ingress"]
        assert [p.policy_id for p in conflict.payload] == ["pol-1", "pol-2"]
        assert [p.priority for p in conflict.payload] == [1, 2]

    def test_requires_the_payload(self) -> None:
        with pytest.raises(ValidationError, match="payload"):
            DeleteProfileConflict.model_validate({"message": "profile in use"})


# ---------------------------------------------------------------------------
# Custom topics
# ---------------------------------------------------------------------------


TOPIC: dict[str, Any] = {
    "topic_id": "t-9",
    "topic_name": "billing-disputes",
    "revision": 3,
    "active": True,
    "description": "Questions about invoices and refunds",
    "examples": ["why was I charged twice", "refund my invoice"],
    "created_by": "scott@example.com",
    "created_ts": "2026-05-01T00:00:00Z",
}


class TestCustomTopic:
    def test_parses_a_full_topic(self) -> None:
        topic = CustomTopic.model_validate(TOPIC)

        assert unmodelled(topic) == []
        assert topic.revision == 3
        assert topic.examples == ["why was I charged twice", "refund my invoice"]
        assert topic.description == "Questions about invoices and refunds"

    @pytest.mark.parametrize("missing", ["description", "examples", "revision", "topic_name"])
    def test_requires_the_fields_the_classifier_needs(self, missing: str) -> None:
        payload = {k: v for k, v in TOPIC.items() if k != missing}

        with pytest.raises(ValidationError, match=missing):
            CustomTopic.model_validate(payload)

    def test_rejects_a_non_numeric_revision(self) -> None:
        with pytest.raises(ValidationError, match="revision"):
            CustomTopic.model_validate({**TOPIC, "revision": "latest"})

    def test_the_create_request_needs_only_a_name(self) -> None:
        """The server fills in revision and audit fields, so creates may be sparse."""
        request = CreateCustomTopicRequest(topic_name="billing-disputes")

        assert (request.description, request.examples, request.revision) == (None, None, None)

    def test_the_create_request_still_needs_a_name(self) -> None:
        with pytest.raises(ValidationError, match="topic_name"):
            CreateCustomTopicRequest.model_validate({"description": "no name"})

    def test_parses_a_page_of_topics(self) -> None:
        page = CustomTopicListResponse.model_validate({"custom_topics": [TOPIC], "next_offset": 10})

        assert page.custom_topics[0].topic_name == "billing-disputes"
        assert page.next_offset == 10

    def test_requires_the_topic_array(self) -> None:
        with pytest.raises(ValidationError, match="custom_topics"):
            CustomTopicListResponse.model_validate({"next_offset": 10})


class TestDeleteTopicConflict:
    def test_names_the_profiles_blocking_deletion(self) -> None:
        conflict = DeleteTopicConflict.model_validate(
            {
                "message": "topic in use",
                "payload": [{"profile_id": "p-1", "profile_name": "prod", "revision": 4}],
            }
        )

        assert unmodelled(conflict) == []
        assert conflict.message == "topic in use"
        assert conflict.payload[0].profile_id == "p-1"
        assert conflict.payload[0].profile_name == "prod"
        assert conflict.payload[0].revision == 4


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


KEY: dict[str, Any] = {
    "api_key_id": "k-1",
    "api_key_last8": "a1b2c3d4",
    "api_key_name": "prod-scanner",
    "auth_code": "I9XXXXXX",
    "csp_id": "csp-1",
    "tsg_id": "1234567890",
    "expiration": "2027-01-01T00:00:00Z",
    "revoked": False,
    "rotation_time_interval": 90,
    "rotation_time_unit": "days",
    "dp_name": "airs-dp",
    "status": "active",
    "avg_text_records": 12500,
    "creation_ts": "2026-01-01T00:00:00Z",
    "customer_appId": "8f1c2d33-3333-4a5b-9c6d-cccccccccccc",
}


class TestApiKey:
    def test_parses_a_full_key_record(self) -> None:
        key = ApiKey.model_validate(KEY)

        assert unmodelled(key) == []
        assert key.api_key_last8 == "a1b2c3d4"
        assert key.revoked is False
        assert key.rotation_time_interval == 90
        assert key.avg_text_records == 12500

    def test_maps_the_mixed_case_customer_app_id(self) -> None:
        assert ApiKey.model_validate(KEY).customer_app_id == KEY["customer_appId"]

    def test_round_trips_the_customer_app_id_alias(self) -> None:
        key = ApiKey.model_validate(KEY)

        assert "customer_appId" in key.model_dump(by_alias=True, exclude_none=True)
        assert "customer_app_id" not in key.model_dump(by_alias=True, exclude_none=True)

    def test_omits_the_secret_on_list_responses(self) -> None:
        """List and get return only ``api_key_last8``; the secret appears on create only."""
        assert ApiKey.model_validate(KEY).api_key is None

    @pytest.mark.parametrize(
        "missing", ["api_key_id", "api_key_last8", "auth_code", "expiration", "revoked"]
    )
    def test_requires_the_identity_fields(self, missing: str) -> None:
        payload = {k: v for k, v in KEY.items() if k != missing}

        with pytest.raises(ValidationError, match=missing):
            ApiKey.model_validate(payload)

    def test_parses_a_page_of_keys(self) -> None:
        page = ApiKeyListResponse.model_validate({"api_keys": [KEY], "next_offset": 50})

        assert page.api_keys is not None
        assert page.api_keys[0].api_key_name == "prod-scanner"
        assert page.next_offset == 50

    def test_preserves_unknown_key_fields(self) -> None:
        key = ApiKey.model_validate({**KEY, "scope_tags": ["eu"]})

        assert key.model_extra == {"scope_tags": ["eu"]}


CREATE_KEY: dict[str, Any] = {
    "auth_code": "I9XXXXXX",
    "cust_app": "checkout",
    "revoked": False,
    "created_by": "scott@example.com",
    "api_key_name": "prod-scanner",
    "rotation_time_interval": 90,
    "rotation_time_unit": "days",
}


class TestApiKeyRequests:
    @pytest.mark.parametrize("missing", sorted(CREATE_KEY))
    def test_create_rejects_a_body_the_api_would_reject(self, missing: str) -> None:
        """Every one of these is required, so the SDK can refuse before the round trip."""
        payload = {k: v for k, v in CREATE_KEY.items() if k != missing}

        with pytest.raises(ValidationError, match=missing):
            ApiKeyCreateRequest.model_validate(payload)

    def test_create_accepts_a_minimal_body(self) -> None:
        request = ApiKeyCreateRequest.model_validate(CREATE_KEY)

        assert unmodelled(request) == []
        assert request.dp_name is None
        assert request.cust_env is None
        assert request.cust_cloud_provider is None
        assert request.cust_ai_agent_framework is None

    def test_regenerate_needs_only_the_rotation_policy(self) -> None:
        request = ApiKeyRegenerateRequest(rotation_time_interval=30, rotation_time_unit="days")

        assert request.updated_by is None

    @pytest.mark.parametrize("missing", ["rotation_time_interval", "rotation_time_unit"])
    def test_regenerate_requires_the_whole_rotation_policy(self, missing: str) -> None:
        payload = {"rotation_time_interval": 30, "rotation_time_unit": "days"}
        del payload[missing]

        with pytest.raises(ValidationError, match=missing):
            ApiKeyRegenerateRequest.model_validate(payload)


# ---------------------------------------------------------------------------
# Customer applications
# ---------------------------------------------------------------------------


APP: dict[str, Any] = {
    "customer_appId": "8f1c2d33-3333-4a5b-9c6d-cccccccccccc",
    "tsg_id": "1234567890",
    "app_name": "checkout-assistant",
    "model_name": "gpt-4o",
    "cloud_provider": "aws",
    "environment": "production",
    "ai_agent_framework": "langchain",
}


class TestCustomerApp:
    def test_parses_an_app_with_its_keys(self) -> None:
        app = CustomerAppWithKeys.model_validate(
            {
                **APP,
                "api_keys_dp_info": [
                    {"api_key_name": "prod-scanner", "dp_name": "airs-dp", "auth_code": "I9XXXXXX"}
                ],
            }
        )

        assert unmodelled(app) == []
        assert app.customer_app_id.startswith("8f1c2d33")
        assert app.api_keys_dp_info is not None
        assert app.api_keys_dp_info[0].dp_name == "airs-dp"
        assert app.api_keys_dp_info[0].api_key_name == "prod-scanner"
        assert app.api_keys_dp_info[0].auth_code == "I9XXXXXX"

    def test_the_list_shape_requires_an_id(self) -> None:
        """The list endpoint only returns persisted apps, which always carry an ID."""
        payload = {k: v for k, v in APP.items() if k != "customer_appId"}

        with pytest.raises(ValidationError, match="customer_app"):
            CustomerAppWithKeys.model_validate(payload)

    def test_the_bare_shape_does_not_require_an_id(self) -> None:
        payload = {k: v for k, v in APP.items() if k != "customer_appId"}

        assert CustomerApp.model_validate(payload).customer_app_id is None

    def test_keeps_the_model_name_field(self) -> None:
        """``model_name`` collides with Pydantic's protected ``model_`` namespace."""
        app = CustomerApp.model_validate(APP)

        assert "model_name" in CustomerApp.model_fields
        assert app.model_extra == {}
        assert app.model_name == "gpt-4o"

    def test_maps_the_mixed_case_customer_app_id_on_the_bare_shape(self) -> None:
        app = CustomerApp.model_validate(APP)

        assert unmodelled(app) == []
        assert app.customer_app_id == APP["customer_appId"]
        assert (
            app.model_dump(by_alias=True, exclude_none=True)["customer_appId"]
            == (APP["customer_appId"])
        )

    @pytest.mark.parametrize("missing", ["tsg_id", "app_name", "cloud_provider", "environment"])
    def test_requires_the_registration_fields(self, missing: str) -> None:
        payload = {k: v for k, v in APP.items() if k != missing}

        with pytest.raises(ValidationError, match=missing):
            CustomerApp.model_validate(payload)

    def test_parses_a_page_of_apps(self) -> None:
        page = CustomerAppListResponse.model_validate({"customer_apps": [APP], "next_offset": 5})

        assert page.customer_apps is not None
        assert page.customer_apps[0].app_name == "checkout-assistant"


# ---------------------------------------------------------------------------
# DLP and deployment profiles
# ---------------------------------------------------------------------------


class TestDlpProfileListResponse:
    def test_parses_profiles_with_kebab_case_keys(self) -> None:
        page = DlpProfileListResponse.model_validate(
            {
                "dlp_profiles": [
                    {
                        "name": "pci",
                        "uuid": "0f2c9d1e-1111-4b8a-9c2f-aaaaaaaaaaaa",
                        "id": "17",
                        "version": "1",
                        "rule1": {"action": "block"},
                        "log-severity": "high",
                        "non-file-based": "enabled",
                        "file-based": "disabled",
                    }
                ]
            }
        )

        assert page.dlp_profiles is not None
        profile = page.dlp_profiles[0]
        assert unmodelled(profile) == []
        assert profile.log_severity == "high"
        assert profile.non_file_based == "enabled"
        assert profile.file_based == "disabled"
        assert profile.rule1 is not None
        assert profile.rule1.action == "block"

    def test_requires_name_and_uuid(self) -> None:
        with pytest.raises(ValidationError, match="uuid"):
            DlpProfileListResponse.model_validate({"dlp_profiles": [{"name": "pci"}]})


class TestDeploymentProfilesResponse:
    def test_parses_the_response(self) -> None:
        response = DeploymentProfilesResponse.model_validate(
            {
                "deployment_profiles": [
                    {
                        "dp_name": "airs-dp",
                        "auth_code": "I9XXXXXX",
                        "tsg_id": "1234567890",
                        "status": "active",
                        "expiration_date": "2027-01-01",
                        "ave_text_records": 100000,
                    }
                ],
                "status": "success",
            }
        )

        assert response.status == "success"
        assert unmodelled(response) == []
        entry = response.deployment_profiles[0]
        assert (entry.dp_name, entry.auth_code, entry.status) == ("airs-dp", "I9XXXXXX", "active")
        assert entry.expiration_date == "2027-01-01"
        assert entry.ave_text_records == 100000

    def test_keeps_the_upstream_ave_text_records_typo(self) -> None:
        """``ave_``, not ``avg_``: it is the wire name, so "fixing" it drops the value.

        Asserted against ``model_fields`` rather than by attribute: ``extra="allow"``
        serves unknown keys through ``__getattr__``, so ``entry.ave_text_records``
        reads back fine even from a model that no longer declares the field.
        """
        assert "ave_text_records" in DeploymentProfileEntry.model_fields
        assert "avg_text_records" not in DeploymentProfileEntry.model_fields

    def test_requires_the_status(self) -> None:
        with pytest.raises(ValidationError, match="status"):
            DeploymentProfilesResponse.model_validate({"deployment_profiles": []})

    def test_requires_the_profile_array(self) -> None:
        with pytest.raises(ValidationError, match="deployment_profiles"):
            DeploymentProfilesResponse.model_validate({"status": "success"})


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


class TestDashboardApplication:
    def test_parses_a_full_application_overview(self) -> None:
        app = DashboardApplication.model_validate(
            {
                "id": "8f1c2d33-3333-4a5b-9c6d-cccccccccccc",
                "name": "checkout-assistant",
                "cloud": "aws",
                "source": "api",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-05-28T00:00:00Z",
                "profiles": ["prod-strict"],
                "token_stats": {
                    "average_daily_tokens": 42.5,
                    "average_daily_tokens_scale": "K",
                    "monthly_total_tokens": 1.3,
                    "monthly_total_tokens_scale": "M",
                },
                "session_stats": {
                    "total": 900,
                    "violating": 12,
                    "violation_breakdown": {"critical": 1, "high": 3, "medium": 5, "low": 3},
                    "last_session_id": "sess-9",
                    "most_recent_session_time": "2026-05-28T11:59:00Z",
                },
            }
        )

        assert unmodelled(app) == []
        assert app.token_stats is not None
        assert app.token_stats.average_daily_tokens == 42.5
        assert app.token_stats.average_daily_tokens_scale == "K"
        assert app.token_stats.monthly_total_tokens == 1.3
        assert app.token_stats.monthly_total_tokens_scale == "M"
        assert app.session_stats is not None
        assert app.session_stats.last_session_id == "sess-9"
        assert app.session_stats.violation_breakdown is not None
        assert app.session_stats.violation_breakdown.critical == 1

    def test_tolerates_the_all_null_body_a_missing_appname_produces(self) -> None:
        """Omitting ``appname`` on the request yields nulls everywhere rather than an error."""
        app = DashboardApplication.model_validate(
            {"id": None, "name": None, "profiles": None, "token_stats": None}
        )

        assert app.token_stats is None

    def test_parses_a_detector_violation_breakdown(self) -> None:
        breakdown = DashboardApplicationViolationBreakdown.model_validate(
            {
                "detection_type_violation_breakdown": [
                    {"detection_type": "pi", "violation_breakdown": {"critical": 4, "total": 4}},
                    {"detection_type": "dlp", "violation_breakdown": {"high": 2, "total": 2}},
                ],
                "total_violating": 6,
            }
        )

        assert breakdown.detection_type_violation_breakdown is not None
        assert [e.detection_type for e in breakdown.detection_type_violation_breakdown] == [
            "pi",
            "dlp",
        ]
        assert breakdown.total_violating == 6

    def test_accepts_a_detector_the_sdk_has_never_seen(self) -> None:
        """The detector set evolves; a new slug must parse without an SDK release."""
        breakdown = DashboardApplicationViolationBreakdown.model_validate(
            {"detection_type_violation_breakdown": [{"detection_type": "quantum_leakage"}]}
        )

        assert breakdown.detection_type_violation_breakdown is not None
        assert breakdown.detection_type_violation_breakdown[0].detection_type == "quantum_leakage"


OVERVIEW: dict[str, Any] = {
    "items": [
        {
            "id": "8f1c2d33-3333-4a5b-9c6d-cccccccccccc",
            "name": "checkout-assistant",
            "cloud": "aws",
            "source": "api",
            "created_at": "2026-01-01T00:00:00Z",
            "sessions": [
                {"bucket_number": 1, "date": "2026-05-27", "total": 40, "violated": 2},
                {"bucket_number": 2, "date": "2026-05-28", "total": 55, "violated": 0},
            ],
            "sessions_total": 95,
            "sessions_violated": 2,
        },
        {
            "id": "8f1c2d33-3333-4a5b-9c6d-cccccccccccc",
            "name": "checkout-assistant-canary",
            "sessions": None,
            "sessions_total": 0,
            "sessions_violated": 0,
        },
    ],
    "pagination": {"limit": 25, "skip": 0, "total_items": 2},
}


class TestDashboardApplicationsOverview:
    def test_parses_a_full_overview(self) -> None:
        overview = DashboardApplicationsOverview.model_validate(OVERVIEW)

        assert unmodelled(overview) == []
        assert overview.items is not None
        assert overview.items[0].sessions is not None
        assert [b.total for b in overview.items[0].sessions] == [40, 55]
        assert [b.bucket_number for b in overview.items[0].sessions] == [1, 2]
        assert [b.violated for b in overview.items[0].sessions] == [2, 0]
        assert overview.items[0].sessions_total == 95
        assert overview.pagination is not None
        assert overview.pagination.total_items == 2

    def test_one_registered_app_can_span_several_buckets(self) -> None:
        """Buckets key off the literal scan-payload app_name, so ``id`` repeats across items."""
        overview = DashboardApplicationsOverview.model_validate(OVERVIEW)

        assert overview.items is not None
        assert len({item.id for item in overview.items}) == 1
        assert len({item.name for item in overview.items}) == 2

    def test_tolerates_null_session_buckets(self) -> None:
        overview = DashboardApplicationsOverview.model_validate(OVERVIEW)

        assert overview.items is not None
        assert overview.items[1].sessions is None


# ---------------------------------------------------------------------------
# Scan logs
# ---------------------------------------------------------------------------


ENTRY: dict[str, Any] = {
    "csp_id": "csp-1",
    "tsg_id": "1234567890",
    "scan_id": "s-1",
    "scan_sub_req_id": 0,
    "api_key_name": "prod-scanner",
    "app_name": "checkout-assistant",
    "tokens": 812,
    "text_records": 2,
    "transaction_id": "tx-1",
    "profile_name": "prod-strict",
    "model_name": "gpt-4o",
    "user": "scott@example.com",
    "environment": "production",
    "cloud_provider": "aws",
    "report_id": "r-1",
    "received_ts": "2026-05-28T11:00:00Z",
    "completed_ts": "2026-05-28T11:00:01Z",
    "status": "complete",
    "verdict": "malicious",
    "action": "block",
    "is_prompt": True,
    "is_response": False,
    "pi_final_verdict": "malicious",
    "dlp_final_verdict": "benign",
    "prompt_pi_verdict": "malicious",
    "prompt_pi_action": "block",
    "prompt_verdict": "malicious",
    "response_dlp_verdict": "benign",
    "response_verdict": "benign",
    "detection_service_flags": 5,
    "content_masked": False,
    "user_ip": "203.0.113.7",
}


class TestPaginatedScanResults:
    def test_parses_a_full_page(self) -> None:
        page = PaginatedScanResults.model_validate(
            {
                "scan_result_for_dashboard": {
                    "text_records_count": 2,
                    "api_calls_count": 1,
                    "threats_count": 1,
                    "all_transactions_count": 1,
                    "benign_transaction_count": 0,
                    "scan_result_entries": [ENTRY],
                },
                "total_pages": 3,
                "page_number": 1,
                "page_size": 50,
                "page_token": "eyJvZmZzZXQiOjUwfQ==",
                "revision": 2,
            }
        )

        assert unmodelled(page) == []
        assert page.page_token == "eyJvZmZzZXQiOjUwfQ=="
        assert (page.total_pages, page.page_number, page.page_size) == (3, 1, 50)
        dashboard = page.scan_result_for_dashboard
        assert dashboard is not None
        assert dashboard.threats_count == 1
        assert dashboard.benign_transaction_count == 0
        assert dashboard.scan_result_entries is not None
        assert dashboard.scan_result_entries[0].scan_id == "s-1"
        assert dashboard.scan_result_entries[0].detection_service_flags == 5

    def test_keeps_direction_and_final_verdicts_separate(self) -> None:
        """A detector can differ per direction, so the final verdict is not derivable."""
        page = PaginatedScanResults.model_validate(
            {"scan_result_for_dashboard": {"scan_result_entries": [ENTRY]}}
        )

        assert page.scan_result_for_dashboard is not None
        assert page.scan_result_for_dashboard.scan_result_entries is not None
        entry = page.scan_result_for_dashboard.scan_result_entries[0]
        assert entry.prompt_verdict == "malicious"
        assert entry.response_verdict == "benign"
        assert entry.pi_final_verdict == "malicious"

    @pytest.mark.parametrize(
        "missing",
        [
            "csp_id",
            "tsg_id",
            "scan_id",
            "scan_sub_req_id",
            "api_key_name",
            "app_name",
            "tokens",
            "text_records",
        ],
    )
    def test_requires_the_correlation_and_billing_fields(self, missing: str) -> None:
        payload = {k: v for k, v in ENTRY.items() if k != missing}

        with pytest.raises(ValidationError, match=missing):
            PaginatedScanResults.model_validate(
                {"scan_result_for_dashboard": {"scan_result_entries": [payload]}}
            )

    def test_preserves_unknown_log_columns(self) -> None:
        page = PaginatedScanResults.model_validate(
            {"scan_result_for_dashboard": {"scan_result_entries": [{**ENTRY, "region": "eu"}]}}
        )

        assert page.scan_result_for_dashboard is not None
        assert page.scan_result_for_dashboard.scan_result_entries is not None
        assert page.scan_result_for_dashboard.scan_result_entries[0].model_extra == {"region": "eu"}


# ---------------------------------------------------------------------------
# OAuth
# ---------------------------------------------------------------------------


class TestOauth:
    def test_parses_a_token_response(self) -> None:
        token = Oauth2Token.model_validate(
            {
                "token_type": "Bearer",
                "issued_at": "1780000000",
                "client_id": "svc-checkout",
                "access_token": "eyJhbGciOiJSUzI1NiJ9.payload.sig",
                "expires_in": "3600",
                "status": "success",
            }
        )

        assert unmodelled(token) == []
        assert token.access_token.startswith("eyJ")
        assert token.expires_in == "3600"
        assert (token.token_type, token.issued_at, token.status) == (
            "Bearer",
            "1780000000",
            "success",
        )
        assert token.client_id == "svc-checkout"

    def test_keeps_expires_in_as_a_string(self) -> None:
        """The wire type is a string; a caller doing arithmetic must convert it first."""
        with pytest.raises(ValidationError, match="expires_in"):
            Oauth2Token.model_validate({"access_token": "t", "expires_in": 3600})

    def test_requires_the_access_token(self) -> None:
        with pytest.raises(ValidationError, match="access_token"):
            Oauth2Token.model_validate({"token_type": "Bearer", "status": "success"})

    def test_binds_a_client_to_a_customer_app(self) -> None:
        """The bind body carries exactly two keys, un-aliased, in wire spelling."""
        body = ClientIdAndCustomerApp(client_id="svc-checkout", customer_app="checkout-assistant")
        wire = {"client_id": "svc-checkout", "customer_app": "checkout-assistant"}

        assert set(ClientIdAndCustomerApp.model_fields) == {"client_id", "customer_app"}
        assert body.model_dump() == wire
        assert body.model_dump(by_alias=True) == wire

    @pytest.mark.parametrize("missing", ["client_id", "customer_app"])
    def test_both_sides_of_the_binding_are_required(self, missing: str) -> None:
        payload = {"client_id": "svc-checkout", "customer_app": "checkout-assistant"}
        del payload[missing]

        with pytest.raises(ValidationError, match=missing):
            ClientIdAndCustomerApp.model_validate(payload)
