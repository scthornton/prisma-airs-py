"""UUID validation and the scan-request payload HMAC."""

from __future__ import annotations

import pytest

from prisma_airs._utils import generate_payload_hash, is_valid_uuid, validate_job_id
from prisma_airs.errors import AISecPayloadError


class TestUuidValidation:
    @pytest.mark.parametrize(
        "value",
        [
            "123e4567-e89b-12d3-a456-426614174000",
            "123E4567-E89B-12D3-A456-426614174000",
        ],
    )
    def test_accepts_canonical_uuids_in_either_case(self, value: str) -> None:
        assert is_valid_uuid(value)

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "not-a-uuid",
            "123e4567e89b12d3a456426614174000",  # unhyphenated
            "{123e4567-e89b-12d3-a456-426614174000}",  # braced
            "urn:uuid:123e4567-e89b-12d3-a456-426614174000",  # URN
            "123e4567-e89b-12d3-a456-42661417400",  # one char short
            "123e4567-e89b-12d3-a456-4266141740000",  # one char long
            "123e4567-e89b-12d3-a456-42661417400g",  # non-hex
        ],
    )
    def test_rejects_spellings_the_api_will_not_accept(self, value: str) -> None:
        """uuid.UUID would accept the braced and URN forms; the service does not."""
        assert not is_valid_uuid(value)

    def test_validate_job_id_names_the_offending_value(self) -> None:
        with pytest.raises(AISecPayloadError, match="Invalid job id: nope"):
            validate_job_id("nope")

    def test_validate_job_id_passes_a_valid_uuid(self) -> None:
        validate_job_id("123e4567-e89b-12d3-a456-426614174000")


class TestPayloadHash:
    def test_matches_the_published_hmac_sha256_vector(self) -> None:
        """A known vector, so a change in digest or encoding cannot pass silently."""
        digest = generate_payload_hash("The quick brown fox jumps over the lazy dog", "key")

        assert digest == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"

    def test_is_stable_for_the_same_input(self) -> None:
        assert generate_payload_hash('{"a":1}', "secret") == generate_payload_hash(
            '{"a":1}', "secret"
        )

    def test_changes_when_the_body_changes(self) -> None:
        assert generate_payload_hash('{"a":1}', "s") != generate_payload_hash('{"a":2}', "s")

    def test_changes_when_the_key_changes(self) -> None:
        assert generate_payload_hash('{"a":1}', "s1") != generate_payload_hash('{"a":1}', "s2")

    def test_handles_non_ascii_bodies(self) -> None:
        """UTF-8 encoding must not raise; the body may carry any prompt text."""
        assert len(generate_payload_hash('{"prompt":"日本語 🔐"}', "secret")) == 64
