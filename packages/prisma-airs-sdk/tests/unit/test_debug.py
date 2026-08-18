"""Debug logging, and the redaction that makes it safe to share."""

from __future__ import annotations

import pytest

from prisma_airs._http.debug import hash_token, is_debug_enabled, sanitize_headers
from prisma_airs.constants import ENV_AI_SEC_DEBUG


class TestDebugToggle:
    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " true "])
    def test_recognises_truthy_spellings(self, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_AI_SEC_DEBUG, value)

        assert is_debug_enabled()

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "", "maybe"])
    def test_treats_everything_else_as_off(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_AI_SEC_DEBUG, value)

        assert not is_debug_enabled()

    def test_is_off_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(ENV_AI_SEC_DEBUG, raising=False)

        assert not is_debug_enabled()


class TestHashToken:
    def test_produces_a_stable_prefixed_digest(self) -> None:
        assert hash_token("secret").startswith("sha256:")
        assert hash_token("secret") == hash_token("secret")

    def test_is_short_enough_to_read_but_long_enough_to_distinguish(self) -> None:
        assert len(hash_token("secret")) == len("sha256:") + 12

    def test_differs_between_secrets(self) -> None:
        assert hash_token("secret-a") != hash_token("secret-b")

    def test_does_not_contain_the_secret(self) -> None:
        assert "hunter2" not in hash_token("hunter2")


class TestSanitizeHeaders:
    def test_redacts_the_authorization_header(self) -> None:
        result = sanitize_headers({"Authorization": "Bearer supersecret"})

        assert "supersecret" not in result["Authorization"]
        assert result["Authorization"].startswith("sha256:")

    def test_redacts_the_api_key_header(self) -> None:
        result = sanitize_headers({"x-pan-token": "my-api-key"})

        assert "my-api-key" not in result["x-pan-token"]

    def test_matches_header_names_case_insensitively(self) -> None:
        """Header casing is not guaranteed, and a miss here leaks a credential."""
        result = sanitize_headers({"AUTHORIZATION": "Bearer s3cret", "X-Pan-Token": "k3y"})

        assert "s3cret" not in result["AUTHORIZATION"]
        assert "k3y" not in result["X-Pan-Token"]

    def test_passes_ordinary_headers_through(self) -> None:
        result = sanitize_headers({"User-Agent": "airs/1.0", "service-name": "api"})

        assert result == {"User-Agent": "airs/1.0", "service-name": "api"}

    def test_does_not_mutate_the_input(self) -> None:
        original = {"Authorization": "Bearer secret"}

        sanitize_headers(original)

        assert original == {"Authorization": "Bearer secret"}
