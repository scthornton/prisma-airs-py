"""Differential parity: this CLI must produce the same request as the reference.

Both clients run as real processes against the same recording server, with the same
credentials and the same arguments; the requests that arrive are then compared.

The strongest assertion is ``x-payload-hash``. The scan service authenticates with an HMAC
over the request body, keyed by the API key. Both clients get the same key, so matching
hashes prove the bodies were byte-identical -- key order, separator whitespace, and
non-ASCII encoding included. Structural equality of the parsed JSON would not prove that.
"""

from __future__ import annotations

from typing import Any

import pytest

from prisma_airs.models.scan import ScanResponse

pytestmark = pytest.mark.parity

ARGUMENT_SETS = [
    pytest.param(["runtime", "scan", "--profile", "prod", "hello"], id="basic"),
    pytest.param(
        ["runtime", "scan", "--profile", "prod", "--response", "there", "hi"],
        id="prompt-and-response",
    ),
    pytest.param(["runtime", "scan", "--profile", "prod", "日本語 🔐"], id="non-ascii"),
    pytest.param(
        ["runtime", "scan", "--profile", "prod", 'quote " and \\ backslash'], id="escapes"
    ),
    pytest.param(["runtime", "scan", "--profile", "prod", ""], id="empty-prompt"),
]


@pytest.mark.parametrize("args", ARGUMENT_SETS)
class TestScanRequestParity:
    def test_same_method_and_path(self, compare_requests: Any, args: list[str]) -> None:
        reference, ported = compare_requests(args)

        assert (ported["method"], ported["path"]) == (reference["method"], reference["path"])

    def test_same_query_parameters(self, compare_requests: Any, args: list[str]) -> None:
        reference, ported = compare_requests(args)

        assert ported["query"] == reference["query"]

    def test_same_body(self, compare_requests: Any, args: list[str]) -> None:
        reference, ported = compare_requests(args)

        assert ported["body"] == reference["body"]

    def test_same_payload_hmac(self, compare_requests: Any, args: list[str]) -> None:
        """Matching hashes prove the serialised bodies were byte-identical.

        Key order, separator whitespace, and ``\\uXXXX`` escaping all change the bytes the
        service hashes while leaving the parsed object identical, so this catches what a
        structural comparison cannot.
        """
        reference, ported = compare_requests(args)

        assert "x-payload-hash" in reference["headers"], "reference sent no payload hash"
        assert ported["headers"]["x-payload-hash"] == reference["headers"]["x-payload-hash"]

    def test_same_headers(self, compare_requests: Any, args: list[str]) -> None:
        reference, ported = compare_requests(args)

        assert ported["headers"] == reference["headers"]


class TestExitCodes:
    """The one place this port knowingly differs, pinned so it cannot drift further."""

    def test_both_exit_zero_on_allow(
        self, recorder: Any, allow_response: dict[str, Any], run_reference: Any, run_port: Any
    ) -> None:
        recorder.response = allow_response
        args = ["runtime", "scan", "--profile", "prod", "hi"]

        assert run_reference(args).returncode == 0
        assert run_port(args).returncode == 0

    def test_both_fail_the_build_on_a_block(
        self, recorder: Any, allow_response: dict[str, Any], run_reference: Any, run_port: Any
    ) -> None:
        """Both exit non-zero. Only the specific code differs, by documented design."""
        recorder.response = {**allow_response, "action": "block", "category": "malicious"}
        args = ["runtime", "scan", "--profile", "prod", "bad"]

        assert run_reference(args).returncode != 0
        assert run_port(args).returncode != 0

        recorder.response = allow_response


class TestHarnessIntegrity:
    """Guards on the harness itself -- a broken one would make every diff pass vacuously."""

    def test_the_recorder_is_listening(self, recorder: Any) -> None:
        assert recorder.base_url.startswith("http://127.0.0.1:")

    def test_the_ignore_list_excludes_only_incidental_headers(
        self, ignored_headers: frozenset[str]
    ) -> None:
        """A broad ignore list would let a real difference slip through unnoticed."""
        for header in ("x-payload-hash", "x-pan-token", "content-type", "authorization"):
            assert header not in ignored_headers

    def test_the_canned_verdict_actually_parses(self, allow_response: dict[str, Any]) -> None:
        """An invalid body would make both clients error, leaving nothing to compare."""
        assert ScanResponse.model_validate(allow_response).action == "allow"
