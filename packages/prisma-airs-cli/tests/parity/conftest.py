"""Fixtures for differential parity tests against the TypeScript reference CLI.

The approach: stand up a local HTTP server that records whatever it is sent and answers
with a canned body, point BOTH clients at it, run equivalent commands through each, and
diff the requests that arrive.

This is the strongest check available without a live tenant. Unit and contract tests prove
the Python client does what *I believe* the API expects; this proves it does what the
reference actually does, which is a different and better claim.

Everything is exposed through fixtures rather than module constants, so test modules never
import from a conftest -- which only works by accident of sys.path.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

#: The reference is the TypeScript source this port was written against, built locally and
#: pointed at by AIRS_REFERENCE_CLI. Deliberately NOT the published npm package: the
#: published tarball for the same version number exposes an older command surface than the
#: repository source, so diffing against npm would measure the wrong thing.
REFERENCE_ENV_VAR = "AIRS_REFERENCE_CLI"

#: Identical for both clients, so the payload HMAC is directly comparable.
API_KEY = "parity-test-key"

#: Headers that legitimately differ between the two clients. Everything else must match.
#: Deliberately short: a broad ignore list would let a real difference slip through.
IGNORED_HEADERS = frozenset(
    {
        "user-agent",  # identifies the language binding, and is meant to differ
        "host",
        "connection",
        "accept",
        "accept-encoding",
        "content-length",  # derived from the body, which is compared directly
        # Added automatically by Node's fetch (undici), not set by the reference client.
        # Comparing them would measure the HTTP stack rather than the port.
        "accept-language",
        "sec-fetch-mode",
    }
)

ALLOW_RESPONSE: dict[str, Any] = {
    "report_id": "R-parity",
    "scan_id": "S-parity",
    "category": "benign",
    "action": "allow",
    "timeout": False,
    "error": False,
    "errors": [],
}


@dataclass
class RecordedRequest:
    """One request as the server saw it."""

    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: str

    def comparable(self, ignored: frozenset[str]) -> dict[str, Any]:
        """The parts that must match between the two clients."""
        return {
            "method": self.method,
            "path": self.path,
            "query": sorted(self.query.split("&")) if self.query else [],
            "headers": {k: v for k, v in sorted(self.headers.items()) if k not in ignored},
            "body": json.loads(self.body) if self.body else None,
        }


@dataclass
class Recorder:
    """Collects requests and hands out canned responses."""

    response: dict[str, Any] = field(default_factory=dict)
    status: int = 200
    requests: list[RecordedRequest] = field(default_factory=list)
    base_url: str = ""

    def reset(self) -> None:
        """Forget prior requests, so each comparison starts clean."""
        self.requests.clear()

    @property
    def last(self) -> RecordedRequest:
        """The most recent request, failing loudly if the client sent none."""
        if not self.requests:
            raise AssertionError("the client sent no request")
        return self.requests[-1]


def _handler_for(recorder: Recorder) -> type[BaseHTTPRequestHandler]:
    """Build a request handler bound to one recorder."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _record_and_reply(self) -> None:
            path, _, query = self.path.partition("?")
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode() if length else ""
            recorder.requests.append(
                RecordedRequest(
                    method=self.command,
                    path=path,
                    query=query,
                    headers={k.lower(): v for k, v in self.headers.items()},
                    body=body,
                )
            )
            payload = json.dumps(recorder.response).encode()
            self.send_response(recorder.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        # BaseHTTPRequestHandler dispatches on these exact names, so the casing is imposed
        # by the stdlib rather than chosen here.
        do_GET = _record_and_reply  # noqa: N815
        do_POST = _record_and_reply  # noqa: N815
        do_PUT = _record_and_reply  # noqa: N815
        do_PATCH = _record_and_reply  # noqa: N815
        do_DELETE = _record_and_reply  # noqa: N815

        def log_message(self, *_args: Any) -> None:
            """Silence the default stderr access log."""

    return Handler


@pytest.fixture(scope="session")
def ignored_headers() -> frozenset[str]:
    """Headers excluded from the request diff."""
    return IGNORED_HEADERS


@pytest.fixture(scope="session")
def allow_response() -> dict[str, Any]:
    """A canned `allow` verdict both clients can parse."""
    return dict(ALLOW_RESPONSE)


@pytest.fixture(scope="session")
def recorder() -> Iterator[Recorder]:
    """A local HTTP server both clients are pointed at."""
    rec = Recorder(response=dict(ALLOW_RESPONSE))
    server = HTTPServer(("127.0.0.1", 0), _handler_for(rec))
    rec.base_url = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield rec
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(scope="session")
def reference_cli() -> list[str]:
    """Command prefix that runs the reference CLI, or skip.

    Opt-in, because it needs Node and a checked-out, built copy of the TypeScript source::

        git clone https://github.com/cdot65/prisma-airs-cli && cd prisma-airs-cli
        npm install && npm run build
        AIRS_PARITY=1 AIRS_REFERENCE_CLI=$PWD/dist/cli/index.js uv run pytest -m parity
    """
    if os.environ.get("AIRS_PARITY") != "1":
        pytest.skip("parity tests are opt-in; set AIRS_PARITY=1")

    entry = os.environ.get(REFERENCE_ENV_VAR)
    if not entry:
        pytest.skip(f"set {REFERENCE_ENV_VAR} to a built reference CLI entry point")
    if not Path(entry).is_file():
        pytest.skip(f"{REFERENCE_ENV_VAR} does not point at a file: {entry}")

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")

    probe = subprocess.run(  # noqa: S603
        [node, entry, "--version"], capture_output=True, text=True, timeout=120, check=False
    )
    if probe.returncode != 0:
        pytest.skip(f"reference CLI is not runnable: {probe.stderr.strip()[:200]}")
    return [node, entry]


RunBoth = Callable[[list[str]], tuple[dict[str, Any], dict[str, Any]]]
RunOne = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _env(recorder: Recorder, home: Path) -> dict[str, str]:
    """Environment pointing a client at the recorder, isolated from real config."""
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "PANW_AI_SEC_API_KEY": API_KEY,
        "PANW_AI_SEC_API_ENDPOINT": recorder.base_url,
        "PRISMA_AIRS_CONFIG": str(home / "absent.json"),
        "NO_COLOR": "1",
        # Wide enough that neither client wraps its help text. A wrapped description
        # continues on a line that looks structurally like a command row, which any parser
        # reading --help will happily mistake for a command.
        "COLUMNS": "200",
        "TERM": "dumb",
    }


@pytest.fixture
def run_reference(reference_cli: list[str], recorder: Recorder, tmp_path: Path) -> RunOne:
    """Run the TypeScript CLI against the recorder."""

    def run(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [*reference_cli, *args],
            env=_env(recorder, tmp_path),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

    return run


@pytest.fixture
def run_port(recorder: Recorder, tmp_path: Path) -> RunOne:
    """Run this CLI against the recorder."""

    def run(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [sys.executable, "-m", "prisma_airs_cli", *args],
            env=_env(recorder, tmp_path),
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )

    return run


@pytest.fixture
def compare_requests(
    recorder: Recorder, run_reference: RunOne, run_port: RunOne, ignored_headers: frozenset[str]
) -> RunBoth:
    """Run both clients with the same arguments and return (reference, ported) requests."""

    def compare(args: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
        recorder.reset()
        run_reference(args)
        reference = recorder.last.comparable(ignored_headers)

        recorder.reset()
        run_port(args)
        ported = recorder.last.comparable(ignored_headers)

        return reference, ported

    return compare
