"""``airs runtime`` behaviour, including the exit codes CI depends on."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from typer.testing import CliRunner, Result

from prisma_airs.constants import DEFAULT_ENDPOINT
from prisma_airs_cli.app import app
from prisma_airs_cli.bulk.state import (
    BulkScanItemState,
    BulkScanItemStatus,
    BulkScanResult,
    BulkScanState,
    load_state,
    save_state,
)
from prisma_airs_cli.commands import runtime


def flat(text: str) -> str:
    """Collapse Rich's line wrapping so assertions can look for whole phrases."""
    return " ".join(text.split())


runner = CliRunner()

SYNC_URL = f"{DEFAULT_ENDPOINT}/v1/scan/sync/request"

ALLOW = {
    "report_id": "R1",
    "scan_id": "S1",
    "category": "benign",
    "action": "allow",
    "timeout": False,
    "error": False,
    "errors": [],
}
BLOCK = {
    **ALLOW,
    "category": "malicious",
    "action": "block",
    "prompt_detected": {"injection": True, "dlp": False},
}


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep tests off the developer's real credentials and config."""
    monkeypatch.setenv("PANW_AI_SEC_API_KEY", "test-key")
    monkeypatch.setenv("PRISMA_AIRS_CONFIG", str(tmp_path / "config.json"))
    for name in ("PANW_AI_SEC_PROFILE", "PANW_AI_SEC_REGION", "PANW_AI_SEC_API_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)


class TestExitCodes:
    """The contract that lets this command gate a pipeline."""

    @respx.mock
    def test_allow_exits_zero(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        result = runner.invoke(app, ["runtime", "scan", "-p", "hi", "--profile", "prod"])

        assert result.exit_code == 0

    @respx.mock
    def test_block_exits_one(self) -> None:
        """A blocked prompt should fail the build, not pass quietly."""
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=BLOCK))

        result = runner.invoke(app, ["runtime", "scan", "-p", "bad", "--profile", "prod"])

        assert result.exit_code == 1

    @respx.mock
    def test_an_api_failure_exits_two(self) -> None:
        """Distinguishable from a block: the scan never produced a verdict."""
        respx.post(SYNC_URL).mock(
            return_value=httpx.Response(403, json={"message": "Invalid API Key"})
        )

        result = runner.invoke(app, ["runtime", "scan", "-p", "hi", "--profile", "prod"])

        assert result.exit_code == 2

    def test_missing_content_exits_two(self) -> None:
        result = runner.invoke(app, ["runtime", "scan", "--profile", "prod"])

        assert result.exit_code == 2

    def test_missing_profile_exits_two(self) -> None:
        result = runner.invoke(app, ["runtime", "scan", "-p", "hi"])

        assert result.exit_code == 2


class TestOutput:
    @respx.mock
    def test_reports_the_action_and_category(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=BLOCK))

        result = runner.invoke(app, ["runtime", "scan", "-p", "bad", "--profile", "prod"])

        assert "BLOCK" in result.output
        assert "malicious" in result.output

    @respx.mock
    def test_names_the_detections_that_fired(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=BLOCK))

        result = runner.invoke(app, ["runtime", "scan", "-p", "bad", "--profile", "prod"])

        assert "prompt.injection" in result.output

    @respx.mock
    def test_does_not_list_detections_that_did_not_fire(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=BLOCK))

        result = runner.invoke(app, ["runtime", "scan", "-p", "bad", "--profile", "prod"])

        assert "prompt.dlp" not in result.output

    @respx.mock
    def test_json_output_is_parseable(self) -> None:
        respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        result = runner.invoke(app, ["runtime", "scan", "-p", "hi", "--profile", "prod", "--json"])

        assert json.loads(result.output)["action"] == "allow"

    def test_the_missing_profile_message_suggests_the_fix(self) -> None:
        result = runner.invoke(app, ["runtime", "scan", "-p", "hi"])

        assert "airs config set profile" in result.output


class TestInputSources:
    @respx.mock
    def test_reads_a_prompt_from_a_file(self, tmp_path: Path) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))
        prompt_file = tmp_path / "prompt.txt"
        prompt_file.write_text("from a file")

        runner.invoke(
            app, ["runtime", "scan", "--prompt-file", str(prompt_file), "--profile", "prod"]
        )

        body = json.loads(route.calls.last.request.content)
        assert body["contents"][0]["prompt"] == "from a file"

    def test_rejects_a_missing_prompt_file(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["runtime", "scan", "--prompt-file", str(tmp_path / "nope.txt"), "--profile", "prod"],
        )

        assert result.exit_code == 2

    @respx.mock
    def test_takes_the_prompt_as_a_positional_argument(self) -> None:
        """The reference client's calling convention, which the parity harness uses."""
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        result = runner.invoke(app, ["runtime", "scan", "--profile", "prod", "positionally"])

        assert result.exit_code == 0
        body = json.loads(route.calls.last.request.content)
        assert body["contents"][0]["prompt"] == "positionally"

    @respx.mock
    def test_rejects_an_empty_prompt_without_a_traceback(self) -> None:
        """The SDK refuses unscannable content; the CLI must say so, not crash."""
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        result = runner.invoke(app, ["runtime", "scan", "--profile", "prod", ""])

        assert result.exit_code == 2
        assert not route.called
        assert "Nothing to scan" in flat(result.output)

    @respx.mock
    def test_rejects_context_with_nothing_to_frame(self) -> None:
        """`--context` is not itself scannable, so it cannot stand alone."""
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        result = runner.invoke(app, ["runtime", "scan", "--profile", "prod", "--context", "ctx"])

        assert result.exit_code == 2
        assert not route.called
        assert "context only accompanies one" in flat(result.output).lower()

    @respx.mock
    def test_sends_the_context_alongside_a_prompt(self) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        runner.invoke(
            app, ["runtime", "scan", "--profile", "prod", "--context", "ctx", "the prompt"]
        )

        body = json.loads(route.calls.last.request.content)
        assert body["contents"][0] == {"prompt": "the prompt", "context": "ctx"}

    @respx.mock
    def test_refuses_a_prompt_supplied_twice(self, tmp_path: Path) -> None:
        """Silently preferring one source would scan text the caller did not mean."""
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        result = runner.invoke(
            app, ["runtime", "scan", "--profile", "prod", "--prompt", "flag", "argument"]
        )

        assert result.exit_code == 2
        assert not route.called
        assert "Give the prompt once" in flat(result.output)

    @respx.mock
    def test_takes_the_profile_from_the_config_file(self, tmp_path: Path) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))
        (tmp_path / "config.json").write_text('{"profile": "from-config"}')

        runner.invoke(app, ["runtime", "scan", "-p", "hi"])

        body = json.loads(route.calls.last.request.content)
        assert body["ai_profile"]["profile_name"] == "from-config"

    @respx.mock
    def test_a_flag_overrides_the_config_file(self, tmp_path: Path) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))
        (tmp_path / "config.json").write_text('{"profile": "from-config"}')

        runner.invoke(app, ["runtime", "scan", "-p", "hi", "--profile", "from-flag"])

        body = json.loads(route.calls.last.request.content)
        assert body["ai_profile"]["profile_name"] == "from-flag"

    @respx.mock
    def test_forwards_tracing_identifiers(self) -> None:
        route = respx.post(SYNC_URL).mock(return_value=httpx.Response(200, json=ALLOW))

        runner.invoke(
            app,
            [
                "runtime",
                "scan",
                "-p",
                "hi",
                "--profile",
                "p",
                "--tr-id",
                "T1",
                "--session-id",
                "S9",
            ],
        )

        body = json.loads(route.calls.last.request.content)
        assert (body["tr_id"], body["session_id"]) == ("T1", "S9")


# ---------------------------------------------------------------------------
# Asynchronous scanning: bulk-scan, results, reports
# ---------------------------------------------------------------------------

ASYNC_URL = f"{DEFAULT_ENDPOINT}/v1/scan/async/request"
RESULTS_URL = f"{DEFAULT_ENDPOINT}/v1/scan/results"
REPORTS_URL = f"{DEFAULT_ENDPOINT}/v1/scan/reports"

SCAN_ID = "11111111-1111-4111-8111-111111111111"
OTHER_SCAN_ID = "22222222-2222-4222-8222-222222222222"
THIRD_SCAN_ID = "33333333-3333-4333-8333-333333333333"


def receipt(scan_id: str = SCAN_ID, report_id: str = "R1") -> dict[str, Any]:
    """Build an async-scan acknowledgement."""
    return {"received": "2026-01-01T00:00:00Z", "scan_id": scan_id, "report_id": report_id}


def batch_row(
    req_id: int,
    *,
    action: str = "allow",
    status: str = "complete",
    scan_id: str = SCAN_ID,
    detected: dict[str, bool] | None = None,
) -> dict[str, Any]:
    """Build one row of a scan-results response."""
    row: dict[str, Any] = {"req_id": req_id, "status": status, "scan_id": scan_id}
    if status != "failed":
        verdict = {
            **ALLOW,
            "scan_id": scan_id,
            "action": action,
            "category": "malicious" if action == "block" else "benign",
        }
        if detected is not None:
            verdict["prompt_detected"] = detected
        row["result"] = verdict
    return row


def run_bulk(
    tmp_path: Path,
    *extra: str,
    prompts: str = "first\nsecond\n",
    name: str = "prompts.txt",
) -> Result:
    """Invoke bulk-scan over a freshly written input file."""
    source = tmp_path / name
    source.write_text(prompts)
    return runner.invoke(
        app,
        [
            "runtime",
            "bulk-scan",
            "--profile",
            "prod",
            "--file",
            str(source),
            "--output-file",
            str(tmp_path / "out.csv"),
            *extra,
        ],
    )


def written_state(tmp_path: Path) -> BulkScanState:
    """Load the single state file the run left behind, validating it on the way in."""
    files = sorted((tmp_path / "bulk-scans").glob("*.bulk-scan.json"))
    assert len(files) == 1, files
    state = load_state(files[0])
    assert state is not None
    return state


class TestBulkScanSubmission:
    @respx.mock
    def test_submits_one_tagged_request_per_prompt(self, tmp_path: Path) -> None:
        submit = respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0), batch_row(1)])
        )

        result = run_bulk(tmp_path, "--session-id", "nightly")

        assert result.exit_code == 0
        body = json.loads(submit.calls.last.request.content)
        assert [entry["req_id"] for entry in body] == [0, 1]
        assert [entry["scan_req"]["contents"][0]["prompt"] for entry in body] == ["first", "second"]
        assert body[0]["scan_req"]["ai_profile"]["profile_name"] == "prod"
        assert body[0]["scan_req"]["session_id"] == "nightly"

    @respx.mock
    def test_generates_a_session_id_when_none_is_given(self, tmp_path: Path) -> None:
        submit = respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0), batch_row(1)])
        )

        run_bulk(tmp_path)

        body = json.loads(submit.calls.last.request.content)
        assert body[0]["scan_req"]["session_id"].startswith("prisma-airs-cli-bulk-")

    @respx.mock
    def test_reads_the_prompt_column_of_a_csv(self, tmp_path: Path) -> None:
        submit = respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(return_value=httpx.Response(200, json=[batch_row(0)]))

        result = run_bulk(
            tmp_path,
            prompts='id,prompt\n1,"hello, world"\n',
            name="prompts.csv",
        )

        assert result.exit_code == 0
        body = json.loads(submit.calls.last.request.content)
        assert [entry["scan_req"]["contents"][0]["prompt"] for entry in body] == ["hello, world"]

    @respx.mock
    def test_chunks_submission_to_the_async_batch_limit(self, tmp_path: Path) -> None:
        """The default 25-prompt batch is submitted in API-sized chunks of twenty."""
        ranges = {SCAN_ID: range(20), OTHER_SCAN_ID: range(20, 25), THIRD_SCAN_ID: range(25, 30)}
        submit = respx.post(ASYNC_URL).mock(
            side_effect=[httpx.Response(200, json=receipt(scan_id)) for scan_id in ranges]
        )

        def respond(request: httpx.Request) -> httpx.Response:
            scan_id = request.url.params["scan_ids"]
            return httpx.Response(
                200, json=[batch_row(index, scan_id=scan_id) for index in ranges[scan_id]]
            )

        respx.get(RESULTS_URL).mock(side_effect=respond)

        result = run_bulk(tmp_path, prompts="\n".join(f"p{i}" for i in range(30)))

        assert result.exit_code == 0
        # 30 prompts batch as 25 then 5, and each batch is chunked to the API limit of 20.
        assert [len(json.loads(call.request.content)) for call in submit.calls] == [20, 5, 5]
        third = json.loads(submit.calls[2].request.content)
        assert [entry["req_id"] for entry in third] == [25, 26, 27, 28, 29]

    @respx.mock
    def test_batch_size_controls_the_submit_poll_cycle(self, tmp_path: Path) -> None:
        submit = respx.post(ASYNC_URL).mock(
            side_effect=[
                httpx.Response(200, json=receipt(SCAN_ID)),
                httpx.Response(200, json=receipt(OTHER_SCAN_ID)),
            ]
        )

        def respond(request: httpx.Request) -> httpx.Response:
            scan_id = request.url.params["scan_ids"]
            index = 0 if scan_id == SCAN_ID else 1
            return httpx.Response(200, json=[batch_row(index, scan_id=scan_id)])

        respx.get(RESULTS_URL).mock(side_effect=respond)

        result = run_bulk(tmp_path, "--batch-size", "1")

        assert result.exit_code == 0
        assert submit.call_count == 2
        assert len(json.loads(submit.calls[0].request.content)) == 1


class TestBulkScanResults:
    @respx.mock
    def test_writes_a_results_csv_in_input_order(self, tmp_path: Path) -> None:
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(
                200,
                json=[
                    batch_row(1, action="block", detected={"injection": True}),
                    batch_row(0),
                ],
            )
        )

        result = run_bulk(tmp_path)

        assert result.exit_code == 0
        rows = list(csv.reader((tmp_path / "out.csv").read_text().splitlines()))
        # Rows come back unordered; the CSV must still follow the input file.
        assert [row[0] for row in rows[1:]] == ["first", "second"]
        assert [row[1] for row in rows[1:]] == ["allow", "block"]

    @respx.mock
    def test_the_csv_columns_match_the_reference_client(self, tmp_path: Path) -> None:
        """Downstream reporting reads both clients' files, so the header is a contract."""
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0), batch_row(1)])
        )

        run_bulk(tmp_path)

        rows = list(csv.reader((tmp_path / "out.csv").read_text().splitlines()))
        assert rows[0] == [
            "prompt",
            "action",
            "category",
            "triggered",
            "topic_violation",
            "injection",
            "toxic_content",
            "dlp",
            "url_cats",
            "malicious_code",
            "source_code",
            "agent",
            "scan_id",
            "report_id",
            "error",
        ]
        assert len(rows[1]) == len(rows[0])

    @respx.mock
    def test_records_which_detector_fired(self, tmp_path: Path) -> None:
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(
                200,
                json=[
                    batch_row(0, action="block", detected={"injection": True, "dlp": False}),
                    batch_row(1),
                ],
            )
        )

        run_bulk(tmp_path)

        rows = list(csv.reader((tmp_path / "out.csv").read_text().splitlines()))
        header = rows[0]
        assert rows[1][header.index("injection")] == "true"
        assert rows[1][header.index("dlp")] == "false"
        assert rows[1][header.index("triggered")] == "true"

    @respx.mock
    def test_defaults_the_output_file_to_the_profile_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(return_value=httpx.Response(200, json=[batch_row(0)]))
        monkeypatch.chdir(tmp_path)
        source = tmp_path / "prompts.txt"
        source.write_text("only\n")

        result = runner.invoke(
            app, ["runtime", "bulk-scan", "--profile", "prod guard", "--file", str(source)]
        )

        assert result.exit_code == 0
        assert (tmp_path / "prod-guard-bulk-scan.csv").is_file()

    @respx.mock
    def test_summarises_the_run(self, tmp_path: Path) -> None:
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0), batch_row(1, action="block")])
        )

        result = run_bulk(tmp_path)

        summary = flat(result.output)
        assert "Bulk Scan Complete" in summary
        assert "Total 2" in summary
        assert "Blocked 1" in summary
        assert "Allowed 1" in summary
        assert "Failed 0" in summary
        assert f"Output {tmp_path / 'out.csv'}" in summary

    @respx.mock
    def test_a_failed_prompt_exits_one_and_keeps_the_others(self, tmp_path: Path) -> None:
        """A partial failure must not discard the results that did land."""
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0), batch_row(1, status="failed")])
        )

        result = run_bulk(tmp_path)

        assert result.exit_code == 1
        rows = list(csv.reader((tmp_path / "out.csv").read_text().splitlines()))
        assert [row[1] for row in rows[1:]] == ["allow", "failed"]

    @respx.mock
    def test_a_timed_out_verdict_is_recorded_as_failed(self, tmp_path: Path) -> None:
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        timed_out = batch_row(0)
        timed_out["result"]["timeout"] = True
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[timed_out, batch_row(1)])
        )

        result = run_bulk(tmp_path)

        assert result.exit_code == 1
        rows = list(csv.reader((tmp_path / "out.csv").read_text().splitlines()))
        header = rows[0]
        assert rows[1][1] == "failed"
        assert rows[1][header.index("error")] == "AIRS scan timed out"

    @respx.mock
    def test_falls_back_to_the_threat_report_when_a_row_names_no_request(
        self, tmp_path: Path
    ) -> None:
        """One terminal row for the whole batch carries no req_id, only a report ID."""
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "status": "complete",
                        "scan_id": SCAN_ID,
                        "result": {**ALLOW, "report_id": "R7"},
                    }
                ],
            )
        )
        reports = respx.get(REPORTS_URL).mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "report_id": "R7",
                        "scan_id": SCAN_ID,
                        "req_id": 0,
                        "detection_results": [
                            {"detection_service": "pi", "verdict": "malicious", "action": "block"}
                        ],
                    }
                ],
            )
        )

        result = run_bulk(tmp_path, prompts="only\n")

        assert result.exit_code == 0
        assert reports.calls.last.request.url.params["report_ids"] == "R7"
        rows = list(csv.reader((tmp_path / "out.csv").read_text().splitlines()))
        header = rows[0]
        assert rows[1][1] == "block"
        assert rows[1][header.index("injection")] == "true"


class TestBulkScanState:
    @respx.mock
    def test_leaves_a_loadable_state_file_behind(self, tmp_path: Path) -> None:
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0), batch_row(1)])
        )

        run_bulk(tmp_path)

        state = written_state(tmp_path)
        assert state.profile == "prod"
        assert [item.status for item in state.items] == [BulkScanItemStatus.COMPLETE] * 2
        assert [item.scan_id for item in state.items] == [SCAN_ID, SCAN_ID]

    @respx.mock
    def test_releases_the_lock_when_the_run_finishes(self, tmp_path: Path) -> None:
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0), batch_row(1)])
        )

        run_bulk(tmp_path)

        assert list((tmp_path / "bulk-scans").glob("*.lock")) == []

    @respx.mock
    def test_a_rejected_submission_parks_prompts_as_pending(self, tmp_path: Path) -> None:
        """A 4xx proves nothing was queued, so those prompts are safe to submit again."""
        respx.post(ASYNC_URL).mock(
            return_value=httpx.Response(400, json={"message": "no such profile"})
        )

        result = run_bulk(tmp_path)

        assert result.exit_code == 2
        assert "no such profile" in flat(result.output)
        state = written_state(tmp_path)
        assert [item.status for item in state.items] == [BulkScanItemStatus.PENDING] * 2

    @respx.mock
    def test_an_unreadable_acknowledgement_parks_prompts_as_ambiguous(self, tmp_path: Path) -> None:
        """The batch may well have been queued, so it must not be silently re-submitted."""
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json={"received": "now"}))

        result = run_bulk(tmp_path)

        assert result.exit_code == 2
        state = written_state(tmp_path)
        assert [item.status for item in state.items] == [BulkScanItemStatus.AMBIGUOUS] * 2

    @respx.mock
    def test_gives_up_when_polling_stops_making_progress(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(runtime, "POLL_INTERVAL_SECONDS", 0)
        monkeypatch.setattr(runtime, "MAX_NO_PROGRESS_POLLS", 2)
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        polls = respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[{"req_id": 0, "status": "pending"}])
        )

        result = run_bulk(tmp_path, prompts="only\n")

        assert result.exit_code == 2
        assert polls.call_count == 2
        assert "resolved nothing" in flat(result.output)


class TestBulkScanValidation:
    def test_rejects_a_zero_batch_size(self, tmp_path: Path) -> None:
        result = run_bulk(tmp_path, "--batch-size", "0")

        assert result.exit_code == 2
        assert "--batch-size must be a positive integer" in flat(result.output)

    def test_rejects_an_input_file_with_no_prompts(self, tmp_path: Path) -> None:
        result = run_bulk(tmp_path, prompts="\n   \n")

        assert result.exit_code == 2
        assert "No prompts found" in flat(result.output)

    def test_rejects_a_csv_without_a_prompt_column(self, tmp_path: Path) -> None:
        result = run_bulk(tmp_path, prompts="id,text\n1,hello\n", name="prompts.csv")

        assert result.exit_code == 2
        assert 'No "prompt" column found in CSV header' in flat(result.output)

    def test_rejects_a_missing_input_file(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "runtime",
                "bulk-scan",
                "--profile",
                "prod",
                "--file",
                str(tmp_path / "nope.txt"),
            ],
        )

        assert result.exit_code == 2

    def test_requires_a_profile(self, tmp_path: Path) -> None:
        source = tmp_path / "prompts.txt"
        source.write_text("only\n")

        result = runner.invoke(app, ["runtime", "bulk-scan", "--file", str(source)])

        assert result.exit_code == 2


class TestResults:
    @respx.mock
    def test_queries_the_requested_scan_ids(self) -> None:
        route = respx.get(RESULTS_URL).mock(return_value=httpx.Response(200, json=[batch_row(0)]))

        result = runner.invoke(
            app,
            ["runtime", "results", "--scan-id", SCAN_ID, "--scan-id", OTHER_SCAN_ID],
        )

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "GET"
        assert request.url.params["scan_ids"] == f"{SCAN_ID},{OTHER_SCAN_ID}"

    @respx.mock
    def test_reports_the_verdict_and_the_request_it_belongs_to(self) -> None:
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(3, action="allow")])
        )

        result = runner.invoke(app, ["runtime", "results", "--scan-id", SCAN_ID])

        assert "request 3" in flat(result.output)
        assert "ALLOW" in result.output

    @respx.mock
    def test_a_blocked_verdict_exits_one(self) -> None:
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0), batch_row(1, action="block")])
        )

        result = runner.invoke(app, ["runtime", "results", "--scan-id", SCAN_ID])

        assert result.exit_code == 1

    @respx.mock
    def test_a_pending_row_does_not_gate(self) -> None:
        """No verdict yet is not a block; a partly-finished batch must not fail a build."""
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[{"req_id": 0, "status": "pending"}])
        )

        result = runner.invoke(app, ["runtime", "results", "--scan-id", SCAN_ID])

        assert result.exit_code == 0

    @respx.mock
    def test_json_output_is_parseable(self) -> None:
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0, action="allow")])
        )

        result = runner.invoke(
            app, ["runtime", "results", "--scan-id", SCAN_ID, "--output", "json"]
        )

        assert json.loads(result.output) == [
            {
                "scan_id": SCAN_ID,
                "req_id": "0",
                "status": "complete",
                "action": "allow",
                "category": "benign",
                "report_id": "R1",
                "detections": "",
            }
        ]

    @respx.mock
    def test_an_empty_response_says_so(self) -> None:
        respx.get(RESULTS_URL).mock(return_value=httpx.Response(200, json=[]))

        result = runner.invoke(app, ["runtime", "results", "--scan-id", SCAN_ID])

        assert result.exit_code == 0
        assert "No scan results found" in flat(result.output)

    @respx.mock
    def test_targets_the_regional_endpoint(self) -> None:
        route = respx.get("https://service-de.api.aisecurity.paloaltonetworks.com/v1/scan/results")
        route.mock(return_value=httpx.Response(200, json=[batch_row(0)]))

        result = runner.invoke(app, ["runtime", "results", "--scan-id", SCAN_ID, "--region", "de"])

        assert result.exit_code == 0
        assert route.called

    def test_rejects_a_malformed_scan_id(self) -> None:
        result = runner.invoke(app, ["runtime", "results", "--scan-id", "not-a-uuid"])

        assert result.exit_code == 2
        assert "Invalid scan_id" in flat(result.output)

    def test_rejects_more_ids_than_the_api_accepts(self) -> None:
        ids: list[str] = []
        for index in range(6):
            ids += ["--scan-id", f"1111111{index}-1111-4111-8111-111111111111"]

        result = runner.invoke(app, ["runtime", "results", *ids])

        assert result.exit_code == 2
        assert "Max of 5" in flat(result.output)

    def test_requires_at_least_one_scan_id(self) -> None:
        result = runner.invoke(app, ["runtime", "results"])

        assert result.exit_code == 2

    @respx.mock
    def test_an_api_failure_exits_two(self) -> None:
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(403, json={"message": "Invalid API Key"})
        )

        result = runner.invoke(app, ["runtime", "results", "--scan-id", SCAN_ID])

        assert result.exit_code == 2
        assert "Invalid API Key" in flat(result.output)


REPORT = {
    "report_id": "R1",
    "scan_id": SCAN_ID,
    "req_id": 0,
    "detection_results": [
        {
            "data_type": "prompt",
            "detection_service": "pi",
            "verdict": "malicious",
            "action": "block",
        },
        {
            "data_type": "prompt",
            "detection_service": "dlp",
            "verdict": "benign",
            "action": "allow",
        },
    ],
}


class TestReports:
    @respx.mock
    def test_queries_the_requested_report_ids(self) -> None:
        route = respx.get(REPORTS_URL).mock(return_value=httpx.Response(200, json=[REPORT]))

        result = runner.invoke(
            app, ["runtime", "reports", "--report-id", "R1", "--report-id", "R2"]
        )

        assert result.exit_code == 0
        request = route.calls.last.request
        assert request.method == "GET"
        assert request.url.params["report_ids"] == "R1,R2"

    @respx.mock
    def test_names_every_detection_service(self) -> None:
        respx.get(REPORTS_URL).mock(return_value=httpx.Response(200, json=[REPORT]))

        result = runner.invoke(app, ["runtime", "reports", "--report-id", "R1"])

        assert "Report R1" in flat(result.output)
        assert "malicious" in result.output
        assert "dlp" in result.output
        assert "block" in result.output

    @respx.mock
    def test_csv_output_carries_one_row_per_detection(self) -> None:
        respx.get(REPORTS_URL).mock(return_value=httpx.Response(200, json=[REPORT]))

        result = runner.invoke(app, ["runtime", "reports", "--report-id", "R1", "--output", "csv"])

        rows = list(csv.reader(result.output.strip().splitlines()))
        assert rows[0] == [
            "Report ID",
            "Scan ID",
            "Req ID",
            "Service",
            "Data Type",
            "Verdict",
            "Action",
        ]
        assert [row[3] for row in rows[1:]] == ["pi", "dlp"]
        assert [row[6] for row in rows[1:]] == ["block", "allow"]

    @respx.mock
    def test_does_not_gate_on_a_blocking_detector(self) -> None:
        """Reports are forensic detail, not a verdict -- `runtime results` is the gate."""
        respx.get(REPORTS_URL).mock(return_value=httpx.Response(200, json=[REPORT]))

        result = runner.invoke(app, ["runtime", "reports", "--report-id", "R1"])

        assert result.exit_code == 0

    @respx.mock
    def test_an_empty_response_says_so(self) -> None:
        respx.get(REPORTS_URL).mock(return_value=httpx.Response(200, json=[]))

        result = runner.invoke(app, ["runtime", "reports", "--report-id", "R1"])

        assert result.exit_code == 0
        assert "No threat reports found" in flat(result.output)

    def test_requires_at_least_one_report_id(self) -> None:
        result = runner.invoke(app, ["runtime", "reports"])

        assert result.exit_code == 2

    @respx.mock
    def test_an_api_failure_exits_two(self) -> None:
        respx.get(REPORTS_URL).mock(
            return_value=httpx.Response(404, json={"message": "no such report"})
        )

        result = runner.invoke(app, ["runtime", "reports", "--report-id", "R1"])

        assert result.exit_code == 2
        assert "no such report" in flat(result.output)


# ---------------------------------------------------------------------------
# runtime resume-poll -- finishing a bulk scan that was interrupted
# ---------------------------------------------------------------------------


def stored_result(index: int, prompt: str, *, scan_id: str = SCAN_ID) -> BulkScanResult:
    """Build the verdict a previous run would have recorded for one prompt."""
    return BulkScanResult(
        index=index,
        req_id=index,
        prompt=prompt,
        scan_id=scan_id,
        report_id="R1",
        action="allow",
        category="benign",
        triggered=False,
        detections={},
    )


def item(
    index: int, prompt: str, status: BulkScanItemStatus, *, scan_id: str = SCAN_ID
) -> BulkScanItemState:
    """Build one state-file entry in the given status, with whatever that status requires."""
    needs_scan_id = status in (
        BulkScanItemStatus.SUBMITTED,
        BulkScanItemStatus.COMPLETE,
        BulkScanItemStatus.FAILED,
    )
    return BulkScanItemState(
        index=index,
        req_id=index,
        prompt=prompt,
        status=status,
        scan_id=scan_id if needs_scan_id else None,
        result=(
            stored_result(index, prompt, scan_id=scan_id)
            if status is BulkScanItemStatus.COMPLETE
            else None
        ),
    )


def write_state(
    tmp_path: Path, items: list[BulkScanItemState], *, output: Path | None = None
) -> Path:
    """Persist a bulk-scan state file the way an interrupted run would have left it."""
    path = tmp_path / "run.bulk-scan.json"
    save_state(
        BulkScanState(
            profile="prod",
            session_id="resumed-session",
            output_file=str(output or tmp_path / "out.csv"),
            batch_size=25,
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-01-01T00:00:00Z",
            items=items,
        ),
        path,
    )
    return path


def results_by_scan_id(mapping: dict[str, list[dict[str, Any]]]) -> Any:
    """Answer a results query with the rows belonging to the scan ID it asked for."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=mapping[request.url.params["scan_ids"]])

    return respond


class TestResumePoll:
    @respx.mock
    def test_collects_a_receipt_already_on_file_without_resubmitting(self, tmp_path: Path) -> None:
        submit = respx.post(ASYNC_URL)
        poll = respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0), batch_row(1)])
        )
        state_path = write_state(
            tmp_path,
            [
                item(0, "first", BulkScanItemStatus.SUBMITTED),
                item(1, "second", BulkScanItemStatus.SUBMITTED),
            ],
        )

        result = runner.invoke(app, ["runtime", "resume-poll", str(state_path)])

        assert result.exit_code == 0
        assert not submit.called, "prompts already accepted must never be scanned twice"
        assert poll.calls.last.request.url.params["scan_ids"] == SCAN_ID
        rows = list(csv.reader((tmp_path / "out.csv").read_text().splitlines()))
        assert [row[0] for row in rows[1:]] == ["first", "second"]

    @respx.mock
    def test_submits_only_the_prompts_that_were_never_accepted(self, tmp_path: Path) -> None:
        submit = respx.post(ASYNC_URL).mock(
            return_value=httpx.Response(200, json=receipt(OTHER_SCAN_ID))
        )
        respx.get(RESULTS_URL).mock(
            side_effect=results_by_scan_id({OTHER_SCAN_ID: [batch_row(1, scan_id=OTHER_SCAN_ID)]})
        )
        state_path = write_state(
            tmp_path,
            [
                item(0, "first", BulkScanItemStatus.COMPLETE),
                item(1, "second", BulkScanItemStatus.PENDING),
            ],
        )

        result = runner.invoke(app, ["runtime", "resume-poll", str(state_path)])

        assert result.exit_code == 0
        body = json.loads(submit.calls.last.request.content)
        assert [entry["req_id"] for entry in body] == [1]
        assert body[0]["scan_req"]["contents"][0]["prompt"] == "second"
        assert body[0]["scan_req"]["ai_profile"]["profile_name"] == "prod"
        assert body[0]["scan_req"]["session_id"] == "resumed-session"
        rows = list(csv.reader((tmp_path / "out.csv").read_text().splitlines()))
        assert [row[0] for row in rows[1:]] == ["first", "second"]

    @pytest.mark.parametrize(
        "status", [BulkScanItemStatus.AMBIGUOUS, BulkScanItemStatus.SUBMITTING]
    )
    @respx.mock
    def test_refuses_to_resubmit_a_prompt_whose_fate_is_unknown(
        self, tmp_path: Path, status: BulkScanItemStatus
    ) -> None:
        """The service may already have scanned it; a duplicate scan cannot be undone."""
        submit = respx.post(ASYNC_URL)
        state_path = write_state(
            tmp_path,
            [item(0, "first", BulkScanItemStatus.COMPLETE), item(1, "second", status)],
        )

        result = runner.invoke(app, ["runtime", "resume-poll", str(state_path)])

        assert result.exit_code == 2
        assert not submit.called
        assert "Cannot safely resubmit prompt 1" in flat(result.output)
        rows = list(csv.reader((tmp_path / "out.csv").read_text().splitlines()))
        assert [row[0] for row in rows[1:]] == ["first"], "known verdicts must be preserved"

    @respx.mock
    def test_writes_to_the_output_file_the_state_recorded(self, tmp_path: Path) -> None:
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(return_value=httpx.Response(200, json=[batch_row(0)]))
        recorded = tmp_path / "recorded.csv"
        state_path = write_state(
            tmp_path, [item(0, "first", BulkScanItemStatus.PENDING)], output=recorded
        )

        result = runner.invoke(app, ["runtime", "resume-poll", str(state_path)])

        assert result.exit_code == 0
        assert list(csv.reader(recorded.read_text().splitlines()))[1][0] == "first"

    @respx.mock
    def test_the_output_file_flag_overrides_the_recorded_path(self, tmp_path: Path) -> None:
        respx.post(ASYNC_URL).mock(return_value=httpx.Response(200, json=receipt()))
        respx.get(RESULTS_URL).mock(return_value=httpx.Response(200, json=[batch_row(0)]))
        state_path = write_state(
            tmp_path, [item(0, "first", BulkScanItemStatus.PENDING)], output=tmp_path / "old.csv"
        )
        elsewhere = tmp_path / "new.csv"

        result = runner.invoke(
            app, ["runtime", "resume-poll", str(state_path), "--output-file", str(elsewhere)]
        )

        assert result.exit_code == 0
        assert list(csv.reader(elsewhere.read_text().splitlines()))[1][0] == "first"
        reloaded = load_state(state_path)
        assert reloaded is not None
        assert reloaded.output_file == str(elsewhere)

    @respx.mock
    def test_a_failed_prompt_exits_one(self, tmp_path: Path) -> None:
        respx.get(RESULTS_URL).mock(
            return_value=httpx.Response(200, json=[batch_row(0, status="failed")])
        )
        state_path = write_state(tmp_path, [item(0, "first", BulkScanItemStatus.SUBMITTED)])

        result = runner.invoke(app, ["runtime", "resume-poll", str(state_path)])

        assert result.exit_code == 1
        assert "Resume Poll Complete" in flat(result.output)

    def test_rejects_a_missing_state_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["runtime", "resume-poll", str(tmp_path / "absent.json")])

        assert result.exit_code == 2
        assert "No bulk-scan state file" in flat(result.output)

    def test_rejects_a_state_file_it_cannot_trust(self, tmp_path: Path) -> None:
        """A half-written state file decides what gets re-submitted; guessing is not safe."""
        broken = tmp_path / "run.bulk-scan.json"
        broken.write_text("{not json")

        result = runner.invoke(app, ["runtime", "resume-poll", str(broken)])

        assert result.exit_code == 2
        assert "not valid JSON" in flat(result.output)

    @respx.mock
    def test_refuses_while_another_process_holds_the_state_file(self, tmp_path: Path) -> None:
        submit = respx.post(ASYNC_URL)
        state_path = write_state(tmp_path, [item(0, "first", BulkScanItemStatus.PENDING)])
        lock = state_path.with_name(state_path.name + ".lock")
        lock.write_text(
            json.dumps(
                {
                    "version": 1,
                    "pid": os.getpid(),
                    "createdAt": "2026-01-01T00:00:00Z",
                    "token": "held-elsewhere",
                }
            )
        )

        result = runner.invoke(app, ["runtime", "resume-poll", str(state_path)])

        assert result.exit_code == 2
        assert not submit.called
        assert "Another bulk scan" in flat(result.output)
