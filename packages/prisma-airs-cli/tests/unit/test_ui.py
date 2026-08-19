"""Console output conventions: stream discipline and quiet mode."""

from __future__ import annotations

import pytest

from prisma_airs_cli.output import Column
from prisma_airs_cli.ui import Ui


@pytest.fixture
def ui() -> Ui:
    """A fresh writer, so quiet state never leaks between tests."""
    return Ui()


class TestStreamDiscipline:
    def test_errors_go_to_stderr(self, ui: Ui, capsys: pytest.CaptureFixture[str]) -> None:
        """So `airs ... --json | jq` never receives an error line as data."""
        ui.error("it broke")

        captured = capsys.readouterr()
        assert "it broke" in captured.err
        assert "it broke" not in captured.out

    def test_progress_goes_to_stderr(self, ui: Ui, capsys: pytest.CaptureFixture[str]) -> None:
        ui.status("scanning 3 of 40")

        captured = capsys.readouterr()
        assert "scanning" in captured.err
        assert captured.out == ""

    def test_results_go_to_stdout(self, ui: Ui, capsys: pytest.CaptureFixture[str]) -> None:
        ui.table([Column("name", "Name")], [{"name": "prod"}])

        assert "prod" in capsys.readouterr().out


class TestQuietMode:
    def test_suppresses_commentary(self, ui: Ui, capsys: pytest.CaptureFixture[str]) -> None:
        ui.set_quiet(True)

        ui.header("Doctor")
        ui.info("checking credentials")
        ui.dim("using ~/.prisma-airs")
        ui.status("connecting")

        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_never_suppresses_errors(self, ui: Ui, capsys: pytest.CaptureFixture[str]) -> None:
        """Quiet means less noise, not less signal."""
        ui.set_quiet(True)

        ui.error("credentials rejected")

        assert "credentials rejected" in capsys.readouterr().err

    def test_never_suppresses_warnings(self, ui: Ui, capsys: pytest.CaptureFixture[str]) -> None:
        ui.set_quiet(True)

        ui.warn("3 items still ambiguous")

        assert "ambiguous" in capsys.readouterr().out

    def test_never_suppresses_results(self, ui: Ui, capsys: pytest.CaptureFixture[str]) -> None:
        ui.set_quiet(True)

        ui.table([Column("name", "Name")], [{"name": "prod"}])

        assert "prod" in capsys.readouterr().out


class TestReadability:
    @pytest.mark.parametrize(
        ("method", "word"),
        [("success", "done"), ("warn", "careful"), ("error", "broken"), ("info", "noted")],
    )
    def test_every_message_carries_its_words_not_just_a_glyph(
        self, ui: Ui, capsys: pytest.CaptureFixture[str], method: str, word: str
    ) -> None:
        """Output has to survive a pipe, a CI log, and a colour-blind reader."""
        getattr(ui, method)(word)

        captured = capsys.readouterr()
        assert word in captured.out + captured.err

    def test_key_value_aligns_on_the_longest_key(
        self, ui: Ui, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ui.key_value([("ID", "abc"), ("Report ID", "xyz")])

        lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
        assert lines[0].index("abc") == lines[1].index("xyz")

    def test_renders_none_as_empty_rather_than_the_word_none(
        self, ui: Ui, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ui.key_value([("Profile", None)])

        assert "None" not in capsys.readouterr().out

    def test_an_empty_list_reads_as_success_not_failure(
        self, ui: Ui, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ui.empty_list("profiles")

        assert "No profiles found" in capsys.readouterr().out
