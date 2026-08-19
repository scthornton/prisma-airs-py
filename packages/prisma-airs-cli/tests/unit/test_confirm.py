"""Confirmation before destructive commands."""

from __future__ import annotations

import pytest
import typer

from prisma_airs_cli.confirm import confirm_or_abort
from prisma_airs_cli.exit_codes import EXIT_ERROR, EXIT_OK


class Recorder:
    """A stand-in prompt that records what it was asked and returns a fixed answer."""

    def __init__(self, answer: bool) -> None:
        self.answer = answer
        self.messages: list[str] = []

    def __call__(self, message: str) -> bool:
        self.messages.append(message)
        return self.answer


def test_force_skips_the_prompt_entirely() -> None:
    prompt = Recorder(answer=True)

    confirm_or_abort("delete everything?", force=True, prompt=prompt)

    assert prompt.messages == []


class TestNonInteractive:
    def test_refuses_rather_than_assuming_yes(self) -> None:
        """A CI job that forgot --force gets an error it can fix, not a deletion."""
        with pytest.raises(typer.Exit) as caught:
            confirm_or_abort("delete?", force=False, is_tty=False)

        assert caught.value.exit_code == EXIT_ERROR

    def test_names_the_action_in_the_refusal(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit):
            confirm_or_abort("delete?", force=False, action="delete 12 profiles", is_tty=False)

        assert "delete 12 profiles" in capsys.readouterr().err

    def test_never_calls_the_prompt(self) -> None:
        """There is nobody to answer, so asking would hang a pipeline."""
        prompt = Recorder(answer=True)

        with pytest.raises(typer.Exit):
            confirm_or_abort("delete?", force=False, is_tty=False, prompt=prompt)

        assert prompt.messages == []


class TestInteractive:
    def test_proceeds_when_confirmed(self) -> None:
        confirm_or_abort("delete?", force=False, is_tty=True, prompt=Recorder(answer=True))

    def test_declining_exits_zero(self) -> None:
        """Changing your mind is a valid outcome, not a failure the shell should flag."""
        with pytest.raises(typer.Exit) as caught:
            confirm_or_abort("delete?", force=False, is_tty=True, prompt=Recorder(answer=False))

        assert caught.value.exit_code == EXIT_OK

    def test_puts_the_message_to_the_user(self) -> None:
        prompt = Recorder(answer=True)

        confirm_or_abort("Delete 3 profiles?", force=False, is_tty=True, prompt=prompt)

        assert prompt.messages == ["Delete 3 profiles?"]

    def test_reports_the_abort(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(typer.Exit):
            confirm_or_abort("delete?", force=False, is_tty=True, prompt=Recorder(answer=False))

        assert "Aborted" in capsys.readouterr().out
