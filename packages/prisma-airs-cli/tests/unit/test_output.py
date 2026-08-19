"""Output formatting across the five supported formats."""

from __future__ import annotations

import csv
import io
import json

import pytest
import yaml

from prisma_airs_cli.output import Column, OutputFormat, format_output

COLUMNS = [Column("name", "Name"), Column("action", "Action")]
ROWS = [
    {"name": "prod", "action": "allow", "secret": "not-a-column"},
    {"name": "staging", "action": "block", "secret": "nor-this"},
]


@pytest.mark.parametrize("fmt", list(OutputFormat))
def test_an_empty_result_set_renders_as_nothing(fmt: OutputFormat) -> None:
    """A pipeline should see no output rather than a bare header it must special-case."""
    assert format_output([], COLUMNS, fmt) == ""


class TestJson:
    def test_emits_a_parseable_array(self) -> None:
        parsed = json.loads(format_output(ROWS, COLUMNS, OutputFormat.JSON))

        assert parsed == [
            {"name": "prod", "action": "allow"},
            {"name": "staging", "action": "block"},
        ]

    def test_drops_fields_outside_the_column_list(self) -> None:
        """Columns are the contract; a row carrying more must not leak it."""
        parsed = json.loads(format_output(ROWS, COLUMNS, OutputFormat.JSON))

        assert "secret" not in parsed[0]

    def test_uses_keys_not_labels(self) -> None:
        """JSON is consumed by machines, so the stable key wins over the human label."""
        parsed = json.loads(
            format_output(ROWS, [Column("name", "Display Name")], OutputFormat.JSON)
        )

        assert "name" in parsed[0]
        assert "Display Name" not in parsed[0]


class TestCsv:
    def test_writes_a_header_of_labels(self) -> None:
        rows = list(csv.reader(io.StringIO(format_output(ROWS, COLUMNS, OutputFormat.CSV))))

        assert rows[0] == ["Name", "Action"]

    def test_writes_one_line_per_row(self) -> None:
        rows = list(csv.reader(io.StringIO(format_output(ROWS, COLUMNS, OutputFormat.CSV))))

        assert rows[1:] == [["prod", "allow"], ["staging", "block"]]

    def test_quotes_a_value_containing_a_comma(self) -> None:
        """Otherwise one prompt with a comma silently becomes two columns."""
        rows = [{"name": "a,b", "action": "allow"}]

        parsed = list(csv.reader(io.StringIO(format_output(rows, COLUMNS, OutputFormat.CSV))))

        assert parsed[1] == ["a,b", "allow"]

    def test_escapes_an_embedded_quote(self) -> None:
        rows = [{"name": 'say "hi"', "action": "allow"}]

        parsed = list(csv.reader(io.StringIO(format_output(rows, COLUMNS, OutputFormat.CSV))))

        assert parsed[1] == ['say "hi"', "allow"]

    def test_renders_a_missing_value_as_empty(self) -> None:
        parsed = list(
            csv.reader(io.StringIO(format_output([{"name": "x"}], COLUMNS, OutputFormat.CSV)))
        )

        assert parsed[1] == ["x", ""]


class TestYaml:
    def test_emits_one_document_per_row(self) -> None:
        documents = list(yaml.safe_load_all(format_output(ROWS, COLUMNS, OutputFormat.YAML)))

        assert documents == [
            {"name": "prod", "action": "allow"},
            {"name": "staging", "action": "block"},
        ]

    def test_round_trips_a_value_that_would_break_naive_yaml(self) -> None:
        """Hand-rolled `key: value` output mangles colons; a real dumper does not."""
        rows = [{"name": "a: b", "action": "allow"}]

        documents = list(yaml.safe_load_all(format_output(rows, COLUMNS, OutputFormat.YAML)))

        assert documents[0]["name"] == "a: b"


class TestTable:
    def test_pads_columns_to_the_widest_cell(self) -> None:
        lines = format_output(ROWS, COLUMNS, OutputFormat.TABLE).splitlines()

        assert len({len(line) for line in lines}) == 1

    def test_includes_a_header_and_a_rule(self) -> None:
        lines = format_output(ROWS, COLUMNS, OutputFormat.TABLE).splitlines()

        assert "Name" in lines[0]
        assert set(lines[1]) <= {"─", "┼"}

    def test_emits_one_line_per_row_after_the_rule(self) -> None:
        lines = format_output(ROWS, COLUMNS, OutputFormat.TABLE).splitlines()

        assert len(lines) == len(ROWS) + 2


def test_pretty_is_left_to_each_command() -> None:
    """Pretty output depends on the shape of the data, so the generic formatter declines."""
    assert format_output(ROWS, COLUMNS, OutputFormat.PRETTY) == ""
