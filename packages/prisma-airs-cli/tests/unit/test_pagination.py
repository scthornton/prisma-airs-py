"""Limit and offset translated into each API's pagination vocabulary."""

from __future__ import annotations

import pytest
import typer

from prisma_airs_cli.pagination import DEFAULT_PAGE_SIZE, resolve_page_params


class TestPassThrough:
    def test_no_arguments_means_let_the_api_decide(self) -> None:
        result = resolve_page_params(None, None)

        assert (result.page, result.size) == (None, None)

    def test_a_limit_alone_sets_only_the_size(self) -> None:
        """Without an offset there is no page to compute."""
        result = resolve_page_params(25, None)

        assert (result.page, result.size) == (None, 25)


class TestOffsetConversion:
    @pytest.mark.parametrize(
        ("limit", "offset", "expected_page"),
        [(25, 0, 0), (25, 25, 1), (25, 50, 2), (10, 95, 9)],
    )
    def test_converts_offset_to_a_zero_based_page(
        self, limit: int, offset: int, expected_page: int
    ) -> None:
        assert resolve_page_params(limit, offset).page == expected_page

    def test_honours_a_one_based_api(self) -> None:
        """Some planes number the first page 1; off-by-one here silently skips a page."""
        assert resolve_page_params(25, 25, index_base=1).page == 2

    def test_uses_the_fallback_size_when_no_limit_is_given(self) -> None:
        assert resolve_page_params(None, DEFAULT_PAGE_SIZE * 3).page == 3

    def test_a_partial_offset_floors_to_the_containing_page(self) -> None:
        assert resolve_page_params(25, 30).page == 1

    def test_a_zero_limit_does_not_divide_by_zero(self) -> None:
        """`--limit 0` is legal input and must not crash the command."""
        assert resolve_page_params(0, 100).page == 100 // DEFAULT_PAGE_SIZE


class TestRejection:
    @pytest.mark.parametrize(("limit", "offset"), [(-1, None), (None, -1)])
    def test_rejects_negative_values(self, limit: int | None, offset: int | None) -> None:
        """Clamping to zero would hide a bug in whatever computed the value."""
        with pytest.raises(typer.Exit):
            resolve_page_params(limit, offset)
