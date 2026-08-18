"""Contract tests for the DLP administration clients.

Each call is checked against the exact request it puts on the wire -- method, URL, query,
headers, and body. Asserting only on the parsed response would pass just as happily
against the wrong endpoint, the wrong content type, or a flag spelled ``True`` instead of
``true``.
"""

from __future__ import annotations

import json
import random
import re
from collections.abc import Iterator
from typing import Any, NamedTuple

import httpx
import pytest
import respx

from prisma_airs.constants import (
    DEFAULT_DLP_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
    MAX_NUMBER_OF_RETRIES,
)
from prisma_airs.dlp.dlp import DlpClient
from prisma_airs.errors import AISecMissingVariableError, AISecPayloadError, AISecServerError
from prisma_airs.models.dlp import (
    AdvancedDataProfileRequest,
    DataFilteringProfileRequest,
    DataPatternDetectionConfig,
    DataPatternMatchingRules,
    DataPatternPatchRequest,
    DataPatternRequest,
    DataPatternTechnique,
    DataPatternType,
    DataProfilePatchRequest,
    DataProfileType,
    DefaultTreeDetectionRule,
    DetectionRuleItem,
    DictionaryCategory,
    DictionaryPatchRequest,
    DictionaryRequest,
    DictionaryType,
    ExpressionOperatorType,
    ExpressionTreeNode,
    FilteringDirection,
    LogSeverity,
    MultiProfileDataNode,
    MultiProfileDetectionRule,
    RuleItemDetectionTechnique,
    RuleItemMatchType,
    WeightedRegex,
)

BASE = DEFAULT_DLP_ENDPOINT
PATTERNS_URL = f"{BASE}/v2/api/data-patterns"
PROFILES_URL = f"{BASE}/v2/api/data-profiles"
FILTERING_URL = f"{BASE}/v2/api/data-filtering-profiles"
DICTIONARIES_URL = f"{BASE}/v2/api/dictionaries"

TOKEN = "tok-1"

PATTERN = {"id": "dp-1", "name": "SSN", "type": "custom", "status": "active"}
PROFILE = {"id": "prof-1", "name": "Confidential", "profile_type": "advanced"}
FILTERING_PROFILE = {"id": "dfp-1", "name": "Finance", "file_based": True, "non_file_based": False}
DICTIONARY = {"id": "dict-1", "name": "PII", "category": "Confidential", "type": "custom"}


def page(item: dict[str, Any]) -> dict[str, Any]:
    """One Spring Page envelope holding a single item."""
    return {
        "content": [item],
        "totalElements": 1,
        "totalPages": 1,
        "number": 0,
        "size": 20,
        "first": True,
        "last": True,
    }


def pattern_request() -> DataPatternRequest:
    return DataPatternRequest(
        name="example-pattern",
        type=DataPatternType.CUSTOM,
        detection_config=DataPatternDetectionConfig(technique=DataPatternTechnique.REGEX),
        matching_rules=DataPatternMatchingRules(
            regexes=[WeightedRegex(regex=r"\bexample\b", weight=1.0)]
        ),
    )


PATTERN_BODY = {
    "name": "example-pattern",
    "type": "custom",
    "detection_config": {"technique": "regex"},
    "matching_rules": {"regexes": [{"regex": "\\bexample\\b", "weight": 1.0}]},
}


def profile_request() -> AdvancedDataProfileRequest:
    return AdvancedDataProfileRequest(
        name="example-profile",
        detection_rules=[
            DefaultTreeDetectionRule(
                rule_type="expression_tree",
                expression_tree=ExpressionTreeNode(
                    operator_type=ExpressionOperatorType.AND,
                    rule_item=DetectionRuleItem(
                        detection_technique=RuleItemDetectionTechnique.REGEX,
                        match_type=RuleItemMatchType.INCLUDE,
                    ),
                ),
            )
        ],
    )


PROFILE_BODY = {
    "name": "example-profile",
    "detection_rules": [
        {
            "rule_type": "expression_tree",
            "expression_tree": {
                "operator_type": "and",
                "rule_item": {"detection_technique": "regex", "match_type": "include"},
            },
        }
    ],
}


def dictionary_request() -> DictionaryRequest:
    return DictionaryRequest(
        category=DictionaryCategory.CONFIDENTIAL,
        name="PII",
        original_file_name="keywords.txt",
        region_name="us-west-2",
        type=DictionaryType.CUSTOM,
    )


DICTIONARY_METADATA = {
    "category": "Confidential",
    "name": "PII",
    "original_file_name": "keywords.txt",
    "region_name": "us-west-2",
    "type": "custom",
}


class Part(NamedTuple):
    """One part of a multipart body."""

    name: str
    filename: str
    content_type: str
    body: bytes


def multipart_parts(request: httpx.Request) -> list[Part]:
    """Split a multipart request body into its parts, in the order they were written."""
    boundary = request.headers["content-type"].partition("boundary=")[2]
    parts: list[Part] = []
    for chunk in request.content.split(f"--{boundary}".encode())[1:-1]:
        head, _, body = chunk.lstrip(b"\r\n").partition(b"\r\n\r\n")
        headers: dict[str, str] = {}
        for line in head.decode().splitlines():
            key, _, value = line.partition(": ")
            headers[key.lower()] = value
        disposition = headers["content-disposition"]
        parts.append(
            Part(
                name=quoted_value(disposition, "name"),
                filename=quoted_value(disposition, "filename"),
                content_type=headers.get("content-type", ""),
                body=body.removesuffix(b"\r\n"),
            )
        )
    return parts


def quoted_value(disposition: str, key: str) -> str:
    """Pull ``key="..."`` out of a Content-Disposition header."""
    found = re.search(rf'{key}="([^"]*)"', disposition)
    return "" if found is None else found.group(1)


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    """A router with the OAuth token endpoint stubbed; every DLP call fetches one first."""
    with respx.mock(assert_all_called=False) as router:
        router.post(DEFAULT_TOKEN_ENDPOINT, name="token").mock(
            return_value=httpx.Response(200, json={"access_token": TOKEN, "expires_in": 900})
        )
        yield router


@pytest.fixture
def no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Collapse the retry backoff so a full-budget run costs milliseconds, not seconds.

    ``execute_with_retry`` binds ``time.sleep`` as a default argument and so cannot be
    replaced, but ``backoff_delay_ms`` resolves ``random.uniform`` at call time. Zeroing
    the jitter leaves the retry *count* -- the thing under test -- untouched.
    """
    monkeypatch.setattr(random, "uniform", lambda _low, _high: 0.0)


def build_client(**overrides: Any) -> DlpClient:
    """A client on working credentials, with room to vary one thing at a time."""
    return DlpClient(
        **{
            "client_id": "cid",
            "client_secret": "csecret",
            "tsg_id": "1016244978",
            "num_retries": 0,
            **overrides,
        }
    )


@pytest.fixture
def dlp(api: respx.MockRouter) -> Iterator[DlpClient]:
    client = build_client()
    yield client
    client.close()


class TestConstruction:
    def test_defaults_to_the_dlp_host(self, dlp: DlpClient) -> None:
        """DLP does not live on the management host, so it carries its own base URL."""
        assert dlp.endpoint == "https://api.dlp.paloaltonetworks.com"

    def test_an_explicit_endpoint_wins(self, api: respx.MockRouter) -> None:
        route = api.get("https://dlp.internal/v2/api/data-patterns").mock(
            return_value=httpx.Response(200, json=page(PATTERN))
        )

        with build_client(endpoint="https://dlp.internal") as client:
            client.data_patterns.list()

        assert route.called

    def test_requires_management_credentials(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("CLIENT_ID", "CLIENT_SECRET", "TSG_ID"):
            monkeypatch.delenv(f"PANW_MGMT_{name}", raising=False)

        with pytest.raises(AISecMissingVariableError) as caught:
            DlpClient()

        assert "PANW_MGMT_CLIENT_ID" in str(caught.value)

    def test_names_the_management_prefix_only_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DLP has no prefix of its own, so there is no second prefix to suggest."""
        for name in ("CLIENT_ID", "CLIENT_SECRET", "TSG_ID"):
            monkeypatch.delenv(f"PANW_MGMT_{name}", raising=False)

        with pytest.raises(AISecMissingVariableError) as caught:
            DlpClient()

        assert str(caught.value).count("PANW_MGMT_CLIENT_ID") == 1

    def test_reads_the_management_prefix_from_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "env-id")
        monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "env-secret")
        monkeypatch.setenv("PANW_MGMT_TSG_ID", "env-tsg")

        with DlpClient() as client:
            assert client.oauth.tsg_id == "env-tsg"

    @pytest.mark.parametrize("value", [-1, 6, 1.5, True])
    def test_rejects_an_unusable_retry_count(self, value: object) -> None:
        """The reference clamps silently; this SDK rejects, matching its own scanner."""
        with pytest.raises(AISecPayloadError, match="num_retries"):
            build_client(num_retries=value)

    def test_fetches_one_token_for_every_subclient(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        """All four resources sit behind one token manager, not four."""
        patterns = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))
        dictionaries = api.get(DICTIONARIES_URL).mock(
            return_value=httpx.Response(200, json=page(DICTIONARY))
        )

        dlp.data_patterns.list()
        dlp.dictionaries.list()

        assert api["token"].call_count == 1
        assert patterns.calls.last.request.headers["authorization"] == f"Bearer {TOKEN}"
        assert dictionaries.calls.last.request.headers["authorization"] == f"Bearer {TOKEN}"

    def test_sends_no_tenant_header(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        """DLP is not the AI Gateway: x-tsg-id belongs to the token scope, not the request."""
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        dlp.data_patterns.list()

        assert "x-tsg-id" not in route.calls.last.request.headers


class TestRetryBudget:
    """The constructor's retry count has to survive the trip to each subclient.

    Nothing else in the suite would notice it going missing: every other test stubs a 2xx,
    and a 2xx is returned on the first attempt whatever the budget says. Only a 5xx makes
    the count observable.
    """

    @pytest.mark.parametrize(("requested", "attempts"), [(0, 1), (2, 3), (5, 6)])
    def test_honours_the_requested_count(
        self, api: respx.MockRouter, no_backoff: None, requested: int, attempts: int
    ) -> None:
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(500, json={}))

        with build_client(num_retries=requested) as client, pytest.raises(AISecServerError):
            client.data_patterns.list()

        assert route.call_count == attempts

    def test_defaults_to_the_full_budget(self, api: respx.MockRouter, no_backoff: None) -> None:
        """An unspecified count is five retries, not zero: silently dropping the budget
        would turn a transient 500 into a hard failure."""
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(500, json={}))

        with (
            DlpClient(client_id="cid", client_secret="csecret", tsg_id="1016244978") as client,
            pytest.raises(AISecServerError),
        ):
            client.data_patterns.list()

        assert route.call_count == MAX_NUMBER_OF_RETRIES + 1

    @pytest.mark.parametrize(
        ("resource", "url"),
        [
            ("data_patterns", PATTERNS_URL),
            ("data_profiles", PROFILES_URL),
            ("data_filtering_profiles", FILTERING_URL),
            ("dictionaries", DICTIONARIES_URL),
        ],
    )
    def test_reaches_every_subclient(
        self, api: respx.MockRouter, no_backoff: None, resource: str, url: str
    ) -> None:
        """Each of the four is constructed by hand, so each is a place the count can be
        dropped or hardcoded without any other test noticing."""
        route = api.get(url).mock(return_value=httpx.Response(500, json={}))

        with build_client(num_retries=1) as client, pytest.raises(AISecServerError):
            getattr(client, resource).list()

        assert route.call_count == 2


class TestConnectionOwnership:
    def test_the_token_fetch_rides_the_same_client(self, api: respx.MockRouter) -> None:
        """One pool for the token and the resource calls alike.

        The token manager is built internally, so nothing outside this test proves it was
        handed the caller's client rather than one of its own -- respx patches every httpx
        client, so a private pool would still answer. A default header set on the supplied
        client is the observable difference: only requests sent through *that* client carry
        it.
        """
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        with httpx.Client(headers={"x-probe": "shared"}) as supplied:
            with build_client(http_client=supplied) as client:
                client.data_patterns.list()

            assert not supplied.is_closed, "a supplied client stays the caller's to close"

        assert api["token"].calls.last.request.headers.get("x-probe") == "shared"
        assert route.calls.last.request.headers.get("x-probe") == "shared"

    def test_close_shuts_the_pool_it_created(self, api: respx.MockRouter) -> None:
        """The other half of the same bargain: what this client opened, it closes."""
        api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))
        client = build_client()

        client.data_patterns.list()
        client.close()

        with pytest.raises(RuntimeError, match="closed"):
            client.data_patterns.list()


class TestPaginationQuery:
    def test_builds_the_page_and_size_query(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        dlp.data_patterns.list(page=2, size=50)

        assert dict(route.calls.last.request.url.params) == {"page": "2", "size": "50"}

    def test_asks_for_page_zero_explicitly(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        """Page 0 is the first page, not an absent value: a truthiness test would drop it."""
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        dlp.data_patterns.list(page=0)

        assert route.calls.last.request.url.params["page"] == "0"

    def test_repeats_the_sort_key_once_per_entry(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        """Each entry is itself ``property,direction``, so they cannot be comma-joined."""
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        dlp.data_patterns.list(sort=["name,asc", "type,desc"])

        sent = route.calls.last.request
        assert sent.url.params.get_list("sort") == ["name,asc", "type,desc"]
        assert sent.url.query.decode() == "sort=name%2Casc&sort=type%2Cdesc"

    def test_sends_no_query_when_nothing_is_set(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        """Omitted parameters leave the server's own defaults in charge."""
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        dlp.data_patterns.list()

        assert route.calls.last.request.url.query == b""

    def test_rejects_a_bare_string_sort(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        """A string is a sequence of characters, so this would become one key per letter."""
        with pytest.raises(AISecPayloadError, match="sort"):
            dlp.data_patterns.list(sort="name,asc")

        assert not api.calls


class TestResourceIdHandling:
    @pytest.mark.parametrize("blank", ["", "   "])
    def test_every_resource_rejects_a_blank_id(
        self, dlp: DlpClient, api: respx.MockRouter, blank: str
    ) -> None:
        """A blank id collapses the item path onto the collection endpoint."""
        for fetch in (
            dlp.data_patterns.get,
            dlp.data_profiles.get,
            dlp.data_filtering_profiles.get,
            dlp.dictionaries.get,
        ):
            with pytest.raises(AISecPayloadError, match="resource_id"):
                fetch(blank)

        assert not api.calls

    def test_percent_encodes_the_id_into_one_path_segment(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        """An id carrying a slash must not grow the path a segment."""
        route = api.get(f"{PATTERNS_URL}/dp%2F1%20x").mock(
            return_value=httpx.Response(200, json=PATTERN)
        )

        dlp.data_patterns.get("dp/1 x")

        assert route.calls.last.request.url.raw_path == b"/v2/api/data-patterns/dp%2F1%20x"


class TestDataPatterns:
    def test_lists_from_the_data_patterns_path(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.get(PATTERNS_URL).mock(return_value=httpx.Response(200, json=page(PATTERN)))

        result = dlp.data_patterns.list()

        sent = route.calls.last.request
        assert (sent.method, str(sent.url)) == ("GET", PATTERNS_URL)
        assert result.total_elements == 1
        assert result.content[0].id == "dp-1"

    def test_creates_from_the_request_model(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.post(PATTERNS_URL).mock(return_value=httpx.Response(200, json=PATTERN))

        dlp.data_patterns.create(pattern_request())

        sent = route.calls.last.request
        assert sent.headers["content-type"] == "application/json"
        assert json.loads(sent.content) == PATTERN_BODY

    def test_gets_one_pattern(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.get(f"{PATTERNS_URL}/dp-1").mock(return_value=httpx.Response(200, json=PATTERN))

        result = dlp.data_patterns.get("dp-1")

        # respx already refuses a wrong method or path, so the assertion worth making is
        # that nothing else rode along: this endpoint takes no query parameters at all.
        assert route.calls.last.request.url.query == b""
        assert (result.id, result.name) == ("dp-1", "SSN")

    def test_replaces_with_put(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.put(f"{PATTERNS_URL}/dp-1").mock(return_value=httpx.Response(200, json=PATTERN))

        dlp.data_patterns.replace("dp-1", pattern_request())

        sent = route.calls.last.request
        assert (sent.method, str(sent.url)) == ("PUT", f"{PATTERNS_URL}/dp-1")
        assert json.loads(sent.content) == PATTERN_BODY

    def test_patches_as_a_merge_patch_document(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        """Explicit nulls clear a field; untouched fields must not appear at all."""
        route = api.patch(f"{PATTERNS_URL}/dp-1").mock(
            return_value=httpx.Response(200, json=PATTERN)
        )

        dlp.data_patterns.patch(
            "dp-1",
            DataPatternPatchRequest(
                name="SSN",
                type=DataPatternType.CUSTOM,
                detection_config=DataPatternDetectionConfig(technique=DataPatternTechnique.REGEX),
                description=None,
            ),
        )

        sent = route.calls.last.request
        assert sent.headers["content-type"] == "application/merge-patch+json"
        assert json.loads(sent.content) == {
            "name": "SSN",
            "type": "custom",
            "detection_config": {"technique": "regex"},
            "description": None,
        }

    def test_deletes_without_a_body(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.delete(f"{PATTERNS_URL}/dp-1").mock(return_value=httpx.Response(204))

        dlp.data_patterns.delete("dp-1")

        sent = route.calls.last.request
        assert (sent.method, str(sent.url)) == ("DELETE", f"{PATTERNS_URL}/dp-1")
        assert sent.content == b""


class TestDataProfiles:
    def test_lists_from_the_data_profiles_path(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.get(PROFILES_URL).mock(return_value=httpx.Response(200, json=page(PROFILE)))

        result = dlp.data_profiles.list(size=5, sort=["name,asc"])

        sent = route.calls.last.request
        assert sent.url.path == "/v2/api/data-profiles"
        assert dict(sent.url.params) == {"size": "5", "sort": "name,asc"}
        assert result.content[0].id == "prof-1"

    def test_creates_from_the_request_model(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.post(PROFILES_URL).mock(return_value=httpx.Response(200, json=PROFILE))

        dlp.data_profiles.create(profile_request())

        assert json.loads(route.calls.last.request.content) == PROFILE_BODY

    def test_gets_one_profile(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.get(f"{PROFILES_URL}/prof-1").mock(
            return_value=httpx.Response(200, json=PROFILE)
        )

        result = dlp.data_profiles.get("prof-1")

        assert route.calls.last.request.url.query == b""
        assert (result.id, result.name) == ("prof-1", "Confidential")

    def test_replaces_with_put(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.put(f"{PROFILES_URL}/prof-1").mock(
            return_value=httpx.Response(200, json=PROFILE)
        )

        dlp.data_profiles.replace("prof-1", profile_request())

        sent = route.calls.last.request
        assert (sent.method, str(sent.url)) == ("PUT", f"{PROFILES_URL}/prof-1")
        assert json.loads(sent.content) == PROFILE_BODY

    def test_patches_keeping_the_rule_discriminator(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        """``exclude_unset`` reaches into nested rules; an untagged rule is a 400 upstream."""
        route = api.patch(f"{PROFILES_URL}/prof-1").mock(
            return_value=httpx.Response(200, json=PROFILE)
        )

        dlp.data_profiles.patch(
            "prof-1",
            DataProfilePatchRequest(
                name="Customer PII",
                profile_type=DataProfileType.ADVANCED,
                detection_rules=[
                    MultiProfileDetectionRule(
                        rule_type="multi_profile",
                        multi_profile=MultiProfileDataNode(data_profile_ids=[11]),
                    )
                ],
            ),
        )

        sent = route.calls.last.request
        assert sent.headers["content-type"] == "application/merge-patch+json"
        assert json.loads(sent.content) == {
            "name": "Customer PII",
            "profile_type": "advanced",
            "detection_rules": [
                {"rule_type": "multi_profile", "multi_profile": {"data_profile_ids": [11]}}
            ],
        }


class TestDataFilteringProfiles:
    def test_lists_with_the_status_and_name_filters(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        route = api.get(FILTERING_URL).mock(
            return_value=httpx.Response(200, json=page(FILTERING_PROFILE))
        )

        result = dlp.data_filtering_profiles.list(size=5, status="enabled", name="Fin")

        sent = route.calls.last.request
        assert sent.url.path == "/v2/api/data-filtering-profiles"
        assert dict(sent.url.params) == {"size": "5", "status": "enabled", "name": "Fin"}
        assert result.content[0].id == "dfp-1"

    def test_omits_the_filters_that_were_not_set(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        route = api.get(FILTERING_URL).mock(
            return_value=httpx.Response(200, json=page(FILTERING_PROFILE))
        )

        dlp.data_filtering_profiles.list(page=1)

        assert dict(route.calls.last.request.url.params) == {"page": "1"}

    def test_gets_one_profile(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.get(f"{FILTERING_URL}/dfp-1").mock(
            return_value=httpx.Response(200, json=FILTERING_PROFILE)
        )

        result = dlp.data_filtering_profiles.get("dfp-1")

        assert route.calls.last.request.url.query == b""
        assert (result.id, result.file_based) == ("dfp-1", True)

    def test_replaces_with_put(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        """PUT is the only way to change one of these -- there is no PATCH and no POST."""
        route = api.put(f"{FILTERING_URL}/dfp-1").mock(
            return_value=httpx.Response(200, json=FILTERING_PROFILE)
        )

        dlp.data_filtering_profiles.replace(
            "dfp-1",
            DataFilteringProfileRequest(
                file_based=True,
                non_file_based=False,
                direction=FilteringDirection.BOTH,
                log_severity=LogSeverity.HIGH,
            ),
        )

        sent = route.calls.last.request
        assert (sent.method, str(sent.url)) == ("PUT", f"{FILTERING_URL}/dfp-1")
        assert json.loads(sent.content) == {
            "file_based": True,
            "non_file_based": False,
            "direction": "BOTH",
            "log_severity": "HIGH",
        }


class TestDictionaries:
    def test_lists_from_the_dictionaries_path(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.get(DICTIONARIES_URL).mock(
            return_value=httpx.Response(200, json=page(DICTIONARY))
        )

        result = dlp.dictionaries.list(size=5)

        assert dict(route.calls.last.request.url.params) == {"size": "5"}
        assert result.content[0].id == "dict-1"

    def test_sends_a_lowercase_keywords_flag(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        """``str(True)`` is ``"True"`` in Python; the wire form has to stay lowercase."""
        route = api.get(DICTIONARIES_URL).mock(
            return_value=httpx.Response(200, json=page(DICTIONARY))
        )

        dlp.dictionaries.list(keywords=True)

        assert route.calls.last.request.url.params["keywords"] == "true"

    def test_sends_a_lowercase_false_flag_too(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.get(DICTIONARIES_URL).mock(
            return_value=httpx.Response(200, json=page(DICTIONARY))
        )

        dlp.dictionaries.list(keywords=False)

        assert route.calls.last.request.url.params["keywords"] == "false"

    def test_omits_the_keywords_flag_when_unset(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        route = api.get(DICTIONARIES_URL).mock(
            return_value=httpx.Response(200, json=page(DICTIONARY))
        )

        dlp.dictionaries.list()

        assert "keywords" not in route.calls.last.request.url.params

    def test_uploads_the_metadata_and_the_keyword_file(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        route = api.post(DICTIONARIES_URL).mock(return_value=httpx.Response(200, json=DICTIONARY))

        dlp.dictionaries.create(metadata=dictionary_request(), file="alpha\nbravo\n")

        sent = route.calls.last.request
        assert sent.headers["content-type"].startswith("multipart/form-data; boundary=")
        parts = multipart_parts(sent)
        assert [part.name for part in parts] == ["json", "file"]
        assert (parts[0].filename, parts[0].content_type) == ("metadata.json", "application/json")
        assert json.loads(parts[0].body) == DICTIONARY_METADATA
        assert parts[1] == Part("file", "keywords.txt", "text/plain", b"alpha\nbravo\n")

    def test_uploads_raw_bytes_as_an_opaque_file(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        """The part type follows the payload, not the file name's extension."""
        route = api.post(DICTIONARIES_URL).mock(return_value=httpx.Response(200, json=DICTIONARY))

        dlp.dictionaries.create(metadata=dictionary_request(), file=b"\x00\x01alpha")

        parts = multipart_parts(route.calls.last.request)
        assert parts[1] == Part(
            "file", "keywords.txt", "application/octet-stream", b"\x00\x01alpha"
        )

    def test_encodes_both_text_parts_as_utf8(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        """Neither part may narrow to a single-byte encoding.

        The reference blobs a string as UTF-8 and stringifies JSON without ``\\uXXXX``
        escapes. An ASCII fixture cannot tell UTF-8 from latin-1, so both are asserted as
        the exact bytes a UTF-8 encoder produces.
        """
        route = api.post(DICTIONARIES_URL).mock(return_value=httpx.Response(200, json=DICTIONARY))

        dlp.dictionaries.create(
            metadata=DictionaryRequest(
                category=DictionaryCategory.CONFIDENTIAL,
                name="Café",
                original_file_name="keywords.txt",
                region_name="eu-west-1",
                type=DictionaryType.CUSTOM,
            ),
            file="café\nnaïve\n",
        )

        parts = multipart_parts(route.calls.last.request)
        assert b'"name":"Caf\xc3\xa9"' in parts[0].body
        assert parts[1].body == b"caf\xc3\xa9\nna\xc3\xafve\n"

    def test_asks_for_the_keywords_back_on_create(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        route = api.post(DICTIONARIES_URL).mock(return_value=httpx.Response(200, json=DICTIONARY))

        dlp.dictionaries.create(
            metadata=dictionary_request(), file="alpha\n", include_keywords=True
        )

        assert route.calls.last.request.url.params["keywords"] == "true"

    def test_gets_one_dictionary_with_its_keywords(
        self, dlp: DlpClient, api: respx.MockRouter
    ) -> None:
        route = api.get(f"{DICTIONARIES_URL}/dict-1").mock(
            return_value=httpx.Response(200, json={**DICTIONARY, "keywords": ["alpha", "bravo"]})
        )

        result = dlp.dictionaries.get("dict-1", include_keywords=True)

        sent = route.calls.last.request
        assert (sent.method, sent.url.path) == ("GET", "/v2/api/dictionaries/dict-1")
        assert sent.url.params["keywords"] == "true"
        assert result.keywords == ["alpha", "bravo"]

    def test_replaces_by_uploading_again(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.put(f"{DICTIONARIES_URL}/dict-1").mock(
            return_value=httpx.Response(200, json=DICTIONARY)
        )

        result = dlp.dictionaries.replace(
            "dict-1", metadata=dictionary_request(), file="alpha\nbravo\ncharlie\n"
        )

        sent = route.calls.last.request
        assert (sent.method, str(sent.url)) == ("PUT", f"{DICTIONARIES_URL}/dict-1")
        parts = multipart_parts(sent)
        assert [part.name for part in parts] == ["json", "file"]
        assert json.loads(parts[0].body) == DICTIONARY_METADATA
        assert parts[1] == Part("file", "keywords.txt", "text/plain", b"alpha\nbravo\ncharlie\n")
        assert result is not None
        assert result.id == "dict-1"

    def test_replace_accepts_an_empty_204_body(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        """This endpoint answers 200+body or 204+nothing; None means success, not failure."""
        api.put(f"{DICTIONARIES_URL}/dict-1").mock(return_value=httpx.Response(204))

        result = dlp.dictionaries.replace("dict-1", metadata=dictionary_request(), file="alpha\n")

        assert result is None

    def test_patches_the_metadata_only(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        """``region_name=None`` is the clearing null, and it has to survive to the wire.

        Handing the model to the transport instead of ``merge_patch_dump()`` would dump it
        with ``exclude_none``, dropping that key and turning "clear the region" into a
        no-op that reports success. ``is_case_sensitive`` is never mentioned, so it must
        not appear at all -- absent means "leave alone", which is not the same as null.
        """
        route = api.patch(f"{DICTIONARIES_URL}/dict-1").mock(
            return_value=httpx.Response(200, json=DICTIONARY)
        )

        dlp.dictionaries.patch(
            "dict-1",
            DictionaryPatchRequest(
                category=DictionaryCategory.CONFIDENTIAL,
                name="PII",
                original_file_name="keywords.txt",
                description="Updated by SDK",
                region_name=None,
            ),
        )

        sent = route.calls.last.request
        assert sent.headers["content-type"] == "application/merge-patch+json"
        assert json.loads(sent.content) == {
            "category": "Confidential",
            "name": "PII",
            "original_file_name": "keywords.txt",
            "description": "Updated by SDK",
            "region_name": None,
        }

    def test_deletes_without_a_body(self, dlp: DlpClient, api: respx.MockRouter) -> None:
        route = api.delete(f"{DICTIONARIES_URL}/dict-1").mock(return_value=httpx.Response(204))

        dlp.dictionaries.delete("dict-1")

        sent = route.calls.last.request
        assert (sent.method, str(sent.url)) == ("DELETE", f"{DICTIONARIES_URL}/dict-1")
        assert sent.content == b""
