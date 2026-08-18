"""Models for the DLP administration APIs served under ``/v2/api``.

Covers data profiles, data patterns, dictionaries, and data filtering profiles, plus the
Spring ``Page`` envelope and audit block that every one of those resources shares.

Two conventions run through the whole module. Response fields are optional *and* nullable:
the live service emits ``null`` rather than omitting a key, so the presence of a key says
nothing about whether it is set. And PATCH bodies follow JSON Merge Patch (RFC 7396), which
needs a dedicated serialiser -- see :class:`MergePatchRequest`.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Generic, Literal, TypeVar

from pydantic import Field

from prisma_airs.models.base import AirsModel

# ---------------------------------------------------------------------------
# Shared building blocks
# ---------------------------------------------------------------------------


class MergePatchRequest(AirsModel):
    """Base for the PATCH bodies, which are JSON Merge Patch (RFC 7396) documents.

    Merge-patch meaning lives entirely in the difference between an absent key and a ``null``
    one: absent leaves the server value alone, ``null`` clears it. A plain ``model_dump()``
    cannot express that -- it emits every unset optional field as ``null`` and would wipe
    columns the caller never mentioned -- so serialise these with :meth:`merge_patch_dump`.

    Send the *dict* that :meth:`merge_patch_dump` returns as the request body, never the model
    itself. The transport's model path dumps with ``exclude_none=True``, which strips exactly
    the ``null`` that clears a field and turns "clear the description" into a silent no-op.
    """

    def merge_patch_dump(self) -> dict[str, Any]:
        """Serialise only the fields the caller actually set.

        Dumps in JSON mode: the result goes straight into a request body, so enums have to
        arrive as their wire strings rather than as members. ``exclude_unset`` recurses, so a
        partially built nested object contributes only its own touched keys.

        Returns:
            A merge-patch body in which an explicit ``None`` means "clear this field" and an
            absent key means "leave unchanged".
        """
        return self.model_dump(mode="json", by_alias=True, exclude_unset=True)


class AuditResponse(AirsModel):
    """Creation and last-update provenance, attached to every DLP resource response.

    Timestamps are typed as ``str | float`` because the service emits both shapes: ISO-8601
    strings on some records and numeric epoch milliseconds on others, for the same field.
    """

    created_at: str | float | None = None
    created_by: str | None = None
    updated_at: str | float | None = None
    updated_by: str | None = None


class SortObject(AirsModel):
    """Spring ``Sort`` descriptor, returned inside every :class:`Page` envelope."""

    empty: bool | None = None
    sorted: bool | None = None
    unsorted: bool | None = None


class PageableObject(AirsModel):
    """Spring ``Pageable`` descriptor: which slice of the result set a page represents."""

    offset: float | None = None
    page_number: Annotated[float | None, Field(alias="pageNumber")] = None
    page_size: Annotated[float | None, Field(alias="pageSize")] = None
    paged: bool | None = None
    unpaged: bool | None = None
    sort: SortObject | None = None


_ItemT = TypeVar("_ItemT")


class Page(AirsModel, Generic[_ItemT]):
    """Spring ``Page<T>`` envelope wrapping the results of every DLP list endpoint.

    Each resource subclasses this with its concrete item type instead of parametrising at the
    call site, so validation errors name the resource rather than ``Page[...]``.
    """

    content: list[_ItemT]
    empty: bool | None = None
    first: bool | None = None
    last: bool | None = None
    number: float | None = None
    number_of_elements: Annotated[float | None, Field(alias="numberOfElements")] = None
    pageable: PageableObject | None = None
    size: float | None = None
    sort: SortObject | None = None
    total_elements: Annotated[float | None, Field(alias="totalElements")] = None
    total_pages: Annotated[float | None, Field(alias="totalPages")] = None


# ---------------------------------------------------------------------------
# Data patterns
# ---------------------------------------------------------------------------


class DataPatternType(str, Enum):
    """Top-level taxonomy for a data pattern."""

    PREDEFINED = "predefined"
    CUSTOM = "custom"
    FILE_PROPERTY = "file_property"


class DataPatternTechnique(str, Enum):
    """Detection technique used by a pattern.

    The same thirteen values appear on :class:`RuleItemDetectionTechnique` and
    :class:`DictionaryDetectionTechnique`. They are kept duplicated rather than aliased so the
    three model surfaces stay independent -- when a new technique ships, update all three.
    """

    EDM = "edm"
    DOCUMENT_FINGERPRINT = "document_fingerprint"
    TRAINABLE_CLASSIFIER = "trainable_classifier"
    ML_DOCUMENT = "ml_document"
    REGEX = "regex"
    WEIGHTED_REGEX = "weighted_regex"
    ML = "ml"
    TITUS_TAG = "titus_tag"
    WILDFIRE = "wildfire"
    FILE_PROPERTY = "file_property"
    DICTIONARY = "dictionary"
    PAB = "pab"
    DOCUMENT_CLASSIFIER = "document_classifier"


class DataPatternConfidenceLevel(str, Enum):
    """Confidence level supported by a pattern."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DataPatternLicenseType(str, Enum):
    """License tier the pattern is gated behind."""

    STANDARD = "standard"
    ENTERPRISE = "enterprise"
    ESSENTIALS = "essentials"


class DataPatternStatus(str, Enum):
    """Lifecycle status of a pattern.

    ``SILENT`` patterns still evaluate but do not raise findings, which is how a pattern gets
    tuned in production without generating noise.
    """

    ACTIVE = "active"
    DISABLED = "disabled"
    DELETED = "deleted"
    DEPRECATED = "deprecated"
    SILENT = "silent"


class ComparisonOperatorType(str, Enum):
    """Comparison operator used by metadata-criterion entries on matching rules."""

    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL_TO = "less_than_or_equal_to"
    GREATER_THAN_OR_EQUAL_TO = "greater_than_or_equal_to"
    GREATER_THAN = "greater_than"
    EQUAL_TO = "equal_to"


class WeightedRegex(AirsModel):
    """One regex and the weight it contributes to a weighted-regex pattern's score."""

    regex: Annotated[str, Field(min_length=1)]
    weight: float


class MetadataCriterion(AirsModel):
    """A file-metadata filter applied on top of a pattern's textual match.

    ``comparisonOperatorType`` arrives camelCase while its siblings are snake_case. The spec is
    inconsistent here; the alias preserves the shape the service actually sends.
    """

    comparison_operator_type: Annotated[
        ComparisonOperatorType | None, Field(alias="comparisonOperatorType")
    ] = None
    name: str | None = None
    type: str | None = None
    value: str | None = None


class DataPatternDetectionConfig(AirsModel):
    """Which technique a pattern uses and which confidence levels that technique offers."""

    technique: DataPatternTechnique
    supported_confidence_levels: list[DataPatternConfidenceLevel] | None = None


class DataPatternMatchingRules(AirsModel):
    """Proximity, delimiter, regex-weight, and metadata controls on a pattern's matching.

    Every field is nullable because the service sends ``null`` for the ones a given technique
    does not use. The 2..1000 bound on ``proximity_distance`` therefore applies only when a
    value is actually present.
    """

    delimiter: str | None = None
    #: Keyword proximity window, in the service's own units. Spec bounds: 2..1000 inclusive.
    proximity_distance: Annotated[int | None, Field(ge=2, le=1000)] = None
    proximity_keywords: list[str] | None = None
    regexes: list[WeightedRegex] | None = None
    metadata_criteria: list[MetadataCriterion] | None = None


class DataPatternTags(AirsModel):
    """Metadata tag arrays used to group patterns for reporting and compliance mapping."""

    classification: list[str] | None = None
    compliance: list[str] | None = None
    geography: list[str] | None = None


class DataPatternRequest(AirsModel):
    """Body for POST (create) and PUT (full replace) on a data pattern."""

    name: Annotated[str, Field(min_length=1, max_length=64)]
    type: DataPatternType
    detection_config: DataPatternDetectionConfig
    description: str | None = None
    matching_rules: DataPatternMatchingRules | None = None
    tags: DataPatternTags | None = None


class DataPatternPatchRequest(MergePatchRequest):
    """Body for PATCH on a data pattern.

    ``detection_config``, ``name``, and ``type`` stay required even on a patch -- the service
    will not let them be cleared. Everything else may be omitted (leave unchanged) or sent as
    ``None`` (clear); serialise with :meth:`MergePatchRequest.merge_patch_dump`.
    """

    name: Annotated[str, Field(min_length=1, max_length=64)]
    type: DataPatternType
    detection_config: DataPatternDetectionConfig
    description: str | None = None
    matching_rules: DataPatternMatchingRules | None = None
    tags: DataPatternTags | None = None


class DataPatternResponse(AirsModel):
    """A data pattern as returned by GET / POST / PUT / PATCH."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    tenant_id: str | None = None
    type: DataPatternType | None = None
    status: DataPatternStatus | None = None
    license_type: DataPatternLicenseType | None = None
    #: True when the pattern is inherited from a parent tenant and cannot be edited locally.
    is_parent_managed: bool | None = None
    version: float | None = None
    detection_config: DataPatternDetectionConfig | None = None
    matching_rules: DataPatternMatchingRules | None = None
    tags: DataPatternTags | None = None
    audit_metadata: AuditResponse | None = None


class PageDataPatternResponse(Page[DataPatternResponse]):
    """One page of data patterns from the list endpoint."""


# ---------------------------------------------------------------------------
# Data profiles
# ---------------------------------------------------------------------------


class ExpressionOperatorType(str, Enum):
    """Boolean operator joining the children of an expression-tree node."""

    AND = "and"
    OR = "or"
    NOT = "not"
    AND_NOT = "and_not"
    OR_NOT = "or_not"


class RuleItemDetectionTechnique(str, Enum):
    """Detection technique on a rule item.

    Shares its vocabulary with :class:`DataPatternTechnique` and
    :class:`DictionaryDetectionTechnique`, deliberately duplicated so the three model surfaces
    stay independent. A new technique has to be added to all three.
    """

    EDM = "edm"
    DOCUMENT_FINGERPRINT = "document_fingerprint"
    TRAINABLE_CLASSIFIER = "trainable_classifier"
    ML_DOCUMENT = "ml_document"
    REGEX = "regex"
    WEIGHTED_REGEX = "weighted_regex"
    ML = "ml"
    TITUS_TAG = "titus_tag"
    WILDFIRE = "wildfire"
    FILE_PROPERTY = "file_property"
    DICTIONARY = "dictionary"
    PAB = "pab"
    DOCUMENT_CLASSIFIER = "document_classifier"


class RuleItemMatchType(str, Enum):
    """How a matched item participates in its rule."""

    INCLUDE = "include"
    EXCLUDE = "exclude"


class RuleItemOccurrenceOperatorType(str, Enum):
    """Comparison operator applied to occurrence-count thresholds."""

    ANY = "any"
    LESS_THAN_EQUAL_TO = "less_than_equal_to"
    MORE_THAN_EQUAL_TO = "more_than_equal_to"
    BETWEEN = "between"


class RuleItemConfidenceLevel(str, Enum):
    """Confidence level required before a rule item counts as a match."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RuleItemEdmMatchCriteria(str, Enum):
    """Whether an EDM field set matches on any field or requires all of them."""

    ANY = "any"
    ALL = "all"


class DataProfileType(str, Enum):
    """Profile shape: ``BASIC`` is a single expression tree, ``ADVANCED`` nests other profiles.

    An advanced profile reaches other profiles through ``multi_profile`` detection rules, which
    is why the two rule variants exist.
    """

    BASIC = "basic"
    ADVANCED = "advanced"


class DataProfileStatus(str, Enum):
    """Lifecycle status of a data profile."""

    ACTIVE = "active"
    DISABLED = "disabled"
    DELETED = "deleted"


class DataProfileSubtype(str, Enum):
    """Whether the profile ships with the product or was created by the tenant."""

    CUSTOM = "custom"
    PREDEFINED = "predefined"


class DetectionRuleItem(AirsModel):
    """A single detection criterion sitting at a leaf of an expression tree.

    The spec splits this into four subtypes (data pattern, dictionary, document type, EDM)
    discriminated by ``detection_technique`` -- but every subtype declares all thirteen
    technique values, so the discriminator partitions nothing. It is modelled as one flat
    object: ``detection_technique`` is required, everything else optional. Populate whichever
    group of fields the chosen technique needs.
    """

    detection_technique: RuleItemDetectionTechnique
    id: str | None = None
    name: str | None = None
    description: str | None = None
    version: int | None = None
    match_type: RuleItemMatchType | None = None
    by_unique_count: bool | None = None
    confidence_level: RuleItemConfidenceLevel | None = None
    supported_confidence_levels: list[RuleItemConfidenceLevel] | None = None
    occurrence_count: int | None = None
    occurrence_high: int | None = None
    occurrence_low: int | None = None
    occurrence_operator_type: RuleItemOccurrenceOperatorType | None = None
    #: Dictionary and document-type scoring.
    score: int | None = None
    score_high: int | None = None
    score_low: int | None = None
    #: Exact-data-match (EDM) fields.
    edm_dataset_id: str | None = None
    primary_fields: list[str] | None = None
    primary_match_criteria: RuleItemEdmMatchCriteria | None = None
    primary_match_any_count: int | None = None
    secondary_fields: list[str] | None = None
    secondary_match_criteria: RuleItemEdmMatchCriteria | None = None
    secondary_match_any_count: int | None = None


class ExpressionTreeNode(AirsModel):
    """One node of a data profile's boolean expression tree.

    A node is either a branch -- ``sub_expressions`` joined by ``operator_type`` -- or a leaf
    carrying a single ``rule_item``. The service does not enforce that split, so both may be
    absent and neither can be relied on being present.
    """

    operator_type: ExpressionOperatorType | None = None
    rule_item: DetectionRuleItem | None = None
    sub_expressions: list[ExpressionTreeNode] | None = None


class MultiProfileDataNode(AirsModel):
    """References to other data profiles, joined by a boolean operator."""

    #: ``int64`` on the wire. Typed ``int``, not the ``float`` an unconstrained JSON number
    #: usually maps to, because Python integers are unbounded -- the TypeScript SDK has to warn
    #: that ids above 2^53 lose precision, and routing through a float would import that
    #: ceiling here for nothing.
    data_profile_ids: list[int] | None = None
    operator_type: ExpressionOperatorType | None = None


class DefaultTreeDetectionRule(AirsModel):
    """The ``expression_tree`` variant of a detection rule.

    ``rule_type`` has no default even though only one value is legal: it is the union
    discriminator, and a default would let it be dropped from a merge-patch body serialised
    with ``exclude_unset``, leaving the service with an untagged rule.
    """

    rule_type: Literal["expression_tree"]
    expression_tree: ExpressionTreeNode | None = None


class MultiProfileDetectionRule(AirsModel):
    """The ``multi_profile`` variant of a detection rule.

    ``rule_type`` is required for the same reason as on :class:`DefaultTreeDetectionRule`.
    """

    rule_type: Literal["multi_profile"]
    multi_profile: MultiProfileDataNode | None = None


#: A detection rule, discriminated on ``rule_type``. The tag must be present in the payload;
#: Pydantic will not guess the variant from the other keys.
DetectionRule = Annotated[
    DefaultTreeDetectionRule | MultiProfileDetectionRule,
    Field(discriminator="rule_type"),
]


class AdvancedDataProfileRequest(AirsModel):
    """Body for POST (create) and PUT (full replace) on a data profile."""

    name: Annotated[str, Field(min_length=1, max_length=64)]
    detection_rules: list[DetectionRule]
    description: str | None = None
    is_granular_data_profile: bool | None = None


class DataProfilePatchRequest(MergePatchRequest):
    """Body for PATCH on a data profile.

    ``name`` and ``profile_type`` stay required even on a patch. The rest may be omitted
    (leave unchanged) or sent as ``None`` (clear); serialise with
    :meth:`MergePatchRequest.merge_patch_dump`.
    """

    name: str
    profile_type: DataProfileType
    description: str | None = None
    detection_rules: list[DetectionRule] | None = None


class DataProfileResponse(AirsModel):
    """A data profile as returned by GET / POST / PUT / PATCH."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    tenant_id: str | None = None
    type: DataProfileSubtype | None = None
    profile_status: DataProfileStatus | None = None
    profile_type: DataProfileType | None = None
    is_granular_data_profile: bool | None = None
    #: True when the profile is inherited from a parent tenant and cannot be edited locally.
    is_parent_managed: bool | None = None
    version: int | None = None
    advance_data_patterns_rule_request: list[str] | None = None
    detection_rules: list[DetectionRule] | None = None
    audit_metadata: AuditResponse | None = None


class PageDataProfileResponse(Page[DataProfileResponse]):
    """One page of data profiles from the list endpoint."""


# ---------------------------------------------------------------------------
# Dictionaries
# ---------------------------------------------------------------------------


class DictionaryType(str, Enum):
    """Whether the dictionary ships with the product or was uploaded by the tenant."""

    PREDEFINED = "predefined"
    CUSTOM = "custom"


class DictionaryCategory(str, Enum):
    """Dictionary category.

    ``SOURCE_CODE`` is ``"Source Code"`` with a literal space, and the values are
    capitalised -- both preserved verbatim from the spec, because the service matches
    on the exact string.
    """

    ACADEMIC = "Academic"
    CONFIDENTIAL = "Confidential"
    EMPLOYMENT = "Employment"
    FINANCIAL = "Financial"
    GOVERNMENT = "Government"
    HEALTHCARE = "Healthcare"
    LEGAL = "Legal"
    MARKETING = "Marketing"
    SOURCE_CODE = "Source Code"


class DictionaryClassification(str, Enum):
    """Classification tag values supported on a dictionary."""

    PAB = "pab"
    ENDPOINT = "endpoint"


class DictionaryDetectionTechnique(str, Enum):
    """Detection technique reported on a dictionary response.

    Same thirteen values as :class:`DataPatternTechnique` and
    :class:`RuleItemDetectionTechnique`, kept as a separate enum on purpose so the model
    surfaces stay independent. Add new techniques to all three.
    """

    EDM = "edm"
    DOCUMENT_FINGERPRINT = "document_fingerprint"
    TRAINABLE_CLASSIFIER = "trainable_classifier"
    ML_DOCUMENT = "ml_document"
    REGEX = "regex"
    WEIGHTED_REGEX = "weighted_regex"
    ML = "ml"
    TITUS_TAG = "titus_tag"
    WILDFIRE = "wildfire"
    FILE_PROPERTY = "file_property"
    DICTIONARY = "dictionary"
    PAB = "pab"
    DOCUMENT_CLASSIFIER = "document_classifier"


class DictionaryDetectionSubTechnique(str, Enum):
    """Detection sub-technique reported on a dictionary response."""

    DNN = "dnn"
    GAMMA = "gamma"
    ML_GATEWAY = "ml_gateway"
    ENCODING = "encoding"
    # Names a file property the detector reports on, not a credential the SDK holds.
    PASSWORD_PROTECTED = "password_protected"  # noqa: S105
    ENCRYPTION = "encryption"
    COMPRESSION = "compression"
    THRESHOLD = "threshold"


class DictionaryMetaDataDTO(AirsModel):
    """Statistics about the keyword file that was uploaded for a dictionary."""

    number_of_keywords: float | None = None
    original_file_name: str | None = None
    original_file_size_in_byte: float | None = None


class DictionaryTags(AirsModel):
    """Tag block attached to a dictionary."""

    classification: list[DictionaryClassification] | None = None


class ResourceModelExtension(AirsModel):
    """A free-form key/value extension entry returned on dictionary responses."""

    key: str | None = None
    value: str | None = None


class DictionaryRequest(AirsModel):
    """The ``json`` part of the multipart create/replace upload for a dictionary.

    The binary keyword ``file`` part travels alongside this and is not modelled here;
    ``original_file_name`` is what ties the two together.
    """

    category: DictionaryCategory
    name: str
    original_file_name: str
    region_name: str
    description: str | None = None
    is_case_sensitive: bool | None = None
    type: DictionaryType | None = None


class DictionaryPatchRequest(MergePatchRequest):
    """Body for PATCH on a dictionary.

    ``category``, ``name``, and ``original_file_name`` stay required even on a patch. The rest
    may be omitted (leave unchanged) or sent as ``None`` (clear); serialise with
    :meth:`MergePatchRequest.merge_patch_dump`.
    """

    category: DictionaryCategory
    name: str
    original_file_name: str
    description: str | None = None
    is_case_sensitive: bool | None = None
    region_name: str | None = None


class DictionaryResponse(AirsModel):
    """A dictionary as returned by GET / POST / PUT / PATCH.

    ``category`` is a plain string here rather than :class:`DictionaryCategory`: the response
    side of the spec leaves it unconstrained, and tightening it would turn a new server-side
    category into a client-side parse failure.
    """

    id: str | None = None
    name: str | None = None
    description: str | None = None
    category: str | None = None
    region_name: str | None = None
    type: DictionaryType | None = None
    is_case_sensitive: bool | None = None
    #: True when the dictionary is inherited from a parent tenant and cannot be edited locally.
    is_parent_managed: bool | None = None
    detection_technique: DictionaryDetectionTechnique | None = None
    detection_sub_technique: DictionaryDetectionSubTechnique | None = None
    dictionary_metadata: DictionaryMetaDataDTO | None = None
    #: Populated only when the request passes ``keywords=true``; otherwise absent even though
    #: the dictionary has keywords.
    keywords: list[str] | None = None
    tags: DictionaryTags | None = None
    attributes: list[ResourceModelExtension] | None = None
    audit_metadata: AuditResponse | None = None


class PageDictionaryResponse(Page[DictionaryResponse]):
    """One page of dictionaries from the list endpoint."""


# ---------------------------------------------------------------------------
# Data filtering profiles
# ---------------------------------------------------------------------------


class ExceptionRuleAction(str, Enum):
    """What an exception rule does with traffic it matches."""

    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"


class LogSeverity(str, Enum):
    """Severity stamped on the log entry a rule produces.

    The spec lists these values in two different orders on the exception rule and on the
    profile request; the set is identical, so they share one enum.
    """

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FilteringDirection(str, Enum):
    """Traffic direction a filtering profile applies to."""

    BOTH = "BOTH"
    UPLOAD = "UPLOAD"
    DOWNLOAD = "DOWNLOAD"


class ScanType(str, Enum):
    """Whether the configured file types are the ones scanned or the ones skipped."""

    INCLUDE = "include"
    EXCLUDE = "exclude"


class AppExclusion(AirsModel):
    """An application-level bypass: traffic to this app skips DLP scanning."""

    app_id: str | None = None
    app_name: str | None = None
    type: str | None = None


class URLExclusion(AirsModel):
    """A URL-level bypass: traffic to this URL skips DLP scanning."""

    type: str | None = None
    url_id: str | None = None
    url_name: str | None = None


class Exclusions(AirsModel):
    """The app, URL, and keyword bypass lists on a filtering profile."""

    app_exclusion_list: list[AppExclusion] | None = None
    url_exclusion_list: list[URLExclusion] | None = None
    #: Category name to excluded keywords. The spec declares it as free-form
    #: ``additionalProperties`` of string arrays, so the key set is not fixed.
    exclusion_list: dict[str, list[str]] | None = None


class SourceAttributes(AirsModel):
    """Which users an exception rule applies to."""

    #: True matches any listed user or group; false requires all of them.
    match_any: bool | None = None
    user_group_ids: list[str] | None = None
    user_ids: list[str] | None = None


class DestinationAttributes(AirsModel):
    """Which destinations an exception rule applies to."""

    #: True matches any listed app or URL pattern; false requires all of them.
    match_any: bool | None = None
    app_ids: list[str] | None = None
    url_patterns: list[str] | None = None


class ExceptionRuleDTO(AirsModel):
    """A bypass evaluated before the profile's main filtering logic."""

    id: str | None = None
    action: ExceptionRuleAction | None = None
    log_severity: LogSeverity | None = None
    #: ``int64`` on the wire; typed ``int`` for the reason given on
    #: :attr:`MultiProfileDataNode.data_profile_ids`.
    data_profile_ids: list[int] | None = None
    destination_attributes: DestinationAttributes | None = None
    source_attributes: SourceAttributes | None = None


class DataFilteringRuleDTO(AirsModel):
    """A secondary filtering rule, occupying the ``rule1`` or ``rule2`` slot on a profile."""

    action: str | None = None
    response_page: str | None = None
    show_rsp_page: str | None = None


class DataFilteringDetails(AirsModel):
    """One granular criteria-detail entry on a filtering profile.

    The spec mixes conventions inside this single object -- ``dataProfileId``, ``fileBased``,
    ``fileTypes``, ``logSeverity``, ``nonFileBased``, and ``scanType`` are camelCase while
    their neighbours are snake_case. The aliases reproduce that verbatim; do not tidy it up.
    """

    action: str | None = None
    #: ``int64`` on the wire; typed ``int`` for the reason given on
    #: :attr:`MultiProfileDataNode.data_profile_ids`.
    data_profile_id: Annotated[int | None, Field(alias="dataProfileId")] = None
    direction: str | None = None
    euc_template_id: str | None = None
    file_based: Annotated[str | None, Field(alias="fileBased")] = None
    file_types: Annotated[list[str] | None, Field(alias="fileTypes")] = None
    is_end_user_coaching_enabled: bool | None = None
    log_severity: Annotated[str | None, Field(alias="logSeverity")] = None
    non_file_based: Annotated[str | None, Field(alias="nonFileBased")] = None
    scan_type: Annotated[str | None, Field(alias="scanType")] = None


class DataFilteringProfileRequest(AirsModel):
    """Body for a full-replace PUT on a data filtering profile.

    There is no create endpoint: profiles come into existence with the deployment, and this
    request replaces one wholesale. Any field left unset is cleared on the server.
    """

    file_based: bool
    non_file_based: bool
    description: str | None = None
    direction: FilteringDirection | None = None
    log_severity: LogSeverity | None = None
    scan_type: ScanType | None = None
    #: ``int64`` on the wire; typed ``int`` for the reason given on
    #: :attr:`MultiProfileDataNode.data_profile_ids`.
    data_profile_id: int | None = None
    euc_template_id: str | None = None
    is_end_user_coaching_enabled: bool | None = None
    is_granular_profile: bool | None = None
    file_type: list[str] | None = None
    criteria_details: list[DataFilteringDetails] | None = None
    exception_rules: list[ExceptionRuleDTO] | None = None
    exclusions: Exclusions | None = None
    rule1: DataFilteringRuleDTO | None = None
    rule2: DataFilteringRuleDTO | None = None


class DataFilteringProfileResponse(AirsModel):
    """A data filtering profile as returned by GET / PUT.

    ``direction``, ``log_severity``, and ``type`` are plain strings here while the request side
    constrains them to enums. That asymmetry is in the spec and is kept: the response is the
    side that has to survive the service adding a value.
    """

    id: str | None = None
    name: str | None = None
    description: str | None = None
    tenant_id: str | None = None
    type: str | None = None
    #: ``int64`` on the wire; typed ``int`` for the reason given on
    #: :attr:`MultiProfileDataNode.data_profile_ids`.
    data_profile_id: int | None = None
    direction: str | None = None
    file_based: bool | None = None
    non_file_based: bool | None = None
    log_severity: str | None = None
    scan_type: ScanType | None = None
    is_end_user_coaching_enabled: bool | None = None
    is_granular_profile: bool | None = None
    #: True when the profile is inherited from a parent tenant and cannot be edited locally.
    is_parent_managed: bool | None = None
    euc_template_id: str | None = None
    version: float | None = None
    file_type: list[str] | None = None
    audit_metadata: AuditResponse | None = None
    criteria_details: list[DataFilteringDetails] | None = None
    exception_rules: list[ExceptionRuleDTO] | None = None
    exclusions: Exclusions | None = None
    rule1: DataFilteringRuleDTO | None = None
    rule2: DataFilteringRuleDTO | None = None


class PageDataFilteringProfileResponse(Page[DataFilteringProfileResponse]):
    """One page of data filtering profiles from the list endpoint."""
