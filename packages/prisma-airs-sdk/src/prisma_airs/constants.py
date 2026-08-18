"""Endpoints, header names, paths, and limits for the Prisma AIRS APIs.

Values here are transcribed from the published API surface and verified against a live
tenant. Several are load-bearing in non-obvious ways -- notably the AI Gateway chart
metric slugs, where plural and singular are not interchangeable -- so prefer adding a
constant over deriving a string at the call site.
"""

from __future__ import annotations

from typing import Final

from prisma_airs import __version__

# ---------------------------------------------------------------------------
# Headers
# ---------------------------------------------------------------------------

HEADER_API_KEY: Final = "x-pan-token"
HEADER_AUTH_TOKEN: Final = "Authorization"
HEADER_PAYLOAD_HASH: Final = "x-payload-hash"
BEARER_PREFIX: Final = "Bearer "

#: Mandatory on every AI Gateway request; omitting it yields a 403 OPA denial.
HEADER_TSG_ID: Final = "x-tsg-id"

USER_AGENT: Final = f"PAN-AIRS/{__version__}-python-sdk"

# ---------------------------------------------------------------------------
# Scan API (runtime security)
# ---------------------------------------------------------------------------

DEFAULT_ENDPOINT: Final = "https://service.api.aisecurity.paloaltonetworks.com"

#: Regional scan endpoints, keyed by the region token accepted on the CLI.
AIRS_ENDPOINTS: Final[dict[str, str]] = {
    "us": "https://service.api.aisecurity.paloaltonetworks.com",
    "de": "https://service-de.api.aisecurity.paloaltonetworks.com",
    "in": "https://service-in.api.aisecurity.paloaltonetworks.com",
    "sg": "https://service-sg.api.aisecurity.paloaltonetworks.com",
}

ENV_AI_SEC_API_KEY: Final = "PANW_AI_SEC_API_KEY"
ENV_AI_SEC_API_TOKEN: Final = "PANW_AI_SEC_API_TOKEN"
ENV_AI_SEC_API_ENDPOINT: Final = "PANW_AI_SEC_API_ENDPOINT"
ENV_AI_SEC_DEBUG: Final = "PANW_AI_SEC_DEBUG"

SYNC_SCAN_PATH: Final = "/v1/scan/sync/request"
ASYNC_SCAN_PATH: Final = "/v1/scan/async/request"
SCAN_RESULTS_PATH: Final = "/v1/scan/results"
SCAN_REPORTS_PATH: Final = "/v1/scan/reports"

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_CONTENT_PROMPT_LENGTH: Final = 2 * 1024 * 1024
MAX_CONTENT_RESPONSE_LENGTH: Final = 2 * 1024 * 1024
MAX_CONTENT_CONTEXT_LENGTH: Final = 100 * 1024 * 1024

MAX_API_KEY_LENGTH: Final = 2048
MAX_TOKEN_LENGTH: Final = 2048

MAX_TRANSACTION_ID_STR_LENGTH: Final = 100
MAX_SESSION_ID_STR_LENGTH: Final = 100
MAX_SCAN_ID_STR_LENGTH: Final = 36
MAX_REPORT_ID_STR_LENGTH: Final = 40
MAX_AI_PROFILE_NAME_LENGTH: Final = 100

MAX_NUMBER_OF_SCAN_IDS: Final = 5
MAX_NUMBER_OF_REPORT_IDS: Final = 5
MAX_NUMBER_OF_BATCH_SCAN_OBJECTS: Final = 20

# ---------------------------------------------------------------------------
# HTTP behaviour
# ---------------------------------------------------------------------------

MAX_CONNECTION_POOL_SIZE: Final = 100
MAX_NUMBER_OF_RETRIES: Final = 5
HTTP_FORCE_RETRY_STATUS_CODES: Final[frozenset[int]] = frozenset({500, 502, 503, 504})
DEFAULT_TIMEOUT_SECONDS: Final = 30.0

# ---------------------------------------------------------------------------
# Management plane
# ---------------------------------------------------------------------------

DEFAULT_MGMT_ENDPOINT: Final = "https://api.sase.paloaltonetworks.com/aisec"
DEFAULT_TOKEN_ENDPOINT: Final = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"

ENV_PREFIX_MGMT: Final = "PANW_MGMT"

MGMT_PROFILE_PATH: Final = "/v1/mgmt/profile"
MGMT_PROFILES_TSG_PATH: Final = "/v1/mgmt/profiles/tsg"
MGMT_TOPIC_PATH: Final = "/v1/mgmt/topic"
MGMT_TOPICS_TSG_PATH: Final = "/v1/mgmt/topics/tsg"
MGMT_TOPIC_FORCE_PATH: Final = "/v1/mgmt/topic/force"
MGMT_API_KEY_PATH: Final = "/v1/mgmt/apikey"
MGMT_API_KEYS_TSG_PATH: Final = "/v1/mgmt/apikeys/tsg"
MGMT_DLP_PROFILES_PATH: Final = "/v1/mgmt/dlpprofiles"
MGMT_DEPLOYMENT_PROFILES_PATH: Final = "/v1/mgmt/deploymentprofiles"
MGMT_SCAN_LOGS_PATH: Final = "/v1/mgmt/scanlogs"
MGMT_CUSTOMER_APP_PATH: Final = "/v1/mgmt/customerapp"
MGMT_CUSTOMER_APPS_TSG_PATH: Final = "/v1/mgmt/customerapp/tsg"
MGMT_OAUTH_INVALIDATE_PATH: Final = "/v1/mgmt/oauth/invalidateToken"
MGMT_OAUTH_TOKEN_PATH: Final = "/v1/mgmt/oauth/client_credential/accesstoken"

MGMT_DASHBOARD_APPLICATION_PATH: Final = "/v1/mgmt/dashboard/v2/apps/application"
MGMT_DASHBOARD_APPLICATION_VIOLATION_BREAKDOWN_PATH: Final = (
    "/v1/mgmt/dashboard/v2/apps/applicationviolationbreakdown"
)
MGMT_DASHBOARD_APPLICATIONS_OVERVIEW_PATH: Final = "/v1/mgmt/dashboard/v2/apps/applicationsoverview"

# ---------------------------------------------------------------------------
# DLP
# ---------------------------------------------------------------------------

DEFAULT_DLP_ENDPOINT: Final = "https://api.dlp.paloaltonetworks.com"

DLP_DATA_FILTERING_PROFILES_PATH: Final = "/v2/api/data-filtering-profiles"
DLP_DATA_PATTERNS_PATH: Final = "/v2/api/data-patterns"
DLP_DICTIONARIES_PATH: Final = "/v2/api/dictionaries"
DLP_DATA_PROFILES_PATH: Final = "/v2/api/data-profiles"

#: RFC 7396. Several DLP update endpoints reject application/json.
CONTENT_TYPE_MERGE_PATCH: Final = "application/merge-patch+json"

# ---------------------------------------------------------------------------
# Model security
# ---------------------------------------------------------------------------

DEFAULT_MODEL_SEC_DATA_ENDPOINT: Final = "https://api.sase.paloaltonetworks.com/aims/data"
DEFAULT_MODEL_SEC_MGMT_ENDPOINT: Final = "https://api.sase.paloaltonetworks.com/aims/mgmt"

ENV_PREFIX_MODEL_SEC: Final = "PANW_MODEL_SEC"

MODEL_SEC_SCANS_PATH: Final = "/v1/scans"
MODEL_SEC_EVALUATIONS_PATH: Final = "/v1/evaluations"
MODEL_SEC_VIOLATIONS_PATH: Final = "/v1/violations"
MODEL_SEC_MODELS_PATH: Final = "/v1/models"
MODEL_SEC_MODEL_VERSIONS_PATH: Final = "/v1/model-versions"
MODEL_SEC_SECURITY_GROUPS_PATH: Final = "/v1/security-groups"
MODEL_SEC_SECURITY_RULES_PATH: Final = "/v1/security-rules"
MODEL_SEC_PYPI_AUTH_PATH: Final = "/v1/pypi/authenticate"

# ---------------------------------------------------------------------------
# Red teaming
# ---------------------------------------------------------------------------

DEFAULT_RED_TEAM_DATA_ENDPOINT: Final = (
    "https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane"
)
DEFAULT_RED_TEAM_MGMT_ENDPOINT: Final = (
    "https://api.sase.paloaltonetworks.com/ai-red-teaming/mgmt-plane"
)
DEFAULT_RED_TEAM_NETWORK_BROKER_ENDPOINT: Final = (
    "https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane/network-broker"
)

ENV_PREFIX_RED_TEAM: Final = "PANW_RED_TEAM"

RED_TEAM_SCAN_PATH: Final = "/v1/scan"
RED_TEAM_CATEGORIES_PATH: Final = "/v1/categories"
RED_TEAM_REPORT_STATIC_PATH: Final = "/v1/report/static"
RED_TEAM_REPORT_DYNAMIC_PATH: Final = "/v1/report/dynamic"
RED_TEAM_REPORT_PATH: Final = "/v1/report"
RED_TEAM_CUSTOM_ATTACKS_REPORT_PATH: Final = "/v1/custom-attacks"
RED_TEAM_DASHBOARD_PATH: Final = "/v1/dashboard"
RED_TEAM_QUOTA_PATH: Final = "/v1/metering/quota"
RED_TEAM_ERROR_LOG_PATH: Final = "/v1/error-log/job"
RED_TEAM_SENTIMENT_PATH: Final = "/v1/sentiment"
RED_TEAM_LANGUAGES_PATH: Final = "/v1/languages"
RED_TEAM_ERROR_LOG_TARGET_PROFILE_PATH: Final = "/v1/error-log/target-profile"

RED_TEAM_TARGET_PATH: Final = "/v1/target"
RED_TEAM_TARGET_VALIDATE_AUTH_PATH: Final = "/v1/target/validate-auth"
RED_TEAM_ADAPTER_PATH: Final = "/v1/adapters"
RED_TEAM_ADAPTER_VALIDATE_PATH: Final = "/v1/adapters/validate"
RED_TEAM_TEMPLATE_PATH: Final = "/v1/template"
RED_TEAM_EULA_PATH: Final = "/v1/eula"
RED_TEAM_INSTANCES_PATH: Final = "/v1/instances"
RED_TEAM_REGISTRY_CREDENTIALS_PATH: Final = "/v1/registry-credentials"
RED_TEAM_CUSTOM_ATTACK_PATH: Final = "/v1/custom-attack"
RED_TEAM_MGMT_DASHBOARD_PATH: Final = "/v1/dashboard/overview"

RED_TEAM_CHANNELS_PATH: Final = "/v1/channels"
RED_TEAM_CHANNELS_STATS_PATH: Final = "/v1/channels/stats"

# ---------------------------------------------------------------------------
# AI Gateway
# ---------------------------------------------------------------------------

# api.apps and api.sase resolve to the same host and behave identically -- one API
# gateway routing by path prefix. api.apps is the documented name; override via the
# environment to reuse an existing api.sase egress allowlist.
DEFAULT_AI_GW_DATA_ENDPOINT: Final = "https://api.apps.paloaltonetworks.com/ai_gw/v2"
DEFAULT_AI_GW_ADMIN_ENDPOINT: Final = "https://api.apps.paloaltonetworks.com/ai_gw/admin/v2"

ENV_PREFIX_AI_GW: Final = "PANW_AI_GW"

AI_GW_WORKSPACES_PATH: Final = "/workspaces"
AI_GW_CONFIGS_PATH: Final = "/configs"
AI_GW_GUARDRAILS_PATH: Final = "/guardrails"
AI_GW_PROVIDERS_PATH: Final = "/providers"
AI_GW_API_KEYS_SERVICE_PATH: Final = "/api-keys/service"
AI_GW_API_KEYS_USER_PATH: Final = "/api-keys/user"
AI_GW_LOGS_PATH: Final = "/logs"
AI_GW_CHARTS_PATH: Final = "/logs/charts"
AI_GW_GROUPS_PATH: Final = "/logs/groups"

AI_GW_INTEGRATIONS_PATH: Final = "/integrations"
AI_GW_MCP_INTEGRATIONS_PATH: Final = "/mcp-integrations"
AI_GW_DEPLOYMENTS_PATH: Final = "/deployments"
AI_GW_PLUGINS_PATH: Final = "/plugins"
AI_GW_ORGANISATIONS_SELF_PATH: Final = "/organisations/self"
AI_GW_AUDIT_LOGS_PATH: Final = "/audit-logs"

#: Chart metric slugs. Bespoke and unguessable -- plural versus singular is load-bearing
#: (``user-trends`` resolves, ``user-trend`` returns 404). Do not derive these.
AI_GW_CHART_METRICS: Final[tuple[str, ...]] = (
    "cost",
    "requests",
    "latency",
    "tokens",
    "errors",
    "users",
    "cache-summary",
    "cache-hit-trend",
    "user-trends",
    "error-trends",
    "rescued-retries",
    "feedback-trend",
    "feedback-weighted",
    "feedback-score-distribution",
    "feedback-models",
)

#: Valid ``logs/groups/{dimension}`` values. Underscored names only; hyphen and camelCase
#: variants return 400.
AI_GW_GROUP_DIMENSIONS: Final[tuple[str, ...]] = ("ai_service", "model", "api_key", "provider")

#: Valid ``columns`` values for ``logs/groups/*``. Invalid names are silently dropped
#: rather than rejected, so a typo shows up as missing data instead of an error.
AI_GW_GROUP_COLUMNS: Final[tuple[str, ...]] = (
    "cost",
    "avg_latency",
    "avg_tokens",
    "total_tokens",
    "success_rate",
    "last_seen",
)


def ai_gw_organisations_auth_settings_path(tsg_id: str) -> str:
    """Build the organisation auth-settings path for ``tsg_id``.

    Args:
        tsg_id: Tenant Service Group identifier. Validate before calling.

    Returns:
        The path segment, without a base URL.
    """
    return f"/organisations/{tsg_id}/auth-settings"
