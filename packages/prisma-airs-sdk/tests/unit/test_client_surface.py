"""Entry clients must expose exactly the sub-clients the reference exposes.

This exists because splitting a client's implementation across two modules is easy to do
and easy to get wrong: the entry client ends up exposing only the half that lives next to
it, and every individual test still passes because each half works fine on its own. The
gap only shows as a missing attribute, in someone else's code, later.

The expected sets below are transcribed from the TypeScript entry clients -- the
``this.<name> = new <Client>()`` assignments in each ``client.ts`` -- converted to
snake_case. Adding a sub-client to a module is not enough; it has to be reachable from the
client a caller actually constructs.
"""

from __future__ import annotations

import pytest

from prisma_airs.ai_gateway.ai_gateway_core import AIGatewayClient
from prisma_airs.dlp.dlp import DlpClient
from prisma_airs.management.management import ManagementClient
from prisma_airs.model_security.model_security import ModelSecurityClient
from prisma_airs.red_team.red_team_core import RedTeamClient

#: Transcribed from red-team/client.ts, ai-gateway/client.ts, management/client.ts,
#: model-security/client.ts, and management/dlp/index.ts.
REFERENCE_SURFACE: dict[type, set[str]] = {
    RedTeamClient: {
        "adapters",
        "custom_attack_reports",
        "custom_attacks",
        "eula",
        "instances",
        "network_broker",
        "reports",
        "scans",
        "targets",
    },
    AIGatewayClient: {
        "api_keys",
        "audit_logs",
        "configs",
        "deployments",
        "guardrails",
        "integrations",
        "mcp_integrations",
        "organisations",
        "plugins",
        "providers",
        "telemetry",
        "workspaces",
    },
    ManagementClient: {
        "api_keys",
        "customer_apps",
        "dashboard",
        "deployment_profiles",
        "dlp",
        "dlp_profiles",
        "oauth",
        "profiles",
        "scan_logs",
        "topics",
    },
    ModelSecurityClient: {
        "models",
        "scans",
        "security_groups",
        "security_rules",
    },
    DlpClient: {
        "data_filtering_profiles",
        "data_patterns",
        "data_profiles",
        "dictionaries",
    },
}


@pytest.fixture(autouse=True)
def credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every entry client resolves credentials at construction."""
    monkeypatch.setenv("PANW_MGMT_CLIENT_ID", "client-id")
    monkeypatch.setenv("PANW_MGMT_CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("PANW_MGMT_TSG_ID", "1016244978")


@pytest.mark.parametrize(
    ("client_class", "expected"),
    REFERENCE_SURFACE.items(),
    ids=lambda v: v.__name__ if isinstance(v, type) else "",
)
def test_exposes_exactly_the_reference_sub_clients(client_class: type, expected: set[str]) -> None:
    """A missing member is a silent parity gap; an extra one is undocumented surface."""
    client = client_class()
    try:
        public = {name for name in vars(client) if not name.startswith("_")}
    finally:
        client.close()

    assert public == expected


@pytest.mark.parametrize("client_class", list(REFERENCE_SURFACE), ids=lambda c: c.__name__)
def test_sub_clients_share_the_parents_connection_pool(client_class: type) -> None:
    """One client should mean one pool, however many sub-clients hang off it.

    Sub-clients that quietly build their own would leak sockets and, worse, bypass any
    HTTP client the caller supplied for proxying or instrumentation.
    """
    client = client_class()
    try:
        pool = client._http
        for name in REFERENCE_SURFACE[client_class]:
            sub = getattr(client, name)
            assert sub._http is pool, f"{name} does not share the parent's HTTP client"
    finally:
        client.close()
