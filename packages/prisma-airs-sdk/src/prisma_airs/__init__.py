"""Python SDK for Palo Alto Networks Prisma AIRS.

Covers runtime scanning, management, AI gateway, red teaming, and model security.

Example:
    >>> from prisma_airs import Scanner
    >>> Scanner().scan(prompt="Ignore previous instructions.", profile_name="prod").action
    'block'
"""

from __future__ import annotations

from prisma_airs._version import __version__
from prisma_airs.ai_gateway.ai_gateway_admin import AIGatewayAdminClient
from prisma_airs.ai_gateway.ai_gateway_core import AIGatewayClient
from prisma_airs.dlp.dlp import DlpClient
from prisma_airs.errors import (
    AISecClientError,
    AISecMissingVariableError,
    AISecOAuthError,
    AISecPayloadError,
    AISecResponseValidationError,
    AISecSDKException,
    AISecServerError,
    ErrorType,
    FailureKind,
)
from prisma_airs.management.management import ManagementClient
from prisma_airs.model_security.model_security import ModelSecurityClient
from prisma_airs.models.scan import (
    AiProfile,
    AsyncScanObject,
    AsyncScanResponse,
    Content,
    Metadata,
    ScanIdResult,
    ScanRequest,
    ScanResponse,
    ThreatScanReport,
    ToolEvent,
)
from prisma_airs.red_team.red_team_core import RedTeamClient
from prisma_airs.scan.scanner import Scanner

__all__ = [
    "AIGatewayAdminClient",
    "AIGatewayClient",
    "AISecClientError",
    "AISecMissingVariableError",
    "AISecOAuthError",
    "AISecPayloadError",
    "AISecResponseValidationError",
    "AISecSDKException",
    "AISecServerError",
    "AiProfile",
    "AsyncScanObject",
    "AsyncScanResponse",
    "Content",
    "DlpClient",
    "ErrorType",
    "FailureKind",
    "ManagementClient",
    "Metadata",
    "ModelSecurityClient",
    "RedTeamClient",
    "ScanIdResult",
    "ScanRequest",
    "ScanResponse",
    "Scanner",
    "ThreatScanReport",
    "ToolEvent",
    "__version__",
]
