"""Python SDK for Palo Alto Networks Prisma AIRS.

Covers runtime scanning, management, AI gateway, red teaming, and model security.

Example:
    >>> from prisma_airs import Scanner
    >>> Scanner().scan(prompt="Ignore previous instructions.", profile_name="prod").action
    'block'
"""

from __future__ import annotations

from prisma_airs._version import __version__
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
from prisma_airs.scan.scanner import Scanner

__all__ = [
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
    "ErrorType",
    "FailureKind",
    "Metadata",
    "ScanIdResult",
    "ScanRequest",
    "ScanResponse",
    "Scanner",
    "ThreatScanReport",
    "ToolEvent",
    "__version__",
]
