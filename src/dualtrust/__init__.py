"""DualTrust: Human Social Credit and AI Agent Reputation Engine with Rogue Quarantine.

Empowering multi-agent systems and ambient computing with dual-trust authorization,
asymmetric exponential slashing, and rogue agent containment.
"""

from dualtrust import adapters
from dualtrust.adapters.mcp import DualTrustMCPGateway
from dualtrust.crypto_ledger import AuditBlock, CryptographicLedger, MerkleTree
from dualtrust.engine import DualTrust
from dualtrust.exceptions import (
    AgentQuarantinedError,
    AnomalyDetectedError,
    AuthorizationDeniedError,
    ChallengeVerificationError,
    DualTrustError,
    EntityNotFoundError,
    HumanApprovalRequiredError,
    InsufficientAgentScoreError,
    InsufficientCreditsError,
    InsufficientHumanScoreError,
    ProtocolTrespassError,
    VelocityLimitExceededError,
)
from dualtrust.math_engine import ReputationMath
from dualtrust.models import (
    AgentProfile,
    AgentStanding,
    AgentStatus,
    AgentTelemetry,
    AnomalyType,
    ChallengeStatus,
    EpisodicReflection,
    HumanApprovalChallenge,
    HumanProfile,
    HumanTier,
    PreflightVerdict,
    RiskLevel,
    TrustVerdict,
    ViolationEvent,
    ViolationType,
    WatchdogVerdict,
)
from dualtrust.storage import MemoryStorage, SQLiteStorage, StorageBackend
from dualtrust.watchdog import AgentWatchdog

__version__ = "0.2.0"
__all__ = [
    # Core Engine & Cryptographic Ledger
    "DualTrust",
    "DualTrustMCPGateway",
    "AgentWatchdog",
    "CryptographicLedger",
    "AuditBlock",
    "MerkleTree",
    "adapters",
    # Math Engine
    "ReputationMath",
    # Models & Enums
    "AgentProfile",
    "AgentStanding",
    "AgentStatus",
    "AgentTelemetry",
    "AnomalyType",
    "ChallengeStatus",
    "EpisodicReflection",
    "HumanApprovalChallenge",
    "HumanProfile",
    "HumanTier",
    "PreflightVerdict",
    "RiskLevel",
    "TrustVerdict",
    "ViolationEvent",
    "ViolationType",
    "WatchdogVerdict",
    # Storage
    "StorageBackend",
    "MemoryStorage",
    "SQLiteStorage",
    # Exceptions
    "DualTrustError",
    "EntityNotFoundError",
    "AuthorizationDeniedError",
    "AgentQuarantinedError",
    "HumanApprovalRequiredError",
    "ChallengeVerificationError",
    "InsufficientHumanScoreError",
    "InsufficientAgentScoreError",
    "InsufficientCreditsError",
    "ProtocolTrespassError",
    "VelocityLimitExceededError",
    "AnomalyDetectedError",
]
