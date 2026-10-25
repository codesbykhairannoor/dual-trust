"""Exception hierarchy for the DualTrust framework."""

from typing import Any, Optional


class DualTrustError(Exception):
    """Base exception for all DualTrust operational errors."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, details={self.details!r})"


class EntityNotFoundError(DualTrustError):
    """Raised when querying a human or agent entity that does not exist in registry."""


class AuthorizationDeniedError(DualTrustError):
    """Raised when an action is rejected by the DualTrust evaluation gate."""


class AgentQuarantinedError(AuthorizationDeniedError):
    """Raised when an action is blocked because the agent is quarantined as rogue."""


class InsufficientHumanScoreError(AuthorizationDeniedError):
    """Raised when human social credit is below the required threshold."""


class InsufficientAgentScoreError(AuthorizationDeniedError):
    """Raised when agent trust score is below the required threshold."""


class InsufficientCreditsError(AuthorizationDeniedError):
    """Raised when the human's available spendable credits are lower than action cost."""


class ProtocolTrespassError(DualTrustError):
    """Raised when an agent attempts an unauthorized cross-system or cross-agent call."""


class HumanApprovalRequiredError(DualTrustError):
    """Raised when an action is paused awaiting step-up human-in-the-loop authorization (NIST SP 800-63B)."""

    def __init__(self, message: str, challenge: Any = None, details: Optional[Any] = None) -> None:
        super().__init__(message, details)
        self.challenge = challenge


class ChallengeVerificationError(DualTrustError):
    """Raised when a human approval challenge token fails cryptographic verification or has expired."""


class VelocityLimitExceededError(AuthorizationDeniedError):
    """Raised when an agent breaches frequency velocity or credit burn limits in a sliding window (MITRE ATLAS AML.T0029)."""


class AnomalyDetectedError(DualTrustError):
    """Raised when the automated security watchdog detects high-risk behavioral anomaly or runaway loop."""
