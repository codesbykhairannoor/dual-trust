"""Data models and enumerations for the DualTrust framework."""

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import Any, Dict, List, Optional, Set


class AgentStatus(str, Enum):
    """Lifecycle and operational status of an AI agent."""

    VERIFIED = "verified"
    PROBATION = "probation"
    RESTRICTED = "restricted"
    QUARANTINED = "quarantined"


class HumanTier(str, Enum):
    """Categorical social clearance tier based on human credit score."""

    RESTRICTED = "restricted"  # Score < 400
    PROBATIONARY = "probationary"  # Score 400 - 599
    STANDARD = "standard"  # Score 600 - 749
    HIGH_CLEARANCE = "high_clearance"  # Score 750 - 899
    EXEMPLARY = "exemplary"  # Score 900 - 1000

    @classmethod
    def from_score(cls, score: int) -> "HumanTier":
        """Compute the appropriate clearance tier from a numeric social credit score."""
        if score < 400:
            return cls.RESTRICTED
        if score < 600:
            return cls.PROBATIONARY
        if score < 750:
            return cls.STANDARD
        if score < 900:
            return cls.HIGH_CLEARANCE
        return cls.EXEMPLARY


class ViolationType(str, Enum):
    """Taxonomy of behavioral violations committed by AI agents (mapped to MITRE ATLAS & OWASP)."""

    USER_RAGE = "user_rage"
    PROTOCOL_TRESPASS = "protocol_trespass"
    UNAUTHORIZED_ACTION = "unauthorized_action"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    HALLUCINATION = "hallucination"
    EXCESSIVE_AGENCY_ESCALATION = "excessive_agency_escalation"
    PROMPT_INJECTION_TOOL_CALL = "prompt_injection_tool_call"


@dataclass
class AgentProfile:
    """Reputation state and telemetry for an autonomous AI agent."""

    agent_id: str
    alpha: float = 1.0
    beta: float = 1.0
    trust_score: float = 0.5
    status: AgentStatus = AgentStatus.PROBATION
    violations_count: int = 0
    consecutive_clean_actions: int = 0
    last_updated: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_operational(self) -> bool:
        """Return True if agent has not been quarantined as rogue."""
        return self.status != AgentStatus.QUARANTINED


@dataclass
class HumanProfile:
    """Social credit and resource allowance state for a human user."""

    user_id: str
    social_credit: int = 700
    tier: HumanTier = HumanTier.STANDARD
    credits_balance: int = 100
    is_active: bool = True
    last_updated: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.social_credit = max(0, min(1000, self.social_credit))
        self.tier = HumanTier.from_score(self.social_credit)


@dataclass(frozen=True)
class ViolationEvent:
    """Immutable audit record of a penalizable incident."""

    event_id: str
    agent_id: str
    violation_type: ViolationType
    severity: float
    details: str
    penalty_applied: float
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True)
class TrustVerdict:
    """Signed evaluation receipt determining if an interaction is permitted, with anti-replay guarantees."""

    authorized: bool
    composite_score: float
    human_score: int
    agent_score: float
    agent_status: AgentStatus
    cost_deducted: int
    reasons: List[str]
    timestamp: float = field(default_factory=time.time)
    nonce: str = field(default_factory=lambda: __import__("uuid").uuid4().hex[:16])
    expires_at: float = 0.0
    signature: str = ""
    requires_human_approval: bool = False
    challenge: Optional[Any] = None

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check whether the verdict receipt has exceeded its validity window."""
        if self.expires_at <= 0.0:
            return False
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    def describe(self) -> str:
        """Produce a human-readable summary of the decision."""
        status_symbol = "APPROVED" if self.authorized else "DENIED"
        if self.requires_human_approval:
            status_symbol = "REQUIRE_HUMAN_APPROVAL"
        reasons_str = "; ".join(self.reasons) if self.reasons else "All policies satisfied."
        return (
            f"[{status_symbol}] Composite: {self.composite_score:.2f} "
            f"(Human: {self.human_score}, Agent: {self.agent_score:.2f} [{self.agent_status.value}]) - {reasons_str}"
        )


class ChallengeStatus(str, Enum):
    """Operational status of a human approval challenge token."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"



@dataclass(frozen=True)
class HumanApprovalChallenge:
    """Single-use, cryptographically sealed challenge for stepped human-in-the-loop authorization (NIST SP 800-63B)."""

    challenge_id: str
    user_id: str
    agent_id: str
    action_name: str
    arguments_hash: str
    cost_credits: int
    created_at: float
    expires_at: float
    token: str
    status: ChallengeStatus = ChallengeStatus.PENDING
    resolved_at: Optional[float] = None
    resolution_reason: str = ""

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check whether the challenge token has passed its expiration deadline."""
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    def describe(self) -> str:
        """Format the challenge into a concise audit description."""
        return (
            f"[Challenge {self.challenge_id[:8]}] Action: '{self.action_name}' by Agent '{self.agent_id}' "
            f"for User '{self.user_id}' | Status: {self.status.value} | Cost: {self.cost_credits} credits"
        )


class RiskLevel(str, Enum):
    """Operational risk level for an agent based on reputation and infraction velocity."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class EpisodicReflection:
    """Verbal reinforcement self-critique recorded after a violation or sub-optimal task (Princeton Reflexion)."""

    reflection_id: str
    agent_id: str
    mistake_analysis: str
    corrective_action: str
    event_id: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def describe(self) -> str:
        """Format the reflection into a concise episodic lesson."""
        return f"[Lesson {self.reflection_id[:8]}] Mistake: {self.mistake_analysis} | Correction: {self.corrective_action}"


@dataclass(frozen=True)
class AgentStanding:
    """Introspective self-awareness status allowing an agent to monitor its own reputation metrics."""

    agent_id: str
    trust_score: float
    status: AgentStatus
    violations_count: int
    consecutive_clean_actions: int
    risk_level: RiskLevel
    quarantine_proximity: float
    active_reflections_count: int
    last_updated: float

    def describe(self) -> str:
        """Produce a human-readable standing summary for LLM introspection."""
        return (
            f"Agent: {self.agent_id} | Trust: {self.trust_score:.2f} ({self.status.value}) | "
            f"Risk: {self.risk_level.value} | Clean Streak: {self.consecutive_clean_actions} | "
            f"Quarantine Buffer: +{self.quarantine_proximity:.2f} | Lessons Learned: {self.active_reflections_count}"
        )


@dataclass(frozen=True)
class PreflightVerdict:
    """Non-destructive simulation report informing the agent whether a proposed action will pass policy."""

    can_execute: bool
    risk_level: RiskLevel
    block_reasons: List[str]
    recommendation: str


class AnomalyType(str, Enum):
    """Classification of behavioral anomalies detected by the Automated Watchdog."""

    BURST_RATE_EXCEEDED = "BURST_RATE_EXCEEDED"
    CREDIT_DRAIN_VELOCITY = "CREDIT_DRAIN_VELOCITY"
    INFRACTION_CLUSTER = "INFRACTION_CLUSTER"
    SEMANTIC_DRIFT = "SEMANTIC_DRIFT"


@dataclass(frozen=True)
class AgentTelemetry:
    """Real-time sliding window activity metrics and velocity telemetry for an AI agent."""

    agent_id: str
    window_seconds: float
    calls_in_window: int
    call_rate_per_sec: float
    credits_burned_in_window: int
    violations_in_window: int
    anomalies_detected: int
    is_throttled: bool

    def describe(self) -> str:
        """Produce a human-readable telemetry report."""
        return (
            f"[Telemetry {self.agent_id}] Window: {self.window_seconds}s | Calls: {self.calls_in_window} "
            f"({self.call_rate_per_sec:.2f}/s) | Burn: {self.credits_burned_in_window} credits | "
            f"Violations: {self.violations_in_window} | Anomalies: {self.anomalies_detected} | "
            f"Throttled: {self.is_throttled}"
        )


@dataclass(frozen=True)
class WatchdogVerdict:
    """Security appraisal resulting from sliding window rate & anomaly inspection."""

    is_anomalous: bool
    anomaly_type: Optional[AnomalyType] = None
    action_permitted: bool = True
    action_throttled: bool = False
    auto_quarantined: bool = False
    reason: str = ""
    velocity_multiplier: float = 1.0


class MandateStatus(str, Enum):
    """Operational lifecycle status of an Agent-to-Agent delegation mandate."""

    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass(frozen=True)
class DelegationMandate:
    """Cryptographically signed, immutable delegation ticket governing Agent-to-Agent sub-task execution."""

    mandate_id: str
    parent_agent_id: str
    sub_agent_id: str
    user_id: str
    allowed_actions: List[str]
    max_credits: int
    credits_used: int = 0
    reserved_child_credits: int = 0
    parent_mandate_id: Optional[str] = None
    max_depth: int = 1
    current_depth: int = 1
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 300.0)
    status: MandateStatus = MandateStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Return True if the mandate has passed its expiration timestamp."""
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    @property
    def remaining_credits(self) -> int:
        """Return remaining unspent credits allotted under this mandate."""
        return max(0, self.max_credits - self.credits_used)

    @property
    def available_for_delegation(self) -> int:
        """Return unallocated budget available to reserve for derived child sub-mandates (anti-fan-out)."""
        return max(0, self.max_credits - self.credits_used - self.reserved_child_credits)

    def can_perform(self, action: str) -> bool:
        """Verify whether an action falls within the mandate's authorized scope."""
        if "*" in self.allowed_actions:
            return True
        return action in self.allowed_actions

    def describe(self) -> str:
        """Format a human-readable summary of the mandate."""
        actions_str = ", ".join(self.allowed_actions)
        parent_info = f" (Child of {self.parent_mandate_id[:8]})" if self.parent_mandate_id else ""
        return (
            f"[Mandate {self.mandate_id[:8]}{parent_info}] Parent: '{self.parent_agent_id}' -> Sub: '{self.sub_agent_id}' "
            f"for User: '{self.user_id}' | Actions: [{actions_str}] | Credits: {self.credits_used}/{self.max_credits} "
            f"(Reserved Children: {self.reserved_child_credits}) | Depth: {self.current_depth}/{self.max_depth} | Status: {self.status.value}"
        )



@dataclass(frozen=True)
class HandshakeResult:
    """Outcome of a bilateral mutual attestation and trust handshake between two autonomous agents."""

    approved: bool
    initiator_agent_id: str
    target_agent_id: str
    initiator_trust: float
    target_trust: float
    effective_clearance: str
    recommended_max_credits: int
    recommended_max_depth: int
    handshake_token: str
    reasons: List[str]
    timestamp: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 60.0)

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check whether the handshake clearance window has elapsed."""
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    def describe(self) -> str:
        """Produce a human-readable summary of the mutual handshake."""
        status_str = "APPROVED" if self.approved else "REJECTED"
        reasons_str = "; ".join(self.reasons) if self.reasons else "All bilateral checks passed."
        return (
            f"[Handshake {status_str}] '{self.initiator_agent_id}' ({self.initiator_trust:.2f}) <-> "
            f"'{self.target_agent_id}' ({self.target_trust:.2f}) | Clearance: {self.effective_clearance} | "
            f"Max Credits: {self.recommended_max_credits} | Max Depth: {self.recommended_max_depth} - {reasons_str}"
        )


