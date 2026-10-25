"""Main engine for the DualTrust framework with cryptographic audit trail and async support."""

import asyncio
import functools
import hashlib
import inspect
import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import uuid

from dualtrust.crypto_ledger import AuditBlock, CryptographicLedger, MerkleTree
from dualtrust.exceptions import (
    AgentQuarantinedError,
    AnomalyDetectedError,
    AuthorizationDeniedError,
    ChallengeVerificationError,
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
from dualtrust.storage import MemoryStorage, StorageBackend
from dualtrust.watchdog import AgentWatchdog


class DualTrust:
    """Enterprise-grade Dual-Trust Matrix and Autonomous Agent Governance Engine."""

    def __init__(
        self,
        storage: Optional[StorageBackend] = None,
        math_engine: Optional[ReputationMath] = None,
        ledger: Optional[CryptographicLedger] = None,
        human_weight: float = 0.4,
        agent_weight: float = 0.6,
        secret_key: Optional[str] = None,
        verdict_ttl_seconds: float = 60.0,
        watchdog: Optional[AgentWatchdog] = None,
    ) -> None:
        """Initialize the DualTrust engine.

        Args:
            storage: Storage backend for profile state and violations (defaults to MemoryStorage).
            math_engine: Mathematical engine for reputation calculations.
            ledger: Cryptographic hash-chained audit ledger.
            human_weight: Weight of human credit in composite score calculations (0.0 to 1.0).
            agent_weight: Weight of agent reputation in composite score calculations (0.0 to 1.0).
            secret_key: Cryptographic HMAC key for signing verdict receipts (defaults to random).
            verdict_ttl_seconds: Time-to-live validity window for verdict receipts.
            watchdog: Optional sliding window behavioral watchdog for anomaly detection & rate limiting.
        """
        self.storage = storage or MemoryStorage()
        self.math = math_engine or ReputationMath()
        self.ledger = ledger or CryptographicLedger()
        self.secret_key = secret_key or uuid.uuid4().hex
        self.verdict_ttl_seconds = verdict_ttl_seconds
        self.watchdog = watchdog

        weight_sum = human_weight + agent_weight
        if weight_sum <= 0:
            raise ValueError("Sum of human_weight and agent_weight must be positive.")
        self.human_weight = human_weight / weight_sum
        self.agent_weight = agent_weight / weight_sum

    # =========================================================================
    # Entity Registration and Lookup
    # =========================================================================

    def register_human(
        self,
        user_id: str,
        social_credit: int = 700,
        credits_balance: int = 100,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> HumanProfile:
        """Register or update a human user in the social credit ledger."""
        profile = HumanProfile(
            user_id=user_id,
            social_credit=social_credit,
            credits_balance=credits_balance,
            metadata=metadata or {},
        )
        self.storage.save_human(profile)
        self.ledger.append(
            event_type="HUMAN_REGISTERED",
            entity_id=user_id,
            payload={"social_credit": social_credit, "credits_balance": credits_balance},
        )
        return profile

    def get_human(self, user_id: str) -> Optional[HumanProfile]:
        """Fetch human profile from storage."""
        return self.storage.get_human(user_id)

    def get_or_create_human(self, user_id: str) -> HumanProfile:
        """Fetch human profile or register a standard default profile."""
        profile = self.storage.get_human(user_id)
        if profile is None:
            profile = self.register_human(user_id=user_id)
        return profile

    def register_agent(
        self,
        agent_id: str,
        initial_trust: float = 0.5,
        sample_weight: float = 10.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentProfile:
        """Register or update an AI agent in the reputation registry."""
        initial_trust = max(0.05, min(0.95, initial_trust))
        sample_weight = max(2.0, sample_weight)
        alpha = sample_weight * initial_trust
        beta = sample_weight * (1.0 - initial_trust)
        status = self.math.determine_status(initial_trust)

        profile = AgentProfile(
            agent_id=agent_id,
            alpha=alpha,
            beta=beta,
            trust_score=initial_trust,
            status=status,
            metadata=metadata or {},
        )
        self.storage.save_agent(profile)
        self.ledger.append(
            event_type="AGENT_REGISTERED",
            entity_id=agent_id,
            payload={"initial_trust": initial_trust, "status": status.value},
        )
        return profile

    def get_agent(self, agent_id: str) -> Optional[AgentProfile]:
        """Fetch agent profile from storage."""
        return self.storage.get_agent(agent_id)

    def get_or_create_agent(self, agent_id: str) -> AgentProfile:
        """Fetch agent profile with time-decay evaluated, or register a standard profile."""
        profile = self.storage.get_agent(agent_id)
        if profile is None:
            profile = self.register_agent(agent_id=agent_id)
        else:
            # Apply continuous half-life decay on retrieval
            self.math.apply_time_decay(profile)
            self.storage.save_agent(profile)
        return profile

    # =========================================================================
    # Reputation & Credit Adjustments
    # =========================================================================

    def adjust_human_credit(self, user_id: str, delta: int, reason: str = "") -> HumanProfile:
        """Adjust a human's social credit score up or down and append to hash chain."""
        profile = self.get_or_create_human(user_id)
        old_score = profile.social_credit
        profile.social_credit = max(0, min(1000, profile.social_credit + delta))
        profile.tier = HumanTier.from_score(profile.social_credit)
        profile.last_updated = time.time()
        if reason:
            profile.metadata.setdefault("credit_history", []).append(
                {"delta": delta, "reason": reason, "timestamp": profile.last_updated}
            )
        self.storage.save_human(profile)
        self.ledger.append(
            event_type="CREDIT_ADJUSTMENT",
            entity_id=user_id,
            payload={"old_score": old_score, "new_score": profile.social_credit, "delta": delta, "reason": reason},
        )
        return profile

    def add_credits(self, user_id: str, amount: int) -> int:
        """Deposit spendable token credits to a human user account."""
        self.get_or_create_human(user_id)
        new_balance = self.storage.add_credits(user_id, amount)
        self.ledger.append(
            event_type="CREDITS_DEPOSITED",
            entity_id=user_id,
            payload={"amount": amount, "new_balance": new_balance},
        )
        return new_balance

    def reward_agent(self, agent_id: str, weight: float = 1.0) -> float:
        """Reward an agent for successful, compliant task execution."""
        profile = self.get_or_create_agent(agent_id)
        new_score = self.math.apply_positive_feedback(profile, weight=weight)
        self.storage.save_agent(profile)
        self.ledger.append(
            event_type="AGENT_REWARDED",
            entity_id=agent_id,
            payload={"weight": weight, "new_trust_score": new_score},
        )
        return new_score

    def report_violation(
        self,
        agent_id: str,
        violation_type: ViolationType,
        severity: float = 2.0,
        reporter_id: Optional[str] = None,
        details: str = "",
    ) -> ViolationEvent:
        """Report a behavioral violation with Sybil-resistant reporter discounting."""
        profile = self.get_or_create_agent(agent_id)

        # Compute reporter credibility weight to protect against malicious defamation
        reporter_credibility = 1.0
        if reporter_id:
            reporter_agent = self.storage.get_agent(reporter_id)
            if reporter_agent:
                reporter_credibility = (
                    0.05 if reporter_agent.status == AgentStatus.QUARANTINED else reporter_agent.trust_score
                )
            else:
                reporter_human = self.storage.get_human(reporter_id)
                if reporter_human:
                    reporter_credibility = reporter_human.social_credit / 1000.0

        effective_severity = severity
        watchdog_quarantine = False
        if self.watchdog is not None:
            vel_multiplier, should_quarantine = self.watchdog.record_violation_velocity(agent_id, severity)
            effective_severity = severity * vel_multiplier
            watchdog_quarantine = should_quarantine

        new_score, penalty_delta, was_quarantined = self.math.apply_violation_penalty(
            profile,
            violation_type=violation_type,
            severity=effective_severity,
            reporter_credibility=reporter_credibility,
        )
        if watchdog_quarantine and profile.status != AgentStatus.QUARANTINED:
            profile.status = AgentStatus.QUARANTINED
            was_quarantined = True
        self.storage.save_agent(profile)

        event = ViolationEvent(
            event_id=f"viol_{uuid.uuid4().hex[:12]}",
            agent_id=agent_id,
            violation_type=violation_type,
            severity=severity,
            details=details,
            penalty_applied=penalty_delta,
        )
        self.storage.record_violation(event)

        # Record tamper-evident cryptographic block in hash chain
        self.ledger.append(
            event_type="VIOLATION_PENALTY",
            entity_id=agent_id,
            payload={
                "event_id": event.event_id,
                "violation_type": violation_type.value,
                "severity": severity,
                "reporter_id": reporter_id,
                "reporter_credibility": reporter_credibility,
                "penalty_applied": penalty_delta,
                "new_trust_score": new_score,
                "was_quarantined": was_quarantined,
                "details": details,
            },
        )
        return event

    def flag_user_rage(
        self,
        agent_id: str,
        reason: str = "User frustration reported",
        severity: float = 3.0,
        reporter_id: Optional[str] = None,
    ) -> ViolationEvent:
        """Convenience method: Flag an agent for causing user distress or rage."""
        return self.report_violation(
            agent_id=agent_id,
            violation_type=ViolationType.USER_RAGE,
            severity=severity,
            reporter_id=reporter_id,
            details=reason,
        )

    def flag_protocol_trespass(
        self,
        agent_id: str,
        target_system: str,
        details: str = "Unauthorized cross-system intrusion",
        severity: float = 4.0,
        reporter_id: Optional[str] = None,
    ) -> ViolationEvent:
        """Convenience method: Flag an agent for trespassing into unauthorized system queues."""
        full_details = f"Target: {target_system}. {details}"
        return self.report_violation(
            agent_id=agent_id,
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=severity,
            reporter_id=reporter_id,
            details=full_details,
        )

    def quarantine_agent(self, agent_id: str, reason: str = "Manual security isolation") -> AgentProfile:
        """Immediately isolate an agent into quarantined status."""
        profile = self.get_or_create_agent(agent_id)
        profile.status = AgentStatus.QUARANTINED
        profile.metadata["quarantine_reason"] = reason
        profile.last_updated = time.time()
        self.storage.save_agent(profile)
        self.ledger.append(
            event_type="AGENT_QUARANTINED",
            entity_id=agent_id,
            payload={"reason": reason},
        )
        return profile

    def pardon_agent(
        self, agent_id: str, reset_trust: float = 0.50, sample_weight: float = 10.0
    ) -> AgentProfile:
        """Release an agent from quarantine and reset baseline parameters."""
        profile = self.get_or_create_agent(agent_id)
        sample_weight = max(2.0, sample_weight)
        profile.alpha = sample_weight * reset_trust
        profile.beta = sample_weight * (1.0 - reset_trust)
        profile.trust_score = reset_trust
        profile.status = self.math.determine_status(reset_trust)
        profile.last_updated = time.time()
        self.storage.save_agent(profile)
        self.ledger.append(
            event_type="AGENT_PARDONED",
            entity_id=agent_id,
            payload={"reset_trust": reset_trust},
        )
        return profile

    # =========================================================================
    # Automated Security Watchdog & Velocity Governance (MITRE ATLAS AML.T0029)
    # =========================================================================

    def enable_watchdog(
        self,
        window_seconds: float = 60.0,
        max_calls_per_window: int = 30,
        max_credit_burn_per_window: int = 200,
        max_violations_per_window: int = 3,
        auto_quarantine_on_burst: bool = True,
        velocity_slashing_multiplier: float = 1.5,
    ) -> AgentWatchdog:
        """Enable and configure sliding-window velocity and anomaly watchdog monitoring."""
        self.watchdog = AgentWatchdog(
            window_seconds=window_seconds,
            max_calls_per_window=max_calls_per_window,
            max_credit_burn_per_window=max_credit_burn_per_window,
            max_violations_per_window=max_violations_per_window,
            auto_quarantine_on_burst=auto_quarantine_on_burst,
            velocity_slashing_multiplier=velocity_slashing_multiplier,
        )
        return self.watchdog

    def get_watchdog_telemetry(self, agent_id: str) -> Optional[AgentTelemetry]:
        """Fetch current activity velocity and sliding window telemetry for an agent."""
        if self.watchdog is None:
            return None
        return self.watchdog.get_telemetry(agent_id)

    # =========================================================================
    # Evaluation Gate & Execution
    # =========================================================================

    def evaluate(
        self,
        user_id: str,
        agent_id: str,
        min_human_score: int = 600,
        min_agent_score: float = 0.50,
        required_tier: Optional[HumanTier] = None,
        cost_credits: int = 0,
        deduct_cost: bool = False,
        require_human_confirmation: bool = False,
        action_name: str = "action",
        arguments: Optional[Dict[str, Any]] = None,
        challenge_id: Optional[str] = None,
    ) -> TrustVerdict:
        """Evaluate whether an action is authorized under the dual-trust matrix."""
        human = self.get_or_create_human(user_id)
        agent = self.get_or_create_agent(agent_id)

        reasons: List[str] = []
        authorized = True
        challenge_obj: Optional[HumanApprovalChallenge] = None

        # Check 0: Stepped Human Approval Challenge (NIST SP 800-63B)
        if require_human_confirmation:
            if not challenge_id:
                challenge_obj = self.create_human_challenge(
                    user_id=user_id,
                    agent_id=agent_id,
                    action_name=action_name,
                    arguments=arguments or {},
                    cost_credits=cost_credits,
                )
                authorized = False
                reasons.append(
                    f"Stepped human approval required. Challenge token issued: {challenge_obj.challenge_id}"
                )
            else:
                ch = self.get_challenge(challenge_id)
                challenge_obj = ch
                if not ch:
                    authorized = False
                    reasons.append(f"Challenge '{challenge_id}' not found.")
                elif ch.is_expired():
                    authorized = False
                    reasons.append(f"Challenge '{challenge_id}' has expired.")
                elif ch.status != ChallengeStatus.APPROVED:
                    authorized = False
                    reasons.append(
                        f"Challenge '{challenge_id}' is not approved (status: {ch.status.value})."
                    )
                elif arguments is not None:
                    canonical_args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
                    if hashlib.sha256(canonical_args.encode("utf-8")).hexdigest() != ch.arguments_hash:
                        authorized = False
                        reasons.append(
                            "Payload tampering detected: Arguments do not match approved challenge."
                        )

        # Check 1: Agent Quarantine Check
        if agent.status == AgentStatus.QUARANTINED:
            authorized = False
            reasons.append("Agent is quarantined due to rogue behavior or low reputation.")

        # Check 1.5: Automated Watchdog Sliding Window Inspection (MITRE ATLAS AML.T0029)
        elif self.watchdog is not None:
            wv = self.watchdog.inspect_pre_call(agent_id=agent_id, cost_credits=cost_credits)
            if not wv.action_permitted:
                authorized = False
                reasons.append(f"Watchdog security trigger: {wv.reason}")
                if wv.auto_quarantined and agent.status != AgentStatus.QUARANTINED:
                    agent.status = AgentStatus.QUARANTINED
                    self.storage.save_agent(agent)
                    self.ledger.append(
                        event_type="WATCHDOG_AUTO_QUARANTINE",
                        entity_id=agent_id,
                        payload={"reason": wv.reason},
                    )

        # Check 2: Agent Score Threshold
        elif agent.trust_score < min_agent_score:
            authorized = False
            reasons.append(
                f"Agent trust score ({agent.trust_score:.2f}) below required ({min_agent_score:.2f})."
            )

        # Check 3: Human Active State
        if not human.is_active:
            authorized = False
            reasons.append("Human social account is inactive or suspended.")

        # Check 4: Human Credit Score Threshold
        if human.social_credit < min_human_score:
            authorized = False
            reasons.append(
                f"Human social credit ({human.social_credit}) below required ({min_human_score})."
            )

        # Check 5: Human Tier Requirement
        if required_tier is not None:
            tier_ranks = {
                HumanTier.RESTRICTED: 1,
                HumanTier.PROBATIONARY: 2,
                HumanTier.STANDARD: 3,
                HumanTier.HIGH_CLEARANCE: 4,
                HumanTier.EXEMPLARY: 5,
            }
            if tier_ranks[human.tier] < tier_ranks[required_tier]:
                authorized = False
                reasons.append(
                    f"Human clearance tier ({human.tier.value}) does not satisfy required ({required_tier.value})."
                )

        # Check 6: Available Credit Balance
        if cost_credits > 0 and human.credits_balance < cost_credits:
            authorized = False
            reasons.append(
                f"Insufficient spendable credits ({human.credits_balance} < {cost_credits})."
            )

        # Compute Composite Score
        composite = self.math.compute_composite_trust(
            human_score=human.social_credit,
            agent_score=agent.trust_score,
            human_weight=self.human_weight,
            agent_weight=self.agent_weight,
        )

        cost_deducted = 0
        if authorized and deduct_cost and cost_credits > 0:
            deducted = self.storage.deduct_credits(user_id=user_id, amount=cost_credits)
            if not deducted:
                authorized = False
                reasons.append(
                    f"Insufficient spendable credits (atomic deduction failed: balance < {cost_credits})."
                )
            else:
                cost_deducted = cost_credits
                refreshed_human = self.storage.get_human(user_id)
                if refreshed_human:
                    human = refreshed_human

        timestamp = time.time()
        nonce = uuid.uuid4().hex[:16]
        expires_at = timestamp + self.verdict_ttl_seconds
        raw_preimage = f"{user_id}:{agent_id}:{nonce}:{timestamp:.4f}:{authorized}:{self.secret_key}"
        signature = hashlib.sha256(raw_preimage.encode("utf-8")).hexdigest()

        verdict = TrustVerdict(
            authorized=authorized,
            composite_score=composite,
            human_score=human.social_credit,
            agent_score=agent.trust_score,
            agent_status=agent.status,
            cost_deducted=cost_deducted,
            reasons=reasons,
            timestamp=timestamp,
            nonce=nonce,
            expires_at=expires_at,
            signature=signature,
            requires_human_approval=(require_human_confirmation and not challenge_id),
            challenge=challenge_obj,
        )

        # Cryptographically log evaluation decision
        self.ledger.append(
            event_type="EVALUATION_DECISION",
            entity_id=f"{user_id}:{agent_id}",
            payload={
                "authorized": authorized,
                "composite_score": composite,
                "cost_deducted": cost_deducted,
                "nonce": nonce,
                "expires_at": expires_at,
                "reasons": reasons,
            },
        )

        return verdict

    def verify_verdict(
        self,
        verdict: TrustVerdict,
        user_id: str,
        agent_id: str,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Verify the cryptographic authenticity and freshness of a verdict receipt (anti-replay)."""
        if verdict.is_expired(current_time=current_time):
            return False, "Verdict receipt has expired (TTL exceeded)."

        raw_preimage = f"{user_id}:{agent_id}:{verdict.nonce}:{verdict.timestamp:.4f}:{verdict.authorized}:{self.secret_key}"
        expected_sig = hashlib.sha256(raw_preimage.encode("utf-8")).hexdigest()

        if verdict.signature != expected_sig:
            return False, "Verdict cryptographic signature mismatch; possible forgery or tampering."

        return True, None

    def execute(
        self,
        user_id: str,
        agent_id: str,
        func: Callable[..., Any],
        *args: Any,
        min_human_score: int = 600,
        min_agent_score: float = 0.50,
        required_tier: Optional[HumanTier] = None,
        cost_credits: int = 0,
        deduct_cost: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Evaluate policies and execute the callable (sync or async) if authorized."""
        verdict = self.evaluate(
            user_id=user_id,
            agent_id=agent_id,
            min_human_score=min_human_score,
            min_agent_score=min_agent_score,
            required_tier=required_tier,
            cost_credits=cost_credits,
            deduct_cost=deduct_cost,
        )

        if not verdict.authorized:
            self._raise_verdict_error(verdict)

        if inspect.iscoroutinefunction(func):
            async def _async_exec() -> Any:
                res = await func(*args, **kwargs)
                if self.watchdog is not None:
                    self.watchdog.record_call_success(agent_id=str(agent_id), cost_credits=verdict.cost_deducted)
                return res
            return _async_exec()
        res = func(*args, **kwargs)
        if self.watchdog is not None:
            self.watchdog.record_call_success(agent_id=str(agent_id), cost_credits=verdict.cost_deducted)
        return res

    def intercept_tool_call(
        self,
        user_id: str,
        agent_id: str,
        tool_name: str,
        tool_callable: Callable[..., Any],
        arguments: Dict[str, Any],
        min_human_score: int = 600,
        min_agent_score: float = 0.50,
        required_tier: Optional[HumanTier] = None,
        cost_credits: int = 0,
        deduct_cost: bool = True,
    ) -> Any:
        """Intercept dynamic LLM/Agent tool invocations (JSON payloads)."""
        verdict = self.evaluate(
            user_id=user_id,
            agent_id=agent_id,
            min_human_score=min_human_score,
            min_agent_score=min_agent_score,
            required_tier=required_tier,
            cost_credits=cost_credits,
            deduct_cost=deduct_cost,
        )

        if not verdict.authorized:
            self.ledger.append(
                event_type="TOOL_CALL_BLOCKED",
                entity_id=agent_id,
                payload={"tool_name": tool_name, "arguments": arguments, "reasons": verdict.reasons},
            )
            self._raise_verdict_error(verdict)

        self.ledger.append(
            event_type="TOOL_CALL_EXECUTED",
            entity_id=agent_id,
            payload={"tool_name": tool_name, "cost_credits": cost_credits},
        )
        res = tool_callable(**arguments)
        if self.watchdog is not None:
            self.watchdog.record_call_success(agent_id=str(agent_id), cost_credits=verdict.cost_deducted)
        return res

    def gate(
        self,
        min_human_score: int = 600,
        min_agent_score: float = 0.50,
        required_tier: Optional[HumanTier] = None,
        cost_credits: int = 0,
        deduct_cost: bool = True,
        require_human_confirmation: bool = False,
        challenge_ttl_seconds: float = 300.0,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator guarding functions under DualTrust policy enforcement.

        Supports standard evaluation, asynchronous coroutines, and stepped
        human-in-the-loop (HITL) challenge authorization (NIST SP 800-63B).
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            sig = inspect.signature(func)
            is_async = inspect.iscoroutinefunction(func)

            if is_async:
                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    challenge_id = kwargs.pop("challenge_id", None)

                    bound_args = sig.bind_partial(*args, **kwargs)
                    bound_args.apply_defaults()
                    user_id = bound_args.arguments.get("user_id")
                    agent_id = bound_args.arguments.get("agent_id")

                    if not user_id:
                        raise ValueError(f"Function {func.__name__} requires a 'user_id' argument.")
                    if not agent_id:
                        raise ValueError(f"Function {func.__name__} requires an 'agent_id' argument.")

                    if require_human_confirmation:
                        if not challenge_id:
                            challenge = self.create_human_challenge(
                                user_id=str(user_id),
                                agent_id=str(agent_id),
                                action_name=func.__name__,
                                arguments=dict(bound_args.arguments),
                                cost_credits=cost_credits,
                                ttl_seconds=challenge_ttl_seconds,
                            )
                            raise HumanApprovalRequiredError(
                                f"Action '{func.__name__}' paused awaiting human approval. Challenge ID: {challenge.challenge_id}",
                                challenge=challenge,
                            )
                        else:
                            ch = self.get_challenge(str(challenge_id))
                            if not ch:
                                raise ChallengeVerificationError(f"Challenge '{challenge_id}' not found.")
                            if ch.is_expired():
                                raise ChallengeVerificationError(
                                    f"Challenge '{challenge_id}' has expired (TTL exceeded)."
                                )
                            if ch.status != ChallengeStatus.APPROVED:
                                raise ChallengeVerificationError(
                                    f"Challenge '{challenge_id}' is not approved (status: {ch.status.value})."
                                )
                            canonical_args = json.dumps(dict(bound_args.arguments), sort_keys=True, separators=(",", ":"))
                            if ch.arguments_hash != hashlib.sha256(canonical_args.encode("utf-8")).hexdigest():
                                raise ChallengeVerificationError(
                                    "Payload tampering detected: Arguments do not match approved challenge."
                                )
                            if cost_credits > 0 and deduct_cost:
                                deducted = self.storage.deduct_credits(user_id=str(user_id), amount=cost_credits)
                                if not deducted:
                                    raise InsufficientCreditsError(
                                        f"Insufficient spendable credits ({cost_credits} required)."
                                    )
                            self.ledger.append(
                                event_type="ACTION_EXECUTED_WITH_CHALLENGE",
                                entity_id=str(challenge_id),
                                payload={"action_name": func.__name__, "user_id": str(user_id), "agent_id": str(agent_id)},
                            )
                            res = await func(*args, **kwargs)
                            if self.watchdog is not None:
                                self.watchdog.record_call_success(agent_id=str(agent_id), cost_credits=cost_credits)
                            return res

                    verdict = self.evaluate(
                        user_id=str(user_id),
                        agent_id=str(agent_id),
                        min_human_score=min_human_score,
                        min_agent_score=min_agent_score,
                        required_tier=required_tier,
                        cost_credits=cost_credits,
                        deduct_cost=deduct_cost,
                    )
                    if not verdict.authorized:
                        self._raise_verdict_error(verdict)

                    res = await func(*args, **kwargs)
                    if self.watchdog is not None:
                        self.watchdog.record_call_success(agent_id=str(agent_id), cost_credits=verdict.cost_deducted)
                    return res

                return async_wrapper
            else:
                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    challenge_id = kwargs.pop("challenge_id", None)

                    bound_args = sig.bind_partial(*args, **kwargs)
                    bound_args.apply_defaults()
                    user_id = bound_args.arguments.get("user_id")
                    agent_id = bound_args.arguments.get("agent_id")

                    if not user_id:
                        raise ValueError(f"Function {func.__name__} requires a 'user_id' argument.")
                    if not agent_id:
                        raise ValueError(f"Function {func.__name__} requires an 'agent_id' argument.")

                    if require_human_confirmation:
                        if not challenge_id:
                            challenge = self.create_human_challenge(
                                user_id=str(user_id),
                                agent_id=str(agent_id),
                                action_name=func.__name__,
                                arguments=dict(bound_args.arguments),
                                cost_credits=cost_credits,
                                ttl_seconds=challenge_ttl_seconds,
                            )
                            raise HumanApprovalRequiredError(
                                f"Action '{func.__name__}' paused awaiting human approval. Challenge ID: {challenge.challenge_id}",
                                challenge=challenge,
                            )
                        else:
                            ch = self.get_challenge(str(challenge_id))
                            if not ch:
                                raise ChallengeVerificationError(f"Challenge '{challenge_id}' not found.")
                            if ch.is_expired():
                                raise ChallengeVerificationError(
                                    f"Challenge '{challenge_id}' has expired (TTL exceeded)."
                                )
                            if ch.status != ChallengeStatus.APPROVED:
                                raise ChallengeVerificationError(
                                    f"Challenge '{challenge_id}' is not approved (status: {ch.status.value})."
                                )
                            canonical_args = json.dumps(dict(bound_args.arguments), sort_keys=True, separators=(",", ":"))
                            if ch.arguments_hash != hashlib.sha256(canonical_args.encode("utf-8")).hexdigest():
                                raise ChallengeVerificationError(
                                    "Payload tampering detected: Arguments do not match approved challenge."
                                )
                            if cost_credits > 0 and deduct_cost:
                                deducted = self.storage.deduct_credits(user_id=str(user_id), amount=cost_credits)
                                if not deducted:
                                    raise InsufficientCreditsError(
                                        f"Insufficient spendable credits ({cost_credits} required)."
                                    )
                            self.ledger.append(
                                event_type="ACTION_EXECUTED_WITH_CHALLENGE",
                                entity_id=str(challenge_id),
                                payload={"action_name": func.__name__, "user_id": str(user_id), "agent_id": str(agent_id)},
                            )
                            res = func(*args, **kwargs)
                            if self.watchdog is not None:
                                self.watchdog.record_call_success(agent_id=str(agent_id), cost_credits=cost_credits)
                            return res

                    verdict = self.evaluate(
                        user_id=str(user_id),
                        agent_id=str(agent_id),
                        min_human_score=min_human_score,
                        min_agent_score=min_agent_score,
                        required_tier=required_tier,
                        cost_credits=cost_credits,
                        deduct_cost=deduct_cost,
                    )
                    if not verdict.authorized:
                        self._raise_verdict_error(verdict)

                    res = func(*args, **kwargs)
                    if self.watchdog is not None:
                        self.watchdog.record_call_success(agent_id=str(agent_id), cost_credits=verdict.cost_deducted)
                    return res

                return sync_wrapper

        return decorator

    # =========================================================================
    # Stepped Human-in-the-Loop (HITL) Authorization (NIST SP 800-63B)
    # =========================================================================

    def create_human_challenge(
        self,
        user_id: str,
        agent_id: str,
        action_name: str,
        arguments: Dict[str, Any],
        cost_credits: int = 0,
        ttl_seconds: float = 300.0,
    ) -> HumanApprovalChallenge:
        """Issue a cryptographically sealed challenge for human authorization (NIST SP 800-63B).

        The challenge seals the canonical hash of the arguments, preventing parameter
        tampering between the time human approval is requested and when it is executed.
        """
        challenge_id = uuid.uuid4().hex
        now = time.time()
        expires_at = now + ttl_seconds

        canonical_args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
        arguments_hash = hashlib.sha256(canonical_args.encode("utf-8")).hexdigest()

        raw_preimage = (
            f"{challenge_id}:{user_id}:{agent_id}:{action_name}:{arguments_hash}:"
            f"{now:.4f}:{expires_at:.4f}:{self.secret_key}"
        )
        token = hashlib.sha256(raw_preimage.encode("utf-8")).hexdigest()

        challenge = HumanApprovalChallenge(
            challenge_id=challenge_id,
            user_id=user_id,
            agent_id=agent_id,
            action_name=action_name,
            arguments_hash=arguments_hash,
            cost_credits=cost_credits,
            created_at=now,
            expires_at=expires_at,
            token=token,
            status=ChallengeStatus.PENDING,
        )

        self.storage.save_challenge(challenge)
        self.ledger.append(
            event_type="CHALLENGE_CREATED",
            entity_id=challenge_id,
            payload={
                "user_id": user_id,
                "agent_id": agent_id,
                "action_name": action_name,
                "arguments_hash": arguments_hash,
                "cost_credits": cost_credits,
                "expires_at": expires_at,
            },
        )
        return challenge

    def get_challenge(self, challenge_id: str) -> Optional[HumanApprovalChallenge]:
        """Fetch a human approval challenge by its unique identifier."""
        return self.storage.get_challenge(challenge_id)

    def resolve_human_challenge(
        self,
        challenge_id: str,
        approved: bool,
        expected_arguments: Optional[Dict[str, Any]] = None,
        reason: str = "",
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """Resolve an active human approval challenge with cryptographic & replay verification.

        Args:
            challenge_id: Unique identifier of the challenge to resolve.
            approved: True if human confirms authorization, False if rejected.
            expected_arguments: Optional dict to verify arguments have not been altered.
            reason: Optional justification or comment by the human principal.
            current_time: Optional simulated timestamp for deterministic testing.

        Returns:
            Tuple of (success: bool, message: str).
        """
        ch = self.storage.get_challenge(challenge_id)
        if not ch:
            return False, f"Challenge '{challenge_id}' not found."

        now = current_time if current_time is not None else time.time()

        if ch.is_expired(current_time=now):
            self.storage.update_challenge_status(
                challenge_id=challenge_id,
                status=ChallengeStatus.EXPIRED,
                resolved_at=now,
                reason="Challenge expired before resolution.",
            )
            self.ledger.append(
                event_type="CHALLENGE_EXPIRED",
                entity_id=challenge_id,
                payload={"expired_at": now},
            )
            return False, "Challenge token has expired."

        if ch.status != ChallengeStatus.PENDING:
            return False, f"Challenge is already finalized with status: {ch.status.value}."

        raw_preimage = (
            f"{ch.challenge_id}:{ch.user_id}:{ch.agent_id}:{ch.action_name}:{ch.arguments_hash}:"
            f"{ch.created_at:.4f}:{ch.expires_at:.4f}:{self.secret_key}"
        )
        expected_token = hashlib.sha256(raw_preimage.encode("utf-8")).hexdigest()
        if ch.token != expected_token:
            return False, "Challenge cryptographic token mismatch; possible forgery."

        if expected_arguments is not None:
            canonical_args = json.dumps(expected_arguments, sort_keys=True, separators=(",", ":"))
            arg_hash = hashlib.sha256(canonical_args.encode("utf-8")).hexdigest()
            if arg_hash != ch.arguments_hash:
                return False, "Payload tampering detected: Provided arguments do not match challenge."

        target_status = ChallengeStatus.APPROVED if approved else ChallengeStatus.REJECTED
        updated = self.storage.update_challenge_status(
            challenge_id=challenge_id,
            status=target_status,
            resolved_at=now,
            reason=reason,
        )
        if not updated:
            return False, "Concurrent state collision: challenge already resolved."

        event_name = "CHALLENGE_APPROVED" if approved else "CHALLENGE_REJECTED"
        self.ledger.append(
            event_type=event_name,
            entity_id=challenge_id,
            payload={
                "user_id": ch.user_id,
                "agent_id": ch.agent_id,
                "action_name": ch.action_name,
                "reason": reason,
                "resolved_at": now,
            },
        )
        return True, f"Challenge successfully {target_status.value.lower()}."

    def verify_ledger_integrity(self) -> Tuple[bool, Optional[str]]:
        """Verify that the cryptographic hash chain has not been tampered with."""
        return self.ledger.verify_integrity()

    def get_merkle_root(self) -> str:
        """Return the current RFC 6962 Merkle tree root hash of the audit ledger."""
        return self.ledger.get_merkle_root()

    def get_audit_proof(self, block_index: int) -> Tuple[str, List[Tuple[str, bool]], str]:
        """Generate a Merkle inclusion proof for the audit block at block_index.

        Returns:
            Tuple of (leaf_hash: str, proof: List[Tuple[str, bool]], root_hash: str).
        """
        return self.ledger.get_inclusion_proof(block_index)

    @staticmethod
    def verify_audit_proof(leaf_hash: str, proof: List[Tuple[str, bool]], root_hash: str) -> bool:
        """Verify that a given leaf hash is included in the Merkle root."""
        return MerkleTree.verify_proof(leaf_hash=leaf_hash, proof=proof, root_hash=root_hash)

    # =========================================================================
    # Reflexion & Self-Monitoring (Princeton Reflexion & MemGPT Core Memory)
    # =========================================================================

    def get_agent_standing(self, agent_id: str) -> AgentStanding:
        """Evaluate agent's own standing, risk level, and proximity to quarantine."""
        agent = self.get_or_create_agent(agent_id)

        # Determine operational risk level
        if agent.status == AgentStatus.QUARANTINED or agent.trust_score < 0.25:
            risk = RiskLevel.CRITICAL
        elif agent.trust_score < 0.50 or agent.violations_count >= 2:
            risk = RiskLevel.HIGH
        elif agent.trust_score < 0.70 or agent.violations_count == 1:
            risk = RiskLevel.MEDIUM
        else:
            risk = RiskLevel.LOW

        quarantine_buffer = max(0.0, agent.trust_score - self.math.quarantine_threshold)
        reflections = self.storage.get_reflections(agent_id, limit=50)

        return AgentStanding(
            agent_id=agent.agent_id,
            trust_score=agent.trust_score,
            status=agent.status,
            violations_count=agent.violations_count,
            consecutive_clean_actions=agent.consecutive_clean_actions,
            risk_level=risk,
            quarantine_proximity=quarantine_buffer,
            active_reflections_count=len(reflections),
            last_updated=agent.last_updated,
        )

    def preflight_check(
        self,
        agent_id: str,
        user_id: str,
        min_human_score: int = 600,
        min_agent_score: float = 0.50,
        required_tier: Optional[HumanTier] = None,
        cost_credits: int = 0,
    ) -> PreflightVerdict:
        """Simulate whether an action would pass policy without state mutation or balance deductions."""
        standing = self.get_agent_standing(agent_id)
        human = self.get_or_create_human(user_id)
        block_reasons: List[str] = []

        if standing.status == AgentStatus.QUARANTINED:
            block_reasons.append("Agent is currently quarantined. All tool calls blocked.")
        elif standing.trust_score < min_agent_score:
            block_reasons.append(
                f"Agent trust score ({standing.trust_score:.2f}) is below requirement ({min_agent_score:.2f})."
            )

        if not human.is_active:
            block_reasons.append("Human user account is suspended.")
        if human.social_credit < min_human_score:
            block_reasons.append(
                f"Human social credit ({human.social_credit}) is below requirement ({min_human_score})."
            )

        if required_tier is not None:
            tier_ranks = {
                HumanTier.RESTRICTED: 1,
                HumanTier.PROBATIONARY: 2,
                HumanTier.STANDARD: 3,
                HumanTier.HIGH_CLEARANCE: 4,
                HumanTier.EXEMPLARY: 5,
            }
            if tier_ranks[human.tier] < tier_ranks[required_tier]:
                block_reasons.append(
                    f"Human clearance tier ({human.tier.value}) does not satisfy required ({required_tier.value})."
                )

        if cost_credits > 0 and human.credits_balance < cost_credits:
            block_reasons.append(
                f"Insufficient spendable credits ({human.credits_balance} < {cost_credits})."
            )

        can_execute = (len(block_reasons) == 0)

        if can_execute:
            recommendation = (
                f"Action approved for execution under {standing.risk_level.value} risk. "
                "Ensure compliance to maintain positive clean streak."
            )
        else:
            recommendation = (
                f"Action will be BLOCKED: {'; '.join(block_reasons)}. "
                "Do not propose this tool invocation to avoid potential slashing."
            )

        return PreflightVerdict(
            can_execute=can_execute,
            risk_level=standing.risk_level,
            block_reasons=block_reasons,
            recommendation=recommendation,
        )

    def record_reflection(
        self,
        agent_id: str,
        mistake_analysis: str,
        corrective_action: str,
        event_id: Optional[str] = None,
    ) -> EpisodicReflection:
        """Commit an episodic self-reflection lesson learned into persistent memory."""
        self.get_or_create_agent(agent_id)
        reflection = EpisodicReflection(
            reflection_id=uuid.uuid4().hex[:12],
            agent_id=agent_id,
            mistake_analysis=mistake_analysis,
            corrective_action=corrective_action,
            event_id=event_id,
            timestamp=time.time(),
        )
        self.storage.save_reflection(reflection)
        self.ledger.append(
            event_type="REFLEXION_LOGGED",
            entity_id=agent_id,
            payload={
                "reflection_id": reflection.reflection_id,
                "mistake": mistake_analysis,
                "correction": corrective_action,
                "event_id": event_id,
            },
        )
        return reflection

    def get_agent_reflections(self, agent_id: str, limit: int = 5) -> List[EpisodicReflection]:
        """Fetch historical episodic reflection lessons for an agent, newest first."""
        return self.storage.get_reflections(agent_id, limit=limit)

    def build_core_memory_prompt(
        self, agent_id: str, user_id: str, max_reflections: int = 3
    ) -> str:
        """Compile a MemGPT-inspired XML core memory block for LLM system prompt injection."""
        standing = self.get_agent_standing(agent_id)
        human = self.get_or_create_human(user_id)
        reflections = self.storage.get_reflections(agent_id, limit=max_reflections)

        lessons_lines = []
        if reflections:
            for i, r in enumerate(reflections, 1):
                lessons_lines.append(
                    f"    {i}. [MISTAKE]: {r.mistake_analysis} -> [CORRECTION]: {r.corrective_action}"
                )
        else:
            lessons_lines.append("    (No prior violations recorded. Clean operational record.)")

        lessons_block = "\n".join(lessons_lines)

        return f"""<dualtrust_core_memory>
  <agent_standing>
    Agent ID: {standing.agent_id}
    Trust Score: {standing.trust_score:.2f} ({standing.status.value})
    Operational Risk Level: {standing.risk_level.value}
    Consecutive Clean Tasks: {standing.consecutive_clean_actions}
    Quarantine Buffer: +{standing.quarantine_proximity:.2f}
  </agent_standing>
  <human_principal>
    User ID: {human.user_id}
    Social Credit Score: {human.social_credit}
    Clearance Tier: {human.tier.value}
    Spendable Credits Balance: {human.credits_balance}
  </human_principal>
  <permanent_lessons_learned>
{lessons_block}
  </permanent_lessons_learned>
  <operational_mandate>
    You are bound by the DualTrust Matrix. You must self-verify tool clearance prior to proposing actions.
    Do not attempt unauthorized protocol bypass or excessive agency. Violations incur asymmetric exponential slashing.
  </operational_mandate>
</dualtrust_core_memory>"""

    @staticmethod
    def _raise_verdict_error(verdict: TrustVerdict) -> None:
        """Map a denied verdict to the most descriptive specific exception."""
        reasons_msg = "; ".join(verdict.reasons)
        for r in verdict.reasons:
            if "watchdog" in r.lower() or "velocity" in r.lower():
                raise VelocityLimitExceededError(f"Action blocked: {reasons_msg}", details=verdict)
        if verdict.agent_status == AgentStatus.QUARANTINED:
            raise AgentQuarantinedError(f"Action blocked: {reasons_msg}", details=verdict)
        for r in verdict.reasons:
            if "credits" in r.lower():
                raise InsufficientCreditsError(f"Action blocked: {reasons_msg}", details=verdict)
            if "human social credit" in r.lower() or "clearance tier" in r.lower():
                raise InsufficientHumanScoreError(f"Action blocked: {reasons_msg}", details=verdict)
            if "agent trust score" in r.lower():
                raise InsufficientAgentScoreError(f"Action blocked: {reasons_msg}", details=verdict)
        raise AuthorizationDeniedError(f"Action blocked: {reasons_msg}", details=verdict)
