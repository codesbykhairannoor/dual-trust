"""Mathematical engine implementing Beta reputation, continuous half-life decay, and Sybil-resistant slashing."""

import math
import time
from typing import Optional, Tuple
from dualtrust.models import AgentProfile, AgentStatus, ViolationType


class ReputationMath:
    """Calculates Beta distributions, continuous half-life decay, and Sybil-discounted slashing."""

    # Default half-life: 14 days expressed in seconds (14 * 86400 = 1,209,600 s)
    DEFAULT_HALF_LIFE_SECONDS = 1_209_600.0

    def __init__(
        self,
        half_life_seconds: float = DEFAULT_HALF_LIFE_SECONDS,
        decay_factor: Optional[float] = None,
        penalty_multiplier: float = 3.5,
        slashing_exponent: float = 1.8,
        quarantine_threshold: float = 0.20,
        recovery_clean_window: int = 20,
        minor_infraction_threshold: int = 3,
    ) -> None:
        """Initialize mathematical configuration.

        Args:
            half_life_seconds: Time in wall-clock seconds for reputation memory to decay by half.
            decay_factor: Optional backwards-compatible daily retention factor (e.g. 0.95).
            penalty_multiplier: Asymmetric weight applied to negative events (kp >= 1.0).
            slashing_exponent: Exponent for repeat infraction escalation (gamma >= 1.0).
            quarantine_threshold: Lower-water trust boundary below which agents are isolated.
            recovery_clean_window: Consecutive clean actions required to decrement the violation count.
            minor_infraction_threshold: Count of minor infractions (severity <= 1.5) before escalating to a formal strike.
        """
        if decay_factor is not None:
            if 0.0 < decay_factor < 1.0:
                half_life_seconds = -86400.0 * math.log(2) / math.log(decay_factor)

        if half_life_seconds <= 0:
            raise ValueError("half_life_seconds must be positive.")
        if penalty_multiplier < 1.0:
            raise ValueError("penalty_multiplier must be >= 1.0")
        if slashing_exponent < 1.0:
            raise ValueError("slashing_exponent must be >= 1.0")
        if recovery_clean_window < 1:
            raise ValueError("recovery_clean_window must be >= 1")
        if minor_infraction_threshold < 1:
            raise ValueError("minor_infraction_threshold must be >= 1")

        self.half_life_seconds = half_life_seconds
        self.penalty_multiplier = penalty_multiplier
        self.slashing_exponent = slashing_exponent
        self.quarantine_threshold = quarantine_threshold
        self.recovery_clean_window = recovery_clean_window
        self.minor_infraction_threshold = minor_infraction_threshold

    @staticmethod
    def expected_trust(alpha: float, beta: float) -> float:
        """Compute the expectation of Beta(alpha, beta)."""
        total = alpha + beta
        if total <= 0.0:
            return 0.5
        score = alpha / total
        return max(0.0, min(1.0, score))

    @staticmethod
    def determine_status(trust_score: float, is_quarantined: bool = False) -> AgentStatus:
        """Map a numeric trust score to an operational agent lifecycle status."""
        if is_quarantined or trust_score < 0.20:
            return AgentStatus.QUARANTINED
        if trust_score < 0.40:
            return AgentStatus.RESTRICTED
        if trust_score < 0.70:
            return AgentStatus.PROBATION
        return AgentStatus.VERIFIED

    def apply_time_decay(
        self, profile: AgentProfile, current_time: Optional[float] = None
    ) -> float:
        """Apply continuous exponential half-life decay to past feedback toward the uninformative prior (1.0)."""
        now = current_time if current_time is not None else time.time()
        delta_seconds = now - profile.last_updated

        if delta_seconds <= 0:
            return profile.trust_score

        # Critical Safety Actuator Exemption: Safety-critical equipment does not passively decay during dormant periods
        is_exempt = getattr(profile, "is_safety_critical", False) or profile.metadata.get("is_safety_critical", False) or profile.metadata.get("decay_exempt", False)
        if is_exempt:
            profile.trust_score = self.expected_trust(profile.alpha, profile.beta)
            profile.last_updated = now
            return profile.trust_score

        # Half-life decay factor: 2 ^ (-delta_t / half_life)
        decay_ratio = math.pow(0.5, delta_seconds / self.half_life_seconds)

        # Asymmetric Memory Invariant: positive standing alpha decays continuously toward uninformative baseline (1.0),
        # but negative malfeasance beta does NOT decay passively.
        e_alpha = max(0.0, profile.alpha - 1.0)
        profile.alpha = 1.0 + (e_alpha * decay_ratio)

        profile.trust_score = self.expected_trust(profile.alpha, profile.beta)
        if profile.status != AgentStatus.QUARANTINED:
            profile.status = self.determine_status(profile.trust_score)

        profile.last_updated = now
        return profile.trust_score

    def apply_positive_feedback(
        self,
        profile: AgentProfile,
        weight: float = 1.0,
        current_time: Optional[float] = None,
    ) -> float:
        """Reward an agent for successful, compliant execution and advance active violation recovery."""
        self.apply_time_decay(profile, current_time=current_time)
        weight = max(0.1, weight)
        profile.alpha += weight

        # Active violation recovery: Sustained compliant streak decays violation escalation counter
        profile.consecutive_clean_actions += 1
        if profile.consecutive_clean_actions >= self.recovery_clean_window:
            profile.violations_count = max(0, profile.violations_count - 1)
            profile.minor_infractions = 0
            profile.consecutive_clean_actions = 0
        elif profile.minor_infractions > 0 and profile.consecutive_clean_actions % 5 == 0:
            profile.minor_infractions = max(0, profile.minor_infractions - 1)

        profile.trust_score = self.expected_trust(profile.alpha, profile.beta)
        if profile.status != AgentStatus.QUARANTINED:
            profile.status = self.determine_status(profile.trust_score)
        profile.last_updated = current_time if current_time is not None else time.time()
        return profile.trust_score

    def apply_violation_penalty(
        self,
        profile: AgentProfile,
        violation_type: ViolationType,
        severity: float,
        reporter_credibility: float = 1.0,
        current_time: Optional[float] = None,
    ) -> Tuple[float, float, bool]:
        """Apply asymmetric power-law slashing (v^1.8) with reporter credibility discounting."""
        self.apply_time_decay(profile, current_time=current_time)

        severity = max(1.0, min(5.0, severity))
        credibility = max(0.0, min(1.0, reporter_credibility))
        # Enforce minimum operational credibility floor for non-zero reported severity to prevent adversarial nullification
        if credibility > 0.0:
            credibility = max(0.05, credibility)

        # Sybil Defamation Defense: Quarantined or untrusted reporters (< 0.20) cannot
        # unilaterally slash a verified entity without independent corroboration
        is_untrusted_reporter = credibility < self.quarantine_threshold
        if is_untrusted_reporter and profile.status == AgentStatus.VERIFIED:
            return profile.trust_score, 0.0, False

        # Sybil Escalation Resistance & Salami Slicing Defense:
        # Accusations from untrusted reporters (< 0.20) must NOT increment escalation counters.
        # Minor transient glitches (severity <= 1.5) accumulate via minor_infractions counter.
        # Once minor_infractions reaches minor_infraction_threshold, it escalates to a formal strike.
        is_minor_glitch = severity <= 1.5
        if is_untrusted_reporter:
            effective_exponent = 1.0
            profile.consecutive_clean_actions = 0
            strike_base = 1
        elif is_minor_glitch:
            profile.minor_infractions += 1
            profile.lifetime_minor_infractions += 1
            profile.consecutive_clean_actions = 0
            lifetime_strikes = profile.lifetime_minor_infractions // self.minor_infraction_threshold
            if profile.minor_infractions >= self.minor_infraction_threshold or lifetime_strikes > profile.violations_count:
                profile.violations_count = max(profile.violations_count + 1, lifetime_strikes)
                profile.lifetime_violations_count = max(getattr(profile, "lifetime_violations_count", 0) + 1, lifetime_strikes)
                profile.minor_infractions = 0
                effective_exponent = self.slashing_exponent
                strike_base = max(1, getattr(profile, "lifetime_violations_count", profile.violations_count))
            else:
                effective_exponent = 1.0
                strike_base = 1
        else:
            profile.violations_count += 1
            profile.lifetime_violations_count = getattr(profile, "lifetime_violations_count", 0) + 1
            profile.consecutive_clean_actions = 0
            effective_exponent = self.slashing_exponent
            strike_base = max(1, getattr(profile, "lifetime_violations_count", profile.violations_count))

        # Effective severity discounted quadratically by reporter credibility (EigenTrust standard)
        effective_severity = severity * math.pow(credibility, 2)

        # Exponential rogue slashing formula: Delta_beta = kp * effective_severity * (lifetime_violations ^ gamma)
        penalty_delta = (
            self.penalty_multiplier
            * effective_severity
            * math.pow(strike_base, effective_exponent)
        )

        # Critical protocol trespass carries a hard multiplier, but ONLY when reported by a credible entity
        is_critical_trespass = (
            violation_type == ViolationType.PROTOCOL_TRESPASS
            and severity >= 3.0
            and not is_untrusted_reporter
        )
        if is_critical_trespass:
            penalty_delta *= 2.0

        profile.beta += penalty_delta
        profile.trust_score = self.expected_trust(profile.alpha, profile.beta)

        # Determine quarantine condition: Untrusted reporters can NEVER force-quarantine any entity
        force_quarantine = is_critical_trespass or (profile.trust_score < self.quarantine_threshold)
        profile.status = self.determine_status(profile.trust_score, is_quarantined=force_quarantine)
        profile.last_updated = current_time if current_time is not None else time.time()

        return profile.trust_score, penalty_delta, (profile.status == AgentStatus.QUARANTINED)

    @staticmethod
    def compute_composite_trust(
        human_score: int,
        agent_score: float,
        human_weight: float = 0.4,
        agent_weight: float = 0.6,
    ) -> float:
        """Calculate weighted composite score combining human credit and agent reputation."""
        normalized_human = max(0.0, min(1.0, human_score / 1000.0))
        normalized_agent = max(0.0, min(1.0, agent_score))
        composite = (human_weight * normalized_human) + (agent_weight * normalized_agent)
        return round(composite, 4)
