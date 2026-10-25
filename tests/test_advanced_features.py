"""Unit tests for half-life decay, Sybil-discounting, and dynamic tool call interception."""

import unittest
from dualtrust.engine import DualTrust
from dualtrust.exceptions import AgentQuarantinedError
from dualtrust.math_engine import ReputationMath
from dualtrust.models import AgentProfile, AgentStatus, ViolationType


class TestAdvancedFeatures(unittest.TestCase):
    """Test half-life continuous decay, reporter discounting, and tool call interceptors."""

    def test_continuous_half_life_decay(self) -> None:
        """Past accrued reputation must decay toward uninformative prior over half-life periods."""
        math = ReputationMath(half_life_seconds=86400.0)  # 1 day half-life for test

        # Agent started with alpha=9.0, beta=1.0 (score = 9/10 = 0.90)
        profile = AgentProfile(agent_id="decay_bot", alpha=9.0, beta=1.0, trust_score=0.90, last_updated=1000.0)

        # After 1 half-life (1 day = 86400s later)
        math.apply_time_decay(profile, current_time=1000.0 + 86400.0)
        # alpha above baseline 1.0 was 8.0, after 1 half-life should be 1.0 + 4.0 = 5.0
        # beta baseline was 1.0, stays 1.0
        # new trust score: 5.0 / (5.0 + 1.0) = 5/6 = ~0.833
        self.assertAlmostEqual(profile.alpha, 5.0, places=2)
        self.assertAlmostEqual(profile.trust_score, 5.0 / 6.0, places=2)

    def test_sybil_resistant_reporter_discounting(self) -> None:
        """Low-reputation / quarantined agents must have their reports heavily discounted."""
        dt = DualTrust()
        dt.register_agent("target_agent", initial_trust=0.90)

        # Rogue reporter with rock-bottom trust
        dt.register_agent("rogue_reporter", initial_trust=0.10)
        dt.quarantine_agent("rogue_reporter", reason="Known defamer")

        # Rogue tries to penalize target agent
        event = dt.report_violation(
            agent_id="target_agent",
            violation_type=ViolationType.USER_RAGE,
            severity=3.0,
            reporter_id="rogue_reporter",
        )

        # The applied penalty must be discounted by 95% (reporter credibility 0.05)
        # Standard penalty delta without discount would be 3.5 * 3.0 * 1 = 10.5
        # With discount: 10.5 * 0.05 = ~0.525
        self.assertLess(event.penalty_applied, 1.0)

        target = dt.get_or_create_agent("target_agent")
        # Target agent remains verified because false report was discounted!
        self.assertEqual(target.status, AgentStatus.VERIFIED)

    def test_dynamic_tool_call_interceptor(self) -> None:
        """Dynamic JSON-payload tool calls must be gated and audited."""
        dt = DualTrust()
        dt.register_human("user_neo", social_credit=880, credits_balance=50)
        dt.register_agent("pilot_agent", initial_trust=0.85)

        executed_payload = {}

        def hardware_actuator(destination: str, speed_mach: float) -> str:
            executed_payload["destination"] = destination
            executed_payload["speed_mach"] = speed_mach
            return f"Cruising to {destination} at Mach {speed_mach}"

        result = dt.intercept_tool_call(
            user_id="user_neo",
            agent_id="pilot_agent",
            tool_name="hardware_actuator",
            tool_callable=hardware_actuator,
            arguments={"destination": "Orbital Station Alpha", "speed_mach": 2.5},
            min_human_score=750,
            cost_credits=10,
        )

        self.assertIn("Orbital Station Alpha", result)
        self.assertEqual(executed_payload["speed_mach"], 2.5)

        # Confirm cryptographic audit ledger logged the tool execution
        is_valid, err = dt.verify_ledger_integrity()
        self.assertTrue(is_valid)
        self.assertIsNone(err)


if __name__ == "__main__":
    unittest.main()
