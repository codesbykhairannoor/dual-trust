"""Unit tests for the mathematical engine and slashing dynamics."""

import unittest
from dualtrust.math_engine import ReputationMath
from dualtrust.models import AgentProfile, AgentStatus, ViolationType


class TestReputationMath(unittest.TestCase):
    """Verify Beta distribution calculations and penalty dynamics."""

    def setUp(self) -> None:
        self.math = ReputationMath(
            decay_factor=0.95,
            penalty_multiplier=3.0,
            slashing_exponent=1.5,
            quarantine_threshold=0.20,
        )

    def test_expected_trust_bounds(self) -> None:
        """Expected trust must strictly reside within [0.0, 1.0]."""
        self.assertEqual(self.math.expected_trust(0.0, 0.0), 0.5)
        self.assertEqual(self.math.expected_trust(10.0, 0.0), 1.0)
        self.assertEqual(self.math.expected_trust(0.0, 10.0), 0.0)
        self.assertAlmostEqual(self.math.expected_trust(1.0, 1.0), 0.5)
        self.assertAlmostEqual(self.math.expected_trust(9.0, 1.0), 0.9)

    def test_determine_status(self) -> None:
        """Verify score mapping to discrete operational states."""
        self.assertEqual(self.math.determine_status(0.85), AgentStatus.VERIFIED)
        self.assertEqual(self.math.determine_status(0.55), AgentStatus.PROBATION)
        self.assertEqual(self.math.determine_status(0.30), AgentStatus.RESTRICTED)
        self.assertEqual(self.math.determine_status(0.15), AgentStatus.QUARANTINED)
        self.assertEqual(self.math.determine_status(0.90, is_quarantined=True), AgentStatus.QUARANTINED)

    def test_positive_feedback(self) -> None:
        """Compliant actions should increment alpha and lift trust score."""
        agent = AgentProfile(agent_id="test_agent", alpha=1.0, beta=1.0, trust_score=0.5)
        new_score = self.math.apply_positive_feedback(agent, weight=2.0)
        self.assertAlmostEqual(agent.alpha, 3.0)
        self.assertAlmostEqual(agent.beta, 1.0)
        self.assertAlmostEqual(new_score, 0.75)
        self.assertEqual(agent.status, AgentStatus.VERIFIED)

    def test_asymmetric_slashing_escalation(self) -> None:
        """Repeat infractions must exponentially accelerate trust degradation."""
        agent = AgentProfile(agent_id="rogue_agent", alpha=5.0, beta=1.0, trust_score=0.833)

        # First violation
        score_1, delta_1, is_quar_1 = self.math.apply_violation_penalty(
            agent, violation_type=ViolationType.USER_RAGE, severity=2.0
        )
        self.assertEqual(agent.violations_count, 1)
        self.assertLess(score_1, 0.833)
        self.assertFalse(is_quar_1)

        # Second violation (penalty must be larger due to power law)
        score_2, delta_2, is_quar_2 = self.math.apply_violation_penalty(
            agent, violation_type=ViolationType.USER_RAGE, severity=2.0
        )
        self.assertEqual(agent.violations_count, 2)
        self.assertGreater(delta_2, delta_1)
        self.assertLess(score_2, score_1)

    def test_critical_protocol_trespass_quarantine(self) -> None:
        """Severe cross-agent trespass must trigger instant isolation."""
        agent = AgentProfile(agent_id="trespasser", alpha=10.0, beta=1.0, trust_score=0.91)
        score, delta, is_quarantined = self.math.apply_violation_penalty(
            agent, violation_type=ViolationType.PROTOCOL_TRESPASS, severity=4.5
        )
        self.assertTrue(is_quarantined)
        self.assertEqual(agent.status, AgentStatus.QUARANTINED)

    def test_composite_trust_computation(self) -> None:
        """Composite calculation should correctly weigh normalized human credit and agent trust."""
        # Human: 800 (0.80), Agent: 0.90 -> 0.4*0.80 + 0.6*0.90 = 0.32 + 0.54 = 0.86
        composite = self.math.compute_composite_trust(human_score=800, agent_score=0.90)
        self.assertAlmostEqual(composite, 0.86, places=2)


if __name__ == "__main__":
    unittest.main()
