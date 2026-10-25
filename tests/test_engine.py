"""Unit tests for the primary DualTrust evaluation and enforcement engine."""

import unittest
from dualtrust.engine import DualTrust
from dualtrust.exceptions import (
    AgentQuarantinedError,
    AuthorizationDeniedError,
    InsufficientAgentScoreError,
    InsufficientCreditsError,
    InsufficientHumanScoreError,
)
from dualtrust.models import AgentStatus, HumanTier, ViolationType


class TestDualTrustEngine(unittest.TestCase):
    """Verify dual-trust matrix gating, rogue penalties, and social credits."""

    def setUp(self) -> None:
        self.dt = DualTrust()

    def test_entity_registration_and_defaults(self) -> None:
        """Registering entities should initialize valid baseline states."""
        human = self.dt.register_human("alice", social_credit=780, credits_balance=150)
        self.assertEqual(human.user_id, "alice")
        self.assertEqual(human.social_credit, 780)
        self.assertEqual(human.tier, HumanTier.HIGH_CLEARANCE)

        agent = self.dt.register_agent("bot_01", initial_trust=0.80)
        self.assertEqual(agent.agent_id, "bot_01")
        self.assertAlmostEqual(agent.trust_score, 0.80)
        self.assertEqual(agent.status, AgentStatus.VERIFIED)

    def test_social_credit_adjustment_bounds(self) -> None:
        """Social credit score must be clamped strictly within [0, 1000]."""
        self.dt.register_human("bob", social_credit=950)
        self.dt.adjust_human_credit("bob", delta=100, reason="Heroic public act")
        bob = self.dt.get_or_create_human("bob")
        self.assertEqual(bob.social_credit, 1000)
        self.assertEqual(bob.tier, HumanTier.EXEMPLARY)

        self.dt.adjust_human_credit("bob", delta=-1500, reason="Civil unrest offense")
        bob = self.dt.get_or_create_human("bob")
        self.assertEqual(bob.social_credit, 0)
        self.assertEqual(bob.tier, HumanTier.RESTRICTED)

    def test_agent_reward_and_trust_elevation(self) -> None:
        """Rewarded agents should rise in reputation."""
        self.dt.register_agent("helper_bot", initial_trust=0.50)
        new_score = self.dt.reward_agent("helper_bot", weight=3.0)
        self.assertGreater(new_score, 0.50)

    def test_user_rage_slashes_reputation(self) -> None:
        """Reporting user frustration must slash agent trust."""
        self.dt.register_agent("flaky_bot", initial_trust=0.75)
        event = self.dt.flag_user_rage("flaky_bot", reason="Customer cursed at model", severity=3.0)
        self.assertGreater(event.penalty_applied, 0)
        agent = self.dt.get_or_create_agent("flaky_bot")
        self.assertLess(agent.trust_score, 0.75)

    def test_protocol_trespass_causes_quarantine(self) -> None:
        """Trespassing into unauthorized system queues must quarantine agent."""
        self.dt.register_agent("hacker_bot", initial_trust=0.90)
        self.dt.flag_protocol_trespass(
            "hacker_bot",
            target_system="aerospace:flight_corridor",
            details="Jumped priority queue without auth handshake",
            severity=4.5,
        )
        agent = self.dt.get_or_create_agent("hacker_bot")
        self.assertEqual(agent.status, AgentStatus.QUARANTINED)

    def test_quarantine_blocks_all_execution(self) -> None:
        """Quarantined agents must be completely barred from executing actions."""
        self.dt.register_human("citizen_01", social_credit=900)
        self.dt.register_agent("quarantined_bot", initial_trust=0.10)
        self.dt.quarantine_agent("quarantined_bot", reason="Rogue escalation detected")

        verdict = self.dt.evaluate(user_id="citizen_01", agent_id="quarantined_bot")
        self.assertFalse(verdict.authorized)
        self.assertEqual(verdict.agent_status, AgentStatus.QUARANTINED)

        with self.assertRaises(AgentQuarantinedError):
            self.dt.execute(
                user_id="citizen_01",
                agent_id="quarantined_bot",
                func=lambda: "Flying vehicle dispatched",
            )

    def test_pardon_restores_agent(self) -> None:
        """Pardoning a quarantined agent restores operational capability."""
        self.dt.register_agent("reformed_bot", initial_trust=0.10)
        self.dt.quarantine_agent("reformed_bot")
        self.dt.pardon_agent("reformed_bot", reset_trust=0.60)
        agent = self.dt.get_or_create_agent("reformed_bot")
        self.assertNotEqual(agent.status, AgentStatus.QUARANTINED)
        self.assertAlmostEqual(agent.trust_score, 0.60)

    def test_successful_dual_trust_gate_and_credit_deduction(self) -> None:
        """High credit human + high trust agent satisfies gate and deducts credits."""
        self.dt.register_human("vip_user", social_credit=850, credits_balance=50)
        self.dt.register_agent("trusted_agent", initial_trust=0.88)

        def book_shuttle(dest: str) -> str:
            return f"Shuttle reserved to {dest}"

        result = self.dt.execute(
            user_id="vip_user",
            agent_id="trusted_agent",
            func=book_shuttle,
            dest="Orbital Gateway",
            min_human_score=750,
            min_agent_score=0.70,
            cost_credits=15,
            deduct_cost=True,
        )

        self.assertEqual(result, "Shuttle reserved to Orbital Gateway")
        human = self.dt.get_or_create_human("vip_user")
        self.assertEqual(human.credits_balance, 35)

    def test_insufficient_human_score_raises_error(self) -> None:
        """Low human social credit must reject action."""
        self.dt.register_human("low_credit_user", social_credit=500)
        self.dt.register_agent("good_agent", initial_trust=0.90)

        with self.assertRaises(InsufficientHumanScoreError):
            self.dt.execute(
                user_id="low_credit_user",
                agent_id="good_agent",
                func=lambda: "Should not execute",
                min_human_score=700,
            )

    def test_insufficient_agent_score_raises_error(self) -> None:
        """Low agent trust score must reject action."""
        self.dt.register_human("high_credit_user", social_credit=850)
        self.dt.register_agent("untested_agent", initial_trust=0.45)

        with self.assertRaises(InsufficientAgentScoreError):
            self.dt.execute(
                user_id="high_credit_user",
                agent_id="untested_agent",
                func=lambda: "Should not execute",
                min_agent_score=0.75,
            )

    def test_insufficient_credit_balance_raises_error(self) -> None:
        """Insufficient spendable balance must block execution."""
        self.dt.register_human("poor_user", social_credit=800, credits_balance=2)
        self.dt.register_agent("prime_agent", initial_trust=0.85)

        with self.assertRaises(InsufficientCreditsError):
            self.dt.execute(
                user_id="poor_user",
                agent_id="prime_agent",
                func=lambda: "Should not execute",
                cost_credits=10,
            )


if __name__ == "__main__":
    unittest.main()
