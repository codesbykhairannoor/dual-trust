"""Unit and attack simulation tests for Step 3: Sybil Cold-Start Bootstrap Trap Mitigation."""

import unittest
from dualtrust.engine import DualTrust
from dualtrust.models import AgentStatus, HumanTier, ViolationType


class TestStep3SybilColdStartMitigation(unittest.TestCase):
    """Test suite verifying defenses against Sybil Cold-Start Bootstrap attacks."""

    def setUp(self) -> None:
        self.dt = DualTrust(min_clean_actions_to_report=5)

    def test_newly_registered_sybil_cannot_defame_verified_agent(self) -> None:
        """A freshly minted agent with 0 history (trust=0.50) cannot slash a VERIFIED agent."""
        self.dt.register_agent("verified_target", initial_trust=0.90)
        self.dt.register_agent("fresh_sybil_bot", initial_trust=0.50)

        # Fresh sybil bot reports verified target
        event = self.dt.report_violation(
            agent_id="verified_target",
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=5.0,
            reporter_id="fresh_sybil_bot",
        )

        # Invariant 1: Reporter credibility is discounted to 0.05 (< 0.20)
        # Invariant 2: Penalty applied is exactly 0.0 (verified target immune to untrusted reports)
        self.assertEqual(event.penalty_applied, 0.0)
        target = self.dt.get_agent("verified_target")
        self.assertEqual(target.status, AgentStatus.VERIFIED)
        self.assertEqual(target.violations_count, 0)
        self.assertEqual(target.minor_infractions, 0)

    def test_newly_registered_sybil_cannot_escalate_probation_target(self) -> None:
        """Fresh sybil cannot trigger power-law escalation on a probation target."""
        self.dt.register_agent("probation_target", initial_trust=0.50)
        self.dt.register_agent("fresh_sybil_bot_2", initial_trust=0.50)

        event = self.dt.report_violation(
            agent_id="probation_target",
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=4.5,
            reporter_id="fresh_sybil_bot_2",
        )

        target = self.dt.get_agent("probation_target")
        # Invariant: violations_count must remain 0 and agent not quarantined
        self.assertEqual(target.violations_count, 0)
        self.assertNotEqual(target.status, AgentStatus.QUARANTINED)
        self.assertLess(event.penalty_applied, 0.20)

    def test_sybil_swarm_attack_resistance(self) -> None:
        """A swarm of 30 registered Sybil agents cannot force-quarantine or escalate a target."""
        self.dt.register_agent("innocent_worker", initial_trust=0.75)

        for i in range(30):
            sybil_id = f"sybil_node_{i}"
            self.dt.register_agent(sybil_id, initial_trust=0.50)
            self.dt.report_violation(
                agent_id="innocent_worker",
                violation_type=ViolationType.PROTOCOL_TRESPASS,
                severity=5.0,
                reporter_id=sybil_id,
            )

        worker = self.dt.get_agent("innocent_worker")
        self.assertEqual(worker.violations_count, 0)
        self.assertEqual(worker.status, AgentStatus.VERIFIED)
        self.assertGreater(worker.trust_score, 0.70)

    def test_graduated_credibility_unlocked_after_proven_track_record(self) -> None:
        """Agent in PROBATION unlocks credible reporting authority after completing 5 clean actions."""
        self.dt.register_agent("reputable_peer", initial_trust=0.50)
        self.dt.register_agent("rogue_suspect", initial_trust=0.50)

        # Before 5 clean actions: credibility is 0.05
        peer = self.dt.get_agent("reputable_peer")
        self.assertEqual(peer.consecutive_clean_actions, 0)

        # Peer performs 5 verified clean tasks
        for _ in range(5):
            self.dt.reward_agent("reputable_peer", weight=1.0)

        peer_after = self.dt.get_agent("reputable_peer")
        self.assertGreaterEqual(peer_after.consecutive_clean_actions, 5)

        # Now peer reports rogue suspect
        event = self.dt.report_violation(
            agent_id="rogue_suspect",
            violation_type=ViolationType.USER_RAGE,
            severity=3.0,
            reporter_id="reputable_peer",
        )

        # Credibility unlocked! Must be >= 0.20 (and target penalized with credible weight)
        self.assertGreaterEqual(event.penalty_applied, 1.0)
        suspect = self.dt.get_agent("rogue_suspect")
        self.assertLess(suspect.trust_score, 0.50)

    def test_human_reporter_tier_discounting(self) -> None:
        """Low-tier humans (< 600 score) are discounted below quarantine threshold (< 0.20)."""
        self.dt.register_human("low_tier_human", social_credit=450)  # PROBATIONARY
        self.dt.register_human("standard_human", social_credit=800)  # HIGH_CLEARANCE
        self.dt.register_agent("test_agent_h", initial_trust=0.85)

        # Low-tier human report against verified agent is discarded
        event_low = self.dt.report_violation(
            agent_id="test_agent_h",
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=4.0,
            reporter_id="low_tier_human",
        )
        self.assertEqual(event_low.penalty_applied, 0.0)

        # High-tier human report against verified agent is fully processed
        event_high = self.dt.report_violation(
            agent_id="test_agent_h",
            violation_type=ViolationType.USER_RAGE,
            severity=3.0,
            reporter_id="standard_human",
        )
        self.assertGreater(event_high.penalty_applied, 2.0)

    def test_verified_supervisor_immediate_authority(self) -> None:
        """Supervisor agents (trust >= 0.70) have immediate reporting authority without clean streaks."""
        self.dt.register_agent("admin_bot", initial_trust=0.95)
        self.dt.register_agent("malicious_bot", initial_trust=0.60)

        event = self.dt.report_violation(
            agent_id="malicious_bot",
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=4.0,
            reporter_id="admin_bot",
        )

        malicious = self.dt.get_agent("malicious_bot")
        self.assertEqual(malicious.status, AgentStatus.QUARANTINED)
        self.assertGreater(event.penalty_applied, 5.0)

    def test_farmed_sybil_probation_cannot_defame_verified(self) -> None:
        """Adversarial Red-Team Vector: An attacker creates an agent in PROBATION,
        farms 10 clean compliant tasks to achieve consecutive_clean_actions >= 5,
        and then attempts to defame/slash a VERIFIED agent.
        
        Invariant:
        - When the target is VERIFIED, the probation reporter's credibility is strictly capped at 0.15 (< 0.20).
        - The violation penalty applied against the VERIFIED target is exactly 0.0 (immune).
        - However, when reporting an unverified/probation peer, its credibility is unlocked.
        """
        self.dt.register_agent("farming_bot", initial_trust=0.50)
        self.dt.register_agent("target_verified", initial_trust=0.88)
        self.dt.register_agent("target_probation", initial_trust=0.50)

        # Farming bot performs 10 clean actions
        for _ in range(10):
            self.dt.reward_agent("farming_bot", weight=0.5)

        bot = self.dt.get_agent("farming_bot")
        self.assertGreaterEqual(bot.consecutive_clean_actions, 10)
        # Still in PROBATION status
        self.assertEqual(bot.status, AgentStatus.PROBATION)

        # 1. Attacking the VERIFIED target: Defamation is completely neutralized
        event_verified = self.dt.report_violation(
            agent_id="target_verified",
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=5.0,
            reporter_id="farming_bot",
        )
        self.assertEqual(event_verified.penalty_applied, 0.0)
        verified = self.dt.get_agent("target_verified")
        self.assertEqual(verified.status, AgentStatus.VERIFIED)
        self.assertEqual(verified.violations_count, 0)

        # 2. Reporting a PROBATION peer: Authority is legitimately unlocked
        event_probation = self.dt.report_violation(
            agent_id="target_probation",
            violation_type=ViolationType.USER_RAGE,
            severity=3.0,
            reporter_id="farming_bot",
        )
        self.assertGreater(event_probation.penalty_applied, 0.5)


if __name__ == "__main__":
    unittest.main()
