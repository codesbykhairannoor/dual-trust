"""Unit tests verifying defenses against threat vectors mapped in docs/THREAT_MODEL.md."""

import time
import unittest
from dualtrust.engine import DualTrust
from dualtrust.exceptions import (
    AgentQuarantinedError,
    InsufficientCreditsError,
    InsufficientHumanScoreError,
)
from dualtrust.models import AgentStatus, HumanTier, ViolationType


class TestThreatModelDefenses(unittest.TestCase):
    """Verify mitigation of MITRE ATLAS & OWASP threats (DT-T01 to DT-T06)."""

    def setUp(self) -> None:
        self.dt = DualTrust(secret_key="test_hmac_secret_key_12345", verdict_ttl_seconds=5.0)

    def test_dt_t01_sleeping_trojan_instant_quarantine(self) -> None:
        """DT-T01: High-reputation agent committing critical trespass is immediately quarantined."""
        self.dt.register_agent("trojan_bot", initial_trust=0.92)

        # Agent commits sudden critical protocol trespass
        self.dt.flag_protocol_trespass(
            agent_id="trojan_bot",
            target_system="aerospace:flight_grid",
            details="Sudden backdoor exploitation attempt",
            severity=4.8,
        )

        agent = self.dt.get_or_create_agent("trojan_bot")
        self.assertEqual(agent.status, AgentStatus.QUARANTINED)

    def test_dt_t02_sybil_defamation_discounting(self) -> None:
        """DT-T02: False reports from compromised/quarantined agents are discounted by up to 95%."""
        self.dt.register_agent("honest_agent", initial_trust=0.88)
        self.dt.register_agent("sybil_attacker", initial_trust=0.10)
        self.dt.quarantine_agent("sybil_attacker")

        # Sybil attacker reports honest agent
        event = self.dt.report_violation(
            agent_id="honest_agent",
            violation_type=ViolationType.USER_RAGE,
            severity=4.0,
            reporter_id="sybil_attacker",
        )

        # Discounted penalty must not demote the honest agent
        self.assertLess(event.penalty_applied, 1.0)
        honest = self.dt.get_or_create_agent("honest_agent")
        self.assertEqual(honest.status, AgentStatus.VERIFIED)

    def test_dt_t03_excessive_agency_blocked(self) -> None:
        """DT-T03: Agent attempting actions above clearance tier is blocked."""
        self.dt.register_human("low_tier_user", social_credit=500)  # PROBATIONARY
        self.dt.register_agent("standard_agent", initial_trust=0.80)

        with self.assertRaises(InsufficientHumanScoreError):
            self.dt.execute(
                user_id="low_tier_user",
                agent_id="standard_agent",
                func=lambda: "Launch physical weapon system",
                required_tier=HumanTier.HIGH_CLEARANCE,
            )

    def test_dt_t04_unbounded_consumption_blocked(self) -> None:
        """DT-T04: Recursive loop attempting to drain wallet is blocked when balance runs out."""
        self.dt.register_human("wallet_user", social_credit=800, credits_balance=15)
        self.dt.register_agent("looping_agent", initial_trust=0.85)

        # First call succeeds and consumes 10 credits
        self.dt.execute(
            user_id="wallet_user",
            agent_id="looping_agent",
            func=lambda: "Call paid API",
            cost_credits=10,
        )

        # Second call attempting 10 credits fails (balance is only 5)
        with self.assertRaises(InsufficientCreditsError):
            self.dt.execute(
                user_id="wallet_user",
                agent_id="looping_agent",
                func=lambda: "Call paid API again",
                cost_credits=10,
            )

    def test_dt_t05_audit_tampering_detected(self) -> None:
        """DT-T05: Modifying historical ledger blocks breaks cryptographic chain verification."""
        self.dt.register_human("user_a", social_credit=800)
        self.dt.adjust_human_credit("user_a", delta=50, reason="Commendation")
        self.dt.adjust_human_credit("user_a", delta=-20, reason="Traffic violation")

        # Initial chain is cryptographically sound
        is_valid, _ = self.dt.verify_ledger_integrity()
        self.assertTrue(is_valid)

        # Adversary directly modifies an event payload in the ledger
        block = self.dt.ledger._chain[1]
        self.dt.ledger._chain[1] = type(block)(
            index=block.index,
            timestamp=block.timestamp,
            event_type=block.event_type,
            entity_id=block.entity_id,
            payload={"delta": 999999},  # Tampered payload!
            prev_hash=block.prev_hash,
            block_hash=block.block_hash,
        )

        is_valid_after, err = self.dt.verify_ledger_integrity()
        self.assertFalse(is_valid_after)
        self.assertIn("tampered", str(err).lower())

    def test_dt_t06_replay_and_stale_verdict_detected(self) -> None:
        """DT-T06: Expired or signature-mismatched verdict receipts are rejected."""
        self.dt.register_human("user_b", social_credit=850)
        self.dt.register_agent("agent_b", initial_trust=0.85)

        verdict = self.dt.evaluate(user_id="user_b", agent_id="agent_b")

        # Immediate verification passes
        valid, err = self.dt.verify_verdict(verdict, user_id="user_b", agent_id="agent_b")
        self.assertTrue(valid)
        self.assertIsNone(err)

        # Stale replay: simulated 10 seconds later (TTL is 5.0s)
        stale_time = verdict.timestamp + 10.0
        valid_stale, err_stale = self.dt.verify_verdict(
            verdict, user_id="user_b", agent_id="agent_b", current_time=stale_time
        )
        self.assertFalse(valid_stale)
        self.assertIn("expired", str(err_stale).lower())

        # Forgery: modified signature
        forged_verdict = type(verdict)(
            authorized=verdict.authorized,
            composite_score=verdict.composite_score,
            human_score=verdict.human_score,
            agent_score=verdict.agent_score,
            agent_status=verdict.agent_status,
            cost_deducted=verdict.cost_deducted,
            reasons=verdict.reasons,
            timestamp=verdict.timestamp,
            nonce=verdict.nonce,
            expires_at=verdict.expires_at,
            signature="deadbeef" * 8,  # Forged signature!
        )
        valid_forged, err_forged = self.dt.verify_verdict(
            forged_verdict, user_id="user_b", agent_id="agent_b"
        )
        self.assertFalse(valid_forged)
        self.assertIn("mismatch", str(err_forged).lower())

    def test_fix4_anonymous_and_unregistered_reporter_discounting(self) -> None:
        """Verify FIX 4: Anonymous (None) and unregistered reporters are severely discounted and cannot quarantine."""
        self.dt.register_agent("verified_target", initial_trust=0.90)
        self.dt.register_agent("probation_target", initial_trust=0.50)

        # 1. Anonymous report against VERIFIED target is completely discarded (c = 0.10 < 0.20)
        event_anon_v = self.dt.report_violation(
            agent_id="verified_target",
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=5.0,
            reporter_id=None,
        )
        self.assertEqual(event_anon_v.penalty_applied, 0.0)
        self.assertEqual(self.dt.get_agent("verified_target").status, AgentStatus.VERIFIED)

        # 2. Fabricated / unregistered reporter ID against VERIFIED target is discarded (c = 0.05 < 0.20)
        event_fake_v = self.dt.report_violation(
            agent_id="verified_target",
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=5.0,
            reporter_id="completely_fabricated_sybil_bot_99",
        )
        self.assertEqual(event_fake_v.penalty_applied, 0.0)
        self.assertEqual(self.dt.get_agent("verified_target").status, AgentStatus.VERIFIED)

        # 3. Unregistered reporter attempting critical trespass against PROBATION target:
        # Must NOT force-quarantine and must NOT increment violations_count!
        event_fake_p = self.dt.report_violation(
            agent_id="probation_target",
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=5.0,
            reporter_id="unregistered_adversary_bot",
        )
        probation_agent = self.dt.get_agent("probation_target")
        self.assertNotEqual(probation_agent.status, AgentStatus.QUARANTINED)
        self.assertEqual(probation_agent.status, AgentStatus.PROBATION)
        self.assertEqual(probation_agent.violations_count, 0)
        self.assertLess(event_fake_p.penalty_applied, 0.20)

    def test_fix4_sybil_swarm_spam_power_law_resistance(self) -> None:
        """Verify FIX 4: Swarm of unregistered Sybils cannot trigger power-law amplification or quarantine probation agents."""
        self.dt.register_agent("probation_worker", initial_trust=0.50)

        # Attacker fires 25 separate false reports using 25 fake reporter IDs
        for i in range(25):
            self.dt.report_violation(
                agent_id="probation_worker",
                violation_type=ViolationType.PROTOCOL_TRESPASS,
                severity=4.5,
                reporter_id=f"sybil_swarm_attacker_{i}",
            )

        worker = self.dt.get_agent("probation_worker")
        # Invariant 1: Escalation counter remains 0 (untrusted reports do not pump v)
        self.assertEqual(worker.violations_count, 0)
        # Invariant 2: Agent is NOT quarantined
        self.assertNotEqual(worker.status, AgentStatus.QUARANTINED)
        # Invariant 3: Cumulative trust score degradation is capped, staying above restricted threshold
        self.assertGreater(worker.trust_score, 0.35)

    def test_fix4_credible_reporter_critical_slashing(self) -> None:
        """Verify FIX 4: Legitimate verified entities retain full authoritative capability to slash rogue agents."""
        self.dt.register_agent("supervisor_agent", initial_trust=0.92)
        self.dt.register_agent("rogue_agent", initial_trust=0.50)

        # Verified supervisor catches rogue agent in protocol trespass
        event = self.dt.report_violation(
            agent_id="rogue_agent",
            violation_type=ViolationType.PROTOCOL_TRESPASS,
            severity=4.0,
            reporter_id="supervisor_agent",
        )
        rogue = self.dt.get_agent("rogue_agent")
        # Credible report must trigger immediate quarantine
        self.assertEqual(rogue.status, AgentStatus.QUARANTINED)
        self.assertGreater(event.penalty_applied, 5.0)


if __name__ == "__main__":
    unittest.main()
