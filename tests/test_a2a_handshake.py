"""Unit tests for Bilateral Agent-to-Agent (A2A) Mutual Handshake, Attestation, and Clearance Gating."""

import unittest

from dualtrust import (
    AgentStatus,
    AgentWatchdog,
    DualTrust,
    HandshakeFailedError,
    HandshakeResult,
    MandateStatus,
    ViolationType,
)


class TestA2AMutualHandshake(unittest.TestCase):
    """Test suite validating bilateral mutual attestation and trust handshake between autonomous agents."""

    def setUp(self) -> None:
        self.dt = DualTrust(secret_key="unit-test-a2a-handshake-secret")
        self.human = self.dt.register_human(user_id="alice", social_credit=850, credits_balance=1000)

        # Register Verified Parent Agent (Smart Glasses) -> initial_trust >= 0.70 gives VERIFIED
        self.parent_agent = self.dt.register_agent(
            agent_id="glasses_alice",
            initial_trust=0.92,
        )

        # Register Verified High-Trust Specialist Agent (Airline Partner)
        self.airline_agent = self.dt.register_agent(
            agent_id="garuda_official_agent",
            initial_trust=0.90,
        )

    def test_successful_mutual_handshake_full_clearance(self) -> None:
        """Verify two high-reputation agents achieve approved mutual handshake with FULL clearance."""
        result = self.dt.verify_mutual_handshake(
            initiator_agent_id="glasses_alice",
            target_agent_id="garuda_official_agent",
            min_trust_score=0.70,
            require_verified=True,
        )

        self.assertIsInstance(result, HandshakeResult)
        self.assertTrue(result.approved)
        self.assertEqual(result.effective_clearance, "FULL")
        self.assertEqual(result.recommended_max_credits, 500)
        self.assertEqual(result.recommended_max_depth, 2)
        self.assertIsNotNone(result.handshake_token)
        self.assertFalse(result.is_expired())
        self.assertIn("APPROVED", result.describe())

        # Verify cryptographic audit block in ledger
        handshake_blocks = [b for b in self.dt.ledger.get_events(limit=100) if b.event_type == "A2A_HANDSHAKE"]
        self.assertGreaterEqual(len(handshake_blocks), 1)
        self.assertEqual(handshake_blocks[-1].payload["clearance"], "FULL")


    def test_handshake_clearance_attenuation_probation(self) -> None:
        """Verify sub-agent with probationary trust receives RESTRICTED clearance and lower credit bounds."""
        self.dt.register_agent(
            agent_id="newbie_hotel_bot",
            initial_trust=0.68,  # In probation range [0.40, 0.70)
        )

        result = self.dt.verify_mutual_handshake(
            initiator_agent_id="glasses_alice",
            target_agent_id="newbie_hotel_bot",
            min_trust_score=0.60,
            require_verified=False,
        )

        self.assertTrue(result.approved)
        self.assertEqual(result.effective_clearance, "RESTRICTED")
        self.assertEqual(result.recommended_max_credits, 100)
        self.assertEqual(result.recommended_max_depth, 1)

    def test_handshake_blocked_on_quarantined_target(self) -> None:
        """Verify that attempting to handshake with a quarantined rogue agent is strictly blocked."""
        # Quarantine the airline agent
        self.dt.quarantine_agent("garuda_official_agent", reason="Rogue escalation detected")

        with self.assertRaises(HandshakeFailedError) as ctx:
            self.dt.verify_mutual_handshake(
                initiator_agent_id="glasses_alice",
                target_agent_id="garuda_official_agent",
                raise_on_failure=True,
            )
        self.assertIn("quarantined as rogue", str(ctx.exception))

        # Check non-raising mode
        result = self.dt.verify_mutual_handshake(
            initiator_agent_id="glasses_alice",
            target_agent_id="garuda_official_agent",
            raise_on_failure=False,
        )
        self.assertFalse(result.approved)
        self.assertEqual(result.effective_clearance, "DENIED")

    def test_handshake_blocked_on_quarantined_initiator(self) -> None:
        """Verify that a rogue initiator cannot initiate an A2A connection."""
        self.dt.quarantine_agent("glasses_alice", reason="Rogue glasses compromised")

        with self.assertRaises(HandshakeFailedError) as ctx:
            self.dt.verify_mutual_handshake(
                initiator_agent_id="glasses_alice",
                target_agent_id="garuda_official_agent",
            )
        self.assertIn("quarantined as rogue", str(ctx.exception))

    def test_handshake_blocked_on_low_trust_score(self) -> None:
        """Verify handshake fails when target does not meet minimum reputation threshold."""
        self.dt.register_agent(
            agent_id="low_trust_agent",
            initial_trust=0.35,  # Restricted range
        )

        with self.assertRaises(HandshakeFailedError) as ctx:
            self.dt.verify_mutual_handshake(
                initiator_agent_id="glasses_alice",
                target_agent_id="low_trust_agent",
                min_trust_score=0.60,
            )
        self.assertIn("below minimum threshold", str(ctx.exception))

    def test_handshake_self_delegation_disallowed(self) -> None:
        """Verify an agent cannot perform a bilateral handshake with itself."""
        with self.assertRaises(HandshakeFailedError) as ctx:
            self.dt.verify_mutual_handshake(
                initiator_agent_id="glasses_alice",
                target_agent_id="glasses_alice",
            )
        self.assertIn("Self-handshake disallowed", str(ctx.exception))

    def test_handshake_missing_agent(self) -> None:
        """Verify handshake fails when querying an unregistered agent."""
        with self.assertRaises(HandshakeFailedError) as ctx:
            self.dt.verify_mutual_handshake(
                initiator_agent_id="glasses_alice",
                target_agent_id="ghost_agent_404",
            )
        self.assertIn("not found in registry", str(ctx.exception))

    def test_handshake_blocked_when_watchdog_throttled(self) -> None:
        """Verify that if an agent is currently throttled by the watchdog, mutual handshake is rejected."""
        watchdog = AgentWatchdog(max_calls_per_window=3, window_seconds=10.0)
        dt_with_watchdog = DualTrust(watchdog=watchdog)

        dt_with_watchdog.register_human("alice", social_credit=800, credits_balance=1000)
        dt_with_watchdog.register_agent("parent_agent", initial_trust=0.90)
        dt_with_watchdog.register_agent("target_agent", initial_trust=0.90)

        # Trigger burst throttle on target_agent
        for _ in range(5):
            watchdog.record_call_success("target_agent", cost_credits=10)

        self.assertTrue(watchdog.get_telemetry("target_agent").is_throttled)


        with self.assertRaises(HandshakeFailedError) as ctx:
            dt_with_watchdog.verify_mutual_handshake("parent_agent", "target_agent")
        self.assertIn("throttled by security watchdog", str(ctx.exception))

    def test_create_delegation_mandate_with_handshake_integration(self) -> None:
        """Verify end-to-end flow of issuing a delegation mandate gated by handshake."""
        mandate = self.dt.create_delegation_mandate(
            parent_agent_id="glasses_alice",
            sub_agent_id="garuda_official_agent",
            user_id="alice",
            allowed_actions=["search_flights", "issue_eticket"],
            max_credits=200,
            ttl_seconds=300.0,
            require_handshake=True,
            min_trust_score=0.70,
        )

        self.assertEqual(mandate.status, MandateStatus.ACTIVE)
        self.assertEqual(mandate.max_credits, 200)
        self.assertEqual(mandate.parent_agent_id, "glasses_alice")
        self.assertEqual(mandate.sub_agent_id, "garuda_official_agent")

        # Verify retrieval
        stored = self.dt.get_mandate(mandate.mandate_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored.mandate_id, mandate.mandate_id)

        # Verify audit ledger
        mandate_blocks = [b for b in self.dt.ledger.get_events(limit=100) if b.event_type == "MANDATE_ISSUED"]
        self.assertEqual(len(mandate_blocks), 1)

    def test_revoke_mandate_via_dualtrust(self) -> None:
        """Verify revoking mandate via DualTrust engine logs to cryptographic ledger."""
        mandate = self.dt.create_delegation_mandate(
            parent_agent_id="glasses_alice",
            sub_agent_id="garuda_official_agent",
            user_id="alice",
            allowed_actions=["search_flights"],
            max_credits=100,
        )

        success = self.dt.revoke_mandate(mandate.mandate_id, reason="User cancelled session")
        self.assertTrue(success)

        revoked = self.dt.get_mandate(mandate.mandate_id)
        self.assertEqual(revoked.status, MandateStatus.REVOKED)

        revocation_blocks = [b for b in self.dt.ledger.get_events(limit=100) if b.event_type == "MANDATE_REVOKED"]
        self.assertEqual(len(revocation_blocks), 1)



if __name__ == "__main__":
    unittest.main()
