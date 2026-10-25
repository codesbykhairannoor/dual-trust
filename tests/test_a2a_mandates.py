"""Unit tests for Agent-to-Agent (A2A) Delegation Mandates, Cryptographic Verification, and Monotonic Attenuation."""

import time
import unittest

from dualtrust import (
    DelegationError,
    DelegationMandate,
    MandateBudgetExceededError,
    MandateDepthExceededError,
    MandateExpiredError,
    MandateManager,
    MandateRevokedError,
    MandateScopeViolationError,
    MandateStatus,
)


class TestA2AMandates(unittest.TestCase):
    """Test suite validating cryptographic A2A delegation mandates and sub-agent confinement."""

    def setUp(self) -> None:
        self.manager = MandateManager(secret_key="unit-test-super-secret-a2a-key")
        self.parent_agent = "glasses_assistant_alice"
        self.sub_agent = "flight_booking_specialist"
        self.user_id = "user_alice"

    def test_issue_and_verify_valid_mandate(self) -> None:
        """Verify standard mandate issuance produces a cryptographically sound ticket."""
        mandate = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["search_flights", "reserve_seat"],
            max_credits=100,
            ttl_seconds=300.0,
            max_depth=2,
        )

        self.assertIsNotNone(mandate.signature)
        self.assertEqual(mandate.status, MandateStatus.ACTIVE)
        self.assertEqual(mandate.remaining_credits, 100)
        self.assertTrue(mandate.can_perform("search_flights"))
        self.assertTrue(mandate.can_perform("reserve_seat"))
        self.assertFalse(mandate.can_perform("delete_database"))

        is_valid, msg = self.manager.verify_mandate(mandate, action="search_flights", cost_credits=20)
        self.assertTrue(is_valid)
        self.assertIn("authorized", msg)

    def test_tamper_detection_in_mandate(self) -> None:
        """Verify that altering any field in the mandate triggers cryptographic rejection."""
        mandate = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["search_flights"],
            max_credits=50,
        )

        # Rogue sub-agent tries to elevate its credit allowance from 50 to 5000
        tampered_mandate = DelegationMandate(
            mandate_id=mandate.mandate_id,
            parent_agent_id=mandate.parent_agent_id,
            sub_agent_id=mandate.sub_agent_id,
            user_id=mandate.user_id,
            allowed_actions=mandate.allowed_actions,
            max_credits=5000,  # Tampered!
            credits_used=mandate.credits_used,
            max_depth=mandate.max_depth,
            current_depth=mandate.current_depth,
            created_at=mandate.created_at,
            expires_at=mandate.expires_at,
            status=mandate.status,
            metadata=mandate.metadata,
            signature=mandate.signature,
        )

        is_valid, reason = self.manager.verify_mandate(tampered_mandate)
        self.assertFalse(is_valid)
        self.assertIn("Cryptographic signature mismatch", reason)

    def test_validate_and_consume_budget_exhaustion(self) -> None:
        """Verify that budget deductions are atomic and block calls once credit pool is depleted."""
        mandate = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["search_flights"],
            max_credits=50,
        )

        # Call 1: spend 30 credits
        updated = self.manager.validate_and_consume(mandate.mandate_id, action="search_flights", cost_credits=30)
        self.assertEqual(updated.credits_used, 30)
        self.assertEqual(updated.remaining_credits, 20)
        self.assertEqual(updated.status, MandateStatus.ACTIVE)

        # Call 2: spend remaining 20 credits
        updated = self.manager.validate_and_consume(mandate.mandate_id, action="search_flights", cost_credits=20)
        self.assertEqual(updated.credits_used, 50)
        self.assertEqual(updated.remaining_credits, 0)
        self.assertEqual(updated.status, MandateStatus.EXHAUSTED)

        # Call 3: attempt to spend 1 more credit -> must raise MandateBudgetExceededError
        with self.assertRaises(MandateBudgetExceededError):
            self.manager.validate_and_consume(mandate.mandate_id, action="search_flights", cost_credits=1)

    def test_scope_violation_error(self) -> None:
        """Verify that sub-agents attempting actions outside allowed scope are strictly blocked."""
        mandate = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["search_flights"],
            max_credits=50,
        )

        with self.assertRaises(MandateScopeViolationError):
            self.manager.validate_and_consume(mandate.mandate_id, action="drain_user_wallet", cost_credits=5)

    def test_ttl_expiration(self) -> None:
        """Verify that mandates cannot be used after their TTL expires."""
        mandate = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["search_flights"],
            max_credits=50,
            ttl_seconds=1.0,
        )

        simulated_future = time.time() + 5.0
        with self.assertRaises(MandateExpiredError):
            self.manager.validate_and_consume(
                mandate.mandate_id, action="search_flights", cost_credits=5, current_time=simulated_future
            )

    def test_mandate_revocation(self) -> None:
        """Verify that parent agent or human can instantaneously revoke a mandate."""
        mandate = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["search_flights"],
            max_credits=50,
        )

        revoked = self.manager.revoke_mandate(mandate.mandate_id, reason="User cancelled flight search")
        self.assertTrue(revoked)

        with self.assertRaises(MandateRevokedError):
            self.manager.validate_and_consume(mandate.mandate_id, action="search_flights", cost_credits=5)

    def test_sub_mandate_attenuation_and_depth_limits(self) -> None:
        """Verify sub-mandate delegation respects maximum depth and prevents infinite recursion."""
        # Parent gives max_depth=2 (glasses -> flight_agent -> aggregator)
        parent_mandate = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id="flight_booking_specialist",
            user_id=self.user_id,
            allowed_actions=["search_flights", "query_aggregators"],
            max_credits=100,
            max_depth=2,
            current_depth=1,
        )

        # Level 2 delegation: flight_agent delegates to aggregator (depth becomes 2)
        sub_mandate = self.manager.derive_sub_mandate(
            parent_mandate_id=parent_mandate.mandate_id,
            new_sub_agent_id="skyscanner_crawler_bot",
            allowed_actions=["query_aggregators"],
            max_credits=40,
        )
        self.assertEqual(sub_mandate.current_depth, 2)
        self.assertEqual(sub_mandate.parent_agent_id, "flight_booking_specialist")
        self.assertEqual(sub_mandate.sub_agent_id, "skyscanner_crawler_bot")
        self.assertEqual(sub_mandate.max_credits, 40)

        # Level 3 delegation: aggregator attempts to delegate to another bot -> MUST BE REJECTED!
        with self.assertRaises(MandateDepthExceededError):
            self.manager.derive_sub_mandate(
                parent_mandate_id=sub_mandate.mandate_id,
                new_sub_agent_id="quaternary_rogue_bot",
            )

    def test_sub_mandate_cannot_escalate_privileges(self) -> None:
        """Verify that sub-mandate derivation strictly enforces the Principle of Least Privilege."""
        parent_mandate = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id="flight_booking_specialist",
            user_id=self.user_id,
            allowed_actions=["search_flights"],
            max_credits=50,
            max_depth=3,
        )

        # Cannot escalate scope
        with self.assertRaises(MandateScopeViolationError):
            self.manager.derive_sub_mandate(
                parent_mandate_id=parent_mandate.mandate_id,
                new_sub_agent_id="sub_worker",
                allowed_actions=["search_flights", "transfer_money"],  # Escalation!
            )

        # Cannot allocate more credits than parent has remaining
        with self.assertRaises(MandateBudgetExceededError):
            self.manager.derive_sub_mandate(
                parent_mandate_id=parent_mandate.mandate_id,
                new_sub_agent_id="sub_worker",
                max_credits=100,  # Parent only has 50!
            )

    def test_invalid_creation_parameters(self) -> None:
        """Verify defense against illegal issuance parameters."""
        with self.assertRaises(DelegationError):
            # Agent cannot delegate to itself
            self.manager.issue_mandate("agent_a", "agent_a", "user_1", ["act"], 10)

        with self.assertRaises(DelegationError):
            # Negative credits
            self.manager.issue_mandate("agent_a", "agent_b", "user_1", ["act"], -10)

        with self.assertRaises(DelegationError):
            # Non-positive TTL
            self.manager.issue_mandate("agent_a", "agent_b", "user_1", ["act"], 10, ttl_seconds=0)


if __name__ == "__main__":
    unittest.main()
