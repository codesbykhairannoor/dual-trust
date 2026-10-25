"""Unit tests for Agent-to-Agent (A2A) Delegation Mandates, Cryptographic Verification, and Monotonic Attenuation."""

from dataclasses import FrozenInstanceError
import os
import tempfile
import time
import unittest

from dualtrust import (
    DelegationError,
    DelegationMandate,
    DualTrust,
    MandateBudgetExceededError,
    MandateDepthExceededError,
    MandateExpiredError,
    MandateManager,
    MandateRevokedError,
    MandateScopeViolationError,
    MandateStatus,
    SQLiteStorage,
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

    def test_fix1_mandate_immutability_and_authoritative_state(self) -> None:
        """Verify FIX 1: Mandates are strictly immutable; direct mutations and forged objects are rejected."""
        mandate = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["search_flights"],
            max_credits=50,
        )

        # 1. Direct mutation attempts on frozen dataclass must raise FrozenInstanceError
        with self.assertRaises(FrozenInstanceError):
            mandate.credits_used = 0  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            mandate.status = MandateStatus.ACTIVE  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            mandate.max_credits = 999999  # type: ignore

        with self.assertRaises(FrozenInstanceError):
            mandate.allowed_actions = ["*"]  # type: ignore

        # 2. Exhaust the mandate legitimately
        self.manager.validate_and_consume(mandate.mandate_id, action="search_flights", cost_credits=50)
        stored = self.manager.get_mandate(mandate.mandate_id)
        self.assertEqual(stored.status, MandateStatus.EXHAUSTED)

        # 3. Even if caller tampers with in-memory attributes via object.__setattr__,
        # manager's verify_mandate uses authoritative internal registry state and rejects execution
        object.__setattr__(stored, "credits_used", 0)
        object.__setattr__(stored, "status", MandateStatus.ACTIVE)
        is_valid, reason = self.manager.verify_mandate(stored, action="search_flights", cost_credits=10)
        self.assertFalse(is_valid)
        self.assertIn("exhausted", reason)

        # 4. Unknown/unregistered mandate ID is rejected by authoritative registry check
        orphan_mandate = DelegationMandate(
            mandate_id="unregistered_fake_id_123",
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["search_flights"],
            max_credits=50,
            signature=mandate.signature,
        )
        is_valid, reason = self.manager.verify_mandate(orphan_mandate)
        self.assertFalse(is_valid)
        self.assertTrue("signature mismatch" in reason or "not found in authoritative registry" in reason)

    def test_fix2_sibling_budget_fanout_denial(self) -> None:
        """Verify FIX 2: Sibling sub-mandate derivation strictly reserves parent budget, blocking fan-out amplification."""
        root = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id="coordinator_bot",
            user_id=self.user_id,
            allowed_actions=["read_data", "write_data"],
            max_credits=100,
            max_depth=3,
        )
        self.assertEqual(root.available_for_delegation, 100)
        self.assertEqual(root.reserved_child_credits, 0)

        # Sibling 1 requests 60 credits -> Allowed (100 - 60 = 40 remaining for delegation)
        child1 = self.manager.derive_sub_mandate(
            parent_mandate_id=root.mandate_id,
            new_sub_agent_id="worker_worker1",
            allowed_actions=["read_data"],
            max_credits=60,
        )
        self.assertEqual(child1.max_credits, 60)
        root_updated = self.manager.get_mandate(root.mandate_id)
        self.assertEqual(root_updated.reserved_child_credits, 60)
        self.assertEqual(root_updated.available_for_delegation, 40)

        # Sibling 2 attempts to request 50 credits -> Must raise MandateBudgetExceededError (only 40 available)
        with self.assertRaises(MandateBudgetExceededError) as ctx:
            self.manager.derive_sub_mandate(
                parent_mandate_id=root.mandate_id,
                new_sub_agent_id="worker_worker2",
                allowed_actions=["read_data"],
                max_credits=50,
            )
        self.assertIn("60 already reserved by sibling sub-mandates", str(ctx.exception))

        # Sibling 2 requests exactly 40 credits -> Allowed (40 - 40 = 0 remaining for delegation)
        child2 = self.manager.derive_sub_mandate(
            parent_mandate_id=root.mandate_id,
            new_sub_agent_id="worker_worker2",
            allowed_actions=["read_data"],
            max_credits=40,
        )
        self.assertEqual(child2.max_credits, 40)
        root_updated2 = self.manager.get_mandate(root.mandate_id)
        self.assertEqual(root_updated2.reserved_child_credits, 100)
        self.assertEqual(root_updated2.available_for_delegation, 0)

        # Sibling 3 attempts to request 1 credit -> Blocked (0 available)
        with self.assertRaises(MandateBudgetExceededError):
            self.manager.derive_sub_mandate(
                parent_mandate_id=root.mandate_id,
                new_sub_agent_id="worker_worker3",
                max_credits=1,
            )

    def test_fix2_direct_parent_spending_confinement(self) -> None:
        """Verify FIX 2: Parent cannot spend credits that have already been reserved for child sub-mandates."""
        root = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id="coordinator_bot",
            user_id=self.user_id,
            allowed_actions=["read_data"],
            max_credits=100,
            max_depth=2,
        )

        # Allocate 80 credits to a child worker
        self.manager.derive_sub_mandate(
            parent_mandate_id=root.mandate_id,
            new_sub_agent_id="sub_worker",
            max_credits=80,
        )

        # Parent attempts direct spending of 30 credits (only 20 unreserved) -> Blocked!
        with self.assertRaises(MandateBudgetExceededError):
            self.manager.validate_and_consume(root.mandate_id, action="read_data", cost_credits=30)

        # Parent spends 15 credits (within 20 unreserved) -> Allowed!
        updated_root = self.manager.validate_and_consume(root.mandate_id, action="read_data", cost_credits=15)
        self.assertEqual(updated_root.credits_used, 15)
        self.assertEqual(updated_root.available_for_delegation, 5)

    def test_fix2_hierarchical_bubble_up_consumption(self) -> None:
        """Verify FIX 2: Child spending bubbles up to all ancestors atomically, updating used & reserved tallies."""
        root = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id="coordinator_bot",
            user_id=self.user_id,
            allowed_actions=["read_data"],
            max_credits=100,
            max_depth=3,
        )
        child = self.manager.derive_sub_mandate(
            parent_mandate_id=root.mandate_id,
            new_sub_agent_id="worker_bot",
            max_credits=60,
        )
        grandchild = self.manager.derive_sub_mandate(
            parent_mandate_id=child.mandate_id,
            new_sub_agent_id="sub_worker_bot",
            max_credits=25,
        )

        # Grandchild executes action costing 20 credits
        self.manager.validate_and_consume(grandchild.mandate_id, action="read_data", cost_credits=20)

        # 1. Grandchild checks
        gc = self.manager.get_mandate(grandchild.mandate_id)
        self.assertEqual(gc.credits_used, 20)
        self.assertEqual(gc.remaining_credits, 5)

        # 2. Child checks (credits_used +20, reserved_child_credits -20)
        c = self.manager.get_mandate(child.mandate_id)
        self.assertEqual(c.credits_used, 20)
        self.assertEqual(c.reserved_child_credits, 5)

        # 3. Root checks (credits_used +20, reserved_child_credits -20)
        r = self.manager.get_mandate(root.mandate_id)
        self.assertEqual(r.credits_used, 20)
        self.assertEqual(r.reserved_child_credits, 40)  # 60 - 20 = 40

    def test_fix2_cascading_revocation_releases_child_quota(self) -> None:
        """Verify FIX 2: Revoking a child mandate dynamically releases its unspent quota back to the parent."""
        root = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id="coordinator_bot",
            user_id=self.user_id,
            allowed_actions=["read_data"],
            max_credits=100,
            max_depth=2,
        )
        child = self.manager.derive_sub_mandate(
            parent_mandate_id=root.mandate_id,
            new_sub_agent_id="worker_bot",
            max_credits=60,
        )
        # Child spends 20 credits, has 40 unspent
        self.manager.validate_and_consume(child.mandate_id, action="read_data", cost_credits=20)
        root_mid = self.manager.get_mandate(root.mandate_id)
        self.assertEqual(root_mid.credits_used, 20)
        self.assertEqual(root_mid.reserved_child_credits, 40)
        self.assertEqual(root_mid.available_for_delegation, 40)

        # Revoke child mandate -> The 40 unspent credits must be released to root's available quota
        self.manager.revoke_mandate(child.mandate_id, reason="Worker task finished early")
        revoked_child = self.manager.get_mandate(child.mandate_id)
        self.assertEqual(revoked_child.status, MandateStatus.REVOKED)

        root_after = self.manager.get_mandate(root.mandate_id)
        self.assertEqual(root_after.reserved_child_credits, 0)
        self.assertEqual(root_after.available_for_delegation, 80)  # 100 - 20 used - 0 reserved = 80!

        # Child can no longer be used
        with self.assertRaises(MandateRevokedError):
            self.manager.validate_and_consume(child.mandate_id, action="read_data", cost_credits=5)

    def test_fix2_cascading_revocation_downward_tree(self) -> None:
        """Verify FIX 2: Revoking an ancestor immediately cascades and revokes all active descendants."""
        root = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id="coordinator_bot",
            user_id=self.user_id,
            allowed_actions=["read_data"],
            max_credits=100,
            max_depth=3,
        )
        child = self.manager.derive_sub_mandate(
            parent_mandate_id=root.mandate_id,
            new_sub_agent_id="worker_bot",
            max_credits=50,
        )
        grandchild = self.manager.derive_sub_mandate(
            parent_mandate_id=child.mandate_id,
            new_sub_agent_id="leaf_bot",
            max_credits=25,
        )

        # Revoke the root mandate
        self.manager.revoke_mandate(root.mandate_id, reason="Security alert on root")

        # All levels must now be REVOKED
        self.assertEqual(self.manager.get_mandate(root.mandate_id).status, MandateStatus.REVOKED)
        self.assertEqual(self.manager.get_mandate(child.mandate_id).status, MandateStatus.REVOKED)
        self.assertEqual(self.manager.get_mandate(grandchild.mandate_id).status, MandateStatus.REVOKED)

        # Attempting execution on grandchild is blocked by cascading revocation
        with self.assertRaises(MandateRevokedError):
            self.manager.validate_and_consume(grandchild.mandate_id, action="read_data", cost_credits=1)

    def test_fix2_compensating_rollback_transaction(self) -> None:
        """Verify FIX 2: rollback_consumption cleanly reverses consumption across the hierarchy."""
        root = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id="coordinator_bot",
            user_id=self.user_id,
            allowed_actions=["read_data"],
            max_credits=100,
            max_depth=2,
        )
        child = self.manager.derive_sub_mandate(
            parent_mandate_id=root.mandate_id,
            new_sub_agent_id="worker_bot",
            max_credits=50,
        )

        # Child consumes 30 credits
        self.manager.validate_and_consume(child.mandate_id, action="read_data", cost_credits=30)
        self.assertEqual(self.manager.get_mandate(child.mandate_id).credits_used, 30)
        self.assertEqual(self.manager.get_mandate(root.mandate_id).credits_used, 30)

        # Simulate compensating transaction rollback (e.g. downstream payment or storage failure)
        self.manager.rollback_consumption(child.mandate_id, cost_credits=30)
        self.assertEqual(self.manager.get_mandate(child.mandate_id).credits_used, 0)
        self.assertEqual(self.manager.get_mandate(root.mandate_id).credits_used, 0)
        self.assertEqual(self.manager.get_mandate(root.mandate_id).reserved_child_credits, 50)

    def test_empty_scope_rejection(self) -> None:
        """Verify FIX 3: allowed_actions=[] and allowed_actions=None are strictly rejected."""
        with self.assertRaises(DelegationError):
            self.manager.issue_mandate(
                parent_agent_id=self.parent_agent,
                sub_agent_id=self.sub_agent,
                user_id=self.user_id,
                allowed_actions=[],  # Empty list must be rejected!
                max_credits=50,
            )

        with self.assertRaises(DelegationError):
            self.manager.issue_mandate(
                parent_agent_id=self.parent_agent,
                sub_agent_id=self.sub_agent,
                user_id=self.user_id,
                allowed_actions=None,  # type: ignore # None must also be rejected!
                max_credits=50,
            )

        parent = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["read_data"],
            max_credits=50,
            max_depth=2,
        )

        with self.assertRaises(DelegationError):
            self.manager.derive_sub_mandate(
                parent_mandate_id=parent.mandate_id,
                new_sub_agent_id="sub_worker",
                allowed_actions=[],  # Empty list in sub-mandate must be rejected!
            )

    def test_fix3_wildcard_scope_escalation_denied(self) -> None:
        """Verify FIX 3: Sub-mandate cannot request wildcard '*' when parent is restricted."""
        parent = self.manager.issue_mandate(
            parent_agent_id=self.parent_agent,
            sub_agent_id=self.sub_agent,
            user_id=self.user_id,
            allowed_actions=["read_data", "filter_rows"],
            max_credits=50,
            max_depth=2,
        )

        # Attempt to escalate from ["read_data", "filter_rows"] to wildcard ["*"]
        with self.assertRaises(MandateScopeViolationError) as ctx:
            self.manager.derive_sub_mandate(
                parent_mandate_id=parent.mandate_id,
                new_sub_agent_id="rogue_escalator",
                allowed_actions=["*"],
            )
        self.assertIn("cannot request wildcard '*'", str(ctx.exception))

    def test_fix6_sqlite_mandate_persistence_across_restarts(self) -> None:
        """Verify FIX 6: Delegation mandates and hierarchical budget reservations persist across SQLite restarts."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "mandates_test.db")

        try:
            storage1 = SQLiteStorage(db_path=db_path)
            dt1 = DualTrust(storage=storage1, secret_key="persistent-mandate-key")
            dt1.register_human("user_root", social_credit=800, credits_balance=200)
            dt1.register_agent("parent_agent", initial_trust=0.90)
            dt1.register_agent("worker_agent", initial_trust=0.85)

            # Issue root parent mandate (100 credits)
            m_parent = dt1.mandate_manager.issue_mandate(
                parent_agent_id="parent_agent",
                sub_agent_id="worker_agent",
                user_id="user_root",
                allowed_actions=["scrape", "summarize"],
                max_credits=100,
                max_depth=3,
            )
            p_id = m_parent.mandate_id

            # Derive sub-mandate (30 credits)
            m_child = dt1.mandate_manager.derive_sub_mandate(
                parent_mandate_id=p_id,
                new_sub_agent_id="sub_worker_agent",
                allowed_actions=["summarize"],
                max_credits=30,
            )
            c_id = m_child.mandate_id

            # Consume 10 credits on child
            dt1.mandate_manager.validate_and_consume(c_id, cost_credits=10, action="summarize")
            storage1.close()

            # Second instance: Re-open with new connection
            storage2 = SQLiteStorage(db_path=db_path)
            dt2 = DualTrust(storage=storage2, secret_key="persistent-mandate-key")

            # Check that child mandate survived restart with updated consumption
            reloaded_child = dt2.mandate_manager.get_mandate(c_id)
            self.assertIsNotNone(reloaded_child)
            self.assertEqual(reloaded_child.credits_used, 10)
            self.assertEqual(reloaded_child.max_credits, 30)
            self.assertEqual(reloaded_child.status, MandateStatus.ACTIVE)

            # Check that parent mandate survived restart with bubble-up and reserved quota
            reloaded_parent = dt2.mandate_manager.get_mandate(p_id)
            self.assertIsNotNone(reloaded_parent)
            self.assertEqual(reloaded_parent.credits_used, 10)
            self.assertEqual(reloaded_parent.reserved_child_credits, 20)
            self.assertEqual(reloaded_parent.max_credits, 100)

            # Verify cryptographic signature check passes on reloaded instance
            is_valid, msg = dt2.mandate_manager.verify_mandate(reloaded_child, action="summarize")
            self.assertTrue(is_valid, f"Verification failed: {msg}")
            storage2.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)


if __name__ == "__main__":
    unittest.main()
