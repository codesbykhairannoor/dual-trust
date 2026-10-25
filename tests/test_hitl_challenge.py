"""Tests for DualTrust Stepped Human-in-the-Loop (HITL) Challenge Engine (NIST SP 800-63B)."""

import asyncio
import os
import tempfile
import time
import unittest

from dualtrust.engine import DualTrust
from dualtrust.exceptions import (
    ChallengeVerificationError,
    HumanApprovalRequiredError,
    InsufficientCreditsError,
)
from dualtrust.models import ChallengeStatus, HumanTier
from dualtrust.storage import MemoryStorage, SQLiteStorage


class TestHumanInTheLoopChallenge(unittest.TestCase):
    """Test suite verifying NIST SP 800-63B stepped authorization and anti-tamper mechanics."""

    def setUp(self) -> None:
        self.dt = DualTrust(storage=MemoryStorage(), secret_key="test-secret-key-42")
        self.dt.register_human(user_id="alice", social_credit=800, credits_balance=100)
        self.dt.register_agent(agent_id="finance_bot", initial_trust=0.90)

    def test_challenge_creation_and_hashing(self) -> None:
        """Verify deterministic hashing and cryptographic token sealing."""
        args = {"user_id": "alice", "agent_id": "finance_bot", "amount": 250, "currency": "USD"}
        ch = self.dt.create_human_challenge(
            user_id="alice",
            agent_id="finance_bot",
            action_name="wire_transfer",
            arguments=args,
            cost_credits=5,
            ttl_seconds=120.0,
        )

        self.assertIsNotNone(ch.challenge_id)
        self.assertEqual(ch.status, ChallengeStatus.PENDING)
        self.assertEqual(ch.cost_credits, 5)
        self.assertTrue(len(ch.arguments_hash) == 64)
        self.assertTrue(len(ch.token) == 64)
        self.assertFalse(ch.is_expired())

        # Verify storage lookup
        retrieved = self.dt.get_challenge(ch.challenge_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.challenge_id, ch.challenge_id)

    def test_sync_gate_hitl_approval_flow(self) -> None:
        """Verify synchronous stepped human authorization and credit deduction."""
        dt = self.dt

        @dt.gate(require_human_confirmation=True, cost_credits=15)
        def process_payroll(user_id: str, agent_id: str, employee_id: str, payout: float) -> str:
            return f"PAID ${payout} to {employee_id}"

        # Step 1: Initial invocation without approval raises HumanApprovalRequiredError
        with self.assertRaises(HumanApprovalRequiredError) as ctx:
            process_payroll(user_id="alice", agent_id="finance_bot", employee_id="EMP-901", payout=4500.0)

        err = ctx.exception
        ch = err.challenge
        self.assertIsNotNone(ch)
        self.assertEqual(ch.action_name, "process_payroll")
        self.assertEqual(ch.cost_credits, 15)
        self.assertEqual(ch.status, ChallengeStatus.PENDING)

        # Step 2: Human reviews and approves the challenge
        success, msg = dt.resolve_human_challenge(
            challenge_id=ch.challenge_id,
            approved=True,
            reason="Verified payroll batch for October",
        )
        self.assertTrue(success)
        self.assertIn("approved", msg.lower())

        # Step 3: Invoking with challenge_id executes successfully
        result = process_payroll(
            user_id="alice",
            agent_id="finance_bot",
            employee_id="EMP-901",
            payout=4500.0,
            challenge_id=ch.challenge_id,
        )
        self.assertEqual(result, "PAID $4500.0 to EMP-901")

        # Step 4: Verify credits deduction (100 - 15 = 85)
        human = dt.get_human("alice")
        self.assertEqual(human.credits_balance, 85)

    def test_async_gate_hitl_approval_flow(self) -> None:
        """Verify asynchronous coroutine stepped authorization."""
        dt = self.dt

        @dt.gate(require_human_confirmation=True, cost_credits=0)
        async def deploy_microservice(user_id: str, agent_id: str, cluster: str) -> str:
            await asyncio.sleep(0.01)
            return f"DEPLOYED TO {cluster}"

        async def _run() -> None:
            # 1. First attempt triggers challenge
            with self.assertRaises(HumanApprovalRequiredError) as ctx:
                await deploy_microservice(user_id="alice", agent_id="finance_bot", cluster="prod-eu-west")

            ch_id = ctx.exception.challenge.challenge_id

            # 2. Human approval
            ok, _ = dt.resolve_human_challenge(ch_id, approved=True)
            self.assertTrue(ok)

            # 3. Second attempt with challenge succeeds
            res = await deploy_microservice(
                user_id="alice", agent_id="finance_bot", cluster="prod-eu-west", challenge_id=ch_id
            )
            self.assertEqual(res, "DEPLOYED TO prod-eu-west")

        asyncio.run(_run())

    def test_rejection_flow_blocks_execution(self) -> None:
        """Verify that human rejection prevents execution."""
        dt = self.dt

        @dt.gate(require_human_confirmation=True)
        def delete_production_database(user_id: str, agent_id: str, db_name: str) -> str:
            return f"DELETED {db_name}"

        with self.assertRaises(HumanApprovalRequiredError) as ctx:
            delete_production_database(user_id="alice", agent_id="finance_bot", db_name="users_db")

        ch_id = ctx.exception.challenge.challenge_id

        # Human explicitly rejects the dangerous action
        ok, msg = dt.resolve_human_challenge(
            challenge_id=ch_id,
            approved=False,
            reason="Unauthorized dangerous operation",
        )
        self.assertTrue(ok)
        self.assertIn("rejected", msg.lower())

        # Attempting to execute with rejected challenge raises ChallengeVerificationError
        with self.assertRaises(ChallengeVerificationError) as ctx_denied:
            delete_production_database(
                user_id="alice", agent_id="finance_bot", db_name="users_db", challenge_id=ch_id
            )
        self.assertIn("is not approved", str(ctx_denied.exception))
        self.assertIn("REJECTED", str(ctx_denied.exception))

    def test_argument_tampering_detection(self) -> None:
        """Verify that altered payload parameters trigger ChallengeVerificationError."""
        dt = self.dt

        @dt.gate(require_human_confirmation=True)
        def transfer_funds(user_id: str, agent_id: str, recipient: str, amount: int) -> str:
            return f"SENT {amount} to {recipient}"

        # 1. Initiates transfer of $50 to Bob
        with self.assertRaises(HumanApprovalRequiredError) as ctx:
            transfer_funds(user_id="alice", agent_id="finance_bot", recipient="bob", amount=50)

        ch_id = ctx.exception.challenge.challenge_id

        # 2. Human approves transfer of $50 to Bob
        dt.resolve_human_challenge(ch_id, approved=True)

        # 3. Attacker alters arguments: amount changed to $50,000 using the approved challenge_id
        with self.assertRaises(ChallengeVerificationError) as ctx_tamper:
            transfer_funds(
                user_id="alice", agent_id="finance_bot", recipient="bob", amount=50000, challenge_id=ch_id
            )
        self.assertIn("Payload tampering detected", str(ctx_tamper.exception))

        # 4. Attacker alters recipient to 'eve'
        with self.assertRaises(ChallengeVerificationError) as ctx_tamper_recip:
            transfer_funds(
                user_id="alice", agent_id="finance_bot", recipient="eve", amount=50, challenge_id=ch_id
            )
        self.assertIn("Payload tampering detected", str(ctx_tamper_recip.exception))

        # 5. Original arguments pass without issue
        result = transfer_funds(
            user_id="alice", agent_id="finance_bot", recipient="bob", amount=50, challenge_id=ch_id
        )
        self.assertEqual(result, "SENT 50 to bob")

    def test_single_use_and_replay_prevention(self) -> None:
        """Verify that once finalized, a challenge cannot be re-approved or altered."""
        dt = self.dt
        ch = dt.create_human_challenge(
            user_id="alice",
            agent_id="finance_bot",
            action_name="test_action",
            arguments={"user_id": "alice", "agent_id": "finance_bot"},
        )

        ok1, msg1 = dt.resolve_human_challenge(ch.challenge_id, approved=True)
        self.assertTrue(ok1)

        # Attempt to resolve again fails
        ok2, msg2 = dt.resolve_human_challenge(ch.challenge_id, approved=False)
        self.assertFalse(ok2)
        self.assertIn("already finalized", msg2.lower())

    def test_challenge_expiration_ttl(self) -> None:
        """Verify that expired challenge tokens cannot be resolved or executed."""
        dt = self.dt
        ch = dt.create_human_challenge(
            user_id="alice",
            agent_id="finance_bot",
            action_name="fast_action",
            arguments={"user_id": "alice", "agent_id": "finance_bot"},
            ttl_seconds=1.0,
        )

        simulated_future = ch.created_at + 10.0
        # Resolve attempted after TTL
        ok, msg = dt.resolve_human_challenge(
            ch.challenge_id, approved=True, current_time=simulated_future
        )
        self.assertFalse(ok)
        self.assertIn("expired", msg.lower())

        expired_ch = dt.get_challenge(ch.challenge_id)
        self.assertEqual(expired_ch.status, ChallengeStatus.EXPIRED)

    def test_evaluate_direct_hitl_support(self) -> None:
        """Verify direct dt.evaluate() usage with require_human_confirmation."""
        dt = self.dt
        args = {"target": "cluster-1"}

        # 1. Initial evaluate without challenge returns unauthorized + challenge
        verdict = dt.evaluate(
            user_id="alice",
            agent_id="finance_bot",
            require_human_confirmation=True,
            action_name="restart_cluster",
            arguments=args,
        )
        self.assertFalse(verdict.authorized)
        self.assertTrue(verdict.requires_human_approval)
        self.assertIsNotNone(verdict.challenge)
        ch_id = verdict.challenge.challenge_id

        # 2. Human approves
        dt.resolve_human_challenge(ch_id, approved=True)

        # 3. Direct evaluate with approved challenge_id returns authorized
        verdict2 = dt.evaluate(
            user_id="alice",
            agent_id="finance_bot",
            require_human_confirmation=True,
            action_name="restart_cluster",
            arguments=args,
            challenge_id=ch_id,
        )
        self.assertTrue(verdict2.authorized)
        self.assertFalse(verdict2.requires_human_approval)

    def test_sqlite_storage_challenge_persistence(self) -> None:
        """Verify that challenges persist across SQLite storage restarts."""
        temp_dir = tempfile.mkdtemp()
        db_path = os.path.join(temp_dir, "test_hitl.db")

        try:
            storage1 = SQLiteStorage(db_path=db_path)
            dt1 = DualTrust(storage=storage1, secret_key="persistent-secret")
            dt1.register_human("alice", social_credit=750, credits_balance=100)
            dt1.register_agent("bot1", initial_trust=0.85)

            ch = dt1.create_human_challenge(
                user_id="alice",
                agent_id="bot1",
                action_name="backup_data",
                arguments={"user_id": "alice", "agent_id": "bot1"},
            )
            ch_id = ch.challenge_id
            storage1.close()

            # Re-open with new storage instance
            storage2 = SQLiteStorage(db_path=db_path)
            dt2 = DualTrust(storage=storage2, secret_key="persistent-secret")

            loaded_ch = dt2.get_challenge(ch_id)
            self.assertIsNotNone(loaded_ch)
            self.assertEqual(loaded_ch.challenge_id, ch_id)
            self.assertEqual(loaded_ch.status, ChallengeStatus.PENDING)

            # Resolve in second instance
            ok, _ = dt2.resolve_human_challenge(ch_id, approved=True)
            self.assertTrue(ok)

            resolved_ch = dt2.get_challenge(ch_id)
            self.assertEqual(resolved_ch.status, ChallengeStatus.APPROVED)
            storage2.close()
        finally:
            if os.path.exists(db_path):
                os.remove(db_path)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)


if __name__ == "__main__":
    unittest.main()
