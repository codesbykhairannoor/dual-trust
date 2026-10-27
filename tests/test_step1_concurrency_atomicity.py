"""Unit and stress tests for Step 1: Concurrency, Atomic Deduction, Input Validation, and Compensating Refund."""

import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import math
import os
import tempfile
import time
import unittest
from dualtrust.crypto_ledger import CryptographicLedger
from dualtrust.engine import DualTrust
from dualtrust.models import HumanTier
from dualtrust.storage import MemoryStorage, SQLiteStorage


class TestStep1ConcurrencyAtomicity(unittest.TestCase):
    """Test suite verifying Step 1 fixes against race conditions and invalid input mutations."""

    def setUp(self) -> None:
        self.mem_storage = MemoryStorage()
        self.mem_ledger = CryptographicLedger()
        self.mem_dt = DualTrust(storage=self.mem_storage, ledger=self.mem_ledger)

        self.temp_dir = tempfile.mkdtemp()
        self.sqlite_db_path = os.path.join(self.temp_dir, "step1_test.db")
        self.sql_storage = SQLiteStorage(db_path=self.sqlite_db_path)
        self.sql_ledger = CryptographicLedger()
        self.sql_dt = DualTrust(storage=self.sql_storage, ledger=self.sql_ledger)

    def tearDown(self) -> None:
        self.sql_storage.close()
        for p in [self.sqlite_db_path, self.sqlite_db_path + "-wal", self.sqlite_db_path + "-shm"]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
        if os.path.exists(self.temp_dir):
            try:
                os.rmdir(self.temp_dir)
            except OSError:
                pass

    # =========================================================================
    # 1. Input Validation Tests
    # =========================================================================

    def test_evaluate_cost_credits_validation(self) -> None:
        """Verify evaluate() rejects negative, non-numeric, NaN, and Inf credit costs."""
        u_id = "val_user_1"
        a_id = "val_agent_1"
        self.mem_dt.register_human(u_id, credits_balance=100)
        self.mem_dt.register_agent(a_id, initial_trust=0.8)

        # Negative credits
        with self.assertRaises(ValueError):
            self.mem_dt.evaluate(user_id=u_id, agent_id=a_id, cost_credits=-5)

        # NaN
        with self.assertRaises(ValueError):
            self.mem_dt.evaluate(user_id=u_id, agent_id=a_id, cost_credits=float("nan"))

        # Inf and -Inf
        with self.assertRaises(ValueError):
            self.mem_dt.evaluate(user_id=u_id, agent_id=a_id, cost_credits=float("inf"))
        with self.assertRaises(ValueError):
            self.mem_dt.evaluate(user_id=u_id, agent_id=a_id, cost_credits=float("-inf"))

        # Non-numeric
        for bad_val in ["10", None, [], {}, object()]:
            with self.assertRaises(ValueError):
                self.mem_dt.evaluate(user_id=u_id, agent_id=a_id, cost_credits=bad_val)  # type: ignore

        # Valid float cast to int
        verdict = self.mem_dt.evaluate(user_id=u_id, agent_id=a_id, cost_credits=10.0, deduct_cost=True)
        self.assertTrue(verdict.authorized)
        self.assertEqual(verdict.cost_deducted, 10)
        human = self.mem_dt.get_human(u_id)
        self.assertIsNotNone(human)
        self.assertEqual(human.credits_balance, 90)

    def test_add_and_adjust_credits_validation(self) -> None:
        """Verify add_credits and adjust_human_credit validate numeric bounds."""
        u_id = "val_user_2"
        self.mem_dt.register_human(u_id, social_credit=700, credits_balance=50)

        # add_credits invalid inputs
        with self.assertRaises(ValueError):
            self.mem_dt.add_credits(u_id, -10)
        with self.assertRaises(ValueError):
            self.mem_dt.add_credits(u_id, float("nan"))
        with self.assertRaises(ValueError):
            self.mem_dt.add_credits(u_id, "50")  # type: ignore

        # adjust_human_credit invalid inputs
        with self.assertRaises(ValueError):
            self.mem_dt.adjust_human_credit(u_id, float("nan"))
        with self.assertRaises(ValueError):
            self.mem_dt.adjust_human_credit(u_id, "score")  # type: ignore

    def test_storage_level_input_validation(self) -> None:
        """Verify storage engines reject invalid numeric inputs directly."""
        u_id = "val_user_storage"
        self.mem_storage.save_human(
            self.mem_dt.register_human(u_id, credits_balance=100)
        )
        with self.assertRaises(ValueError):
            self.mem_storage.deduct_credits(u_id, -10)
        with self.assertRaises(ValueError):
            self.mem_storage.deduct_credits(u_id, float("nan"))
        with self.assertRaises(ValueError):
            self.mem_storage.add_credits(u_id, -5)

    # =========================================================================
    # 2. Concurrency & Race Condition Double-Spending Tests
    # =========================================================================

    def _run_concurrent_evaluate_blast(self, dt: DualTrust, initial_balance: int, cost: int, total_calls: int) -> None:
        u_id = f"blast_user_{time.time()}"
        a_id = f"blast_agent_{time.time()}"
        dt.register_human(user_id=u_id, social_credit=850, credits_balance=initial_balance)
        dt.register_agent(agent_id=a_id, initial_trust=0.90)

        expected_successes = initial_balance // cost
        expected_failures = total_calls - expected_successes

        def call_eval() -> bool:
            v = dt.evaluate(
                user_id=u_id,
                agent_id=a_id,
                cost_credits=cost,
                deduct_cost=True,
            )
            return v.authorized

        successes = 0
        failures = 0

        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(call_eval) for _ in range(total_calls)]
            for fut in as_completed(futures):
                if fut.result():
                    successes += 1
                else:
                    failures += 1

        self.assertEqual(
            successes,
            expected_successes,
            f"Expected exactly {expected_successes} authorized verdicts, got {successes}",
        )
        self.assertEqual(
            failures,
            expected_failures,
            f"Expected exactly {expected_failures} rejected verdicts, got {failures}",
        )

        final_human = dt.get_human(u_id)
        self.assertIsNotNone(final_human)
        self.assertEqual(
            final_human.credits_balance,
            0,
            f"Expected remaining credits to be exactly 0, got {final_human.credits_balance}",
        )

    def test_memory_storage_concurrent_double_spend_prevention(self) -> None:
        """MemoryStorage: 60 concurrent threads competing for 100 credits at 10 credits/call."""
        self._run_concurrent_evaluate_blast(self.mem_dt, initial_balance=100, cost=10, total_calls=60)

    def test_sqlite_storage_concurrent_double_spend_prevention(self) -> None:
        """SQLiteStorage: 60 concurrent threads competing for 100 credits at 10 credits/call."""
        self._run_concurrent_evaluate_blast(self.sql_dt, initial_balance=100, cost=10, total_calls=60)

    def test_striped_locks_multi_user_parallelism(self) -> None:
        """Verify 10 different users can be concurrently evaluated without deadlocks."""
        num_users = 10
        user_ids = [f"multi_user_{i}" for i in range(num_users)]
        agent_id = "shared_agent"
        self.mem_dt.register_agent(agent_id, initial_trust=0.85)

        for u in user_ids:
            self.mem_dt.register_human(u, social_credit=800, credits_balance=100)

        def eval_user(user_id: str) -> bool:
            return self.mem_dt.evaluate(
                user_id=user_id,
                agent_id=agent_id,
                cost_credits=10,
                deduct_cost=True,
            ).authorized

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(eval_user, u) for u in user_ids for _ in range(5)]
            results = [f.result() for f in as_completed(futures)]

        self.assertEqual(len(results), 50)
        self.assertTrue(all(results))

        for u in user_ids:
            h = self.mem_dt.get_human(u)
            self.assertIsNotNone(h)
            self.assertEqual(h.credits_balance, 50)

    # =========================================================================
    # 3. Compensating Rollback / Automatic Refund Tests
    # =========================================================================

    def test_execute_rollback_on_sync_exception(self) -> None:
        """Verify dt.execute() refunds credits when synchronous callable raises exception."""
        u_id = "refund_user_sync"
        a_id = "refund_agent_sync"
        self.mem_dt.register_human(u_id, social_credit=800, credits_balance=100)
        self.mem_dt.register_agent(a_id, initial_trust=0.85)

        def faulty_task() -> None:
            raise RuntimeError("Downstream API timeout")

        initial_blocks = len(self.mem_ledger.get_blocks())

        with self.assertRaises(RuntimeError):
            self.mem_dt.execute(
                user_id=u_id,
                agent_id=a_id,
                func=faulty_task,
                cost_credits=30,
                deduct_cost=True,
            )

        # Credits must be refunded back to 100
        human = self.mem_dt.get_human(u_id)
        self.assertIsNotNone(human)
        self.assertEqual(human.credits_balance, 100)

        # Rollback block must exist in cryptographic ledger
        blocks = self.mem_ledger.get_blocks()
        rollback_blocks = [b for b in blocks if b.event_type == "EXECUTION_ROLLBACK_REFUND"]
        self.assertEqual(len(rollback_blocks), 1)
        self.assertEqual(rollback_blocks[0].payload["amount"], 30)
        self.assertEqual(rollback_blocks[0].entity_id, u_id)
        self.assertIn("Downstream API timeout", rollback_blocks[0].payload["reason"])

    def test_execute_rollback_on_async_exception(self) -> None:
        """Verify dt.execute() refunds credits when async coroutine raises exception."""
        u_id = "refund_user_async"
        a_id = "refund_agent_async"
        self.mem_dt.register_human(u_id, social_credit=800, credits_balance=100)
        self.mem_dt.register_agent(a_id, initial_trust=0.85)

        async def faulty_async_task() -> None:
            await asyncio.sleep(0.01)
            raise ValueError("Async LLM provider failed")

        async def run_test() -> None:
            coro = self.mem_dt.execute(
                user_id=u_id,
                agent_id=a_id,
                func=faulty_async_task,
                cost_credits=45,
                deduct_cost=True,
            )
            await coro

        with self.assertRaises(ValueError):
            asyncio.run(run_test())

        human = self.mem_dt.get_human(u_id)
        self.assertIsNotNone(human)
        self.assertEqual(human.credits_balance, 100)

        blocks = self.mem_ledger.get_blocks()
        rollback_blocks = [b for b in blocks if b.event_type == "EXECUTION_ROLLBACK_REFUND"]
        self.assertEqual(len(rollback_blocks), 1)
        self.assertEqual(rollback_blocks[0].payload["amount"], 45)

    def test_intercept_tool_call_rollback_on_exception(self) -> None:
        """Verify dt.intercept_tool_call() refunds credits when tool callable raises exception."""
        u_id = "refund_user_tool"
        a_id = "refund_agent_tool"
        self.mem_dt.register_human(u_id, social_credit=800, credits_balance=100)
        self.mem_dt.register_agent(a_id, initial_trust=0.85)

        def failing_tool(query: str) -> None:
            raise ConnectionResetError("Database connection lost")

        with self.assertRaises(ConnectionResetError):
            self.mem_dt.intercept_tool_call(
                user_id=u_id,
                agent_id=a_id,
                tool_name="db_query",
                tool_callable=failing_tool,
                arguments={"query": "SELECT 1"},
                cost_credits=25,
                deduct_cost=True,
            )

        human = self.mem_dt.get_human(u_id)
        self.assertIsNotNone(human)
        self.assertEqual(human.credits_balance, 100)

        blocks = self.mem_ledger.get_blocks()
        rollback_blocks = [b for b in blocks if b.event_type == "EXECUTION_ROLLBACK_REFUND"]
        self.assertEqual(len(rollback_blocks), 1)
        self.assertEqual(rollback_blocks[0].payload["amount"], 25)
        self.assertEqual(rollback_blocks[0].payload["tool_name"], "db_query")

    def test_gate_decorator_rollback_on_sync_and_async_exception(self) -> None:
        """Verify @dt.gate() refunds credits when decorated function raises exception."""
        u_id = "refund_user_gate"
        a_id = "refund_agent_gate"
        self.mem_dt.register_human(u_id, social_credit=800, credits_balance=100)
        self.mem_dt.register_agent(a_id, initial_trust=0.85)

        @self.mem_dt.gate(cost_credits=35, deduct_cost=True)
        def sync_gated_action(user_id: str, agent_id: str) -> None:
            raise ZeroDivisionError("Math error in action")

        with self.assertRaises(ZeroDivisionError):
            sync_gated_action(user_id=u_id, agent_id=a_id)

        human = self.mem_dt.get_human(u_id)
        self.assertIsNotNone(human)
        self.assertEqual(human.credits_balance, 100)

        @self.mem_dt.gate(cost_credits=40, deduct_cost=True)
        async def async_gated_action(user_id: str, agent_id: str) -> None:
            raise KeyError("Missing payload key")

        with self.assertRaises(KeyError):
            asyncio.run(async_gated_action(user_id=u_id, agent_id=a_id))

        human = self.mem_dt.get_human(u_id)
        self.assertIsNotNone(human)
        self.assertEqual(human.credits_balance, 100)

    def test_deterministic_sha256_striped_locks(self) -> None:
        """Verify that _get_user_lock maps user IDs to buckets deterministically
        via SHA-256 independent of Python's randomized PYTHONHASHSEED.
        """
        import hashlib
        for uid in ["alice", "bob", "carol", "user_12345", "agent_worker_99"]:
            lock = self.mem_dt._get_user_lock(uid)
            expected_bucket = int.from_bytes(hashlib.sha256(uid.encode("utf-8")).digest()[:4], "big") % 64
            expected_lock = self.mem_dt._striped_user_locks[expected_bucket]
            self.assertIs(lock, expected_lock)


if __name__ == "__main__":
    unittest.main()
