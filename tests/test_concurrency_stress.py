"""Concurrency and high-throughput stress tests for SQLite WAL and DualTrust."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import random
import tempfile
import time
import unittest
from dualtrust.crypto_ledger import CryptographicLedger
from dualtrust.engine import DualTrust
from dualtrust.models import AgentStatus, HumanTier, ViolationType
from dualtrust.storage import SQLiteStorage


class TestConcurrencyStress(unittest.TestCase):
    """Stress testing SQLite WAL mode, atomic balance operations, and concurrent hash chaining."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "stress_test.db")
        self.storage = SQLiteStorage(db_path=self.db_path)
        self.ledger = CryptographicLedger()
        self.engine = DualTrust(storage=self.storage, ledger=self.ledger)

    def tearDown(self) -> None:
        self.storage.checkpoint()
        self.storage.close()
        time.sleep(0.05)
        for path in [self.db_path, self.db_path + "-wal", self.db_path + "-shm"]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass
        if os.path.exists(self.temp_dir):
            try:
                os.rmdir(self.temp_dir)
            except OSError:
                pass

    def test_atomic_credit_deduction_race_condition(self) -> None:
        """Verify atomic deduction prevents race condition overdrafts under heavy multi-threading."""
        user_id = "user_stress_wallet"
        initial_balance = 500
        cost_per_request = 10
        total_requests = 70  # 70 * 10 = 700 attempted, only 50 should succeed
        expected_successes = initial_balance // cost_per_request

        self.storage.save_human(
            self.engine.register_human(user_id=user_id, social_credit=800, credits_balance=initial_balance)
        )

        def attempt_deduction() -> bool:
            return self.storage.deduct_credits(user_id=user_id, amount=cost_per_request)

        success_count = 0
        failure_count = 0

        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = [executor.submit(attempt_deduction) for _ in range(total_requests)]
            for future in as_completed(futures):
                if future.result():
                    success_count += 1
                else:
                    failure_count += 1

        # Invariant Assertions
        self.assertEqual(
            success_count,
            expected_successes,
            f"Expected exactly {expected_successes} deductions to succeed, got {success_count}",
        )
        self.assertEqual(
            failure_count,
            total_requests - expected_successes,
            f"Expected exactly {total_requests - expected_successes} deductions to fail, got {failure_count}",
        )

        final_profile = self.storage.get_human(user_id)
        self.assertIsNotNone(final_profile)
        self.assertEqual(
            final_profile.credits_balance,
            0,
            f"Expected remaining credits to be exactly 0, got {final_profile.credits_balance}",
        )

    def test_concurrent_1000_operations_high_throughput(self) -> None:
        """Simulate 1,000 concurrent operations across 20 worker threads.

        Verifies:
        1. Zero SQLite locks or OperationalErrors.
        2. Cryptographic ledger hash chain preserves 100% integrity.
        3. Merkle inclusion proofs verify deterministically under high write load.
        """
        # Register a cohort of users and agents
        num_users = 10
        num_agents = 10

        users = [f"stress_user_{i}" for i in range(num_users)]
        agents = [f"stress_agent_{i}" for i in range(num_agents)]

        for u in users:
            self.engine.register_human(user_id=u, social_credit=750, credits_balance=1000)
        for a in agents:
            self.engine.register_agent(agent_id=a, initial_trust=0.70)

        total_operations = 1000
        worker_threads = 20

        def run_worker_task(task_id: int) -> str:
            # Deterministically mix operations: 50% evaluate, 30% reward, 20% violation
            op_type = task_id % 10
            u = users[task_id % num_users]
            a = agents[task_id % num_agents]

            if op_type < 5:
                # 50% access evaluation with credit deduction
                verdict = self.engine.evaluate(
                    user_id=u,
                    agent_id=a,
                    min_human_score=600,
                    min_agent_score=0.40,
                    cost_credits=1,
                    deduct_cost=True,
                )
                return f"eval_{verdict.authorized}"
            elif op_type < 8:
                # 30% positive feedback reward
                new_trust = self.engine.reward_agent(agent_id=a, weight=0.5)
                return f"reward_{new_trust:.2f}"
            else:
                # 20% violation slashing
                event = self.engine.report_violation(
                    agent_id=a,
                    violation_type=ViolationType.USER_RAGE,
                    severity=1.0,
                    reporter_id=u,
                    details=f"Concurrent stress test violation {task_id}",
                )
                return f"violation_{event.event_id}"

        start_time = time.perf_counter()
        results = []
        with ThreadPoolExecutor(max_workers=worker_threads) as executor:
            futures = [executor.submit(run_worker_task, i) for i in range(total_operations)]
            for future in as_completed(futures):
                results.append(future.result())
        elapsed_seconds = time.perf_counter() - start_time

        # 1. Throughput verification
        self.assertEqual(len(results), total_operations)
        ops_per_second = total_operations / elapsed_seconds
        self.assertGreater(ops_per_second, 100, f"Expected > 100 ops/sec, achieved {ops_per_second:.1f}")

        # 2. Cryptographic ledger integrity verification
        is_valid, err = self.engine.verify_ledger_integrity()
        self.assertTrue(is_valid, f"Ledger integrity verification failed: {err}")
        self.assertGreaterEqual(self.engine.ledger.length, total_operations)

        # 3. Merkle inclusion proof verification under concurrent audit log
        merkle_root = self.engine.get_merkle_root()
        self.assertEqual(len(merkle_root), 64)

        # Sample 20 random blocks from across the entire run
        sample_indices = [random.randint(0, self.engine.ledger.length - 1) for _ in range(20)]
        for idx in sample_indices:
            leaf_hash, proof, root = self.engine.get_audit_proof(idx)
            self.assertEqual(root, merkle_root)
            self.assertTrue(
                self.engine.verify_audit_proof(leaf_hash, proof, root),
                f"Merkle inclusion proof invalid for sampled block {idx}",
            )


if __name__ == "__main__":
    unittest.main()
