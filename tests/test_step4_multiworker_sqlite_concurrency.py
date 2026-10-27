"""Step 4: Tests for multi-worker process synchronization, SQLite lock contention,
BEGIN IMMEDIATE write transactions, and PRAGMA data_version cache invalidation.
"""

import multiprocessing
import os
import shutil
import tempfile
import time
import unittest

from dualtrust.models import AgentProfile, AgentStatus, HumanProfile, HumanTier
from dualtrust.storage import SQLiteStorage


# Top-level functions for Windows multiprocessing spawn compatibility
def _worker_deduct_credits_job(db_path: str, user_id: str, amount: int, attempts: int, out_queue):
    storage = SQLiteStorage(db_path=db_path)
    successes = 0
    failures = 0
    for _ in range(attempts):
        if storage.deduct_credits(user_id=user_id, amount=amount):
            successes += 1
        else:
            failures += 1
    storage.close()
    out_queue.put((successes, failures))


def _worker_update_agent_job(db_path: str, agent_id: str, new_violations: int, ready_event, done_event):
    ready_event.wait(timeout=5.0)
    storage = SQLiteStorage(db_path=db_path)
    agent = storage.get_agent(agent_id)
    if agent:
        agent.violations_count = new_violations
        storage.save_agent(agent)
    storage.close()
    done_event.set()


def _worker_rapid_writers_job(db_path: str, worker_id: int, num_writes: int, out_queue):
    storage = SQLiteStorage(db_path=db_path)
    errors = 0
    for i in range(num_writes):
        try:
            agent = AgentProfile(
                agent_id=f"agent_w{worker_id}_{i}",
                alpha=10.0,
                beta=2.0,
                trust_score=0.83,
                status=AgentStatus.VERIFIED,
                violations_count=0,
            )
            storage.save_agent(agent)
        except Exception:
            errors += 1
    storage.close()
    out_queue.put(errors)


class TestStep4MultiWorkerSQLiteConcurrency(unittest.TestCase):
    """Test suite validating Multi-Worker Process Desynchronization and SQLite Lock Contention fixes."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_step4.db")
        self.storage = SQLiteStorage(db_path=self.db_path)

    def tearDown(self):
        self.storage.close()
        time.sleep(0.05)
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except Exception:
                pass

    def test_reentrant_write_transaction(self):
        """Verify _write_transaction supports nested reentrant calls cleanly."""
        agent = AgentProfile(
            agent_id="reentrant_agent",
            alpha=5.0,
            beta=1.0,
            trust_score=0.83,
            status=AgentStatus.VERIFIED,
        )
        with self.storage._write_transaction():
            self.storage.save_agent(agent)
            with self.storage._write_transaction():
                loaded = self.storage.get_agent("reentrant_agent")
                self.assertIsNotNone(loaded)
                self.assertEqual(loaded.agent_id, "reentrant_agent")

    def test_cross_process_data_version_cache_invalidation(self):
        """Verify memory cache is properly invalidated across OS processes via PRAGMA data_version."""
        # 1. Main process creates and caches agent
        agent = AgentProfile(
            agent_id="synced_agent",
            alpha=10.0,
            beta=1.0,
            trust_score=0.91,
            status=AgentStatus.VERIFIED,
            violations_count=0,
        )
        self.storage.save_agent(agent)

        # Confirm main process cached it
        cached_agent = self.storage.get_agent("synced_agent")
        self.assertEqual(cached_agent.violations_count, 0)
        self.assertIn("synced_agent", self.storage._cache_agents)

        # 2. Spawn separate OS worker process to update the agent in SQLite
        ready_event = multiprocessing.Event()
        done_event = multiprocessing.Event()

        p = multiprocessing.Process(
            target=_worker_update_agent_job,
            args=(self.db_path, "synced_agent", 42, ready_event, done_event),
        )
        p.start()
        ready_event.set()
        done_event.wait(timeout=5.0)
        p.join(timeout=5.0)

        # 3. Main process reads again - data_version increment must invalidate cache!
        updated_agent = self.storage.get_agent("synced_agent")
        self.assertIsNotNone(updated_agent)
        self.assertEqual(
            updated_agent.violations_count,
            42,
            "Main process returned stale cached data! PRAGMA data_version sync failed.",
        )

    def test_multi_process_credit_deduction_atomicity(self):
        """Stress-test 4 separate OS worker processes concurrently deducting credits with 0 overdrafts."""
        user_id = "multiworker_user"
        initial_balance = 500
        cost_per_request = 10
        total_success_possible = initial_balance // cost_per_request  # 50

        # Register human
        human = HumanProfile(
            user_id=user_id,
            social_credit=850,
            tier=HumanTier.EXEMPLARY,
            credits_balance=initial_balance,
        )
        self.storage.save_human(human)

        # 4 processes each run 25 deductions = 100 attempted deductions (worth 1000 credits)
        num_workers = 4
        attempts_per_worker = 25
        queue = multiprocessing.Queue()
        processes = []

        for _ in range(num_workers):
            p = multiprocessing.Process(
                target=_worker_deduct_credits_job,
                args=(self.db_path, user_id, cost_per_request, attempts_per_worker, queue),
            )
            processes.append(p)
            p.start()

        total_successes = 0
        total_failures = 0
        for _ in range(num_workers):
            succ, fail = queue.get(timeout=10.0)
            total_successes += succ
            total_failures += fail

        for p in processes:
            p.join(timeout=5.0)

        self.assertEqual(total_successes, total_success_possible)
        self.assertEqual(total_failures, (num_workers * attempts_per_worker) - total_success_possible)

        final_human = self.storage.get_human(user_id)
        self.assertEqual(final_human.credits_balance, 0)

    def test_multi_process_concurrent_writes_zero_deadlocks(self):
        """Stress-test 4 separate OS processes rapidly inserting records simultaneously without lock deadlocks."""
        num_workers = 4
        writes_per_worker = 25
        queue = multiprocessing.Queue()
        processes = []

        for w_id in range(num_workers):
            p = multiprocessing.Process(
                target=_worker_rapid_writers_job,
                args=(self.db_path, w_id, writes_per_worker, queue),
            )
            processes.append(p)
            p.start()

        total_errors = 0
        for _ in range(num_workers):
            errs = queue.get(timeout=10.0)
            total_errors += errs

        for p in processes:
            p.join(timeout=5.0)

        self.assertEqual(total_errors, 0, f"Expected 0 errors under multi-process contention, got {total_errors}")

        # Check all records saved
        for w_id in range(num_workers):
            for i in range(writes_per_worker):
                agent = self.storage.get_agent(f"agent_w{w_id}_{i}")
                self.assertIsNotNone(agent)


if __name__ == "__main__":
    unittest.main()
