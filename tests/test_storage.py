"""Unit tests for memory and SQLite storage backends."""

import os
import tempfile
import unittest
from dualtrust.models import (
    AgentProfile,
    AgentStatus,
    HumanProfile,
    HumanTier,
    ViolationEvent,
    ViolationType,
)
from dualtrust.storage import MemoryStorage, SQLiteStorage


class TestStorageBackends(unittest.TestCase):
    """Test storage persistence and query functionality across backends."""

    def test_memory_storage_operations(self) -> None:
        """Verify memory storage CRUD and violation indexing."""
        storage = MemoryStorage()

        # Agent save & get
        agent = AgentProfile(agent_id="ag_01", trust_score=0.88, status=AgentStatus.VERIFIED)
        storage.save_agent(agent)
        retrieved_agent = storage.get_agent("ag_01")
        self.assertIsNotNone(retrieved_agent)
        self.assertEqual(retrieved_agent.trust_score, 0.88)
        self.assertEqual(retrieved_agent.status, AgentStatus.VERIFIED)

        # Human save & get
        human = HumanProfile(user_id="usr_01", social_credit=850, credits_balance=250)
        storage.save_human(human)
        retrieved_human = storage.get_human("usr_01")
        self.assertIsNotNone(retrieved_human)
        self.assertEqual(retrieved_human.social_credit, 850)
        self.assertEqual(retrieved_human.tier, HumanTier.HIGH_CLEARANCE)

        # Record violation & fetch
        event = ViolationEvent(
            event_id="ev_01",
            agent_id="ag_01",
            violation_type=ViolationType.USER_RAGE,
            severity=3.0,
            details="User shouted at agent",
            penalty_applied=12.5,
        )
        storage.record_violation(event)
        # Credit deduction & deposit on MemoryStorage
        self.assertTrue(storage.deduct_credits("usr_01", 50))
        self.assertEqual(storage.get_human("usr_01").credits_balance, 200)
        self.assertFalse(storage.deduct_credits("usr_01", 300))
        new_bal = storage.add_credits("usr_01", 100)
        self.assertEqual(new_bal, 300)
        self.assertEqual(storage.get_human("usr_01").credits_balance, 300)

    def test_sqlite_storage_operations(self) -> None:
        """Verify persistent SQLite schema, atomic credits, and transactions."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        storage = None
        storage_reopened = None
        try:
            storage = SQLiteStorage(db_path=db_path)

            agent = AgentProfile(
                agent_id="sql_agent",
                alpha=4.5,
                beta=1.5,
                trust_score=0.75,
                status=AgentStatus.VERIFIED,
                violations_count=2,
            )
            storage.save_agent(agent)

            human = HumanProfile(user_id="sql_user", social_credit=920, credits_balance=500)
            storage.save_human(human)

            # Atomic deduction & addition
            self.assertTrue(storage.deduct_credits("sql_user", 200))
            self.assertEqual(storage.get_human("sql_user").credits_balance, 300)
            self.assertFalse(storage.deduct_credits("sql_user", 400))  # Exceeds 300
            new_bal = storage.add_credits("sql_user", 150)
            self.assertEqual(new_bal, 450)

            event = ViolationEvent(
                event_id="sql_ev_1",
                agent_id="sql_agent",
                violation_type=ViolationType.PROTOCOL_TRESPASS,
                severity=4.0,
                details="Attempted unauthorized queue bypass",
                penalty_applied=24.0,
            )
            storage.record_violation(event)

            # Re-read through fresh instance to guarantee persistence from disk
            storage_reopened = SQLiteStorage(db_path=db_path)
            loaded_agent = storage_reopened.get_agent("sql_agent")
            self.assertIsNotNone(loaded_agent)
            self.assertEqual(loaded_agent.violations_count, 2)
            self.assertEqual(loaded_agent.status, AgentStatus.VERIFIED)

            loaded_human = storage_reopened.get_human("sql_user")
            self.assertIsNotNone(loaded_human)
            self.assertEqual(loaded_human.tier, HumanTier.EXEMPLARY)
            self.assertEqual(loaded_human.credits_balance, 450)

            loaded_violations = storage_reopened.get_violations(agent_id="sql_agent")
            self.assertEqual(len(loaded_violations), 1)
            self.assertEqual(loaded_violations[0].violation_type, ViolationType.PROTOCOL_TRESPASS)

        finally:
            if storage:
                storage.checkpoint()
                storage.close()
            if storage_reopened:
                storage_reopened.checkpoint()
                storage_reopened.close()
            for p in [db_path, db_path + "-wal", db_path + "-shm"]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass


if __name__ == "__main__":
    unittest.main()
