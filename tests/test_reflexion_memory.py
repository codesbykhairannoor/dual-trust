"""Unit and persistence tests for Reflexion, Self-Monitoring, and Immortal Core Memory."""

import os
import tempfile
import time
import unittest
from dualtrust.engine import DualTrust
from dualtrust.models import HumanTier, RiskLevel, ViolationType
from dualtrust.storage import MemoryStorage, SQLiteStorage


class TestReflexionMemory(unittest.TestCase):
    """Test Princeton Reflexion verbal reinforcement and MemGPT-style immortal context."""

    def test_agent_standing_introspective_monitoring(self) -> None:
        """Agent can introspect its own standing, risk level, and quarantine proximity."""
        dt = DualTrust(storage=MemoryStorage())
        dt.register_agent("agent_inspector", initial_trust=0.88)

        standing = dt.get_agent_standing("agent_inspector")
        self.assertEqual(standing.agent_id, "agent_inspector")
        self.assertAlmostEqual(standing.trust_score, 0.88, places=2)
        self.assertEqual(standing.risk_level, RiskLevel.LOW)
        self.assertGreater(standing.quarantine_proximity, 0.60)
        self.assertIn("Trust: 0.88", standing.describe())

        # Cause violations to verify dynamic risk escalation
        dt.report_violation(
            agent_id="agent_inspector",
            violation_type=ViolationType.USER_RAGE,
            severity=3.0,
            details="User yelled at agent for sluggish response",
        )
        standing_medium = dt.get_agent_standing("agent_inspector")
        self.assertIn(standing_medium.risk_level, [RiskLevel.MEDIUM, RiskLevel.HIGH])

        # Quarantining forces CRITICAL risk level
        dt.quarantine_agent("agent_inspector", reason="Manual security quarantine")
        standing_crit = dt.get_agent_standing("agent_inspector")
        self.assertEqual(standing_crit.risk_level, RiskLevel.CRITICAL)

    def test_preflight_check_simulation(self) -> None:
        """Agent can perform preflight policy simulation prior to proposing tool calls."""
        dt = DualTrust(storage=MemoryStorage())
        dt.register_human("user_corp", social_credit=720, credits_balance=50)  # STANDARD tier
        dt.register_agent("tool_caller", initial_trust=0.80)

        # 1. Permitted action
        safe_check = dt.preflight_check(
            agent_id="tool_caller",
            user_id="user_corp",
            min_human_score=600,
            min_agent_score=0.50,
            cost_credits=10,
        )
        self.assertTrue(safe_check.can_execute)
        self.assertEqual(len(safe_check.block_reasons), 0)
        self.assertIn("approved", safe_check.recommendation.lower())

        # 2. Blocked due to excessive credit cost (balance is 50, cost is 100)
        expensive_check = dt.preflight_check(
            agent_id="tool_caller",
            user_id="user_corp",
            cost_credits=100,
        )
        self.assertFalse(expensive_check.can_execute)
        self.assertTrue(any("credits" in r.lower() for r in expensive_check.block_reasons))

        # 3. Blocked due to clearance tier mismatch (user is STANDARD, required is HIGH_CLEARANCE)
        tier_check = dt.preflight_check(
            agent_id="tool_caller",
            user_id="user_corp",
            required_tier=HumanTier.HIGH_CLEARANCE,
        )
        self.assertFalse(tier_check.can_execute)
        self.assertTrue(any("clearance tier" in r.lower() for r in tier_check.block_reasons))

    def test_episodic_reflection_recording(self) -> None:
        """Episodic lessons learned are recorded into storage and cryptographically hashed."""
        dt = DualTrust(storage=MemoryStorage())
        dt.register_agent("reflective_agent", initial_trust=0.75)

        r1 = dt.record_reflection(
            agent_id="reflective_agent",
            mistake_analysis="Invoked physical shuttle API without confirming human clearance tier.",
            corrective_action="Always run preflight_check on destination tier requirements prior to calling.",
        )
        self.assertIsNotNone(r1.reflection_id)
        self.assertEqual(r1.agent_id, "reflective_agent")
        self.assertIn("Lesson", r1.describe())

        # Verify cryptographic block created in audit ledger
        latest_block = dt.ledger.latest_block
        self.assertIsNotNone(latest_block)
        self.assertEqual(latest_block.event_type, "REFLEXION_LOGGED")
        self.assertEqual(latest_block.payload["reflection_id"], r1.reflection_id)

        # Retrieve reflections
        reflections = dt.get_agent_reflections("reflective_agent")
        self.assertEqual(len(reflections), 1)
        self.assertEqual(reflections[0].mistake_analysis, r1.mistake_analysis)

    def test_build_core_memory_prompt_schema(self) -> None:
        """MemGPT-inspired core memory prompt compiles standing, human credentials, and lessons."""
        dt = DualTrust(storage=MemoryStorage())
        dt.register_human("alice_neo", social_credit=850, credits_balance=200)
        dt.register_agent("smartglass_ai", initial_trust=0.82)

        dt.record_reflection(
            agent_id="smartglass_ai",
            mistake_analysis="Spoke over user during emergency alert display.",
            corrective_action="Yield audio channel immediately when priority HUD warning is active.",
        )

        prompt_context = dt.build_core_memory_prompt(agent_id="smartglass_ai", user_id="alice_neo")

        self.assertIn("<dualtrust_core_memory>", prompt_context)
        self.assertIn("smartglass_ai", prompt_context)
        self.assertIn("Trust Score: 0.82", prompt_context)
        self.assertIn("alice_neo", prompt_context)
        self.assertIn("Social Credit Score: 850", prompt_context)
        self.assertIn(f"Clearance Tier: {HumanTier.HIGH_CLEARANCE.value}", prompt_context)
        self.assertIn("Spoke over user during emergency alert display", prompt_context)
        self.assertIn("Yield audio channel immediately", prompt_context)
        self.assertIn("</dualtrust_core_memory>", prompt_context)

    def test_immortal_memory_persists_across_database_restarts(self) -> None:
        """Verify the 'Never Loses Memory Forever' invariant: reflections survive session restarts."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        agent_id = "eternal_agent_007"
        user_id = "commander_z"

        # Session 1: Agent acts, commits mistake, records reflection
        storage_1 = SQLiteStorage(db_path=db_path)
        dt_1 = DualTrust(storage=storage_1)
        dt_1.register_human(user_id=user_id, social_credit=900, credits_balance=500)
        dt_1.register_agent(agent_id=agent_id, initial_trust=0.85)

        dt_1.record_reflection(
            agent_id=agent_id,
            mistake_analysis="Attempted unauthorized queue jump at Sky-Port Neo-7.",
            corrective_action="Always wait for priority queue handshake confirmation from airspace controller.",
        )
        storage_1.checkpoint()
        storage_1.close()

        # Session 2: Complete restart in a fresh engine instance reading from disk
        storage_2 = None
        try:
            storage_2 = SQLiteStorage(db_path=db_path)
            dt_2 = DualTrust(storage=storage_2)

            # Agent introspects standing in new session
            standing = dt_2.get_agent_standing(agent_id)
            self.assertEqual(standing.agent_id, agent_id)
            self.assertEqual(standing.active_reflections_count, 1)

            # Retrieve immortal reflections
            saved_reflections = dt_2.get_agent_reflections(agent_id)
            self.assertEqual(len(saved_reflections), 1)
            self.assertIn("Attempted unauthorized queue jump", saved_reflections[0].mistake_analysis)

            # Core memory prompt is faithfully reconstructed from disk
            prompt = dt_2.build_core_memory_prompt(agent_id=agent_id, user_id=user_id)
            self.assertIn("<dualtrust_core_memory>", prompt)
            self.assertIn("commander_z", prompt)
            self.assertIn("Attempted unauthorized queue jump", prompt)

        finally:
            if storage_2:
                storage_2.checkpoint()
                storage_2.close()
            time.sleep(0.05)
            for p in [db_path, db_path + "-wal", db_path + "-shm"]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass


if __name__ == "__main__":
    unittest.main()
