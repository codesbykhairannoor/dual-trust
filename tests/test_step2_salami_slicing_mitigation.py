"""Unit and attack simulation tests for Step 2: 'Low-and-Slow' Salami Slicing Attack Mitigation."""

import os
import tempfile
import unittest
from dualtrust.engine import DualTrust
from dualtrust.math_engine import ReputationMath
from dualtrust.models import AgentProfile, AgentStatus, ViolationType
from dualtrust.storage import MemoryStorage, SQLiteStorage


class TestStep2SalamiSlicingMitigation(unittest.TestCase):
    """Test suite verifying mitigation of 'Low-and-Slow' Salami Slicing attacks on Math Engine."""

    def setUp(self) -> None:
        self.math = ReputationMath(
            penalty_multiplier=3.5,
            slashing_exponent=1.8,
            minor_infraction_threshold=3,
            recovery_clean_window=20,
        )
        self.mem_dt = DualTrust(math_engine=self.math)

        self.temp_dir = tempfile.mkdtemp()
        self.sqlite_db_path = os.path.join(self.temp_dir, "step2_test.db")
        self.sql_storage = SQLiteStorage(db_path=self.sqlite_db_path)
        self.sql_dt = DualTrust(storage=self.sql_storage, math_engine=self.math)

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

    def test_single_minor_infraction_linear_penalty(self) -> None:
        """A single transient minor glitch (severity <= 1.5) must not escalate violations_count."""
        agent = AgentProfile(agent_id="honest_agent", alpha=10.0, beta=1.0, trust_score=0.91)

        score, delta, is_quarantined = self.math.apply_violation_penalty(
            agent,
            violation_type=ViolationType.RESOURCE_EXHAUSTION,
            severity=1.2,
            reporter_credibility=1.0,
        )

        self.assertEqual(agent.minor_infractions, 1)
        self.assertEqual(agent.violations_count, 0)
        self.assertFalse(is_quarantined)
        # Linear scaling delta: kp * severity * 1^1.0 = 3.5 * 1.2 * 1 = 4.2
        self.assertAlmostEqual(delta, 3.5 * 1.2, places=4)

    def test_clean_streak_recovery_decays_minor_infractions(self) -> None:
        """Honest agent with minor infraction recovers via consecutive clean actions."""
        agent = AgentProfile(agent_id="recovering_agent", alpha=10.0, beta=1.0, trust_score=0.91)

        # 1 minor infraction
        self.math.apply_violation_penalty(
            agent,
            violation_type=ViolationType.RESOURCE_EXHAUSTION,
            severity=1.3,
            reporter_credibility=1.0,
        )
        self.assertEqual(agent.minor_infractions, 1)

        # 4 clean actions: streak is 4 (< 5), minor_infractions still 1
        for _ in range(4):
            self.math.apply_positive_feedback(agent)
        self.assertEqual(agent.minor_infractions, 1)

        # 5th clean action: streak reaches 5, minor_infractions decays to 0
        self.math.apply_positive_feedback(agent)
        self.assertEqual(agent.minor_infractions, 0)

    def test_salami_slicing_attack_escalation(self) -> None:
        """Simulate an attacker executing low-and-slow minor infractions to bypass slashing.
        
        Invariant:
        - Infractions 1 & 2 accumulate in minor_infractions without increasing violations_count.
        - Infraction 3 hits threshold (3), escalating violations_count to 1 with power-law slashing.
        - Infraction 6 escalates violations_count to 2 with compounded power-law multiplier.
        """
        agent = AgentProfile(agent_id="salami_attacker", alpha=20.0, beta=1.0, trust_score=0.95)

        # Infraction 1 (severity 1.4)
        _, delta_1, _ = self.math.apply_violation_penalty(
            agent, violation_type=ViolationType.RESOURCE_EXHAUSTION, severity=1.4, reporter_credibility=1.0
        )
        self.assertEqual(agent.minor_infractions, 1)
        self.assertEqual(agent.violations_count, 0)

        # Infraction 2 (severity 1.4)
        _, delta_2, _ = self.math.apply_violation_penalty(
            agent, violation_type=ViolationType.RESOURCE_EXHAUSTION, severity=1.4, reporter_credibility=1.0
        )
        self.assertEqual(agent.minor_infractions, 2)
        self.assertEqual(agent.violations_count, 0)
        self.assertAlmostEqual(delta_1, delta_2)

        # Infraction 3 (severity 1.4) -> Escalation trigger!
        _, delta_3, _ = self.math.apply_violation_penalty(
            agent, violation_type=ViolationType.RESOURCE_EXHAUSTION, severity=1.4, reporter_credibility=1.0
        )
        self.assertEqual(agent.minor_infractions, 0)
        self.assertEqual(agent.violations_count, 1)
        self.assertGreater(delta_3, 0)

        # Infraction 4 & 5
        self.math.apply_violation_penalty(
            agent, violation_type=ViolationType.RESOURCE_EXHAUSTION, severity=1.4, reporter_credibility=1.0
        )
        self.assertEqual(agent.minor_infractions, 1)
        self.assertEqual(agent.violations_count, 1)

        self.math.apply_violation_penalty(
            agent, violation_type=ViolationType.RESOURCE_EXHAUSTION, severity=1.4, reporter_credibility=1.0
        )
        self.assertEqual(agent.minor_infractions, 2)
        self.assertEqual(agent.violations_count, 1)

        # Infraction 6 -> Second Escalation trigger!
        _, delta_6, _ = self.math.apply_violation_penalty(
            agent, violation_type=ViolationType.RESOURCE_EXHAUSTION, severity=1.4, reporter_credibility=1.0
        )
        self.assertEqual(agent.minor_infractions, 0)
        self.assertEqual(agent.violations_count, 2)

        # Delta 6 must be substantially larger than Delta 1 due to 2^1.8 power-law multiplier
        expected_multiplier = 2.0 ** 1.8
        self.assertGreater(delta_6, delta_1 * 3.0)
        self.assertAlmostEqual(delta_6, delta_1 * expected_multiplier, places=4)

    def test_salami_slicing_leads_to_eventual_quarantine(self) -> None:
        """Sustained micro-infractions eventually isolate the rogue agent into QUARANTINED."""
        self.mem_dt.register_agent("persistent_salami_bot", initial_trust=0.70)

        # Fire 12 minor violations through engine
        for i in range(12):
            self.mem_dt.report_violation(
                agent_id="persistent_salami_bot",
                violation_type=ViolationType.RESOURCE_EXHAUSTION,
                severity=1.5,
                reporter_id="system",
            )

        agent = self.mem_dt.get_agent("persistent_salami_bot")
        self.assertIsNotNone(agent)
        # 12 minor infractions / 3 = 4 violations_count
        self.assertEqual(agent.violations_count, 4)
        self.assertEqual(agent.status, AgentStatus.QUARANTINED)
        self.assertLess(agent.trust_score, 0.20)

    def test_sybil_untrusted_reporter_cannot_pump_minor_infractions(self) -> None:
        """Untrusted reporters (< 0.20) cannot increment minor_infractions counter."""
        self.mem_dt.register_agent("probation_target", initial_trust=0.50)

        for i in range(10):
            self.mem_dt.report_violation(
                agent_id="probation_target",
                violation_type=ViolationType.RESOURCE_EXHAUSTION,
                severity=1.2,
                reporter_id=f"sybil_fake_reporter_{i}",
            )

        agent = self.mem_dt.get_agent("probation_target")
        self.assertIsNotNone(agent)
        self.assertEqual(agent.minor_infractions, 0)
        self.assertEqual(agent.violations_count, 0)
        self.assertNotEqual(agent.status, AgentStatus.QUARANTINED)

    def test_sqlite_storage_minor_infractions_persistence(self) -> None:
        """Verify SQLiteStorage persists and restores minor_infractions across reloads."""
        a_id = "sql_minor_test"
        agent = self.sql_dt.register_agent(a_id, initial_trust=0.80)
        agent.minor_infractions = 2
        agent.violations_count = 1
        self.sql_storage.save_agent(agent)

        loaded_agent = self.sql_storage.get_agent(a_id)
        self.assertIsNotNone(loaded_agent)
        self.assertEqual(loaded_agent.minor_infractions, 2)
        self.assertEqual(loaded_agent.violations_count, 1)

    def test_pardon_and_standing_minor_infractions(self) -> None:
        """Verify dt.pardon_agent resets minor_infractions and get_agent_standing reports it."""
        a_id = "pardon_minor_agent"
        agent = self.mem_dt.register_agent(a_id, initial_trust=0.80)
        agent.minor_infractions = 2
        agent.violations_count = 1
        self.mem_dt.quarantine_agent(a_id)

        # Standing reports minor infractions
        standing = self.mem_dt.get_agent_standing(a_id)
        self.assertEqual(standing.minor_infractions, 2)

        # Pardon resets all counters
        pardoned = self.mem_dt.pardon_agent(a_id)
        self.assertEqual(pardoned.minor_infractions, 0)
        self.assertEqual(pardoned.violations_count, 0)

        standing_after = self.mem_dt.get_agent_standing(a_id)
        self.assertEqual(standing_after.minor_infractions, 0)
        self.assertEqual(standing_after.violations_count, 0)

    def test_interleaved_salami_slicing_attack_blocked(self) -> None:
        """Adversarial Red-Team Vector: Attacker attempts to interleave minor infractions
        with clean actions (2 glitches -> 10 clean actions -> 2 glitches -> 10 clean actions)
        to stay perpetually below the minor_infraction_threshold of 3.
        
        Invariant:
        - Lifetime minor infractions accumulator cannot be erased by clean streaks.
        - Cumulative infractions inevitably trigger violations_count escalation and power-law slashing.
        """
        agent = AgentProfile(agent_id="adversarial_interleaver", alpha=20.0, beta=1.0, trust_score=0.95)

        # Round 1: 2 minor infractions (severity 1.3)
        self.math.apply_violation_penalty(agent, ViolationType.RESOURCE_EXHAUSTION, severity=1.3)
        self.math.apply_violation_penalty(agent, ViolationType.RESOURCE_EXHAUSTION, severity=1.3)
        self.assertEqual(agent.minor_infractions, 2)
        self.assertEqual(agent.lifetime_minor_infractions, 2)
        self.assertEqual(agent.violations_count, 0)

        # Attacker executes 10 clean dummy actions to scrub minor_infractions to 0
        for _ in range(10):
            self.math.apply_positive_feedback(agent)
        self.assertEqual(agent.minor_infractions, 0)
        self.assertEqual(agent.lifetime_minor_infractions, 2)  # Lifetime counter preserved!

        # Round 2: 1 more minor infraction (Cumulative lifetime reaches 3 = threshold!)
        _, delta, _ = self.math.apply_violation_penalty(agent, ViolationType.RESOURCE_EXHAUSTION, severity=1.3)

        # Invariant: Lifetime threshold triggers strike escalation despite window having been scrubbed!
        self.assertEqual(agent.lifetime_minor_infractions, 3)
        self.assertEqual(agent.violations_count, 1)
        self.assertEqual(agent.minor_infractions, 0)
        # Power-law slashing applied
        self.assertGreater(delta, 0.0)


if __name__ == "__main__":
    unittest.main()
